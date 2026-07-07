/**
 * Orquestracao de uma sessao VNC: valida o token efemero, conecta ao asset,
 * termina o handshake RFB dos dois lados e faz o splice binario ate o fim.
 * Todo caminho de saida encerra os dois sockets e audita (HR-10).
 */
import net from "node:net";
import { WebSocket } from "ws";
import type { IncomingMessage } from "node:http";
import { SocketByteStream, WsByteStream } from "./byte-stream.js";
import { assetHandshake, browserHandshake, withTimeout } from "./handshake.js";
import { RfbError } from "./rfb.js";
import { resolveCredential } from "./config.js";
import { Db, sha256 } from "./db.js";

// Codigos de close do WebSocket (docs/api-contract.md secao 4).
const CLOSE = {
  NORMAL: 1000,
  RFB_CLIENT_INVALID: 4400,
  TOKEN_INVALID: 4401,
  SESSION_INVALID: 4403,
  CREDENTIAL_FAIL: 4502,
  ASSET_FAIL: 4503,
  VNC_AUTH_FAIL: 4504,
} as const;

function tokenFromSubprotocol(req: IncomingMessage): string | null {
  const header = req.headers["sec-websocket-protocol"];
  if (!header) return null;
  const parts = Array.isArray(header) ? header.join(",") : header;
  for (const raw of parts.split(",")) {
    const p = raw.trim();
    if (p.startsWith("pam.token.")) return p.slice("pam.token.".length);
  }
  return null;
}

function clientIp(req: IncomingMessage): string | null {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.length > 0) return fwd.split(",")[0].trim();
  return req.socket.remoteAddress ?? null;
}

export async function runSession(ws: WebSocket, req: IncomingMessage, db: Db): Promise<void> {
  const connectionIp = clientIp(req);
  const handshakeTimeoutMs = Number(process.env.HANDSHAKE_TIMEOUT_MS ?? 10_000);

  const token = tokenFromSubprotocol(req);
  if (!token) {
    await db.audit("session.token_rejected", { sourceIp: connectionIp, details: { reason: "sem token" } });
    ws.close(CLOSE.TOKEN_INVALID, "token ausente");
    return;
  }

  const session = await db.consumeToken(sha256(token));
  if (!session) {
    await db.audit("session.token_rejected", { sourceIp: connectionIp, details: { reason: "token invalido/expirado/usado" } });
    ws.close(CLOSE.TOKEN_INVALID, "token invalido");
    return;
  }

  // IP de origem: o fixado na criacao da sessao (autoritativo p/ HR-10); cai
  // para o IP da conexao apenas se ausente.
  const sourceIp = session.clientIp ?? connectionIp;
  const base = { userId: session.userId, assetId: session.assetId, sessionId: session.sessionId, sourceIp };

  // Estado de encerramento — garante teardown e auditoria uma unica vez.
  let socket: net.Socket | null = null;
  let ended = false;
  let startedAt = 0;
  const end = async (
    status: "closed" | "failed" | "terminated",
    reason: string,
    closeCode: number,
  ): Promise<void> => {
    if (ended) return;
    ended = true;
    try {
      socket?.destroy();
    } catch { /* ignore */ }
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close(closeCode, reason.slice(0, 120));
    }
    await db.markEnded(session.sessionId, status, reason);
    const durationSeconds = startedAt ? Math.round((Date.now() - startedAt) / 1000) : 0;
    await db.audit("session.ended", { ...base, details: { endReason: reason, durationSeconds } });
  };

  try {
    if (session.assetStatus !== "active") {
      await db.audit("session.denied", { ...base, details: { reason: "asset_inactive" } });
      return end("failed", "asset_inactive", CLOSE.SESSION_INVALID);
    }

    // Re-checagem da allowlist no gateway (HR-04, defesa em profundidade).
    if (!(await db.isPortAllowed(session.port))) {
      await db.audit("gateway.port_blocked", { ...base, details: { port: session.port } });
      return end("failed", "port_blocked", CLOSE.ASSET_FAIL);
    }

    let password: string;
    try {
      password = await resolveCredential(session.credentialRef);
      await db.audit("credential.read", { ...base }); // sem valor do segredo (HR-06)
    } catch {
      await db.audit("credential.error", { ...base });
      return end("failed", "credential_error", CLOSE.CREDENTIAL_FAIL);
    }

    // Conecta ao asset — destino vem SOMENTE do banco (HR-03).
    socket = net.connect({ host: session.ip, port: session.port });
    try {
      await withTimeout(
        new Promise<void>((resolve, reject) => {
          socket!.once("connect", resolve);
          socket!.once("error", reject);
        }),
        handshakeTimeoutMs,
        "tcp-connect",
      );
    } catch {
      await db.audit("gateway.connect_failed", { ...base });
      return end("failed", "asset_connect_failed", CLOSE.ASSET_FAIL);
    }

    const assetStream = new SocketByteStream(socket);
    let serverInit: Buffer;
    try {
      serverInit = await withTimeout(
        assetHandshake(assetStream, (b) => socket!.write(b), password),
        handshakeTimeoutMs,
        "asset-rfb",
      );
    } catch (err) {
      const isAuth = err instanceof RfbError && /autentica/.test(err.message);
      const isBanner = err instanceof RfbError && /banner|RFB/.test(err.message);
      if (isBanner) await db.audit("gateway.banner_mismatch", { ...base });
      else if (isAuth) await db.audit("gateway.vnc_auth_failed", { ...base });
      else await db.audit("gateway.asset_handshake_failed", { ...base });
      return end("failed", isAuth ? "vnc_auth_failed" : "asset_handshake_failed",
        isAuth ? CLOSE.VNC_AUTH_FAIL : CLOSE.ASSET_FAIL);
    }

    const wsStream = new WsByteStream(ws);
    try {
      await withTimeout(
        browserHandshake(wsStream, (b) => ws.send(b, { binary: true }), serverInit),
        handshakeTimeoutMs,
        "browser-rfb",
      );
    } catch {
      await db.audit("gateway.client_handshake_failed", { ...base });
      return end("failed", "client_handshake_failed", CLOSE.RFB_CLIENT_INVALID);
    }

    // Sessao estabelecida.
    startedAt = Date.now();
    await db.markStarted(session.sessionId);
    await db.audit("session.started", { ...base });

    // Splice binario transparente. Flush de qualquer residual bufferizado.
    const assetResidual = assetStream.detach();
    if (assetResidual.length) ws.send(assetResidual, { binary: true });
    const wsResidual = wsStream.detach();
    if (wsResidual.length) socket.write(wsResidual);

    socket.on("data", (d) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(d, { binary: true });
    });
    ws.on("message", (d: Buffer, isBinary: boolean) => {
      if (isBinary && socket && !socket.destroyed) socket.write(d);
    });

    socket.on("close", () => void end("closed", "asset_disconnect", CLOSE.NORMAL));
    socket.on("error", () => void end("failed", "asset_error", CLOSE.ASSET_FAIL));
    ws.on("close", () => void end("closed", "client_disconnect", CLOSE.NORMAL));
    ws.on("error", () => void end("failed", "client_error", CLOSE.NORMAL));
  } catch (err) {
    await db.audit("gateway.unexpected_error", { ...base });
    await end("failed", "unexpected_error", CLOSE.ASSET_FAIL);
  }
}
