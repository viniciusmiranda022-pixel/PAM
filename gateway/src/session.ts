/**
 * Orquestracao de sessao (agnostica de protocolo — PR-16): valida o token
 * efemero, resolve destino/credencial do banco, conecta o TCP e delega a
 * TERMINACAO DO HANDSHAKE ao adapter do protocolo do asset. Faz o splice binario
 * ate o fim. Nunca ha proxy TCP generico (HR-08/HR-09). Todo caminho de saida
 * encerra os dois sockets e audita (HR-10).
 */
import net from "node:net";
import { WebSocket } from "ws";
import type { IncomingMessage } from "node:http";
import { WsByteStream } from "./byte-stream.js";
import { withTimeout } from "./timeout.js";
import { getAdapter } from "./adapters/index.js";
import { AdapterHandshakeError, ADAPTER_CLOSE } from "./adapters/types.js";
import { resolveCredential, tlsClientOptions } from "./config.js";
import { Db, sha256 } from "./db.js";
import { registerSession, unregisterSession } from "./registry.js";
import { metrics } from "./metrics.js";
import { SessionRecorder } from "./recorder.js";
import path from "node:path";

// Codigos de close do WebSocket (docs/api-contract.md secao 4). Os codigos de
// falha de handshake ficam em ADAPTER_CLOSE (donos do adapter).
const CLOSE = {
  NORMAL: 1000,
  TOKEN_INVALID: 4401,
  SESSION_INVALID: 4403,
  CREDENTIAL_FAIL: 4502,
  ASSET_FAIL: 4503,
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

// IP da conexao (fallback de auditoria — o autoritativo e fixado pelo backend
// na criacao da sessao). O X-Forwarded-For so e aceito com GATEWAY_TRUST_PROXY
// (compose liga: o nginx sobrescreve o header com $remote_addr); e usa-se o
// ULTIMO valor — o unico escrito por um proxy confiavel, nunca pelo cliente.
function clientIp(req: IncomingMessage): string | null {
  if (process.env.GATEWAY_TRUST_PROXY === "true") {
    const fwd = req.headers["x-forwarded-for"];
    if (typeof fwd === "string" && fwd.length > 0) {
      const parts = fwd.split(",");
      return parts[parts.length - 1].trim();
    }
  }
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
  let socket: net.Socket | null = null; // TCP cru (base do TLS, se houver)
  let assetSock: NodeJS.WritableStream & { destroyed?: boolean } | null = null; // efetivo (TLS ou cru)
  let ended = false;
  let startedAt = 0;
  let recorder: SessionRecorder | null = null;
  const end = async (
    status: "closed" | "failed" | "terminated",
    reason: string,
    closeCode: number,
  ): Promise<void> => {
    if (ended) return;
    ended = true;
    unregisterSession(session.sessionId);
    recorder?.close();
    if (startedAt) metrics.sessionEnded(reason);
    try {
      (assetSock as unknown as net.Socket | null)?.destroy?.();
      socket?.destroy(); // garante o TCP base fechado mesmo com TLS por cima
    } catch { /* ignore */ }
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close(closeCode, reason.slice(0, 120));
    }
    await db.markEnded(session.sessionId, status, reason);
    const durationSeconds = startedAt ? Math.round((Date.now() - startedAt) / 1000) : 0;
    await db.audit("session.ended", { ...base, details: { endReason: reason, durationSeconds, protocol: session.protocol } });
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

    // Resolve o adapter pelo protocolo do asset. Protocolo sem adapter
    // registrado e RECUSADO — nunca ha fallback para proxy generico (HR-09).
    const adapter = getAdapter(session.protocol);
    if (!adapter) {
      await db.audit("gateway.protocol_unsupported", { ...base, details: { protocol: session.protocol } });
      return end("failed", "protocol_unsupported", CLOSE.SESSION_INVALID);
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

    // Terminacao do handshake dos dois lados, delegada ao adapter do protocolo.
    // O adapter valida o banner do protocolo (HR-08) e nunca envia credencial ao
    // navegador (HR-05); em falha, lanca AdapterHandshakeError (evento + close).
    const wsStream = new WsByteStream(ws);
    let serverInit: Buffer | null;
    let assetStream: import("./byte-stream-types.js").ByteStreamReader;
    try {
      const result = await adapter.connect({
        assetSocket: socket,
        credential: password,
        tlsRequired: session.tlsRequired,
        tlsOptions: tlsClientOptions(),
        ws,
        wsStream,
        wsSend: (b) => ws.send(b, { binary: true }),
        timeoutMs: handshakeTimeoutMs,
        withTimeout,
      });
      serverInit = result.recordingPreamble;
      assetStream = result.assetStream;
      assetSock = result.effectiveAssetSocket as unknown as typeof assetSock; // TLS quando VeNCrypt
      if (result.tlsEstablished) await db.audit("gateway.tls_established", { ...base });
    } catch (err) {
      if (err instanceof AdapterHandshakeError) {
        await db.audit(err.auditEvent, { ...base });
        return end("failed", err.reason, err.closeCode);
      }
      await db.audit("gateway.asset_handshake_failed", { ...base });
      return end("failed", "asset_handshake_failed", ADAPTER_CLOSE.ASSET_FAIL);
    }

    // Pipe RFB estabelecido dos dois lados. Registra o teardown ANTES de qualquer
    // await abaixo (markStarted/audit/recording): se o browser desconectar nessa
    // janela, o evento 'close' nao pode se perder — senao a sessao vaza o TCP do
    // asset (HR-07) e 'session.ended' nunca e auditado (HR-10).
    const effAsset = assetSock as unknown as net.Socket;
    effAsset.on("close", () => void end("closed", "asset_disconnect", CLOSE.NORMAL));
    effAsset.on("error", () => void end("failed", "asset_error", CLOSE.ASSET_FAIL));
    ws.on("close", () => void end("closed", "client_disconnect", CLOSE.NORMAL));
    ws.on("error", () => void end("failed", "client_error", CLOSE.NORMAL));
    // Registra no watchdog na MESMA volta do event loop que os handlers acima, antes
    // de qualquer await: se o browser desconectar durante o setup, o unregister em
    // end() nunca ocorre antes do register — evita entrada fantasma no registro de
    // sessoes ativas. Watchdog: derruba WS+TCP ao vivo quando o backend termina.
    registerSession(session.sessionId, (reason) =>
      void end("terminated", reason, CLOSE.SESSION_INVALID),
    );

    // Sessao estabelecida.
    startedAt = Date.now();
    await db.markStarted(session.sessionId);
    await db.audit("session.started", { ...base, details: { protocol: session.protocol } });
    metrics.sessionStarted();

    // Gravacao (Fase 5.1): tela (servidor->cliente) + ServerInit p/ playback.
    // Teclado do usuario (cliente->servidor) NAO e gravado (pode conter senhas
    // digitadas dentro da sessao — coerente com HR-06).
    const recordingsDir = process.env.RECORDINGS_DIR;
    if (session.recordSessions && recordingsDir && serverInit) {
      try {
        const filePath = path.join(recordingsDir, `${session.sessionId}.pamrec`);
        recorder = new SessionRecorder(filePath, serverInit);
        await db.setRecordingPath(session.sessionId, filePath);
        await db.audit("recording.started", { ...base });
      } catch {
        recorder = null;
        await db.audit("recording.error", { ...base });
      }
    }

    // Se o browser (ou o asset) desconectou durante o setup acima, o teardown ja
    // rodou via os handlers registrados logo apos o handshake — nao inicia o splice
    // sobre sockets ja destruidos.
    if (ended) return;

    // Splice binario transparente. Flush de qualquer residual bufferizado.
    const assetResidual = assetStream.detach();
    if (assetResidual.length) {
      ws.send(assetResidual, { binary: true });
      recorder?.write(assetResidual);
    }
    const wsResidual = wsStream.detach();
    if (wsResidual.length) assetSock!.write(wsResidual);

    // Splice sobre o socket EFETIVO (o TLS quando houve VeNCrypt). Os handlers de
    // close/error ja foram registrados acima (antes dos awaits) para nao perder o
    // encerramento; aqui liga-se apenas o fluxo de dados.
    effAsset.on("data", (d: Buffer) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(d, { binary: true });
      recorder?.write(d);
    });
    ws.on("message", (d: Buffer, isBinary: boolean) => {
      if (isBinary && !effAsset.destroyed) effAsset.write(d);
    });
  } catch (err) {
    await db.audit("gateway.unexpected_error", { ...base });
    await end("failed", "unexpected_error", CLOSE.ASSET_FAIL);
  }
}
