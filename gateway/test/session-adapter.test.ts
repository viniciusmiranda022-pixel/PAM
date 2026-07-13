/**
 * runSession end-to-end in-process (PR-16): prova que (a) o protocolo VNC
 * continua funcionando pela camada de adapter, com `protocol=vnc` na auditoria,
 * e (b) protocolo sem adapter registrado e RECUSADO (nunca proxy generico).
 * Sem Postgres e sem rede externa: fake Db + fake asset RFB + par WebSocket real.
 */
import net from "node:net";
import { beforeAll, describe, expect, it } from "vitest";
import { WebSocket, WebSocketServer } from "ws";
import type { IncomingMessage } from "node:http";
import { runSession } from "../src/session.ts";
import type { ConsumedSession } from "../src/db.ts";

// O gateway resolve a credencial (provider env:) antes de conectar. O asset de
// teste oferece security type None, entao a senha nao chega a ser usada.
beforeAll(() => { process.env.PAM_TEST_VNC = "labpw"; });

// ── Fake Db: devolve a sessao pedida e registra os eventos de auditoria ──────
type AuditCall = { event: string; details?: Record<string, unknown> };
function fakeDb(session: ConsumedSession | null) {
  const audits: AuditCall[] = [];
  return {
    audits,
    consumeToken: async () => session,
    isPortAllowed: async () => true,
    markStarted: async () => {},
    markEnded: async () => {},
    setRecordingPath: async () => {},
    audit: async (event: string, fields: { details?: Record<string, unknown> } = {}) => {
      audits.push({ event, details: fields.details });
    },
  };
}

function baseSession(over: Partial<ConsumedSession>): ConsumedSession {
  return {
    sessionId: "11111111-1111-4111-8111-111111111111",
    userId: "22222222-2222-4222-8222-222222222222",
    assetId: "33333333-3333-4333-8333-333333333333",
    protocol: "vnc",
    ip: "127.0.0.1",
    port: 5901,
    credentialRef: "env:PAM_TEST_VNC",
    assetStatus: "active",
    clientIp: "203.0.113.9",
    recordSessions: false,
    tlsRequired: false,
    ...over,
  };
}

/** Asset RFB minimo (security type None): fala o lado servidor do RFB 3.8. */
function fakeRfbAsset(): Promise<{ port: number; close: () => void }> {
  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    const need = (n: number) => new Promise<Buffer>((resolve) => {
      const tryTake = () => {
        if (buf.length >= n) { const b = buf.subarray(0, n); buf = buf.subarray(n); resolve(b); }
        else sock.once("data", (d) => { buf = Buffer.concat([buf, d]); tryTake(); });
      };
      tryTake();
    });
    (async () => {
      sock.write(Buffer.from("RFB 003.008\n"));
      await need(12);                        // versao do cliente (gateway)
      sock.write(Buffer.from([1, 1]));       // count=1, security type None
      await need(1);                         // gateway seleciona None
      sock.write(Buffer.from([0, 0, 0, 0])); // SecurityResult OK
      await need(1);                         // ClientInit
      const name = Buffer.from("fake-asset");
      const head = Buffer.alloc(24);
      head.writeUInt16BE(800, 0); head.writeUInt16BE(600, 2);
      head.writeUInt32BE(name.length, 20);
      sock.write(Buffer.concat([head, name])); // ServerInit
    })().catch(() => sock.destroy());
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => {
    const port = (server.address() as net.AddressInfo).port;
    resolve({ port, close: () => server.close() });
  }));
}

/** Executa runSession contra um par WebSocket real; devolve o db (com auditoria). */
async function runWithClient(
  session: ConsumedSession | null,
  driveBrowser: (client: WebSocket) => Promise<void>,
) {
  const db = fakeDb(session);
  const wss = new WebSocketServer({ port: 0, handleProtocols: (p) => (p.has("binary") ? "binary" : false) });
  await new Promise((r) => wss.once("listening", r));
  const port = (wss.address() as net.AddressInfo).port;

  const done = new Promise<void>((resolve) => {
    wss.on("connection", (ws, req) => {
      runSession(ws, req as IncomingMessage, db as never).finally(() => resolve());
    });
  });

  const client = new WebSocket(`ws://127.0.0.1:${port}/gateway/vnc/x`, ["binary", "pam.token.tok"]);
  await new Promise((r) => client.once("open", r));
  await driveBrowser(client);                       // resolve ao ver o ServerInit
  await new Promise((r) => setTimeout(r, 100));      // deixa markStarted/audit rodar
  client.close();                                    // encerra a sessao (runSession retorna)
  await done;
  wss.close();
  return db;
}

/** Lado navegador (noVNC) do handshake RFB, roteirizado por contagem de bytes. */
function browserClient(): { drive: (c: WebSocket) => Promise<void>; sawServerInit: () => boolean } {
  let sawServerInit = false;
  const drive = (c: WebSocket) => new Promise<void>((resolve, reject) => {
    let buf = Buffer.alloc(0);
    let stage = 0;
    c.on("message", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 12) { // ServerVersion
        buf = buf.subarray(12); stage = 1;
        c.send(Buffer.from("RFB 003.008\n"));
      }
      if (stage === 1 && buf.length >= 2) {   // [count, None]
        buf = buf.subarray(2); stage = 2;
        c.send(Buffer.from([1]));             // seleciona None
      }
      if (stage === 2 && buf.length >= 4) {   // SecurityResult
        buf = buf.subarray(4); stage = 3;
        c.send(Buffer.from([1]));             // ClientInit
      }
      if (stage === 3 && buf.length >= 24) {  // ServerInit
        sawServerInit = true; stage = 4;
        resolve();
      }
    });
    c.on("error", reject);
  });
  return { drive, sawServerInit: () => sawServerInit };
}

describe("runSession com adapter (PR-16)", () => {
  it("protocolo vnc: handshake completo e auditoria com protocol=vnc", async () => {
    const asset = await fakeRfbAsset();
    const bc = browserClient();
    const db = await runWithClient(baseSession({ port: asset.port }), bc.drive);
    asset.close();

    expect(bc.sawServerInit()).toBe(true);
    const started = db.audits.find((a) => a.event === "session.started");
    expect(started?.details?.protocol).toBe("vnc");
  });

  it("protocolo sem adapter (rdp): recusado, sem conectar", async () => {
    const db = fakeDb(baseSession({ protocol: "rdp" }));
    const wss = new WebSocketServer({ port: 0, handleProtocols: () => "binary" });
    await new Promise((r) => wss.once("listening", r));
    const port = (wss.address() as net.AddressInfo).port;
    let closeCode = 0;
    const done = new Promise<void>((resolve) => {
      wss.on("connection", (ws, req) => { runSession(ws, req as IncomingMessage, db as never).finally(() => resolve()); });
    });
    const client = new WebSocket(`ws://127.0.0.1:${port}/gateway/vnc/x`, ["binary", "pam.token.tok"]);
    client.on("close", (c) => { closeCode = c; });
    await done;
    wss.close();

    expect(db.audits.some((a) => a.event === "gateway.protocol_unsupported" && a.details?.protocol === "rdp")).toBe(true);
    expect(db.audits.some((a) => a.event === "session.started")).toBe(false);
  });
});
