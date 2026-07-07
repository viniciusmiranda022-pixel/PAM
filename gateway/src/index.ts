import http from "node:http";
import { WebSocketServer } from "ws";
import { loadConfig } from "./config.js";
import { Db } from "./db.js";
import { runSession } from "./session.js";
import { registry } from "./metrics.js";
import { activeSessionCount } from "./registry.js";
import { startTerminationWatchdog } from "./watchdog.js";

const config = loadConfig();
const db = new Db(config.databaseUrl);

const server = http.createServer((req, res) => {
  if (req.url === "/healthz") {
    // Readiness: reflete o banco (do qual dependem token e watchdog).
    db.ping().then((dbOk) => {
      const status = dbOk ? "ok" : "degraded";
      res.writeHead(dbOk ? 200 : 503, { "content-type": "application/json" });
      res.end(JSON.stringify({ status, db: dbOk, activeSessions: activeSessionCount() }));
    });
    return;
  }
  if (req.url === "/metrics") {
    registry
      .metrics()
      .then((body) => {
        res.writeHead(200, { "content-type": registry.contentType });
        res.end(body);
      })
      .catch(() => res.writeHead(500).end());
    return;
  }
  res.writeHead(404).end();
});

const wss = new WebSocketServer({
  server,
  path: undefined, // validamos o prefixo abaixo
  // O cliente oferece ['binary', 'pam.token.<token>']; selecionamos 'binary'.
  handleProtocols: (protocols) => (protocols.has("binary") ? "binary" : false),
});

wss.on("connection", (ws, req) => {
  // Apenas o prefixo do gateway VNC — nao e um proxy WebSocket generico.
  if (!req.url || !req.url.startsWith("/gateway/vnc/")) {
    ws.close(4404, "rota invalida");
    return;
  }
  runSession(ws, req, db).catch(() => {
    try {
      ws.close(4500, "erro interno");
    } catch { /* ignore */ }
  });
});

server.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ msg: "gateway ouvindo", port: config.port }));
});

const watchdog = startTerminationWatchdog(db, config.watchdogIntervalMs);

async function shutdown(): Promise<void> {
  clearInterval(watchdog);
  wss.clients.forEach((c) => c.close(1001, "gateway_shutdown"));
  await new Promise<void>((r) => server.close(() => r()));
  await db.close();
  process.exit(0);
}
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
