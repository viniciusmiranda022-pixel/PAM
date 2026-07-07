// Servidor estatico minimo do portal (Fase 1). Serve public/ e expoe a
// biblioteca noVNC (unico cliente de protocolo permitido — HR-09) sob /novnc/.
// Sem build step, sem framework: a PoC prioriza o fluxo seguro, nao telas.
import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, "public");
const NOVNC = path.join(ROOT, "node_modules", "@novnc", "novnc");
const PORT = Number(process.env.PORT ?? 8080);

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

async function send(res, base, rel) {
  // Impede path traversal para fora da base servida.
  const full = path.normalize(path.join(base, rel));
  if (!full.startsWith(base)) {
    res.writeHead(403).end();
    return;
  }
  try {
    const body = await readFile(full);
    res.writeHead(200, { "content-type": TYPES[path.extname(full)] ?? "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404).end("not found");
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");
  let pathname = url.pathname;
  if (pathname === "/healthz") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"status":"ok"}');
    return;
  }
  if (pathname.startsWith("/novnc/")) {
    return send(res, NOVNC, pathname.slice("/novnc/".length));
  }
  if (pathname === "/") pathname = "/index.html";
  if (pathname === "/admin") pathname = "/admin.html";
  return send(res, PUBLIC, pathname.slice(1));
});

server.listen(PORT, () => console.log(JSON.stringify({ msg: "frontend ouvindo", port: PORT })));
