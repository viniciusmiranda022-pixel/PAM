// Playback de gravação (Fase 5.1). Baixa o arquivo PAMREC01 da sessão e o
// reproduz no noVNC via um "canal falso" que emula o lado servidor do RFB:
// re-emite o mesmo handshake sintético que o gateway fez ao vivo (None +
// ServerInit gravado) e então entrega os frames de tela com o timing original.
import RFB from "/novnc/core/rfb.js";

const MAGIC = "PAMREC01";
const qs = new URLSearchParams(location.search);
const sessionId = qs.get("sessionId");

function setStatus(t) {
  document.getElementById("status").textContent = t;
}

function parseRecording(buf) {
  const view = new DataView(buf);
  const dec = new TextDecoder("ascii");
  if (buf.byteLength < 12 || dec.decode(new Uint8Array(buf, 0, 8)) !== MAGIC) {
    throw new Error("gravação inválida");
  }
  const siLen = view.getUint32(8);
  let off = 12 + siLen;
  const serverInit = new Uint8Array(buf.slice(12, off));
  const frames = [];
  while (off + 9 <= buf.byteLength) {
    const direction = view.getUint8(off);
    const deltaMs = view.getUint32(off + 1);
    const len = view.getUint32(off + 5);
    if (off + 9 + len > buf.byteLength) break; // truncado
    frames.push({ direction, deltaMs, data: new Uint8Array(buf.slice(off + 9, off + 9 + len)) });
    off += 9 + len;
  }
  return { serverInit, frames };
}

// Canal que o noVNC "attacha" no lugar de um WebSocket.
class ReplayChannel {
  constructor(recording, speed) {
    this.recording = recording;
    this.speed = speed;
    this.binaryType = "arraybuffer";
    this.protocol = "";
    this.readyState = 1; // OPEN
    this.onopen = null;
    this.onmessage = null;
    this.onclose = null;
    this.onerror = null;
    this._step = 0;
    this._timers = [];
  }

  _deliver(bytes) {
    this.onmessage?.({ data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) });
  }

  fireOpen() {
    this.onopen?.();
    // Passo 0: entrega a ProtocolVersion do servidor.
    this._deliver(new TextEncoder().encode("RFB 003.008\n"));
  }

  // O noVNC (cliente) envia; respondemos com o script do lado servidor e
  // ignoramos o conteúdo do cliente (replay não interage com asset nenhum).
  send() {
    this._step += 1;
    if (this._step === 1) {
      this._deliver(new Uint8Array([1, 1])); // 1 security type: None
    } else if (this._step === 2) {
      this._deliver(new Uint8Array([0, 0, 0, 0])); // SecurityResult OK
    } else if (this._step === 3) {
      this._deliver(this.recording.serverInit); // ServerInit gravado
      this._startPlayback();
    }
    // passos seguintes (SetPixelFormat, SetEncodings, FBUR...) são engolidos
  }

  _startPlayback() {
    const frames = this.recording.frames;
    let last = 0;
    for (const f of frames) {
      const t = setTimeout(() => this._deliver(f.data), f.deltaMs / this.speed);
      this._timers.push(t);
      last = Math.max(last, f.deltaMs / this.speed);
    }
    setTimeout(() => setStatus(`reprodução concluída (${frames.length} frames)`), last + 50);
  }

  close() {
    this._timers.forEach(clearTimeout);
    this.readyState = 3;
    this.onclose?.({ code: 1000 });
  }
}

async function main() {
  if (!sessionId) {
    setStatus("sessionId ausente na URL");
    return;
  }
  const me = await fetch("/api/v1/auth/me", { credentials: "same-origin" });
  if (!me.ok || (await me.json()).role !== "admin") {
    setStatus("acesso restrito a administradores");
    return;
  }
  setStatus("baixando gravação…");
  const res = await fetch(`/api/v1/admin/sessions/${sessionId}/recording`, { credentials: "same-origin" });
  if (!res.ok) {
    setStatus(`gravação indisponível (${res.status})`);
    return;
  }
  const recording = parseRecording(await res.arrayBuffer());
  setStatus(`reproduzindo ${recording.frames.length} frames…`);

  const speed = Number(document.getElementById("speed").value) || 1;
  const channel = new ReplayChannel(recording, speed);
  const rfb = new RFB(document.getElementById("screen"), channel, {});
  rfb.viewOnly = true; // replay: sem entrada do teclado/mouse
  rfb.scaleViewport = true;
  setTimeout(() => channel.fireOpen(), 0);
}

document.getElementById("speed").addEventListener("change", () => location.reload());
main().catch((e) => setStatus("erro: " + e.message));
