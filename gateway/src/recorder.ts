/**
 * Gravacao da sessao VNC (Fase 5.1) — formato binario `PAMREC01`:
 *
 *   header:  "PAMREC01" (8 bytes ascii)
 *            u32BE len(ServerInit) + ServerInit
 *   frames:  u8  direcao (0 = servidor->cliente)
 *            u32BE delta em ms desde o inicio da gravacao
 *            u32BE len + payload
 *
 * Grava apenas o sentido servidor->cliente (a tela). Eventos de teclado do
 * usuario (cliente->servidor) NAO sao gravados de proposito: podem conter
 * senhas digitadas dentro da sessao (coerente com HR-06).
 */
import fs from "node:fs";
import path from "node:path";

export const RECORDING_MAGIC = "PAMREC01";
export const DIR_SERVER_TO_CLIENT = 0;

export class SessionRecorder {
  private stream: fs.WriteStream;
  private start = Date.now();
  private closed = false;

  constructor(
    public readonly filePath: string,
    serverInit: Buffer,
  ) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    this.stream = fs.createWriteStream(filePath, { flags: "w" });
    const head = Buffer.alloc(8 + 4);
    head.write(RECORDING_MAGIC, 0, "ascii");
    head.writeUInt32BE(serverInit.length, 8);
    this.stream.write(Buffer.concat([head, serverInit]));
  }

  /** Anexa um frame servidor->cliente. Silencioso apos close/erro. */
  write(data: Buffer): void {
    if (this.closed || data.length === 0) return;
    const frame = Buffer.alloc(1 + 4 + 4);
    frame.writeUInt8(DIR_SERVER_TO_CLIENT, 0);
    frame.writeUInt32BE(Math.min(Date.now() - this.start, 0xffffffff), 1);
    frame.writeUInt32BE(data.length, 5);
    this.stream.write(Buffer.concat([frame, data]));
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.stream.end();
  }
}

export interface RecordedFrame {
  direction: number;
  deltaMs: number;
  data: Buffer;
}

/** Parser do formato (usado em teste e utilitarios). */
export function parseRecording(buf: Buffer): { serverInit: Buffer; frames: RecordedFrame[] } {
  if (buf.length < 12 || buf.subarray(0, 8).toString("ascii") !== RECORDING_MAGIC) {
    throw new Error("gravacao invalida: magic ausente");
  }
  const siLen = buf.readUInt32BE(8);
  let off = 12 + siLen;
  const serverInit = buf.subarray(12, off);
  const frames: RecordedFrame[] = [];
  while (off + 9 <= buf.length) {
    const direction = buf.readUInt8(off);
    const deltaMs = buf.readUInt32BE(off + 1);
    const len = buf.readUInt32BE(off + 5);
    if (off + 9 + len > buf.length) break; // frame truncado (sessao interrompida)
    frames.push({ direction, deltaMs, data: buf.subarray(off + 9, off + 9 + len) });
    off += 9 + len;
  }
  return { serverInit, frames };
}
