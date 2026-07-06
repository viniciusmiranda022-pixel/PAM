/**
 * Leitura de bytes exatos por cima de fontes orientadas a eventos: um net.Socket
 * (lado asset) e um WebSocket `ws` (lado navegador). Durante o handshake RFB
 * consumimos contagens exatas; depois dele fazemos `detach()` e o codigo de
 * splice assume, recebendo qualquer residual bufferizado.
 */
import type { Socket } from "node:net";
import type { WebSocket } from "ws";

interface Waiter {
  need: number;
  resolve: (b: Buffer) => void;
  reject: (e: Error) => void;
}

abstract class ByteStream {
  protected chunks: Buffer[] = [];
  protected buffered = 0;
  protected waiter: Waiter | null = null;
  protected ended = false;
  protected detached = false;

  protected push(data: Buffer): void {
    if (this.detached) return;
    this.chunks.push(data);
    this.buffered += data.length;
    this.serve();
  }

  protected fail(err: Error): void {
    this.ended = true;
    if (this.waiter) {
      const w = this.waiter;
      this.waiter = null;
      w.reject(err);
    }
  }

  private serve(): void {
    if (!this.waiter) return;
    if (this.buffered < this.waiter.need) {
      if (this.ended) {
        const w = this.waiter;
        this.waiter = null;
        w.reject(new Error("stream encerrado durante o handshake"));
      }
      return;
    }
    const w = this.waiter;
    this.waiter = null;
    w.resolve(this.take(w.need));
  }

  private take(n: number): Buffer {
    const all = Buffer.concat(this.chunks);
    const out = all.subarray(0, n);
    const rest = all.subarray(n);
    this.chunks = rest.length ? [rest] : [];
    this.buffered = rest.length;
    return out;
  }

  read(n: number): Promise<Buffer> {
    if (this.waiter) return Promise.reject(new Error("leitura concorrente"));
    if (this.buffered >= n) return Promise.resolve(this.take(n));
    if (this.ended) return Promise.reject(new Error("stream encerrado"));
    return new Promise((resolve, reject) => {
      this.waiter = { need: n, resolve, reject };
    });
  }

  /** Encerra o modo de handshake, devolvendo bytes ja recebidos e nao lidos. */
  detach(): Buffer {
    this.detached = true;
    this.teardown();
    const residual = Buffer.concat(this.chunks);
    this.chunks = [];
    this.buffered = 0;
    return residual;
  }

  protected abstract teardown(): void;
}

export class SocketByteStream extends ByteStream {
  constructor(private socket: Socket) {
    super();
    socket.on("data", this.onData);
    socket.on("close", this.onClose);
    socket.on("error", this.onError);
  }
  private onData = (d: Buffer) => this.push(d);
  private onClose = () => this.fail(new Error("socket TCP fechado"));
  private onError = (e: Error) => this.fail(e);
  protected teardown(): void {
    this.socket.off("data", this.onData);
    this.socket.off("close", this.onClose);
    this.socket.off("error", this.onError);
  }
}

export class WsByteStream extends ByteStream {
  constructor(private ws: WebSocket) {
    super();
    ws.on("message", this.onMessage);
    ws.on("close", this.onClose);
    ws.on("error", this.onError);
  }
  private onMessage = (data: Buffer, isBinary: boolean) => {
    // RFB e binario; ignore frames de texto (nao fazem parte do protocolo).
    if (isBinary) this.push(Buffer.isBuffer(data) ? data : Buffer.from(data));
  };
  private onClose = () => this.fail(new Error("websocket fechado"));
  private onError = (e: Error) => this.fail(e);
  protected teardown(): void {
    this.ws.off("message", this.onMessage);
    this.ws.off("close", this.onClose);
    this.ws.off("error", this.onError);
  }
}
