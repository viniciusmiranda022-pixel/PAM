/**
 * VeNCrypt (security type 19) — Fase 5.4. Cifra o trecho gateway→asset com TLS.
 *
 * Suporta os subtypes X509 (o servidor apresenta certificado): X509None (260)
 * e X509Vnc (261). Subtypes anonimos (TLS*) usam Diffie-Hellman anonimo, que o
 * OpenSSL moderno desabilita — por isso exigimos X509.
 *
 * Fluxo (gateway = cliente), apos selecionar 19:
 *   S→C version[2]  ·  C→S version[2]=0.2  ·  S→C ack[1]
 *   S→C count[1] + subtypes(u32*count)  ·  C→S subtype(u32)
 *   → handshake TLS  → seguranca interna (None/VNCAuth) sobre o TLS
 */
import tls from "node:tls";
import type { Socket } from "node:net";
import { SocketByteStream } from "./byte-stream.js";
import type { ByteStreamReader } from "./byte-stream-types.js";
import { RFB_SECURITY, RfbError } from "./rfb.js";

export const RFB_SEC_VENCRYPT = 19;
const SUB_X509_NONE = 260;
const SUB_X509_VNC = 261;

export interface TlsClientOptions {
  rejectUnauthorized: boolean;
  ca?: Buffer;
  servername?: string;
}

export interface VeNCryptResult {
  socket: tls.TLSSocket;
  stream: ByteStreamReader;
  innerSecurity: number; // RFB_SECURITY.NONE ou VNC_AUTH
}

/**
 * Executa o sub-handshake VeNCrypt e faz o upgrade do socket para TLS.
 * `stream` deve estar posicionado logo apos o envio do byte [19].
 */
export async function veNCryptUpgrade(
  socket: Socket,
  stream: ByteStreamReader,
  send: (b: Buffer) => void,
  tlsOptions: TlsClientOptions,
): Promise<VeNCryptResult> {
  const version = await stream.read(2); // [major, minor] do servidor
  if (version[0] !== 0) throw new RfbError(`VeNCrypt major ${version[0]} nao suportado`);
  send(Buffer.from([0, 2])); // pedimos 0.2
  const ack = (await stream.read(1))[0];
  if (ack !== 0) throw new RfbError("VeNCrypt: servidor rejeitou a versao");

  const count = (await stream.read(1))[0];
  if (count === 0) throw new RfbError("VeNCrypt: servidor nao ofereceu subtypes");
  const listBuf = await stream.read(count * 4);
  const subtypes: number[] = [];
  for (let i = 0; i < count; i++) subtypes.push(listBuf.readUInt32BE(i * 4));

  let chosen: number;
  let innerSecurity: number;
  if (subtypes.includes(SUB_X509_VNC)) {
    chosen = SUB_X509_VNC;
    innerSecurity = RFB_SECURITY.VNC_AUTH;
  } else if (subtypes.includes(SUB_X509_NONE)) {
    chosen = SUB_X509_NONE;
    innerSecurity = RFB_SECURITY.NONE;
  } else {
    throw new RfbError("VeNCrypt: nenhum subtype X509 suportado pelo servidor");
  }
  const sel = Buffer.alloc(4);
  sel.writeUInt32BE(chosen, 0);
  send(sel);

  // Qualquer byte de TLS que ja tenha sido bufferizado pelo leitor precisa
  // voltar ao socket antes do tls.connect (evita perder o ServerHello).
  const residual = stream.detach();
  if (residual.length) socket.unshift(residual);

  const tlsSocket = await new Promise<tls.TLSSocket>((resolve, reject) => {
    const s = tls.connect({
      socket,
      rejectUnauthorized: tlsOptions.rejectUnauthorized,
      ca: tlsOptions.ca,
      servername: tlsOptions.servername,
    });
    s.once("secureConnect", () => resolve(s));
    s.once("error", reject);
  });

  return { socket: tlsSocket, stream: new SocketByteStream(tlsSocket), innerSecurity };
}
