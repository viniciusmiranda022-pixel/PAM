/**
 * Terminacao do handshake RFB nos dois lados (docs/architecture.md secao 4).
 *
 *  - Lado asset: o gateway age como CLIENTE e autentica com `VNC Authentication`
 *    usando a senha do cofre. A senha nunca sai deste processo.
 *  - Lado navegador: o gateway age como SERVIDOR, forca RFB 3.8 e oferece apenas
 *    security type `None` — nenhuma senha trafega ate o browser (HR-05).
 *
 * Depois que o ServerInit do asset e repassado ao browser, ambos os lados estao
 * na fase de mensagens normais e o chamador faz splice binario.
 */
import type { Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import type { ByteStreamReader } from "../../byte-stream-types.js";
import { SocketByteStream } from "../../byte-stream.js";
import {
  RFB_SECURITY,
  RfbError,
  formatProtocolVersion,
  negotiatedVersion,
  parseProtocolVersion,
  vncEncryptChallenge,
} from "./rfb.js";
import { RFB_SEC_VENCRYPT, veNCryptUpgrade, type TlsClientOptions } from "./vencrypt.js";

type Send = (b: Buffer) => void;

async function readReason(stream: ByteStreamReader): Promise<string> {
  const len = (await stream.read(4)).readUInt32BE(0);
  if (len === 0 || len > 4096) return "";
  return (await stream.read(len)).toString("utf8");
}

/**
 * Handshake com o asset. Retorna o bloco ServerInit para ser repassado ao
 * navegador. Lanca RfbError se o destino nao falar RFB ou a auth falhar.
 */
export async function assetHandshake(
  stream: ByteStreamReader,
  send: Send,
  password: string,
): Promise<Buffer> {
  const server = parseProtocolVersion(await stream.read(12)); // valida banner RFB
  const neg = negotiatedVersion(server);
  send(formatProtocolVersion(neg));

  let chosen: number;
  if (neg.minor >= 7) {
    const count = (await stream.read(1)).readUInt8(0);
    if (count === 0) {
      throw new RfbError(`asset recusou conexao: ${await readReason(stream)}`);
    }
    const list = await stream.read(count);
    if (list.includes(RFB_SECURITY.VNC_AUTH)) chosen = RFB_SECURITY.VNC_AUTH;
    else if (list.includes(RFB_SECURITY.NONE)) chosen = RFB_SECURITY.NONE;
    else throw new RfbError("asset nao oferece security type suportado");
    send(Buffer.from([chosen]));
  } else {
    // RFB 3.3: o servidor dita o security type (U32), cliente nao seleciona.
    chosen = (await stream.read(4)).readUInt32BE(0);
    if (chosen === RFB_SECURITY.INVALID) {
      throw new RfbError(`asset recusou conexao: ${await readReason(stream)}`);
    }
    if (chosen !== RFB_SECURITY.NONE && chosen !== RFB_SECURITY.VNC_AUTH) {
      throw new RfbError("asset exige security type nao suportado");
    }
  }

  if (chosen === RFB_SECURITY.VNC_AUTH) {
    const challenge = await stream.read(16);
    send(vncEncryptChallenge(password, challenge));
  }

  // SecurityResult: sempre no 3.8; no 3.7/3.3 apenas apos VNC Authentication.
  const expectResult = neg.minor >= 8 || chosen === RFB_SECURITY.VNC_AUTH;
  if (expectResult) {
    const result = (await stream.read(4)).readUInt32BE(0);
    if (result !== 0) {
      const reason = neg.minor >= 8 ? await readReason(stream) : "auth rejeitada";
      throw new RfbError(`autenticacao VNC falhou: ${reason}`);
    }
  }

  send(Buffer.from([1])); // ClientInit: shared = 1
  return readServerInit(stream);
}

async function readServerInit(stream: ByteStreamReader): Promise<Buffer> {
  const head = await stream.read(24); // width(2) height(2) pixel-format(16) name-len(4)
  const nameLen = head.readUInt32BE(20);
  const name = nameLen > 0 ? await stream.read(nameLen) : Buffer.alloc(0);
  return Buffer.concat([head, name]);
}

export interface AssetHandshakeResult {
  serverInit: Buffer;
  /** Socket efetivo (o TLS quando houve VeNCrypt) — usar no splice. */
  socket: Socket | TLSSocket;
  /** Reader sobre o socket efetivo — dele sai o residual pro splice. */
  stream: ByteStreamReader;
}

/**
 * Variante de produção: opera sobre o socket para poder fazer o upgrade TLS do
 * VeNCrypt. Quando `tlsRequired`, exige que o asset ofereça VeNCrypt (senão
 * falha) e cifra o trecho gateway→asset; a autenticação VNC ocorre dentro do
 * túnel TLS. Sem `tlsRequired`, comporta-se como o caminho RFB simples.
 */
export async function assetHandshakeTls(
  socket: Socket,
  password: string,
  tlsRequired: boolean,
  tlsOptions: TlsClientOptions,
): Promise<AssetHandshakeResult> {
  let effSocket: Socket | TLSSocket = socket;
  let stream: ByteStreamReader = new SocketByteStream(socket);
  const send: Send = (b) => void effSocket.write(b);

  const server = parseProtocolVersion(await stream.read(12));
  const neg = negotiatedVersion(server);
  send(formatProtocolVersion(neg));

  let security: number;

  if (neg.minor < 7) {
    if (tlsRequired) throw new RfbError("asset em RFB 3.3 nao suporta VeNCrypt/TLS");
    security = (await stream.read(4)).readUInt32BE(0);
    if (security === RFB_SECURITY.INVALID) {
      throw new RfbError(`asset recusou conexao: ${await readReason(stream)}`);
    }
    if (security !== RFB_SECURITY.NONE && security !== RFB_SECURITY.VNC_AUTH) {
      throw new RfbError("asset exige security type nao suportado");
    }
  } else {
    const count = (await stream.read(1)).readUInt8(0);
    if (count === 0) throw new RfbError(`asset recusou conexao: ${await readReason(stream)}`);
    const list = await stream.read(count);
    if (tlsRequired) {
      if (!list.includes(RFB_SEC_VENCRYPT)) {
        throw new RfbError("tls_required, mas o asset nao oferece VeNCrypt");
      }
      send(Buffer.from([RFB_SEC_VENCRYPT]));
      const up = await veNCryptUpgrade(socket, stream, send, tlsOptions);
      effSocket = up.socket;
      stream = up.stream;
      security = up.innerSecurity;
    } else if (list.includes(RFB_SECURITY.VNC_AUTH)) {
      security = RFB_SECURITY.VNC_AUTH;
      send(Buffer.from([security]));
    } else if (list.includes(RFB_SECURITY.NONE)) {
      security = RFB_SECURITY.NONE;
      send(Buffer.from([security]));
    } else {
      throw new RfbError("asset nao oferece security type suportado");
    }
  }

  if (security === RFB_SECURITY.VNC_AUTH) {
    const challenge = await stream.read(16);
    send(vncEncryptChallenge(password, challenge)); // agora sobre o TLS, se houver
  }

  const expectResult = neg.minor >= 8 || security === RFB_SECURITY.VNC_AUTH;
  if (expectResult) {
    const result = (await stream.read(4)).readUInt32BE(0);
    if (result !== 0) {
      const reason = neg.minor >= 8 ? await readReason(stream) : "auth rejeitada";
      throw new RfbError(`autenticacao VNC falhou: ${reason}`);
    }
  }

  send(Buffer.from([1])); // ClientInit
  const serverInit = await readServerInit(stream);
  return { serverInit, socket: effSocket, stream };
}

/**
 * Handshake com o navegador (noVNC). Forca RFB 3.8 + `None`, envia o ServerInit
 * do asset e retorna. Nenhuma senha e enviada ao browser.
 */
export async function browserHandshake(
  stream: ByteStreamReader,
  send: Send,
  serverInit: Buffer,
): Promise<void> {
  send(formatProtocolVersion({ major: 3, minor: 8 }));
  parseProtocolVersion(await stream.read(12)); // valida que o cliente fala RFB
  send(Buffer.from([1, RFB_SECURITY.NONE])); // 1 security type: None
  const selected = (await stream.read(1)).readUInt8(0);
  if (selected !== RFB_SECURITY.NONE) {
    throw new RfbError("cliente nao selecionou o security type None");
  }
  send(Buffer.from([0, 0, 0, 0])); // SecurityResult OK (obrigatorio no 3.8)
  await stream.read(1); // ClientInit do cliente (shared flag) — ignorado
  send(serverInit);
}
