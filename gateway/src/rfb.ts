/**
 * RFB (Remote Framebuffer / VNC) — apenas o necessario para o gateway terminar
 * o handshake dos dois lados. VNC-only por design: este modulo nao conhece
 * nenhum outro protocolo.
 *
 * Escopo suportado: RFB 3.3, 3.7 e 3.8; security types `None` (1) e
 * `VNC Authentication` (2). Ver docs/architecture.md secao 4.
 */
import { createCipheriv } from "node:crypto";

export const RFB_SECURITY = {
  INVALID: 0,
  NONE: 1,
  VNC_AUTH: 2,
} as const;

export interface ProtocolVersion {
  major: number;
  minor: number;
}

/** 12 bytes: "RFB xxx.yyy\n". Lanca se o banner nao for RFB (defesa HR-08). */
export function parseProtocolVersion(buf: Buffer): ProtocolVersion {
  if (buf.length !== 12) {
    throw new RfbError("banner RFB com tamanho invalido");
  }
  const text = buf.toString("ascii");
  const m = /^RFB (\d{3})\.(\d{3})\n$/.exec(text);
  if (!m) {
    // Nao e VNC: recusar. Impede o gateway de alcancar servicos nao-VNC.
    throw new RfbError("destino nao respondeu banner RFB");
  }
  return { major: Number(m[1]), minor: Number(m[2]) };
}

export function formatProtocolVersion(v: ProtocolVersion): Buffer {
  const major = String(v.major).padStart(3, "0");
  const minor = String(v.minor).padStart(3, "0");
  return Buffer.from(`RFB ${major}.${minor}\n`, "ascii");
}

/**
 * Versao efetiva negociada: nunca acima da que o servidor ofereceu, com teto em
 * 3.8 (maxima que sabemos falar).
 */
export function negotiatedVersion(server: ProtocolVersion): ProtocolVersion {
  if (server.major !== 3) {
    throw new RfbError(`RFB major ${server.major} nao suportado`);
  }
  const minor = Math.min(server.minor, 8);
  return { major: 3, minor };
}

/** Inverte a ordem dos bits de um byte (peculiaridade da chave DES do VNC). */
export function mirrorBits(byte: number): number {
  let r = 0;
  for (let i = 0; i < 8; i++) {
    r = (r << 1) | ((byte >> i) & 1);
  }
  return r & 0xff;
}

/** Chave DES do VNC: senha em 8 bytes (pad com zero, truncada) e bits espelhados. */
export function vncDesKey(password: string): Buffer {
  const raw = Buffer.alloc(8, 0);
  const pw = Buffer.from(password, "latin1");
  pw.copy(raw, 0, 0, Math.min(8, pw.length));
  const key = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) key[i] = mirrorBits(raw[i]);
  return key;
}

/**
 * Resposta ao challenge do `VNC Authentication`: DES-ECB de cada bloco de 8
 * bytes do challenge (16 no total) com a chave derivada da senha.
 *
 * DES simples esta desabilitado no OpenSSL 3, entao usamos 3DES com a chave
 * triplicada (EDE com K1=K2=K3=K colapsa para DES simples). Validado contra
 * vetores conhecidos em test/rfb.test.ts.
 */
export function vncEncryptChallenge(password: string, challenge: Buffer): Buffer {
  if (challenge.length !== 16) {
    throw new RfbError("challenge VNC deve ter 16 bytes");
  }
  const key8 = vncDesKey(password);
  const key24 = Buffer.concat([key8, key8, key8]);
  const cipher = createCipheriv("des-ede3-ecb", key24, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(challenge), cipher.final()]);
}

export class RfbError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RfbError";
  }
}
