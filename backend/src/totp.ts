/**
 * TOTP (RFC 6238) sobre HOTP (RFC 4226) — HMAC-SHA1, passo de 30s, 6 digitos,
 * janela de verificacao de ±1 passo. Implementado com node:crypto (sem
 * dependencia externa). Vetores oficiais do RFC 6238 em test/totp.test.ts.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const TOTP_STEP_SECONDS = 30;
export const TOTP_DIGITS = 6;

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("base32 invalido");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(key: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", key).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const code =
    (((mac[offset] & 0x7f) << 24) |
      (mac[offset + 1] << 16) |
      (mac[offset + 2] << 8) |
      mac[offset + 3]) %
    10 ** TOTP_DIGITS;
  return String(code).padStart(TOTP_DIGITS, "0");
}

export function totpAt(secretBase32: string, unixSeconds: number): string {
  const counter = Math.floor(unixSeconds / TOTP_STEP_SECONDS);
  return hotp(base32Decode(secretBase32), counter);
}

/** Verifica com janela de ±1 passo (tolerancia a clock skew). */
export function verifyTotp(secretBase32: string, code: string, nowSeconds = Date.now() / 1000): boolean {
  if (!/^\d{6}$/.test(code)) return false;
  const counter = Math.floor(nowSeconds / TOTP_STEP_SECONDS);
  const key = base32Decode(secretBase32);
  for (const c of [counter - 1, counter, counter + 1]) {
    if (c < 0) continue;
    const expected = Buffer.from(hotp(key, c));
    if (expected.length === code.length && timingSafeEqual(expected, Buffer.from(code))) {
      return true;
    }
  }
  return false;
}

export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20)); // 160 bits, padrao dos authenticators
}

export function otpauthUrl(secretBase32: string, username: string, issuer = "PAM VNC-Only"): string {
  const enc = encodeURIComponent;
  return `otpauth://totp/${enc(issuer)}:${enc(username)}?secret=${secretBase32}&issuer=${enc(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;
}
