import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

/**
 * KDF de senha do PoC.
 *
 * NOTA DE SEGURANCA: docs/security-requirements.md especifica Argon2id como
 * alvo. Aqui usamos scrypt (nativo do Node, zero dependencia/compilacao) para
 * manter o build reproduzivel na PoC. A troca para Argon2id acontece ao
 * endurecer o cofre de usuarios na Fase 2/3 — o formato marcado abaixo torna a
 * migracao transparente. Nenhuma senha e logada.
 */
const N = 16384;
const R = 8;
const P = 1;
const KEYLEN = 64;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEYLEN, { N, r: R, p: P });
  return `scrypt$${N}$${R}$${P}$${salt.toString("hex")}$${hash.toString("hex")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, n, r, p, saltHex, hashHex] = parts;
  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const actual = scryptSync(password, salt, expected.length, {
    N: Number(n),
    r: Number(r),
    p: Number(p),
  });
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
