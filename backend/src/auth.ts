import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

/**
 * KDF de senha local: scrypt (node:crypto, zero dependencia nativa).
 * Decisao registrada em docs/adr/0002-kdf-scrypt.md — Argon2id foi avaliado e
 * rejeitado por exigir dependencia com build nativo; scrypt e aceito pela
 * OWASP com os parametros abaixo.
 *
 * Parametros default (OWASP): N=2^17, r=8, p=1 (~128 MiB por hash). O formato
 * armazenado e auto-descritivo (`scrypt$N$r$p$salt$hash`), entao elevar os
 * parametros nao invalida hashes antigos — eles continuam verificaveis e sao
 * re-hasheados de forma transparente no proximo login (needsRehash).
 * SCRYPT_N existe para ambientes com pouca memoria (ex.: CI) — nunca abaixe em
 * producao.
 */
const R = 8;
const P = 1;
const KEYLEN = 64;

// Lido por chamada: permite baixar o custo em CI/testes (SCRYPT_N) sem recarregar
// o modulo. Nunca reduzir em producao (ADR 0002).
function targetN(): number {
  return Number(process.env.SCRYPT_N ?? 131072);
}

// Node limita scrypt a 32 MiB por default; N=2^17/r=8 usa 128*N*r = 128 MiB.
function maxmemFor(n: number, r: number): number {
  return 256 * n * r; // 2x o necessario, com folga
}

export function hashPassword(password: string): string {
  const n = targetN();
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEYLEN, { N: n, r: R, p: P, maxmem: maxmemFor(n, R) });
  return `scrypt$${n}$${R}$${P}$${salt.toString("hex")}$${hash.toString("hex")}`;
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
    maxmem: maxmemFor(Number(n), Number(r)),
  });
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** Hash gerado com parametros mais fracos que os atuais? (re-hash no login) */
export function needsRehash(stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return true;
  const [, n, r, p] = parts;
  return Number(n) < targetN() || Number(r) < R || Number(p) < P;
}
