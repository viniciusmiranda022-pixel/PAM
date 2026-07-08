import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword, needsRehash } from "../src/auth.ts";

// KDF rapido nos testes (ADR 0002 permite SCRYPT_N reduzido fora de producao).
process.env.SCRYPT_N = process.env.SCRYPT_N ?? "16384";

describe("KDF scrypt (ADR 0002)", () => {
  it("hash e verify batem", () => {
    const h = hashPassword("s3nha-forte");
    expect(h.startsWith("scrypt$")).toBe(true);
    expect(verifyPassword("s3nha-forte", h)).toBe(true);
    expect(verifyPassword("errada", h)).toBe(false);
  });

  it("nunca contem a senha em claro", () => {
    expect(hashPassword("abracadabra")).not.toContain("abracadabra");
  });

  it("hash com N mais fraco pede rehash", () => {
    const weak = `scrypt$1024$8$1$${"00".repeat(16)}$${"11".repeat(64)}`;
    expect(needsRehash(weak)).toBe(true);
  });

  it("hash gerado com o N atual nao pede rehash", () => {
    expect(needsRehash(hashPassword("x"))).toBe(false);
  });

  it("formato invalido pede rehash (defensivo)", () => {
    expect(needsRehash("bcrypt$2$...")).toBe(true);
    expect(needsRehash("")).toBe(true);
  });
});
