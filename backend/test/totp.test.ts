import { describe, expect, it } from "vitest";
import { base32Decode, base32Encode, totpAt, verifyTotp, generateTotpSecret, otpauthUrl } from "../src/totp.ts";

// RFC 6238, Apendice B — segredo SHA1 "12345678901234567890" (ascii).
// Os vetores oficiais sao de 8 digitos; com 6 digitos usamos os 6 finais.
const RFC_SECRET = base32Encode(Buffer.from("12345678901234567890", "ascii"));

describe("TOTP — vetores do RFC 6238 (SHA1, 6 dígitos)", () => {
  const vectors: Array<[number, string]> = [
    [59, "287082"],          // 94287082
    [1111111109, "081804"],  // 07081804
    [1111111111, "050471"],  // 14050471
    [1234567890, "005924"],  // 89005924
    [2000000000, "279037"],  // 69279037
    [20000000000, "353130"], // 65353130
  ];
  for (const [t, expected] of vectors) {
    it(`T=${t} => ${expected}`, () => {
      expect(totpAt(RFC_SECRET, t)).toBe(expected);
    });
  }
});

describe("verifyTotp", () => {
  it("aceita o código do passo atual e ±1 passo", () => {
    expect(verifyTotp(RFC_SECRET, "287082", 59)).toBe(true);
    expect(verifyTotp(RFC_SECRET, "287082", 59 + 30)).toBe(true);  // passo seguinte
    expect(verifyTotp(RFC_SECRET, "287082", 59 - 30)).toBe(true);  // passo anterior
  });
  it("rejeita código fora da janela e formatos inválidos", () => {
    expect(verifyTotp(RFC_SECRET, "287082", 59 + 120)).toBe(false);
    expect(verifyTotp(RFC_SECRET, "000000", 59)).toBe(false);
    expect(verifyTotp(RFC_SECRET, "28708", 59)).toBe(false);
    expect(verifyTotp(RFC_SECRET, "abcdef", 59)).toBe(false);
  });
});

describe("base32", () => {
  it("round-trip", () => {
    for (const len of [1, 5, 10, 20, 33]) {
      const buf = Buffer.from(Array.from({ length: len }, (_, i) => (i * 37) % 256));
      expect(base32Decode(base32Encode(buf)).equals(buf)).toBe(true);
    }
  });
  it("rejeita caracteres inválidos", () => {
    expect(() => base32Decode("11@!")).toThrow();
  });
});

describe("geração e otpauth", () => {
  it("segredo tem 160 bits e URL contém issuer/período", () => {
    const s = generateTotpSecret();
    expect(base32Decode(s).length).toBe(20);
    const url = otpauthUrl(s, "vinicius");
    expect(url.startsWith("otpauth://totp/")).toBe(true);
    expect(url).toContain(`secret=${s}`);
    expect(url).toContain("period=30");
    expect(url).toContain("digits=6");
  });
});
