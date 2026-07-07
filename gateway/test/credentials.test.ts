import { describe, expect, it } from "vitest";
import { createCipheriv, randomBytes } from "node:crypto";
import { resolveCredential } from "../src/config.ts";

// Cifra no mesmo formato do backend (enc:v1:<nonce>:<ct+tag>).
function encrypt(plaintext: string, key: Buffer): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const blob = Buffer.concat([ct, cipher.getAuthTag()]);
  return `enc:v1:${nonce.toString("base64url")}:${blob.toString("base64url")}`;
}

describe("resolveCredential", () => {
  const key = randomBytes(32);
  const env = { CREDENTIAL_MASTER_KEY: key.toString("base64") } as NodeJS.ProcessEnv;

  it("resolve provider env:", async () => {
    expect(await resolveCredential("env:LAB", { LAB: "labonly1" } as NodeJS.ProcessEnv)).toBe("labonly1");
  });

  it("decifra provider enc:v1 (round-trip com o backend)", async () => {
    const ref = encrypt("s3nh4-vnc", key);
    expect(await resolveCredential(ref, env)).toBe("s3nh4-vnc");
  });

  it("falha se a master key estiver errada (GCM tag)", async () => {
    const ref = encrypt("x", key);
    const wrong = { CREDENTIAL_MASTER_KEY: randomBytes(32).toString("base64") } as NodeJS.ProcessEnv;
    await expect(resolveCredential(ref, wrong)).rejects.toThrow();
  });

  it("rejeita ref nulo e provider desconhecido", async () => {
    await expect(resolveCredential(null)).rejects.toThrow();
    await expect(resolveCredential("desconhecido:x")).rejects.toThrow();
  });
});
