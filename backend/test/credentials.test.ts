import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { encryptCredential } from "../src/credentials.ts";

const env = { CREDENTIAL_MASTER_KEY: randomBytes(32).toString("base64") } as NodeJS.ProcessEnv;

describe("encryptCredential (cofre write-only)", () => {
  it("produz ref no formato enc:v1 e NAO revela a senha", () => {
    const ref = encryptCredential("s3nh4-super-secreta", env);
    expect(ref.startsWith("enc:v1:")).toBe(true);
    expect(ref).not.toContain("s3nh4-super-secreta");
  });

  it("usa nonce aleatorio (refs diferentes p/ a mesma senha)", () => {
    expect(encryptCredential("x", env)).not.toBe(encryptCredential("x", env));
  });

  it("exige master key de 32 bytes", () => {
    expect(() => encryptCredential("x", { CREDENTIAL_MASTER_KEY: "curta" } as NodeJS.ProcessEnv)).toThrow();
    expect(() => encryptCredential("x", {} as NodeJS.ProcessEnv)).toThrow();
  });
});
