import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { pkcePair, oidcConfig } from "../src/oidc.ts";

describe("PKCE (PR-15)", () => {
  it("challenge = BASE64URL(SHA256(verifier))", () => {
    const { verifier, challenge } = pkcePair();
    expect(verifier.length).toBeGreaterThanOrEqual(43); // 32 bytes base64url
    const expected = createHash("sha256").update(verifier, "ascii").digest("base64url");
    expect(challenge).toBe(expected);
  });

  it("cada par é único", () => {
    expect(pkcePair().verifier).not.toBe(pkcePair().verifier);
  });
});

describe("oidcConfig (PR-15)", () => {
  it("nulo sem as 4 variáveis obrigatórias", () => {
    expect(oidcConfig({} as NodeJS.ProcessEnv)).toBeNull();
  });

  it("aplica defaults e lê as opções enterprise", () => {
    const cfg = oidcConfig({
      OIDC_ISSUER: "https://idp/", OIDC_CLIENT_ID: "c", OIDC_CLIENT_SECRET: "s",
      OIDC_REDIRECT_URI: "https://rp/cb", OIDC_TOKEN_AUTH: "basic",
      OIDC_ADMIN_GROUP: "PAM-Admins", OIDC_PROVIDER_LABEL: "Entra",
    } as NodeJS.ProcessEnv)!;
    expect(cfg.issuer).toBe("https://idp"); // barra final removida
    expect(cfg.scopes).toBe("openid email profile");
    expect(cfg.tokenAuth).toBe("basic");
    expect(cfg.groupsClaim).toBe("groups");
    expect(cfg.adminGroup).toBe("PAM-Admins");
    expect(cfg.label).toBe("Entra");
  });
});
