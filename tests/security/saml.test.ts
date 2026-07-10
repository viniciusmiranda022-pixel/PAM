import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type pg from "pg";
import { resetData, setupDatabase } from "../helpers/db.js";
import { makeServer } from "../helpers/server.js";
import { startFakeSamlIdp, requestIdFromLoginLocation, type FakeSamlIdp } from "../helpers/saml-idp.js";

/**
 * SAML 2.0 SP (PR-15) end-to-end: fluxo SP-initiated com Assertion assinada de
 * verdade (xml-crypto). Prova mapeamento de usuario, elevacao grupo->papel e
 * rejeicao de resposta forjada. A validacao de assinatura e a de producao
 * (@node-saml/node-saml).
 */
describe("SAML enterprise (PR-15)", () => {
  let pool: pg.Pool;
  let idp: FakeSamlIdp;
  const SP_ISSUER = "https://pam.test/saml/metadata";
  const ACS = "http://127.0.0.1/api/v1/auth/saml/callback";
  const saved: Record<string, string | undefined> = {};

  beforeAll(async () => {
    pool = await setupDatabase();
    idp = startFakeSamlIdp();
  });
  afterAll(async () => { idp.cleanup(); await pool.end(); });
  beforeEach(async () => {
    await resetData(pool);
    for (const k of ["SAML_IDP_ENTRYPOINT","SAML_IDP_CERT","SAML_SP_ISSUER","SAML_CALLBACK_URL","SAML_ADMIN_GROUP"]) saved[k] = process.env[k];
    process.env.SAML_IDP_ENTRYPOINT = "https://idp.test/sso";
    process.env.SAML_IDP_CERT = idp.certPem;
    process.env.SAML_SP_ISSUER = SP_ISSUER;
    process.env.SAML_CALLBACK_URL = ACS;
    delete process.env.SAML_ADMIN_GROUP;
  });
  afterEach(() => { for (const [k, v] of Object.entries(saved)) v === undefined ? delete process.env[k] : (process.env[k] = v); });

  // /saml/login (captura o ID do AuthnRequest) e /saml/callback com a resposta assinada.
  async function samlLogin(profile: { nameId: string; email?: string; name?: string; groups?: string[] }) {
    const { app, db } = makeServer();
    const login = await app.inject({ method: "GET", url: "/api/v1/auth/saml/login" });
    const inResponseTo = requestIdFromLoginLocation(login.headers.location as string);
    const SAMLResponse = idp.buildResponse({ inResponseTo, recipient: ACS, audience: SP_ISSUER, ...profile });
    const cb = await app.inject({
      method: "POST",
      url: "/api/v1/auth/saml/callback",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ SAMLResponse }).toString(),
    });
    return { app, db, cb };
  }

  it("faz login por SAML e provisiona o usuário", async () => {
    const { app, db, cb } = await samlLogin({ nameId: "s-1", email: "alice@corp.com", name: "Alice" });
    expect(cb.statusCode).toBe(302);
    const { rows } = await pool.query("SELECT username, role FROM users WHERE saml_subject = 's-1'");
    expect(rows[0]).toMatchObject({ username: "alice@corp.com", role: "user" });
    await app.close(); await db.close();
  });

  it("grupo do IdP eleva a admin (só eleva)", async () => {
    process.env.SAML_ADMIN_GROUP = "PAM-Admins";
    const { app, db, cb } = await samlLogin({ nameId: "s-2", email: "bob@corp.com", groups: ["PAM-Admins"] });
    expect(cb.statusCode).toBe(302);
    const { rows } = await pool.query("SELECT role FROM users WHERE saml_subject = 's-2'");
    expect(rows[0].role).toBe("admin");
    await app.close(); await db.close();
  });

  it("resposta não assinada/forjada é rejeitada (401)", async () => {
    const { app, db } = makeServer();
    await app.inject({ method: "GET", url: "/api/v1/auth/saml/login" });
    const forged = Buffer.from(
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
      `<saml:Assertion><saml:Subject><saml:NameID>evil</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`,
    ).toString("base64");
    const cb = await app.inject({
      method: "POST", url: "/api/v1/auth/saml/callback",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ SAMLResponse: forged }).toString(),
    });
    expect(cb.statusCode).toBe(401);
    const { rows } = await pool.query("SELECT 1 FROM users WHERE saml_subject = 'evil'");
    expect(rows.length).toBe(0);
    await app.close(); await db.close();
  });
});
