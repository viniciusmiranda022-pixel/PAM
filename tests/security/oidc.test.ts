import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type pg from "pg";
import { resetData, setupDatabase } from "../helpers/db.js";
import { makeServer } from "../helpers/server.js";
import { startFakeIdp, type FakeIdp } from "../helpers/oidc-idp.js";

/**
 * OIDC consolidado (PR-15) end-to-end contra um IdP simulado (RSA real, RS256):
 * PKCE, rotação de JWKS, client_secret_basic e mapeamento grupo→papel.
 */
describe("OIDC enterprise (PR-15)", () => {
  let pool: pg.Pool;
  let idp: FakeIdp;
  const CLIENT_ID = "pam-portal";
  const REDIRECT = "http://127.0.0.1/api/v1/auth/oidc/callback";
  const saved: Record<string, string | undefined> = {};

  beforeAll(async () => {
    pool = await setupDatabase();
    idp = await startFakeIdp();
  });
  afterAll(async () => { await idp.close(); await pool.end(); });
  beforeEach(async () => {
    await resetData(pool);
    for (const k of ["OIDC_ISSUER","OIDC_CLIENT_ID","OIDC_CLIENT_SECRET","OIDC_REDIRECT_URI",
      "OIDC_TOKEN_AUTH","OIDC_GROUPS_CLAIM","OIDC_ADMIN_GROUP"]) saved[k] = process.env[k];
    process.env.OIDC_ISSUER = idp.issuer;
    process.env.OIDC_CLIENT_ID = CLIENT_ID;
    process.env.OIDC_CLIENT_SECRET = "sekret";
    process.env.OIDC_REDIRECT_URI = REDIRECT;
    delete process.env.OIDC_TOKEN_AUTH;
    delete process.env.OIDC_GROUPS_CLAIM;
    delete process.env.OIDC_ADMIN_GROUP;
  });
  afterEach(() => { for (const [k, v] of Object.entries(saved)) v === undefined ? delete process.env[k] : (process.env[k] = v); });

  // Executa /oidc/login (captura state/nonce/cookie) e /oidc/callback com um
  // `code` que carrega as claims que o IdP deve assinar.
  async function ssoLogin(claims: Record<string, unknown>) {
    const { app, db } = makeServer();
    const login = await app.inject({ method: "GET", url: "/api/v1/auth/oidc/login" });
    const loc = new URL(login.headers.location as string);
    const state = loc.searchParams.get("state")!;
    const nonce = loc.searchParams.get("nonce")!;
    const challenge = loc.searchParams.get("code_challenge");
    const method = loc.searchParams.get("code_challenge_method");
    const setCookie = login.headers["set-cookie"];
    const cookie = (Array.isArray(setCookie) ? setCookie[0] : String(setCookie)).split(";")[0];

    const full = { iss: idp.issuer, aud: CLIENT_ID, exp: Math.floor(Date.now() / 1000) + 300, nonce, ...claims };
    const code = Buffer.from(JSON.stringify(full)).toString("base64url");
    const cb = await app.inject({
      method: "GET",
      url: `/api/v1/auth/oidc/callback?code=${code}&state=${encodeURIComponent(state)}`,
      headers: { cookie },
    });
    return { app, db, cb, challenge, method };
  }

  it("faz login por OIDC com PKCE S256 e provisiona o usuário", async () => {
    const { app, db, cb, challenge, method } = await ssoLogin({ sub: "u-1", email: "alice@corp.com", name: "Alice" });
    expect(challenge).toBeTruthy();          // PKCE presente
    expect(method).toBe("S256");
    expect(idp.lastToken?.body.code_verifier).toBeTruthy(); // verifier enviado
    expect(cb.statusCode).toBe(302);         // redirect ao portal, logado
    const { rows } = await pool.query("SELECT username, role FROM users WHERE oidc_subject = 'u-1'");
    expect(rows[0]).toMatchObject({ username: "alice@corp.com", role: "user" });
    await app.close(); await db.close();
  });

  it("client_secret_basic: envia Authorization Basic no token endpoint", async () => {
    process.env.OIDC_TOKEN_AUTH = "basic";
    const { app, db, cb } = await ssoLogin({ sub: "u-2", email: "bob@corp.com" });
    expect(cb.statusCode).toBe(302);
    expect(idp.lastToken?.authHeader).toMatch(/^Basic /);
    expect(idp.lastToken?.body.client_secret).toBeUndefined(); // não vai no corpo
    await app.close(); await db.close();
  });

  it("grupo do IdP eleva a admin (só eleva)", async () => {
    process.env.OIDC_GROUPS_CLAIM = "groups";
    process.env.OIDC_ADMIN_GROUP = "PAM-Admins";
    const { app, db, cb } = await ssoLogin({ sub: "u-3", email: "carol@corp.com", groups: ["PAM-Admins", "Other"] });
    expect(cb.statusCode).toBe(302);
    const { rows } = await pool.query("SELECT role FROM users WHERE oidc_subject = 'u-3'");
    expect(rows[0].role).toBe("admin");
    const audit = await pool.query("SELECT 1 FROM audit_logs WHERE event_type = 'auth.role_elevated_by_idp'");
    expect(audit.rowCount).toBe(1);
    await app.close(); await db.close();
  });

  it("sem o grupo admin, permanece user", async () => {
    process.env.OIDC_GROUPS_CLAIM = "groups";
    process.env.OIDC_ADMIN_GROUP = "PAM-Admins";
    const { app, db, cb } = await ssoLogin({ sub: "u-4", email: "dave@corp.com", groups: ["Other"] });
    expect(cb.statusCode).toBe(302);
    const { rows } = await pool.query("SELECT role FROM users WHERE oidc_subject = 'u-4'");
    expect(rows[0].role).toBe("user");
    await app.close(); await db.close();
  });

  it("rotação de chave do IdP não quebra o login (JWKS refetch por kid)", async () => {
    const a = await ssoLogin({ sub: "u-5", email: "e@corp.com" });
    expect(a.cb.statusCode).toBe(302);
    await a.app.close(); await a.db.close();
    idp.rotateKey(); // IdP passa a assinar com novo kid
    const b = await ssoLogin({ sub: "u-5", email: "e@corp.com" });
    expect(b.cb.statusCode).toBe(302); // ainda passa: backend re-busca o JWKS
    await b.app.close(); await b.db.close();
  });

  it("nonce inválido é rejeitado (401)", async () => {
    const { app, db } = makeServer();
    const login = await app.inject({ method: "GET", url: "/api/v1/auth/oidc/login" });
    const loc = new URL(login.headers.location as string);
    const state = loc.searchParams.get("state")!;
    const cookie = String(login.headers["set-cookie"]).split(";")[0];
    const claims = { iss: idp.issuer, aud: CLIENT_ID, exp: Math.floor(Date.now() / 1000) + 300, nonce: "ERRADO", sub: "u-x" };
    const code = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const cb = await app.inject({ method: "GET", url: `/api/v1/auth/oidc/callback?code=${code}&state=${encodeURIComponent(state)}`, headers: { cookie } });
    expect(cb.statusCode).toBe(401);
    await app.close(); await db.close();
  });
});
