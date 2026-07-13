import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import type pg from "pg";
// Consumo de token do lado do gateway (build dist) — mesma logica de producao.
import { Db as GatewayDb, sha256 as gwSha256 } from "../../gateway/dist/db.js";
import { resetData, setupDatabase } from "../helpers/db.js";
import { ADMIN_URL } from "../helpers/db.js";
import { makeServer, seedUser, seedAssetForUser, login } from "../helpers/server.js";

/**
 * Fluxo de sessao ponta-a-ponta (backend + consumo pelo gateway), contra
 * Postgres real: login -> criar sessao por assetId -> token efemero de uso
 * unico com TTL. Reafirma HR-01/02 (so assetId) e HR-08 (token single-use).
 */
describe("fluxo de sessao (integracao)", () => {
  let pool: pg.Pool;
  let gw: GatewayDb;

  beforeAll(async () => {
    pool = await setupDatabase();
    gw = new GatewayDb(ADMIN_URL);
  });
  afterAll(async () => { await gw.close(); await pool.end(); });
  beforeEach(async () => { await resetData(pool); });

  async function createSession(): Promise<{ token: string; assetId: string }> {
    const { app, db } = makeServer();
    const userId = await seedUser(pool, { username: "carol", password: "senha-carol-1" });
    const assetId = await seedAssetForUser(pool, userId, { port: 5901 });
    const cookie = await login(app, "carol", "senha-carol-1");
    const res = await app.inject({
      method: "POST", url: "/api/v1/sessions",
      headers: { cookie }, payload: { assetId },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    await app.close(); await db.close();
    return { token: body.token, assetId };
  }

  it("cria sessao por assetId e devolve token efemero", async () => {
    const { token } = await createSession();
    expect(typeof token).toBe("string");
    expect(token.length).toBeGreaterThan(20);
    // O banco guarda apenas o hash do token (nunca o valor).
    const stored = await pool.query("SELECT token_hash FROM sessions ORDER BY created_at DESC LIMIT 1");
    const expectedHash = createHash("sha256").update(token, "utf8").digest();
    expect(Buffer.from(stored.rows[0].token_hash).equals(expectedHash)).toBe(true);
  });

  it("rejeita host/port no corpo (HR-01/02)", async () => {
    const { app, db } = makeServer();
    const userId = await seedUser(pool, { username: "dave", password: "senha-dave-1" });
    const assetId = await seedAssetForUser(pool, userId, { port: 5902 });
    const cookie = await login(app, "dave", "senha-dave-1");
    const res = await app.inject({
      method: "POST", url: "/api/v1/sessions",
      headers: { cookie },
      payload: { assetId, host: "10.0.0.9", port: 5900 },
    });
    expect(res.statusCode).toBe(400);
    await app.close(); await db.close();
  });

  it("token e de uso unico (segundo consumo falha)", async () => {
    const { token } = await createSession();
    const first = await gw.consumeToken(gwSha256(token));
    expect(first).not.toBeNull();
    const second = await gw.consumeToken(gwSha256(token));
    expect(second).toBeNull();
  });

  it("token expirado nao e consumido", async () => {
    const { token } = await createSession();
    // Expira artificialmente a sessao pendente.
    await pool.query("UPDATE sessions SET token_expires_at = now() - interval '1 second'");
    const consumed = await gw.consumeToken(gwSha256(token));
    expect(consumed).toBeNull();
  });

  it("consumeToken devolve o protocolo do asset (PR-16; default vnc)", async () => {
    const { token } = await createSession();
    const consumed = await gw.consumeToken(gwSha256(token));
    expect(consumed?.protocol).toBe("vnc"); // o gateway resolve o adapter por este valor
  });
});
