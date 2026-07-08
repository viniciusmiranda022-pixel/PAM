import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type pg from "pg";
import { resetData, setupDatabase } from "../helpers/db.js";
import { makeServer, seedUser } from "../helpers/server.js";

/**
 * HR-10 / PR-13: o IP de origem auditado nao pode ser forjado pelo cliente via
 * X-Forwarded-For. Sem proxy confiavel configurado (TRUST_PROXY=false), o header
 * e ignorado; com TRUST_PROXY=1 (nginx sobrescreve o header), ele e respeitado.
 */
describe("X-Forwarded-For nao spoofa o IP de auditoria", () => {
  let pool: pg.Pool;
  const SOCKET_IP = "203.0.113.7";
  const FORGED = "1.2.3.4";

  beforeAll(async () => { pool = await setupDatabase(); });
  afterAll(async () => { await pool.end(); });
  beforeEach(async () => { await resetData(pool); });

  async function auditedLoginIp(trustProxy: string): Promise<string | null> {
    const { app, db } = makeServer({ trustProxy });
    await seedUser(pool, { username: "alice", password: "senha-correta-1" });
    await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { username: "alice", password: "senha-correta-1" },
      headers: { "x-forwarded-for": FORGED },
      remoteAddress: SOCKET_IP,
    });
    const { rows } = await pool.query(
      "SELECT host(source_ip) AS ip FROM audit_logs WHERE event_type = 'auth.login' ORDER BY id DESC LIMIT 1",
    );
    await app.close();
    await db.close();
    return rows[0]?.ip ?? null;
  }

  it("TRUST_PROXY=false: usa o IP do socket, ignora o header forjado", async () => {
    expect(await auditedLoginIp("false")).toBe(SOCKET_IP);
  });

  it("TRUST_PROXY=1: confia no header (proxy sobrescreve com $remote_addr)", async () => {
    // Prova que a fonte e configuravel; em producao o nginx garante que o unico
    // valor do header e $remote_addr, nao um valor do cliente.
    expect(await auditedLoginIp("1")).toBe(FORGED);
  });
});
