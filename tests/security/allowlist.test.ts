import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type pg from "pg";
import { resetData, setupDatabase } from "../helpers/db.js";
import { makeServer, seedUser, login } from "../helpers/server.js";

/**
 * HR-04: allowlist de portas. Um admin nao consegue cadastrar asset em porta do
 * denylist imutavel (ex.: 3389/RDP, 22/SSH) nem fora da allowlist. Defesa na
 * API + FK no banco.
 */
describe("allowlist/denylist de portas (HR-04)", () => {
  let pool: pg.Pool;
  beforeAll(async () => { pool = await setupDatabase(); });
  afterAll(async () => { await pool.end(); });
  beforeEach(async () => { await resetData(pool); });

  it("admin nao adiciona porta do denylist (3389) na allowlist", async () => {
    const { app, db } = makeServer();
    await seedUser(pool, { username: "root", password: "admin-forte-1", role: "admin" });
    const cookie = await login(app, "root", "admin-forte-1");
    const res = await app.inject({
      method: "POST",
      url: "/api/v1/admin/allowed-ports",
      headers: { cookie },
      payload: { port: 3389, description: "rdp" },
    });
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    const { rows } = await pool.query("SELECT 1 FROM allowed_ports WHERE port = 3389");
    expect(rows.length).toBe(0);
    await app.close(); await db.close();
  });

  it("banco rejeita asset em porta fora da allowlist (FK)", async () => {
    await expect(
      pool.query(
        `INSERT INTO assets (name, environment, ip_address, port, credential_ref)
         VALUES ('bad', 'lab', '172.28.0.10', 4444, 'env:X')`,
      ),
    ).rejects.toThrow(/foreign key|allowed_ports/i);
  });
});
