import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Writable } from "node:stream";
import type pg from "pg";
import { resetData, setupDatabase } from "../helpers/db.js";
import { makeServer, seedUser } from "../helpers/server.js";

/**
 * HR-06: nenhum segredo em log. Executa login (certo e errado) com uma senha
 * sentinela e garante que ela nunca aparece nos logs estruturados do backend.
 */
describe("sentinela: senha nunca aparece em log (HR-06)", () => {
  let pool: pg.Pool;
  const SENTINEL = "SENHA-SENTINELA-Zx9-nao-deve-vazar";

  beforeAll(async () => { pool = await setupDatabase(); });
  afterAll(async () => { await pool.end(); });
  beforeEach(async () => { await resetData(pool); });

  it("login certo e errado nao logam a senha", async () => {
    let logged = "";
    const sink = new Writable({
      write(chunk, _enc, cb) { logged += chunk.toString(); cb(); },
    });
    const { app, db } = makeServer({ logStream: sink });
    await seedUser(pool, { username: "bob", password: SENTINEL });

    await app.inject({
      method: "POST", url: "/api/v1/auth/login",
      payload: { username: "bob", password: SENTINEL },
    });
    await app.inject({
      method: "POST", url: "/api/v1/auth/login",
      payload: { username: "bob", password: SENTINEL + "-errada" },
    });

    await app.close(); await db.close();
    expect(logged.length).toBeGreaterThan(0); // houve log
    expect(logged).not.toContain(SENTINEL);
  });
});
