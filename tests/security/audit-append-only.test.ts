import { afterAll, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import { APP_URL, setupDatabase } from "../helpers/db.js";

/**
 * PR-13: a role de runtime pam_app tem privilegio minimo — auditoria
 * append-only (anti-repudio, HR-10). Prova que ela insere/le audit_logs mas
 * NAO consegue alterar nem apagar (UPDATE/DELETE negados).
 */
describe("audit_logs append-only via role pam_app", () => {
  let admin: pg.Pool;
  let appPool: pg.Pool;

  beforeAll(async () => {
    admin = await setupDatabase(); // garante schema + role pam_app
    appPool = new pg.Pool({ connectionString: APP_URL });
  });
  afterAll(async () => { await appPool.end(); await admin.end(); });

  it("pam_app consegue INSERT e SELECT", async () => {
    await appPool.query("INSERT INTO audit_logs (event_type, source_ip) VALUES ('test.insert', '10.0.0.2')");
    const { rows } = await appPool.query(
      "SELECT count(*)::int AS n FROM audit_logs WHERE event_type = 'test.insert'",
    );
    expect(rows[0].n).toBeGreaterThanOrEqual(1);
  });

  it("pam_app NAO consegue UPDATE (permission denied)", async () => {
    await expect(
      appPool.query("UPDATE audit_logs SET event_type = 'tampered'"),
    ).rejects.toThrow(/permission denied/i);
  });

  it("pam_app NAO consegue DELETE (permission denied)", async () => {
    await expect(
      appPool.query("DELETE FROM audit_logs"),
    ).rejects.toThrow(/permission denied/i);
  });

  it("pam_app NAO consegue TRUNCATE (permission denied)", async () => {
    await expect(
      appPool.query("TRUNCATE audit_logs"),
    ).rejects.toThrow(/permission denied|must be owner/i);
  });

  it("pam_app mantem CRUD nas tabelas operacionais (ex.: assets INSERT)", async () => {
    const { rows } = await appPool.query(
      "SELECT has_table_privilege('pam_app','assets','INSERT') AS ok",
    );
    expect(rows[0].ok).toBe(true);
  });
});
