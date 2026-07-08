import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pg from "pg";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const initDir = path.join(repoRoot, "infra", "postgres", "init");

export const ADMIN_URL =
  process.env.DATABASE_URL ?? "postgres://pam:pampw@127.0.0.1:5433/pam";
export const APP_URL =
  process.env.PAM_APP_URL ?? "postgres://pam_app:apppw@127.0.0.1:5433/pam";
const APP_PASSWORD = process.env.PAM_APP_PASSWORD ?? "apppw";

const DATA_TABLES = [
  "audit_logs",
  "access_requests",
  "permissions",
  "sessions",
  "assets",
  "user_groups",
  "groups",
  "users",
  "allowed_ports",
];

/** Aplica as migracoes 001..006 (idempotente) e cria a role pam_app. */
export async function setupDatabase(): Promise<pg.Pool> {
  const pool = new pg.Pool({ connectionString: ADMIN_URL });
  const applied = await pool.query("SELECT to_regclass('public.users') AS t");
  if (!applied.rows[0].t) {
    const files = readdirSync(initDir)
      .filter((f) => /^\d+.*\.sql$/.test(f))
      .sort();
    for (const f of files) {
      await pool.query(readFileSync(path.join(initDir, f), "utf8"));
    }
  }
  await ensureAppRole(pool);
  return pool;
}

/** Cria/atualiza a role de runtime com privilegio minimo (espelha 007-app-role.sh). */
async function ensureAppRole(pool: pg.Pool): Promise<void> {
  await pool.query(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pam_app') THEN
        CREATE ROLE pam_app LOGIN PASSWORD '${APP_PASSWORD}';
      ELSE
        ALTER ROLE pam_app WITH LOGIN PASSWORD '${APP_PASSWORD}';
      END IF;
    END $$;`);
  await pool.query("GRANT USAGE ON SCHEMA public TO pam_app");
  await pool.query(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON
       users, groups, user_groups, assets, permissions, allowed_ports, access_requests
     TO pam_app`,
  );
  await pool.query("GRANT SELECT, INSERT, UPDATE ON sessions TO pam_app");
  await pool.query("GRANT SELECT, INSERT ON audit_logs TO pam_app");
}

/** Limpa os dados entre casos, preservando o schema. */
export async function resetData(pool: pg.Pool): Promise<void> {
  await pool.query(`TRUNCATE ${DATA_TABLES.join(", ")} RESTART IDENTITY CASCADE`);
}
