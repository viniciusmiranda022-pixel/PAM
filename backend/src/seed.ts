/**
 * Seed de laboratorio (Fase 1). Idempotente. Cria:
 *   - usuario `poc` (senha via SEED_USER_PASSWORD — obrigatoria, sem default)
 *   - usuario `admin` (senha via SEED_ADMIN_PASSWORD — obrigatoria, sem default)
 *   - grupo `vnc-ops` com o usuario
 *   - asset `lab-vnc` -> 172.28.0.10:5901, credencial em env:LAB_VNC_PASSWORD
 *   - permissao do grupo ao asset
 *
 * PR-13: sem senha default e sem senha no stdout (HR-06) — defina
 * SEED_USER_PASSWORD e SEED_ADMIN_PASSWORD no infra/.env.
 *
 * Rodar: docker compose --profile app run --rm backend node dist/seed.js
 */
import pg from "pg";
import { hashPassword } from "./auth.js";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL nao definido");

function requiredPassword(name: "SEED_USER_PASSWORD" | "SEED_ADMIN_PASSWORD"): string {
  const value = process.env[name];
  if (!value || value.length < 8) {
    throw new Error(
      `${name} ausente ou curta (>=8 chars). O seed nao usa senha default — defina no infra/.env.`,
    );
  }
  return value;
}
const userPassword = requiredPassword("SEED_USER_PASSWORD");
const adminPassword = requiredPassword("SEED_ADMIN_PASSWORD");

const pool = new pg.Pool({ connectionString: databaseUrl });

async function main(): Promise<void> {
  const user = await pool.query(
    `INSERT INTO users (username, display_name, password_hash, role)
     VALUES ('poc', 'PoC User', $1, 'user')
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
     RETURNING id`,
    [hashPassword(userPassword)],
  );
  const userId = user.rows[0].id;

  await pool.query(
    `INSERT INTO users (username, display_name, password_hash, role)
     VALUES ('admin', 'Administrador', $1, 'admin')
     ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`,
    [hashPassword(adminPassword)],
  );

  const group = await pool.query(
    `INSERT INTO groups (name, description) VALUES ('vnc-ops', 'Operadores VNC de laboratorio')
     ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
     RETURNING id`,
  );
  const groupId = group.rows[0].id;

  await pool.query(
    `INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)
     ON CONFLICT DO NOTHING`,
    [userId, groupId],
  );

  const asset = await pool.query(
    `INSERT INTO assets (name, description, environment, ip_address, port, credential_ref)
     VALUES ('lab-vnc', 'Asset VNC de laboratorio', 'lab', '172.28.0.10', 5901, 'env:LAB_VNC_PASSWORD')
     ON CONFLICT (name) DO UPDATE
       SET ip_address = EXCLUDED.ip_address, port = EXCLUDED.port,
           credential_ref = EXCLUDED.credential_ref, status = 'active'
     RETURNING id`,
  );
  const assetId = asset.rows[0].id;

  await pool.query(
    `INSERT INTO permissions (asset_id, group_id) VALUES ($1, $2)
     ON CONFLICT DO NOTHING`,
    [assetId, groupId],
  );

  // HR-06: senha NUNCA em log/stdout — só os usernames criados.
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ msg: "seed concluido", users: ["poc", "admin"], asset: "lab-vnc" }));
  await pool.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
