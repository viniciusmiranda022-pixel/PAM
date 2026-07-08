/**
 * Seed de laboratorio (Fase 1). Idempotente. Cria:
 *   - usuario `poc` (senha via SEED_USER_PASSWORD, default 'poc-pass')
 *   - grupo `vnc-ops` com o usuario
 *   - asset `lab-vnc` -> 172.28.0.10:5901, credencial em env:LAB_VNC_PASSWORD
 *   - permissao do grupo ao asset
 *
 * Rodar: docker compose --profile app run --rm backend node dist/seed.js
 */
import pg from "pg";
import { hashPassword } from "./auth.js";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL nao definido");
const userPassword = process.env.SEED_USER_PASSWORD ?? "poc-pass";

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

  const adminPassword = process.env.SEED_ADMIN_PASSWORD ?? "admin-pass";
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

  // Nao imprime senhas/credenciais no stdout (higiene operacional de logs). As
  // senhas de login sao definidas por SEED_USER_PASSWORD / SEED_ADMIN_PASSWORD.
  // eslint-disable-next-line no-console
  console.log(
    JSON.stringify({
      msg: "seed concluido",
      users: ["poc", "admin"],
      asset: "lab-vnc",
    }),
  );
  await pool.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
