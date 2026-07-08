import type pg from "pg";
// Importa o BUILD de backend (dist) — CI compila antes de rodar a suite.
import { buildServer } from "../../backend/dist/server.js";
import { Db } from "../../backend/dist/db.js";
import { loadConfig } from "../../backend/dist/config.js";
import { hashPassword } from "../../backend/dist/auth.js";
import { ADMIN_URL } from "./db.js";

export interface TestServerOptions {
  /** Valor de TRUST_PROXY (default "false" — ignora X-Forwarded-For). */
  trustProxy?: string;
  /** Stream para capturar logs (sentinela de segredo). */
  logStream?: NodeJS.WritableStream;
}

export function makeServer(opts: TestServerOptions = {}) {
  const config = loadConfig({
    DATABASE_URL: ADMIN_URL,
    COOKIE_SECRET: "test-cookie-secret-32-bytes-min!!",
    SECURE_COOKIE: "false",
    CREDENTIAL_MASTER_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    RATE_LIMIT_LOGIN_PER_MIN: "1000",
    RATE_LIMIT_SESSION_PER_MIN: "1000",
    TRUST_PROXY: opts.trustProxy ?? "false",
    SCRYPT_N: "16384", // KDF rapido nos testes (ADR 0002)
  } as NodeJS.ProcessEnv);
  const db = new Db(config.databaseUrl);
  const app = buildServer(db, config, opts.logStream);
  return { app, db, config };
}

let userSeq = 0;

/** Cria um usuario local com senha (hash real). Retorna o id. */
export async function seedUser(
  pool: pg.Pool,
  opts: { username?: string; password: string; role?: "user" | "admin" } = { password: "x" },
): Promise<string> {
  const username = opts.username ?? `u${++userSeq}`;
  const { rows } = await pool.query(
    `INSERT INTO users (username, display_name, password_hash, role)
     VALUES ($1, $1, $2, $3::user_role) RETURNING id`,
    [username, hashPassword(opts.password), opts.role ?? "user"],
  );
  return rows[0].id as string;
}

/** Garante uma porta na allowlist. */
export async function seedAllowedPort(pool: pg.Pool, port: number): Promise<void> {
  await pool.query(
    "INSERT INTO allowed_ports (port, description) VALUES ($1, 'test') ON CONFLICT DO NOTHING",
    [port],
  );
}

/** Cria um asset e concede permissao direta ao usuario. Retorna o assetId. */
export async function seedAssetForUser(
  pool: pg.Pool,
  userId: string,
  opts: { port?: number; ip?: string; credentialRef?: string } = {},
): Promise<string> {
  const port = opts.port ?? 5901;
  await seedAllowedPort(pool, port);
  const asset = await pool.query(
    `INSERT INTO assets (name, environment, ip_address, port, credential_ref, record_sessions)
     VALUES ($1, 'lab', $2, $3, $4, false) RETURNING id`,
    [`asset-${port}-${Math.random().toString(36).slice(2, 8)}`, opts.ip ?? "172.28.0.10", port,
     opts.credentialRef ?? "env:LAB_VNC_PASSWORD"],
  );
  const assetId = asset.rows[0].id as string;
  await pool.query("INSERT INTO permissions (asset_id, user_id) VALUES ($1, $2)", [assetId, userId]);
  return assetId;
}

/** Faz login e retorna o cookie de sessao assinado. */
export async function login(
  app: Awaited<ReturnType<typeof makeServer>>["app"],
  username: string,
  password: string,
  headers: Record<string, string> = {},
): Promise<string> {
  const res = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: { username, password },
    headers,
  });
  if (res.statusCode !== 204) throw new Error(`login falhou: ${res.statusCode} ${res.body}`);
  const setCookie = res.headers["set-cookie"];
  const raw = Array.isArray(setCookie) ? setCookie[0] : String(setCookie);
  return raw.split(";")[0];
}
