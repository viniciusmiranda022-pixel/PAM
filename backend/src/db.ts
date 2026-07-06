import pg from "pg";

export interface UserRow {
  id: string;
  username: string;
  displayName: string;
  role: "user" | "admin";
  passwordHash: string;
  status: "active" | "inactive";
}

export interface AssetListItem {
  id: string;
  name: string;
  description: string | null;
  environment: string;
  status: "active" | "inactive";
}

export class Db {
  private pool: pg.Pool;
  constructor(connectionString: string) {
    this.pool = new pg.Pool({ connectionString, max: 10 });
  }

  async findUserByUsername(username: string): Promise<UserRow | null> {
    const { rows } = await this.pool.query(
      `SELECT id, username, display_name, role, password_hash, status
         FROM users WHERE username = $1`,
      [username],
    );
    if (rows.length === 0) return null;
    const r = rows[0];
    return {
      id: r.id,
      username: r.username,
      displayName: r.display_name,
      role: r.role,
      passwordHash: r.password_hash,
      status: r.status,
    };
  }

  async findUserById(id: string): Promise<UserRow | null> {
    const { rows } = await this.pool.query(
      `SELECT id, username, display_name, role, password_hash, status
         FROM users WHERE id = $1`,
      [id],
    );
    if (rows.length === 0) return null;
    const r = rows[0];
    return {
      id: r.id,
      username: r.username,
      displayName: r.display_name,
      role: r.role,
      passwordHash: r.password_hash,
      status: r.status,
    };
  }

  /** Assets ativos que o usuario pode ver (direto ou por grupo). Sem IP/porta. */
  async listAssetsForUser(userId: string): Promise<AssetListItem[]> {
    const { rows } = await this.pool.query(
      `SELECT DISTINCT a.id, a.name, a.description, a.environment, a.status
         FROM assets a
         JOIN permissions p ON p.asset_id = a.id
         LEFT JOIN user_groups ug ON ug.group_id = p.group_id AND ug.user_id = $1
        WHERE a.status = 'active'
          AND (p.user_id = $1 OR ug.user_id = $1)
        ORDER BY a.name`,
      [userId],
    );
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      environment: r.environment,
      status: r.status,
    }));
  }

  async userCanAccessAsset(userId: string, assetId: string): Promise<boolean> {
    const { rows } = await this.pool.query(
      `SELECT 1
         FROM permissions p
         LEFT JOIN user_groups ug ON ug.group_id = p.group_id AND ug.user_id = $1
        WHERE p.asset_id = $2 AND (p.user_id = $1 OR ug.user_id = $1)
        LIMIT 1`,
      [userId, assetId],
    );
    return rows.length > 0;
  }

  async getAsset(
    assetId: string,
  ): Promise<{ id: string; port: number; status: "active" | "inactive" } | null> {
    const { rows } = await this.pool.query(
      "SELECT id, port, status FROM assets WHERE id = $1",
      [assetId],
    );
    if (rows.length === 0) return null;
    return { id: rows[0].id, port: rows[0].port, status: rows[0].status };
  }

  async isPortAllowed(port: number): Promise<boolean> {
    const { rows } = await this.pool.query(
      "SELECT 1 FROM allowed_ports WHERE port = $1",
      [port],
    );
    return rows.length > 0;
  }

  async createSession(params: {
    userId: string;
    assetId: string;
    tokenHash: Buffer;
    ttlSeconds: number;
    clientIp: string | null;
  }): Promise<string> {
    const { rows } = await this.pool.query(
      `INSERT INTO sessions (user_id, asset_id, token_hash, token_expires_at, status, client_ip)
       VALUES ($1, $2, $3, now() + ($4 || ' seconds')::interval, 'pending', $5)
       RETURNING id`,
      [params.userId, params.assetId, params.tokenHash, String(params.ttlSeconds), params.clientIp],
    );
    return rows[0].id;
  }

  async getSessionOwner(
    sessionId: string,
  ): Promise<{ id: string; userId: string; status: string } | null> {
    const { rows } = await this.pool.query(
      "SELECT id, user_id, status FROM sessions WHERE id = $1",
      [sessionId],
    );
    if (rows.length === 0) return null;
    return { id: rows[0].id, userId: rows[0].user_id, status: rows[0].status };
  }

  async terminateSession(sessionId: string, reason: string): Promise<void> {
    await this.pool.query(
      `UPDATE sessions
          SET status = 'terminated', ended_at = now(), end_reason = $2
        WHERE id = $1 AND ended_at IS NULL`,
      [sessionId, reason],
    );
  }

  async audit(
    eventType: string,
    fields: {
      userId?: string | null;
      assetId?: string | null;
      sessionId?: string | null;
      sourceIp?: string | null;
      details?: Record<string, unknown>;
    } = {},
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_logs (event_type, user_id, asset_id, session_id, source_ip, details)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        eventType,
        fields.userId ?? null,
        fields.assetId ?? null,
        fields.sessionId ?? null,
        fields.sourceIp ?? null,
        JSON.stringify(fields.details ?? {}),
      ],
    );
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
