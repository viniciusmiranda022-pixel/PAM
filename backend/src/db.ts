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

  // ───────────────────────────── Admin: assets ─────────────────────────────

  async adminListAssets(): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query(
      `SELECT id, name, description, environment, host(ip_address) AS ip_address,
              port, status, created_at
         FROM assets ORDER BY name`,
    );
    return rows;
  }

  async adminCreateAsset(p: {
    name: string;
    description: string | null;
    environment: string;
    ipAddress: string;
    port: number;
    credentialRef: string;
  }): Promise<Record<string, unknown>> {
    const { rows } = await this.pool.query(
      `INSERT INTO assets (name, description, environment, ip_address, port, credential_ref)
       VALUES ($1, $2, $3, $4::inet, $5::int, $6)
       RETURNING id, name, description, environment, host(ip_address) AS ip_address, port, status, created_at`,
      [p.name, p.description, p.environment, p.ipAddress, p.port, p.credentialRef],
    );
    return rows[0]; // nunca retorna credential_ref / senha
  }

  async adminUpdateAsset(
    id: string,
    p: {
      description?: string;
      environment?: string;
      ipAddress?: string;
      port?: number;
      credentialRef?: string;
      status?: "active" | "inactive";
    },
  ): Promise<Record<string, unknown> | null> {
    const { rows } = await this.pool.query(
      `UPDATE assets SET
          description    = COALESCE($2, description),
          environment    = COALESCE($3, environment),
          ip_address     = COALESCE($4::inet, ip_address),
          port           = COALESCE($5::int, port),
          credential_ref = COALESCE($6, credential_ref),
          status         = COALESCE($7::entity_status, status),
          updated_at     = now()
        WHERE id = $1
        RETURNING id, name, description, environment, host(ip_address) AS ip_address, port, status`,
      [
        id,
        p.description ?? null,
        p.environment ?? null,
        p.ipAddress ?? null,
        p.port ?? null,
        p.credentialRef ?? null,
        p.status ?? null,
      ],
    );
    return rows[0] ?? null;
  }

  /** Soft delete se houver historico de sessoes; hard delete caso contrario. */
  async adminDeleteAsset(id: string): Promise<"soft" | "hard" | "not_found"> {
    const exists = await this.pool.query("SELECT 1 FROM assets WHERE id = $1", [id]);
    if (exists.rows.length === 0) return "not_found";
    const used = await this.pool.query("SELECT 1 FROM sessions WHERE asset_id = $1 LIMIT 1", [id]);
    if (used.rows.length > 0) {
      await this.pool.query("UPDATE assets SET status = 'inactive', updated_at = now() WHERE id = $1", [id]);
      return "soft";
    }
    await this.pool.query("DELETE FROM assets WHERE id = $1", [id]);
    return "hard";
  }

  // ───────────────────────────── Admin: users ──────────────────────────────

  async adminListUsers(): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query(
      `SELECT id, username, display_name, email, role, status, created_at
         FROM users ORDER BY username`,
    );
    return rows; // nunca retorna password_hash
  }

  async adminCreateUser(p: {
    username: string;
    displayName: string;
    email: string | null;
    passwordHash: string;
    role: "user" | "admin";
  }): Promise<Record<string, unknown>> {
    const { rows } = await this.pool.query(
      `INSERT INTO users (username, display_name, email, password_hash, role)
       VALUES ($1, $2, $3, $4, $5::user_role)
       RETURNING id, username, display_name, email, role, status, created_at`,
      [p.username, p.displayName, p.email, p.passwordHash, p.role],
    );
    return rows[0];
  }

  async adminUpdateUser(
    id: string,
    p: {
      displayName?: string;
      email?: string;
      passwordHash?: string;
      role?: "user" | "admin";
      status?: "active" | "inactive";
    },
  ): Promise<Record<string, unknown> | null> {
    const { rows } = await this.pool.query(
      `UPDATE users SET
          display_name  = COALESCE($2, display_name),
          email         = COALESCE($3, email),
          password_hash = COALESCE($4, password_hash),
          role          = COALESCE($5::user_role, role),
          status        = COALESCE($6::entity_status, status),
          updated_at    = now()
        WHERE id = $1
        RETURNING id, username, display_name, email, role, status`,
      [id, p.displayName ?? null, p.email ?? null, p.passwordHash ?? null, p.role ?? null, p.status ?? null],
    );
    return rows[0] ?? null;
  }

  // ───────────────────────────── Admin: groups ─────────────────────────────

  async adminListGroups(): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query(
      `SELECT g.id, g.name, g.description, COUNT(ug.user_id)::int AS members
         FROM groups g
         LEFT JOIN user_groups ug ON ug.group_id = g.id
        GROUP BY g.id ORDER BY g.name`,
    );
    return rows;
  }

  async adminCreateGroup(name: string, description: string | null): Promise<Record<string, unknown>> {
    const { rows } = await this.pool.query(
      "INSERT INTO groups (name, description) VALUES ($1, $2) RETURNING id, name, description",
      [name, description],
    );
    return rows[0];
  }

  async adminDeleteGroup(id: string): Promise<boolean> {
    const { rowCount } = await this.pool.query("DELETE FROM groups WHERE id = $1", [id]);
    return (rowCount ?? 0) > 0;
  }

  async adminAddMember(groupId: string, userId: string): Promise<void> {
    await this.pool.query(
      "INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [userId, groupId],
    );
  }

  async adminRemoveMember(groupId: string, userId: string): Promise<void> {
    await this.pool.query("DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2", [userId, groupId]);
  }

  // ─────────────────────────── Admin: permissions ──────────────────────────

  async adminListPermissions(assetId?: string): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query(
      `SELECT p.id, p.asset_id, p.user_id, p.group_id, a.name AS asset_name,
              u.username, g.name AS group_name, p.created_at
         FROM permissions p
         JOIN assets a ON a.id = p.asset_id
         LEFT JOIN users u ON u.id = p.user_id
         LEFT JOIN groups g ON g.id = p.group_id
        WHERE ($1::uuid IS NULL OR p.asset_id = $1)
        ORDER BY p.created_at DESC`,
      [assetId ?? null],
    );
    return rows;
  }

  async adminCreatePermission(p: {
    assetId: string;
    userId?: string;
    groupId?: string;
    grantedBy: string;
  }): Promise<Record<string, unknown>> {
    const { rows } = await this.pool.query(
      `INSERT INTO permissions (asset_id, user_id, group_id, granted_by)
       VALUES ($1, $2, $3, $4)
       RETURNING id, asset_id, user_id, group_id, created_at`,
      [p.assetId, p.userId ?? null, p.groupId ?? null, p.grantedBy],
    );
    return rows[0];
  }

  async adminDeletePermission(id: string): Promise<boolean> {
    const { rowCount } = await this.pool.query("DELETE FROM permissions WHERE id = $1", [id]);
    return (rowCount ?? 0) > 0;
  }

  // ────────────────────────── Admin: allowed_ports ─────────────────────────

  async listAllowedPorts(): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query(
      "SELECT port, description, created_at FROM allowed_ports ORDER BY port",
    );
    return rows;
  }

  async adminCreateAllowedPort(port: number, description: string): Promise<void> {
    await this.pool.query(
      "INSERT INTO allowed_ports (port, description) VALUES ($1, $2)",
      [port, description],
    );
  }

  /** Bloqueia remocao se algum asset ATIVO ainda usa a porta. */
  async adminDeleteAllowedPort(port: number): Promise<"ok" | "in_use" | "not_found"> {
    const inUse = await this.pool.query(
      "SELECT 1 FROM assets WHERE port = $1 AND status = 'active' LIMIT 1",
      [port],
    );
    if (inUse.rows.length > 0) return "in_use";
    const { rowCount } = await this.pool.query("DELETE FROM allowed_ports WHERE port = $1", [port]);
    return (rowCount ?? 0) > 0 ? "ok" : "not_found";
  }

  // ──────────────────────── Admin: sessions / auditoria ────────────────────

  async adminListSessions(f: {
    status?: string;
    userId?: string;
    assetId?: string;
    limit: number;
  }): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query(
      `SELECT s.id, s.user_id, u.username, s.asset_id, a.name AS asset_name,
              s.status, host(s.client_ip) AS client_ip,
              s.started_at, s.ended_at, s.end_reason, s.created_at
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         JOIN assets a ON a.id = s.asset_id
        WHERE ($1::session_status IS NULL OR s.status = $1::session_status)
          AND ($2::uuid IS NULL OR s.user_id = $2)
          AND ($3::uuid IS NULL OR s.asset_id = $3)
        ORDER BY s.created_at DESC
        LIMIT $4`,
      [f.status ?? null, f.userId ?? null, f.assetId ?? null, f.limit],
    );
    return rows;
  }

  async adminListAuditLogs(f: {
    eventType?: string;
    userId?: string;
    assetId?: string;
    limit: number;
    offset: number;
  }): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query(
      `SELECT id, event_type, user_id, asset_id, session_id,
              host(source_ip) AS source_ip, details, created_at
         FROM audit_logs
        WHERE ($1::text IS NULL OR event_type = $1)
          AND ($2::uuid IS NULL OR user_id = $2)
          AND ($3::uuid IS NULL OR asset_id = $3)
        ORDER BY id DESC
        LIMIT $4 OFFSET $5`,
      [f.eventType ?? null, f.userId ?? null, f.assetId ?? null, f.limit, f.offset],
    );
    return rows;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
