import pg from "pg";
import { createHash } from "node:crypto";

export interface ConsumedSession {
  sessionId: string;
  userId: string;
  assetId: string;
  /** Protocolo do asset (resolve o adapter no gateway — PR-16). */
  protocol: string;
  ip: string;
  port: number;
  credentialRef: string | null;
  assetStatus: "active" | "inactive";
  /** IP de origem fixado na criacao da sessao (fonte autoritativa p/ HR-10). */
  clientIp: string | null;
  recordSessions: boolean;
  tlsRequired: boolean;
}

export function sha256(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

export class Db {
  private pool: pg.Pool;
  constructor(connectionString: string) {
    this.pool = new pg.Pool({ connectionString, max: 5 });
  }

  /**
   * Consome o token efemero de forma atomica (uso unico + TTL) e devolve o
   * destino do asset. 0 linhas => token invalido/expirado/ja usado.
   * O destino (ip/porta) vem SEMPRE do banco, nunca do cliente (HR-03).
   */
  async consumeToken(tokenHash: Buffer): Promise<ConsumedSession | null> {
    const { rows } = await this.pool.query(
      `WITH consumed AS (
         UPDATE sessions s
            SET token_used_at = now()
          WHERE s.token_hash = $1
            AND s.token_used_at IS NULL
            AND s.token_expires_at > now()
            AND s.status = 'pending'
        RETURNING s.id, s.user_id, s.asset_id, s.client_ip)
       SELECT c.id AS session_id, c.user_id, c.asset_id,
              COALESCE(a.protocol, 'vnc') AS protocol,
              host(a.ip_address) AS ip, a.port,
              a.credential_ref, a.status AS asset_status,
              host(c.client_ip) AS client_ip,
              COALESCE(a.record_sessions, true) AS record_sessions,
              COALESCE(a.tls_required, false) AS tls_required
         FROM consumed c
         JOIN assets a ON a.id = c.asset_id`,
      [tokenHash],
    );
    if (rows.length === 0) return null;
    const r = rows[0];
    return {
      sessionId: r.session_id,
      userId: r.user_id,
      assetId: r.asset_id,
      protocol: r.protocol,
      ip: r.ip,
      port: r.port,
      credentialRef: r.credential_ref,
      assetStatus: r.asset_status,
      clientIp: r.client_ip,
      recordSessions: r.record_sessions,
      tlsRequired: r.tls_required,
    };
  }

  /** Re-checagem da allowlist no gateway (defesa em profundidade — HR-04). */
  async isPortAllowed(port: number): Promise<boolean> {
    const { rows } = await this.pool.query(
      "SELECT 1 FROM allowed_ports WHERE port = $1",
      [port],
    );
    return rows.length > 0;
  }

  async markStarted(sessionId: string): Promise<void> {
    await this.pool.query(
      "UPDATE sessions SET status = 'active', started_at = now() WHERE id = $1",
      [sessionId],
    );
  }

  async markEnded(
    sessionId: string,
    status: "closed" | "failed" | "terminated",
    endReason: string,
  ): Promise<void> {
    await this.pool.query(
      `UPDATE sessions
          SET status = $2, ended_at = now(), end_reason = $3
        WHERE id = $1 AND ended_at IS NULL`,
      [sessionId, status, endReason],
    );
  }

  /** Auditoria (HR-10). `details` nunca deve conter segredo (HR-06). */
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

  async setRecordingPath(sessionId: string, recordingPath: string): Promise<void> {
    await this.pool.query(
      "UPDATE sessions SET recording_path = $2 WHERE id = $1",
      [sessionId, recordingPath],
    );
  }

  /** IDs (dentre os informados) cujas sessoes nao estao mais 'active'. */
  async findTerminatedAmong(ids: string[]): Promise<string[]> {
    if (ids.length === 0) return [];
    const { rows } = await this.pool.query(
      "SELECT id FROM sessions WHERE id = ANY($1::uuid[]) AND status <> 'active'",
      [ids],
    );
    return rows.map((r) => r.id as string);
  }

  async ping(): Promise<boolean> {
    try {
      await this.pool.query("SELECT 1");
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
