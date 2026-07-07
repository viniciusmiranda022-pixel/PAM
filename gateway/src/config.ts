import { createDecipheriv } from "node:crypto";

export interface Config {
  port: number;
  databaseUrl: string;
  handshakeTimeoutMs: number;
}

export function loadConfig(env = process.env): Config {
  const databaseUrl = env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL nao definido");
  return {
    port: Number(env.GATEWAY_PORT ?? 8081),
    databaseUrl,
    handshakeTimeoutMs: Number(env.HANDSHAKE_TIMEOUT_MS ?? 10_000),
  };
}

function masterKey(env: NodeJS.ProcessEnv): Buffer {
  const b64 = env.CREDENTIAL_MASTER_KEY;
  if (!b64) throw new Error("CREDENTIAL_MASTER_KEY nao definido");
  const key = Buffer.from(b64, "base64");
  if (key.length !== 32) throw new Error("CREDENTIAL_MASTER_KEY deve ter 32 bytes (base64)");
  return key;
}

/**
 * Resolve a referencia de credencial de um asset para a senha VNC.
 *
 * Unico ponto que materializa uma senha (seam do cofre). Providers:
 *   - `env:NOME`        -> variavel de ambiente (asset de laboratorio)
 *   - `enc:v1:<n>:<b>`  -> AES-256-GCM cifrado pelo backend (Fase 2)
 * Na Fase 3 entra o Vault (`vault:caminho`) sem mudar o resto do gateway.
 * A senha jamais e logada.
 */
export function resolveCredential(ref: string | null, env = process.env): string {
  if (!ref) throw new Error("asset sem credential_ref");
  if (ref.startsWith("env:")) {
    const name = ref.slice(4);
    const value = env[name];
    if (value === undefined) throw new Error(`credencial ausente: ${name}`);
    return value;
  }
  if (ref.startsWith("enc:v1:")) {
    const parts = ref.split(":");
    if (parts.length !== 4) throw new Error("credential_ref cifrado malformado");
    const nonce = Buffer.from(parts[2], "base64url");
    const blob = Buffer.from(parts[3], "base64url");
    const tag = blob.subarray(blob.length - 16);
    const ct = blob.subarray(0, blob.length - 16);
    const decipher = createDecipheriv("aes-256-gcm", masterKey(env), nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  }
  throw new Error("provider de credencial nao suportado");
}
