import { randomUUID } from "node:crypto";

/**
 * Cliente minimo do HashiCorp Vault (KV v2). Escreve a senha VNC e devolve o
 * credential_ref `vault:<path>`. Fase 3 — substitui o cofre AES-GCM interino.
 * Nenhuma senha e logada. Autenticacao por token (dev/lab); AppRole em producao.
 */
export interface VaultConfig {
  addr: string;
  token: string;
  mount: string;
}

export function vaultConfigFromEnv(env = process.env): VaultConfig {
  const addr = env.VAULT_ADDR;
  if (!addr) throw new Error("VAULT_ADDR nao definido");
  const token = env.VAULT_TOKEN;
  if (!token) throw new Error("VAULT_TOKEN nao definido");
  return { addr: addr.replace(/\/+$/, ""), token, mount: env.VAULT_KV_MOUNT ?? "secret" };
}

export async function writeVaultSecret(password: string, env = process.env): Promise<string> {
  const cfg = vaultConfigFromEnv(env);
  const path = `vnc/${randomUUID()}`;
  const res = await fetch(`${cfg.addr}/v1/${cfg.mount}/data/${path}`, {
    method: "POST",
    headers: { "X-Vault-Token": cfg.token, "content-type": "application/json" },
    body: JSON.stringify({ data: { password } }),
  });
  if (!res.ok) throw new Error(`vault write falhou: ${res.status}`);
  return `vault:${path}`;
}
