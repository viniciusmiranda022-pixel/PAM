import type { Config } from "./config.js";
import { encryptCredential } from "./credentials.js";
import { writeVaultSecret } from "./vault.js";

/**
 * Guarda a senha VNC no provider configurado e devolve o `credential_ref`.
 * Este e o unico ponto de escrita de segredo do backend — o mesmo seam que o
 * gateway usa para ler (resolveCredential). A senha nunca vai ao banco em claro.
 */
export async function storeCredential(
  password: string,
  config: Config,
  env = process.env,
): Promise<string> {
  if (config.credentialProvider === "vault") return writeVaultSecret(password, env);
  return encryptCredential(password, env);
}
