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

/**
 * Resolve a referencia de credencial de um asset para a senha VNC.
 *
 * Este e o unico ponto que materializa uma senha e e o seam do cofre: na Fase 1
 * o provider e `env:NOME` (variavel de ambiente); na Fase 3 entra o Vault
 * (`vault:caminho`) sem mudar o resto do gateway. A senha jamais e logada.
 */
export function resolveCredential(ref: string | null, env = process.env): string {
  if (!ref) throw new Error("asset sem credential_ref");
  if (ref.startsWith("env:")) {
    const name = ref.slice(4);
    const value = env[name];
    if (value === undefined) throw new Error(`credencial ausente: ${name}`);
    return value;
  }
  throw new Error(`provider de credencial nao suportado nesta fase: ${ref}`);
}
