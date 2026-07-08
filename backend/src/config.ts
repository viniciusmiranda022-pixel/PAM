export interface Config {
  port: number;
  databaseUrl: string;
  cookieSecret: string;
  gatewayPublicUrl: string;
  sessionTokenTtlSeconds: number;
  secureCookie: boolean;
  rateLimitLoginPerMin: number;
  rateLimitSessionPerMin: number;
  credentialProvider: "enc" | "vault";
  /** Proxies confiaveis na frente do backend — ver parseTrustProxy. */
  trustProxy: boolean | number | string;
}

/**
 * TRUST_PROXY controla de onde vem o IP de auditoria (HR-10):
 *   ausente/"false" -> false: ignora X-Forwarded-For; IP = socket (imune a spoof)
 *   "1", "2", ...   -> confia nesse numero de hops (compose usa 1: o nginx,
 *                      que SOBRESCREVE o X-Forwarded-For com $remote_addr)
 *   "true"          -> confia em qualquer proxy — NAO usar em producao
 *   outro valor     -> repassado ao Fastify (lista de IPs/CIDRs confiaveis)
 */
export function parseTrustProxy(value: string | undefined): boolean | number | string {
  if (!value || value === "false") return false;
  if (value === "true") return true;
  const n = Number(value);
  if (Number.isInteger(n) && n >= 0) return n;
  return value;
}

export function loadConfig(env = process.env): Config {
  const databaseUrl = env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL nao definido");
  const cookieSecret = env.COOKIE_SECRET;
  if (!cookieSecret || cookieSecret.length < 16) {
    throw new Error("COOKIE_SECRET ausente ou muito curto (>=16 chars)");
  }
  return {
    port: Number(env.BACKEND_PORT ?? 3000),
    databaseUrl,
    cookieSecret,
    gatewayPublicUrl: env.GATEWAY_PUBLIC_URL ?? "wss://localhost/gateway/vnc",
    sessionTokenTtlSeconds: Number(env.SESSION_TOKEN_TTL_SECONDS ?? 30),
    secureCookie: env.SECURE_COOKIE !== "false",
    rateLimitLoginPerMin: Number(env.RATE_LIMIT_LOGIN_PER_MIN ?? 5),
    rateLimitSessionPerMin: Number(env.RATE_LIMIT_SESSION_PER_MIN ?? 10),
    credentialProvider: env.CREDENTIAL_PROVIDER === "vault" ? "vault" : "enc",
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
  };
}
