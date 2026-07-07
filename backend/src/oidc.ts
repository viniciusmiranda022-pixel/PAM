/**
 * Cliente OIDC (Authorization Code flow) — Fase 5.5. Sem dependencia externa:
 * a verificacao do id_token (RS256) usa node:crypto (createPublicKey a partir do
 * JWK do JWKS). Valida assinatura, iss, aud, exp e nonce.
 */
import { createPublicKey, verify as cryptoVerify, type JsonWebKey } from "node:crypto";

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  autoProvision: boolean;
}

export function oidcConfig(env = process.env): OidcConfig | null {
  const { OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI } = env;
  if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !OIDC_CLIENT_SECRET || !OIDC_REDIRECT_URI) return null;
  return {
    issuer: OIDC_ISSUER.replace(/\/+$/, ""),
    clientId: OIDC_CLIENT_ID,
    clientSecret: OIDC_CLIENT_SECRET,
    redirectUri: OIDC_REDIRECT_URI,
    autoProvision: env.OIDC_AUTO_PROVISION !== "false",
  };
}

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

const discoveryCache = new Map<string, Discovery>();
const jwksCache = new Map<string, { keys: Array<Record<string, unknown> & { kid?: string }> }>();

export async function discover(issuer: string): Promise<Discovery> {
  const cached = discoveryCache.get(issuer);
  if (cached) return cached;
  const res = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery falhou: ${res.status}`);
  const d = (await res.json()) as Discovery;
  discoveryCache.set(issuer, d);
  return d;
}

export function buildAuthUrl(disc: Discovery, cfg: OidcConfig, state: string, nonce: string): string {
  const u = new URL(disc.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", cfg.clientId);
  u.searchParams.set("redirect_uri", cfg.redirectUri);
  u.searchParams.set("scope", "openid email profile");
  u.searchParams.set("state", state);
  u.searchParams.set("nonce", nonce);
  return u.toString();
}

export async function exchangeCode(disc: Discovery, cfg: OidcConfig, code: string): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
  });
  const res = await fetch(disc.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new Error(`OIDC token exchange falhou: ${res.status}`);
  const tokens = (await res.json()) as { id_token?: string };
  if (!tokens.id_token) throw new Error("OIDC: resposta sem id_token");
  return tokens.id_token;
}

async function getJwks(jwksUri: string): Promise<{ keys: Array<Record<string, unknown> & { kid?: string }> }> {
  const cached = jwksCache.get(jwksUri);
  if (cached) return cached;
  const res = await fetch(jwksUri);
  if (!res.ok) throw new Error(`OIDC JWKS falhou: ${res.status}`);
  const jwks = (await res.json()) as { keys: Array<Record<string, unknown> & { kid?: string }> };
  jwksCache.set(jwksUri, jwks);
  return jwks;
}

export interface OidcClaims {
  sub: string;
  email?: string;
  preferredUsername?: string;
  name?: string;
}

/** Verifica assinatura (RS256) + iss/aud/exp/nonce e retorna as claims. */
export async function verifyIdToken(
  idToken: string,
  cfg: OidcConfig,
  disc: Discovery,
  expectedNonce: string,
  now = Date.now() / 1000,
): Promise<OidcClaims> {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("id_token malformado");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as { alg: string; kid?: string };
  if (header.alg !== "RS256") throw new Error(`alg ${header.alg} nao suportado`);

  const jwks = await getJwks(disc.jwks_uri);
  const jwk = jwks.keys.find((k) => k.kid === header.kid) ?? jwks.keys[0];
  if (!jwk) throw new Error("JWKS sem chave utilizavel");
  const key = createPublicKey({ key: jwk as unknown as JsonWebKey, format: "jwk" });

  const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sig = Buffer.from(parts[2], "base64url");
  if (!cryptoVerify("RSA-SHA256", signed, key, sig)) throw new Error("assinatura do id_token invalida");

  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Record<string, unknown>;
  if (claims.iss !== cfg.issuer) throw new Error("iss invalido");
  const aud = claims.aud;
  const audOk = Array.isArray(aud) ? aud.includes(cfg.clientId) : aud === cfg.clientId;
  if (!audOk) throw new Error("aud invalido");
  if (typeof claims.exp !== "number" || claims.exp < now) throw new Error("id_token expirado");
  if (claims.nonce !== expectedNonce) throw new Error("nonce invalido");

  return {
    sub: String(claims.sub),
    email: typeof claims.email === "string" ? claims.email : undefined,
    preferredUsername: typeof claims.preferred_username === "string" ? claims.preferred_username : undefined,
    name: typeof claims.name === "string" ? claims.name : undefined,
  };
}
