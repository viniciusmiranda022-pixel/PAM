/**
 * Cliente OIDC (Authorization Code flow + PKCE) — Fase 5.5, consolidado no
 * PR-15 (auth enterprise). Sem dependencia externa: a verificacao do id_token
 * (RS256) usa node:crypto (createPublicKey a partir do JWK do JWKS). Valida
 * assinatura, iss, aud, exp e nonce.
 *
 * Consolidacoes do PR-15 (ADR 0003):
 *  - JWKS com TTL e refresh automatico quando aparece um `kid` desconhecido
 *    (rotacao de chave do IdP nao derruba mais o login).
 *  - PKCE S256 (obrigatorio p/ IdPs modernos; ADFS 2019+ e Entra ID suportam).
 *  - Metodo de autenticacao no token endpoint configuravel:
 *    client_secret_post (default) ou client_secret_basic (alguns ADFS).
 *  - Scopes configuraveis e claim de grupos p/ mapeamento de papel.
 */
import { createHash, createPublicKey, randomBytes, verify as cryptoVerify, type JsonWebKey } from "node:crypto";

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  autoProvision: boolean;
  /** Scopes do authorize (default: openid email profile). */
  scopes: string;
  /** Autenticacao no token endpoint: post (body) | basic (Authorization). */
  tokenAuth: "post" | "basic";
  /** Nome da claim que carrega os grupos (default: groups). */
  groupsClaim: string;
  /** Grupo do IdP que eleva a papel admin (vazio = sem mapeamento). */
  adminGroup: string | null;
  /** Rotulo do botao no portal (default: SSO). */
  label: string;
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
    scopes: env.OIDC_SCOPES || "openid email profile",
    tokenAuth: env.OIDC_TOKEN_AUTH === "basic" ? "basic" : "post",
    groupsClaim: env.OIDC_GROUPS_CLAIM || "groups",
    adminGroup: env.OIDC_ADMIN_GROUP || null,
    label: env.OIDC_PROVIDER_LABEL || "SSO",
  };
}

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

type Jwks = { keys: Array<Record<string, unknown> & { kid?: string }> };

const JWKS_TTL_MS = 10 * 60 * 1000; // re-busca periodica mesmo sem rotacao

const discoveryCache = new Map<string, Discovery>();
const jwksCache = new Map<string, { jwks: Jwks; fetchedAt: number }>();

export async function discover(issuer: string): Promise<Discovery> {
  const cached = discoveryCache.get(issuer);
  if (cached) return cached;
  const res = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery falhou: ${res.status}`);
  const d = (await res.json()) as Discovery;
  discoveryCache.set(issuer, d);
  return d;
}

/** PKCE S256: verifier aleatorio + challenge = BASE64URL(SHA256(verifier)). */
export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  return { verifier, challenge };
}

export function buildAuthUrl(
  disc: Discovery,
  cfg: OidcConfig,
  state: string,
  nonce: string,
  codeChallenge?: string,
): string {
  const u = new URL(disc.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", cfg.clientId);
  u.searchParams.set("redirect_uri", cfg.redirectUri);
  u.searchParams.set("scope", cfg.scopes);
  u.searchParams.set("state", state);
  u.searchParams.set("nonce", nonce);
  if (codeChallenge) {
    u.searchParams.set("code_challenge", codeChallenge);
    u.searchParams.set("code_challenge_method", "S256");
  }
  return u.toString();
}

export async function exchangeCode(
  disc: Discovery,
  cfg: OidcConfig,
  code: string,
  codeVerifier?: string,
): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: cfg.redirectUri,
  });
  if (codeVerifier) body.set("code_verifier", codeVerifier);

  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (cfg.tokenAuth === "basic") {
    // client_secret_basic (RFC 6749 §2.3.1) — exigido por alguns ADFS.
    const cred = Buffer.from(
      `${encodeURIComponent(cfg.clientId)}:${encodeURIComponent(cfg.clientSecret)}`,
    ).toString("base64");
    headers.authorization = `Basic ${cred}`;
  } else {
    body.set("client_id", cfg.clientId);
    body.set("client_secret", cfg.clientSecret);
  }

  const res = await fetch(disc.token_endpoint, { method: "POST", headers, body });
  if (!res.ok) throw new Error(`OIDC token exchange falhou: ${res.status}`);
  const tokens = (await res.json()) as { id_token?: string };
  if (!tokens.id_token) throw new Error("OIDC: resposta sem id_token");
  return tokens.id_token;
}

async function fetchJwks(jwksUri: string): Promise<Jwks> {
  const res = await fetch(jwksUri);
  if (!res.ok) throw new Error(`OIDC JWKS falhou: ${res.status}`);
  const jwks = (await res.json()) as Jwks;
  jwksCache.set(jwksUri, { jwks, fetchedAt: Date.now() });
  return jwks;
}

/**
 * Retorna o JWKS, re-buscando quando (a) o TTL venceu ou (b) `kid` nao esta no
 * cache — assim a rotacao de chave do IdP nao exige reiniciar o backend.
 */
async function getJwks(jwksUri: string, kid?: string): Promise<Jwks> {
  const cached = jwksCache.get(jwksUri);
  const fresh = cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS;
  const hasKid = cached && (!kid || cached.jwks.keys.some((k) => k.kid === kid));
  if (cached && fresh && hasKid) return cached.jwks;
  return fetchJwks(jwksUri);
}

export interface OidcClaims {
  sub: string;
  email?: string;
  preferredUsername?: string;
  name?: string;
  /** Grupos do usuario no IdP (claim configuravel; ausente = []). */
  groups: string[];
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

  const jwks = await getJwks(disc.jwks_uri, header.kid);
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

  const rawGroups = claims[cfg.groupsClaim];
  const groups = Array.isArray(rawGroups) ? rawGroups.filter((g): g is string => typeof g === "string") : [];

  return {
    sub: String(claims.sub),
    email: typeof claims.email === "string" ? claims.email : undefined,
    preferredUsername: typeof claims.preferred_username === "string" ? claims.preferred_username : undefined,
    name: typeof claims.name === "string" ? claims.name : undefined,
    groups,
  };
}
