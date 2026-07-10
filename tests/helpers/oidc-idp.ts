// IdP OIDC simulado in-process para os testes (RSA real, RS256). Serve
// discovery, JWKS e token endpoint; permite rotacionar a chave e inspecionar a
// ultima requisicao ao token endpoint (para checar PKCE / client_secret_basic).
import http from "node:http";
import { generateKeyPairSync, createPublicKey, sign as cryptoSign, type KeyObject } from "node:crypto";

interface KeyEntry { kid: string; priv: KeyObject; jwk: Record<string, unknown>; }

export interface FakeIdp {
  issuer: string;
  /** Assina um id_token com a chave ativa. */
  makeIdToken: (claims: Record<string, unknown>) => string;
  /** Troca a chave ativa (simula rotacao no IdP). */
  rotateKey: () => void;
  /** Ultima requisicao recebida no token endpoint. */
  lastToken: { body: Record<string, string>; authHeader?: string } | null;
  close: () => Promise<void>;
}

function toJwk(kid: string, pub: KeyObject): Record<string, unknown> {
  return { ...(pub.export({ format: "jwk" }) as Record<string, unknown>), kid, alg: "RS256", use: "sig" };
}

function newKey(kid: string): KeyEntry {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { kid, priv: privateKey, jwk: toJwk(kid, publicKey) };
}

export async function startFakeIdp(): Promise<FakeIdp> {
  let active = newKey("k1");
  let counter = 1;
  const state: FakeIdp = { issuer: "", makeIdToken: () => "", rotateKey: () => {}, lastToken: null, close: async () => {} };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", state.issuer);
    if (url.pathname === "/.well-known/openid-configuration") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        issuer: state.issuer,
        authorization_endpoint: `${state.issuer}/authorize`,
        token_endpoint: `${state.issuer}/token`,
        jwks_uri: `${state.issuer}/jwks`,
      }));
      return;
    }
    if (url.pathname === "/jwks") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [active.jwk] }));
      return;
    }
    if (url.pathname === "/token" && req.method === "POST") {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()));
      state.lastToken = { body, authHeader: req.headers.authorization };
      // O `code` carrega as claims que o IdP deve assinar (simula a sessao de
      // login lembrada pelo IdP entre authorize e token).
      let idToken = "";
      try {
        const claims = JSON.parse(Buffer.from(body.code, "base64url").toString());
        idToken = state.makeIdToken(claims);
      } catch { /* code invalido -> id_token vazio */ }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id_token: idToken }));
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  state.issuer = `http://127.0.0.1:${port}`;

  state.makeIdToken = (claims) => {
    const header = { alg: "RS256", typ: "JWT", kid: active.kid };
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const signingInput = `${b64(header)}.${b64(claims)}`;
    const sig = cryptoSign("RSA-SHA256", Buffer.from(signingInput), active.priv).toString("base64url");
    return `${signingInput}.${sig}`;
  };
  state.rotateKey = () => { counter += 1; active = newKey(`k${counter}`); };
  state.close = () => new Promise<void>((r) => server.close(() => r()));
  return state;
}
