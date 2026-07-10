/**
 * SAML 2.0 Service Provider (PR-15 — ADFS via SAML). Complementa o OIDC para
 * IdPs que so federam por SAML (ADFS legado, Shibboleth...).
 *
 * ADR 0003: a validacao de assinatura XML (XML-DSig) NAO e implementada a mao —
 * canonicalizacao + signature wrapping tornam isso um campo minado classico.
 * Usamos @node-saml/node-saml (mantida, usada pelo passport-saml), com:
 *   - resposta/assercao assinada obrigatoria (wantAssertionsSigned)
 *   - audience restrita ao entityID do SP
 *   - InResponseTo validado (anti-replay; cache in-memory — nota de HA na doc)
 *
 * O mapeamento de usuario segue o mesmo padrao do OIDC: por subject, senao
 * vincula por email, senao provisiona; grupo do IdP pode ELEVAR a admin
 * (nunca rebaixa automaticamente).
 */
import { SAML, ValidateInResponseTo } from "@node-saml/node-saml";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "./config.js";
import type { Db, UserRow } from "./db.js";
import { metrics } from "./metrics.js";

export interface SamlConfig {
  /** URL de SSO do IdP (redirect binding). */
  entryPoint: string;
  /** Certificado publico do IdP (PEM ou base64) p/ validar a assinatura. */
  idpCert: string;
  /** entityID deste SP. */
  issuer: string;
  /** ACS: URL publica do callback POST. */
  callbackUrl: string;
  autoProvision: boolean;
  /** Atributo com email (default: claim padrao do ADFS). */
  emailAttr: string;
  /** Atributo com nome de exibicao (default: claim padrao do ADFS). */
  nameAttr: string;
  /** Atributo com grupos (default: claim de Group do ADFS). */
  groupsAttr: string;
  /** Grupo que eleva a admin (vazio = sem mapeamento). */
  adminGroup: string | null;
  /** Rotulo do botao no portal. */
  label: string;
}

const ADFS_CLAIMS = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";

export function samlConfig(env = process.env): SamlConfig | null {
  const { SAML_IDP_ENTRYPOINT, SAML_IDP_CERT, SAML_SP_ISSUER, SAML_CALLBACK_URL } = env;
  if (!SAML_IDP_ENTRYPOINT || !SAML_IDP_CERT || !SAML_SP_ISSUER || !SAML_CALLBACK_URL) return null;
  return {
    entryPoint: SAML_IDP_ENTRYPOINT,
    idpCert: SAML_IDP_CERT,
    issuer: SAML_SP_ISSUER,
    callbackUrl: SAML_CALLBACK_URL,
    autoProvision: env.SAML_AUTO_PROVISION !== "false",
    emailAttr: env.SAML_EMAIL_ATTR || `${ADFS_CLAIMS}/emailaddress`,
    nameAttr: env.SAML_NAME_ATTR || `${ADFS_CLAIMS}/name`,
    groupsAttr: env.SAML_GROUPS_ATTR || "http://schemas.xmlsoap.org/claims/Group",
    adminGroup: env.SAML_ADMIN_GROUP || null,
    label: env.SAML_PROVIDER_LABEL || "SSO corporativo (SAML)",
  };
}

// A instancia e memoizada por configuracao. Isso e OBRIGATORIO: o
// validateInResponseTo usa um cache in-memory por instancia; se cada requisicao
// criasse uma instancia nova, o ID gerado em /saml/login nunca seria encontrado
// no /saml/callback e todo login SP-initiated falharia (nota de HA: em multi-
// instancia esse cache precisa ser compartilhado — ADR 0003).
let cachedSaml: { key: string; saml: SAML } | null = null;

function makeSaml(cfg: SamlConfig): SAML {
  const key = JSON.stringify(cfg);
  if (cachedSaml && cachedSaml.key === key) return cachedSaml.saml;
  const saml = new SAML({
    entryPoint: cfg.entryPoint,
    idpCert: cfg.idpCert,
    issuer: cfg.issuer,
    callbackUrl: cfg.callbackUrl,
    // Assinatura obrigatoria na assercao (defesa principal contra forja).
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false, // ADFS assina a assercao por padrao
    audience: cfg.issuer, // Audience da assercao precisa ser este SP
    validateInResponseTo: ValidateInResponseTo.always, // anti-replay
    acceptedClockSkewMs: 30_000,
  });
  cachedSaml = { key, saml };
  return saml;
}

interface Helpers {
  setSession: (reply: FastifyReply, userId: string) => void;
  clientIp: (req: FastifyRequest) => string | null;
  fail: (reply: FastifyReply, status: number, code: string, message: string) => void;
}

function attr(profile: Record<string, unknown>, name: string): string | undefined {
  const v = profile[name];
  if (typeof v === "string") return v;
  if (Array.isArray(v) && typeof v[0] === "string") return v[0];
  return undefined;
}

function attrList(profile: Record<string, unknown>, name: string): string[] {
  const v = profile[name];
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
  return [];
}

export function registerSamlRoutes(app: FastifyInstance, db: Db, config: Config, h: Helpers): void {
  // O ACS recebe application/x-www-form-urlencoded (HTTP-POST binding).
  // Parser minimo via URLSearchParams — sem dependencia nova.
  app.addContentTypeParser(
    "application/x-www-form-urlencoded",
    { parseAs: "string" },
    (_req, body, done) => {
      const out: Record<string, string> = {};
      for (const [k, v] of new URLSearchParams(String(body))) out[k] = v;
      done(null, out);
    },
  );

  app.get("/api/v1/auth/saml/login", async (req, reply) => {
    const cfg = samlConfig();
    if (!cfg) return h.fail(reply, 404, "NOT_FOUND", "SAML nao configurado");
    const saml = makeSaml(cfg);
    const url = await saml.getAuthorizeUrlAsync("", undefined, {});
    return reply.redirect(url);
  });

  app.post<{ Body: { SAMLResponse?: string; RelayState?: string } }>(
    "/api/v1/auth/saml/callback",
    async (req, reply) => {
      const cfg = samlConfig();
      if (!cfg) return h.fail(reply, 404, "NOT_FOUND", "SAML nao configurado");
      if (!req.body?.SAMLResponse) return h.fail(reply, 400, "INVALID_BODY", "SAMLResponse ausente");

      const saml = makeSaml(cfg);
      let profile: Record<string, unknown> & { nameID?: string };
      try {
        const r = await saml.validatePostResponseAsync({ SAMLResponse: req.body.SAMLResponse });
        if (!r.profile || r.loggedOut) throw new Error("resposta sem perfil");
        profile = r.profile as typeof profile;
      } catch {
        await db.audit("auth.saml_failed", { sourceIp: h.clientIp(req), details: { reason: "response_invalid" } });
        return h.fail(reply, 401, "NOT_AUTHENTICATED", "falha na verificacao SAML");
      }

      const subject = profile.nameID;
      if (!subject) {
        await db.audit("auth.saml_failed", { sourceIp: h.clientIp(req), details: { reason: "sem_nameid" } });
        return h.fail(reply, 401, "NOT_AUTHENTICATED", "assercao sem NameID");
      }
      const email = attr(profile, cfg.emailAttr) ?? (subject.includes("@") ? subject : undefined);
      const name = attr(profile, cfg.nameAttr);
      const groups = attrList(profile, cfg.groupsAttr);
      const isAdminByGroup = cfg.adminGroup !== null && groups.includes(cfg.adminGroup);

      // Mapeia subject -> usuario: por subject, senao vincula por email, senao provisiona.
      let user: UserRow | null = await db.findUserBySamlSubject(subject);
      if (!user && email) {
        const byEmail = await db.findUserByEmail(email);
        if (byEmail) {
          await db.linkSamlSubject(byEmail.id, subject);
          user = byEmail;
          await db.audit("auth.saml_linked", { userId: user.id, sourceIp: h.clientIp(req) });
        }
      }
      if (!user) {
        if (!cfg.autoProvision) {
          await db.audit("auth.saml_failed", { sourceIp: h.clientIp(req), details: { reason: "no_account" } });
          return h.fail(reply, 403, "NOT_AUTHORIZED", "sem conta local para este SSO");
        }
        const username = email ?? `saml-${subject.slice(0, 12)}`;
        user = await db.createSamlUser(subject, username, name || username, email ?? null);
        await db.audit("auth.saml_provisioned", { userId: user.id, sourceIp: h.clientIp(req) });
      }
      if (user.status !== "active") return h.fail(reply, 403, "NOT_AUTHORIZED", "usuario inativo");

      // Grupo->papel: SO ELEVA (mesma regra do OIDC — ADR 0003).
      if (isAdminByGroup && user.role !== "admin") {
        await db.setUserRole(user.id, "admin");
        user = { ...user, role: "admin" };
        await db.audit("auth.role_elevated_by_idp", {
          userId: user.id,
          sourceIp: h.clientIp(req),
          details: { group: cfg.adminGroup, via: "saml" },
        });
      }

      h.setSession(reply, user.id);
      metrics.login("ok");
      await db.audit("auth.login", { userId: user.id, sourceIp: h.clientIp(req), details: { via: "saml" } });
      return reply.redirect("/");
    },
  );
}
