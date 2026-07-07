import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import cookie from "@fastify/cookie";
import { randomBytes, createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { Config } from "./config.js";
import type { Db, UserRow } from "./db.js";
import { hashPassword, verifyPassword } from "./auth.js";
import { storeCredential } from "./credential-store.js";
import { decryptCredential, encryptCredential } from "./credentials.js";
import { generateTotpSecret, otpauthUrl, verifyTotp } from "./totp.js";
import { portRejectionReason } from "./ports.js";
import { RateLimiter } from "./rate-limit.js";
import { metrics, registry } from "./metrics.js";
import {
  approveAccessRequestSchema,
  createAccessRequestSchema,
  createAllowedPortSchema,
  createAssetSchema,
  createGroupSchema,
  createPermissionSchema,
  createSessionSchema,
  createUserSchema,
  denyAccessRequestSchema,
  loginSchema,
  mfaCodeSchema,
  updateAssetSchema,
  updateUserSchema,
} from "./schemas.js";

/** Mapeia erros do Postgres para respostas amigaveis. */
function pgError(reply: FastifyReply, err: unknown): void {
  const code = (err as { code?: string }).code;
  if (code === "23505") return fail(reply, 409, "CONFLICT", "recurso ja existe");
  if (code === "23503") return fail(reply, 422, "VALIDATION_FAILED", "referencia invalida (ex.: porta fora da allowlist)");
  throw err;
}

const COOKIE_NAME = "pam_session";

function sha256(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

function fail(reply: FastifyReply, status: number, code: string, message: string): void {
  reply.code(status).send({ error: { code, message } });
}

function clientIp(req: FastifyRequest): string | null {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd.length > 0) return fwd.split(",")[0].trim();
  return req.ip ?? null;
}

export function buildServer(db: Db, config: Config, logStream?: NodeJS.WritableStream) {
  const app = Fastify({
    trustProxy: true,
    logger: {
      // HR-06: nenhum segredo em log. Redacao estrutural, nao por disciplina.
      redact: {
        paths: [
          "req.headers.cookie",
          "req.headers.authorization",
          "req.body.password",
          "req.body.vncPassword",
          "*.password",
          "*.vncPassword",
          "*.token",
          "*.secret",
        ],
        remove: true,
      },
      ...(logStream ? { stream: logStream } : {}),
    },
  });

  app.register(cookie, { secret: config.cookieSecret });

  // Rate limit (HR / DoS): login por IP, criacao de sessao por usuario.
  const loginLimiter = new RateLimiter(config.rateLimitLoginPerMin, 60_000);
  const sessionLimiter = new RateLimiter(config.rateLimitSessionPerMin, 60_000);
  const pruneTimer = setInterval(() => {
    loginLimiter.prune();
    sessionLimiter.prune();
  }, 60_000);
  pruneTimer.unref?.();
  app.addHook("onClose", async () => clearInterval(pruneTimer));

  async function requireUser(req: FastifyRequest, reply: FastifyReply): Promise<UserRow | null> {
    const raw = req.cookies[COOKIE_NAME];
    if (!raw) {
      fail(reply, 401, "NOT_AUTHENTICATED", "sem login valido");
      return null;
    }
    const unsigned = app.unsignCookie(raw);
    if (!unsigned.valid || !unsigned.value) {
      fail(reply, 401, "NOT_AUTHENTICATED", "cookie invalido");
      return null;
    }
    const user = await db.findUserById(unsigned.value);
    if (!user || user.status !== "active") {
      fail(reply, 401, "NOT_AUTHENTICATED", "usuario inativo");
      return null;
    }
    return user;
  }

  app.get("/healthz", async (_req, reply) => {
    // Readiness: reflete o banco (do qual dependem auth e sessoes).
    const dbOk = await db.ping();
    reply.code(dbOk ? 200 : 503);
    return { status: dbOk ? "ok" : "degraded", db: dbOk };
  });

  // Metricas Prometheus — rede interna apenas (sem auth; nao publicar no Nginx).
  app.get("/metrics", async (_req, reply) => {
    reply.header("content-type", registry.contentType);
    return registry.metrics();
  });

  app.post("/api/v1/auth/login", async (req, reply) => {
    const ip = clientIp(req) ?? "unknown";
    if (!loginLimiter.check(ip)) {
      metrics.rateLimited("login");
      await db.audit("auth.rate_limited", { sourceIp: ip });
      return fail(reply, 429, "RATE_LIMITED", "muitas tentativas de login");
    }
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "payload invalido");
    const { username, password, totp } = parsed.data;
    const user = await db.findUserByUsername(username);
    const ok = user && user.status === "active" && verifyPassword(password, user.passwordHash);
    if (!ok || !user) {
      metrics.login("fail");
      await db.audit("auth.login_failed", { sourceIp: clientIp(req), details: { username } });
      return fail(reply, 401, "NOT_AUTHENTICATED", "credenciais invalidas");
    }
    // MFA (Fase 5.2): senha correta nao basta se o TOTP estiver habilitado.
    if (user.mfaEnabled && user.mfaSecretEnc) {
      if (!totp) {
        // Codigo dedicado: o frontend mostra o campo TOTP sem revelar se a
        // senha estava certa para quem nao passou da primeira etapa.
        return fail(reply, 401, "MFA_REQUIRED", "informe o codigo TOTP");
      }
      if (!verifyTotp(decryptCredential(user.mfaSecretEnc), totp)) {
        metrics.login("fail");
        await db.audit("auth.login_failed", { userId: user.id, sourceIp: clientIp(req), details: { reason: "totp_invalid" } });
        return fail(reply, 401, "NOT_AUTHENTICATED", "codigo TOTP invalido");
      }
    }
    metrics.login("ok");
    reply.setCookie(COOKIE_NAME, user.id, {
      httpOnly: true,
      sameSite: "strict",
      secure: config.secureCookie,
      signed: true,
      path: "/",
      maxAge: 8 * 60 * 60,
    });
    await db.audit("auth.login", { userId: user.id, sourceIp: clientIp(req) });
    return reply.code(204).send();
  });

  app.post("/api/v1/auth/logout", async (_req, reply) => {
    reply.clearCookie(COOKIE_NAME, { path: "/" });
    return reply.code(204).send();
  });

  app.get("/api/v1/auth/me", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;
    return {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      role: user.role,
      mfaEnabled: user.mfaEnabled,
    };
  });

  // ─────────────────────────── MFA (TOTP, Fase 5.2) ────────────────────────

  // Gera segredo pendente (cifrado no banco) e retorna otpauth p/ authenticator.
  app.post("/api/v1/auth/mfa/setup", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;
    if (user.mfaEnabled) return fail(reply, 409, "CONFLICT", "MFA ja habilitado");
    const secret = generateTotpSecret();
    await db.setMfaSecret(user.id, encryptCredential(secret));
    await db.audit("mfa.setup_started", { userId: user.id, sourceIp: clientIp(req) });
    // O segredo e mostrado UMA vez para cadastro no authenticator.
    return { secret, otpauthUrl: otpauthUrl(secret, user.username) };
  });

  // Confirma o cadastro provando posse do authenticator.
  app.post("/api/v1/auth/mfa/enable", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;
    const parsed = mfaCodeSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "informe code de 6 digitos");
    if (!user.mfaSecretEnc) return fail(reply, 422, "VALIDATION_FAILED", "faca o setup antes");
    if (!verifyTotp(decryptCredential(user.mfaSecretEnc), parsed.data.code)) {
      return fail(reply, 401, "NOT_AUTHENTICATED", "codigo TOTP invalido");
    }
    await db.setMfaEnabled(user.id, true);
    await db.audit("mfa.enabled", { userId: user.id, sourceIp: clientIp(req) });
    return reply.code(204).send();
  });

  // Desabilita exigindo um codigo valido (nao basta ter a sessao logada).
  app.post("/api/v1/auth/mfa/disable", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;
    const parsed = mfaCodeSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "informe code de 6 digitos");
    if (!user.mfaEnabled || !user.mfaSecretEnc) {
      return fail(reply, 422, "VALIDATION_FAILED", "MFA nao esta habilitado");
    }
    if (!verifyTotp(decryptCredential(user.mfaSecretEnc), parsed.data.code)) {
      return fail(reply, 401, "NOT_AUTHENTICATED", "codigo TOTP invalido");
    }
    await db.setMfaEnabled(user.id, false);
    await db.audit("mfa.disabled", { userId: user.id, sourceIp: clientIp(req) });
    return reply.code(204).send();
  });

  app.get("/api/v1/assets", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;
    // A resposta NAO contem IP nem porta — nem para exibicao (HR-01).
    return { items: await db.listAssetsForUser(user.id) };
  });

  // ─────────────── Acesso just-in-time — usuario (Fase 5.3) ────────────────

  // Catalogo: apenas assets que o admin marcou como 'requestable'. Os demais
  // permanecem invisiveis (preserva "usuario ve so o autorizado"). Sem IP/porta.
  app.get("/api/v1/catalog", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;
    return { items: await db.listRequestableAssets() };
  });

  app.post("/api/v1/access-requests", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;
    const parsed = createAccessRequestSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "assetId e justificativa (>=3) obrigatorios");
    if (!(await db.isAssetRequestable(parsed.data.assetId))) {
      return fail(reply, 403, "NOT_AUTHORIZED", "asset nao disponivel para solicitacao");
    }
    const id = await db.createAccessRequest(user.id, parsed.data.assetId, parsed.data.justification);
    await db.audit("access.requested", { userId: user.id, assetId: parsed.data.assetId, sourceIp: clientIp(req) });
    return reply.code(201).send({ id, status: "pending" });
  });

  app.get("/api/v1/access-requests", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;
    return { items: await db.listAccessRequestsForUser(user.id) };
  });

  // ─────────────── Acesso just-in-time — admin (Fase 5.3) ──────────────────

  app.get<{ Querystring: { status?: string } }>("/api/v1/admin/access-requests", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    return { items: await db.adminListAccessRequests(req.query.status) };
  });

  app.post<{ Params: { id: string } }>("/api/v1/admin/access-requests/:id/approve", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const parsed = approveAccessRequestSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "windowMinutes (1..1440) obrigatorio");
    const request = await db.getAccessRequest(req.params.id);
    if (!request) return fail(reply, 404, "NOT_FOUND", "solicitacao inexistente");
    if (request.status !== "pending") return fail(reply, 409, "CONFLICT", "solicitacao ja decidida");
    await db.approveAccessRequest(req.params.id, admin.id, parsed.data.windowMinutes);
    await db.audit("access.approved", {
      userId: admin.id,
      assetId: request.assetId,
      sourceIp: clientIp(req),
      details: { requestId: req.params.id, targetUser: request.userId, windowMinutes: parsed.data.windowMinutes },
    });
    return reply.code(204).send();
  });

  app.post<{ Params: { id: string } }>("/api/v1/admin/access-requests/:id/deny", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const parsed = denyAccessRequestSchema.safeParse(req.body ?? {});
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "payload invalido");
    if (!(await db.denyAccessRequest(req.params.id, admin.id, parsed.data.note ?? null))) {
      return fail(reply, 409, "CONFLICT", "solicitacao inexistente ou ja decidida");
    }
    await db.audit("access.denied", { userId: admin.id, sourceIp: clientIp(req), details: { requestId: req.params.id } });
    return reply.code(204).send();
  });

  app.post("/api/v1/sessions", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;

    if (!sessionLimiter.check(user.id)) {
      metrics.rateLimited("session");
      await db.audit("session.rate_limited", { userId: user.id, sourceIp: clientIp(req) });
      return fail(reply, 429, "RATE_LIMITED", "muitas sessoes em pouco tempo");
    }

    const parsed = createSessionSchema.safeParse(req.body);
    if (!parsed.success) {
      // host/port ou qualquer campo extra caem aqui (HR-01/02).
      return fail(reply, 400, "INVALID_BODY", "corpo aceita somente assetId");
    }
    const { assetId, justification } = parsed.data;
    const ip = clientIp(req);

    if (!(await db.userCanAccessAsset(user.id, assetId))) {
      // Inclui permissao expirada (janela JIT vencida) — mesmo 403.
      await db.audit("session.denied", { userId: user.id, assetId, sourceIp: ip, details: { reason: "no_permission" } });
      return fail(reply, 403, "NOT_AUTHORIZED", "sem permissao no asset");
    }

    // Justificativa obrigatoria por asset (Fase 5.3).
    if (await db.assetRequiresJustification(assetId)) {
      if (!justification || justification.trim().length < 3) {
        return fail(reply, 422, "VALIDATION_FAILED", "justificativa obrigatoria para este asset");
      }
    }

    const asset = await db.getAsset(assetId);
    if (!asset || asset.status !== "active") {
      return fail(reply, 422, "VALIDATION_FAILED", "asset indisponivel");
    }
    // Defesa em profundidade: o banco ja garante por FK, revalidamos (HR-04).
    if (!(await db.isPortAllowed(asset.port))) {
      await db.audit("session.denied", { userId: user.id, assetId, sourceIp: ip, details: { reason: "port_not_allowed" } });
      return fail(reply, 422, "VALIDATION_FAILED", "porta fora da allowlist");
    }

    const token = randomBytes(32).toString("base64url");
    const sessionId = await db.createSession({
      userId: user.id,
      assetId,
      tokenHash: sha256(token),
      ttlSeconds: config.sessionTokenTtlSeconds,
      clientIp: ip,
      justification: justification ?? null,
    });
    await db.audit("session.created", {
      userId: user.id,
      assetId,
      sessionId,
      sourceIp: ip,
      details: { hasJustification: Boolean(justification) },
    });
    metrics.sessionCreated();

    // A resposta nunca inclui host/porta/credencial.
    return reply.code(201).send({
      sessionId,
      gatewayUrl: `${config.gatewayPublicUrl}/${sessionId}`,
      token,
      tokenExpiresInSeconds: config.sessionTokenTtlSeconds,
    });
  });

  app.delete<{ Params: { sessionId: string } }>(
    "/api/v1/sessions/:sessionId",
    async (req, reply) => {
      const user = await requireUser(req, reply);
      if (!user) return;
      const session = await db.getSessionOwner(req.params.sessionId);
      if (!session) return fail(reply, 404, "NOT_FOUND", "sessao inexistente");
      const isOwner = session.userId === user.id;
      if (!isOwner && user.role !== "admin") {
        return fail(reply, 403, "NOT_AUTHORIZED", "sem permissao na sessao");
      }
      const reason = isOwner ? "user_request" : "admin_terminate";
      await db.terminateSession(session.id, reason);
      await db.audit("session.terminated", {
        userId: user.id,
        sessionId: session.id,
        sourceIp: clientIp(req),
        details: { reason },
      });
      return reply.code(204).send();
    },
  );

  // ─────────────────────────────── Admin ───────────────────────────────────

  async function requireAdmin(req: FastifyRequest, reply: FastifyReply): Promise<UserRow | null> {
    const user = await requireUser(req, reply);
    if (!user) return null;
    if (user.role !== "admin") {
      fail(reply, 403, "NOT_AUTHORIZED", "requer perfil admin");
      return null;
    }
    return user;
  }

  // Assets ----------------------------------------------------------------
  app.get("/api/v1/admin/assets", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    return { items: await db.adminListAssets() };
  });

  app.post("/api/v1/admin/assets", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const parsed = createAssetSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "payload invalido");
    const a = parsed.data;
    const denied = portRejectionReason(a.port);
    if (denied) return fail(reply, 422, "VALIDATION_FAILED", denied);
    if (!(await db.isPortAllowed(a.port))) {
      return fail(reply, 422, "VALIDATION_FAILED", "porta nao esta na allowlist");
    }
    try {
      // vncPassword e write-only: guardada no cofre; DB so tem a referencia.
      const credentialRef = await storeCredential(a.vncPassword, config);
      const created = await db.adminCreateAsset({
        name: a.name,
        description: a.description ?? null,
        environment: a.environment,
        ipAddress: a.ipAddress,
        port: a.port,
        credentialRef,
        recordSessions: a.recordSessions,
        requestable: a.requestable,
        requireJustification: a.requireJustification,
      });
      await db.audit("asset.created", { userId: admin.id, assetId: created.id as string, sourceIp: clientIp(req) });
      return reply.code(201).send(created); // sem credential_ref
    } catch (err) {
      return pgError(reply, err);
    }
  });

  app.patch<{ Params: { id: string } }>("/api/v1/admin/assets/:id", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const parsed = updateAssetSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "payload invalido");
    const p = parsed.data;
    if (p.port !== undefined) {
      const denied = portRejectionReason(p.port);
      if (denied) return fail(reply, 422, "VALIDATION_FAILED", denied);
      if (!(await db.isPortAllowed(p.port))) {
        return fail(reply, 422, "VALIDATION_FAILED", "porta nao esta na allowlist");
      }
    }
    try {
      const credentialRef = p.vncPassword !== undefined ? await storeCredential(p.vncPassword, config) : undefined;
      const updated = await db.adminUpdateAsset(req.params.id, {
        description: p.description,
        environment: p.environment,
        ipAddress: p.ipAddress,
        port: p.port,
        credentialRef,
        status: p.status,
        recordSessions: p.recordSessions,
        requestable: p.requestable,
        requireJustification: p.requireJustification,
      });
      if (!updated) return fail(reply, 404, "NOT_FOUND", "asset inexistente");
      await db.audit("asset.updated", {
        userId: admin.id,
        assetId: req.params.id,
        sourceIp: clientIp(req),
        details: { rotatedCredential: credentialRef !== undefined },
      });
      return updated;
    } catch (err) {
      return pgError(reply, err);
    }
  });

  app.delete<{ Params: { id: string } }>("/api/v1/admin/assets/:id", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const result = await db.adminDeleteAsset(req.params.id);
    if (result === "not_found") return fail(reply, 404, "NOT_FOUND", "asset inexistente");
    await db.audit("asset.deleted", {
      userId: admin.id,
      assetId: req.params.id,
      sourceIp: clientIp(req),
      details: { mode: result },
    });
    return reply.code(204).send();
  });

  // Users -----------------------------------------------------------------
  app.get("/api/v1/admin/users", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    return { items: await db.adminListUsers() };
  });

  app.post("/api/v1/admin/users", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const parsed = createUserSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "payload invalido");
    const u = parsed.data;
    try {
      const created = await db.adminCreateUser({
        username: u.username,
        displayName: u.displayName,
        email: u.email ?? null,
        passwordHash: hashPassword(u.password),
        role: u.role,
      });
      await db.audit("user.created", { userId: admin.id, sourceIp: clientIp(req), details: { created: created.id } });
      return reply.code(201).send(created);
    } catch (err) {
      return pgError(reply, err);
    }
  });

  app.patch<{ Params: { id: string } }>("/api/v1/admin/users/:id", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const parsed = updateUserSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "payload invalido");
    const p = parsed.data;
    try {
      const updated = await db.adminUpdateUser(req.params.id, {
        displayName: p.displayName,
        email: p.email,
        passwordHash: p.password !== undefined ? hashPassword(p.password) : undefined,
        role: p.role,
        status: p.status,
      });
      if (!updated) return fail(reply, 404, "NOT_FOUND", "usuario inexistente");
      if (p.mfaReset) {
        // Recuperacao operada pelo admin (usuario perdeu o authenticator).
        await db.setMfaEnabled(req.params.id, false);
        await db.audit("mfa.reset_by_admin", { userId: admin.id, sourceIp: clientIp(req), details: { target: req.params.id } });
      }
      await db.audit("user.updated", { userId: admin.id, sourceIp: clientIp(req), details: { updated: req.params.id, mfaReset: p.mfaReset ?? false } });
      return updated;
    } catch (err) {
      return pgError(reply, err);
    }
  });

  // Groups ----------------------------------------------------------------
  app.get("/api/v1/admin/groups", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    return { items: await db.adminListGroups() };
  });

  app.post("/api/v1/admin/groups", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const parsed = createGroupSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "payload invalido");
    try {
      const created = await db.adminCreateGroup(parsed.data.name, parsed.data.description ?? null);
      return reply.code(201).send(created);
    } catch (err) {
      return pgError(reply, err);
    }
  });

  app.delete<{ Params: { id: string } }>("/api/v1/admin/groups/:id", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    if (!(await db.adminDeleteGroup(req.params.id))) return fail(reply, 404, "NOT_FOUND", "grupo inexistente");
    return reply.code(204).send();
  });

  app.put<{ Params: { groupId: string; userId: string } }>(
    "/api/v1/admin/groups/:groupId/members/:userId",
    async (req, reply) => {
      const admin = await requireAdmin(req, reply);
      if (!admin) return;
      try {
        await db.adminAddMember(req.params.groupId, req.params.userId);
        return reply.code(204).send();
      } catch (err) {
        return pgError(reply, err);
      }
    },
  );

  app.delete<{ Params: { groupId: string; userId: string } }>(
    "/api/v1/admin/groups/:groupId/members/:userId",
    async (req, reply) => {
      const admin = await requireAdmin(req, reply);
      if (!admin) return;
      await db.adminRemoveMember(req.params.groupId, req.params.userId);
      return reply.code(204).send();
    },
  );

  // Permissions -----------------------------------------------------------
  app.get<{ Querystring: { assetId?: string } }>("/api/v1/admin/permissions", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    return { items: await db.adminListPermissions(req.query.assetId) };
  });

  app.post("/api/v1/admin/permissions", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const parsed = createPermissionSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "informe assetId e exatamente um entre userId/groupId");
    try {
      const created = await db.adminCreatePermission({ ...parsed.data, grantedBy: admin.id });
      await db.audit("permission.granted", {
        userId: admin.id,
        assetId: parsed.data.assetId,
        sourceIp: clientIp(req),
        details: { targetUser: parsed.data.userId ?? null, targetGroup: parsed.data.groupId ?? null },
      });
      return reply.code(201).send(created);
    } catch (err) {
      return pgError(reply, err);
    }
  });

  app.delete<{ Params: { id: string } }>("/api/v1/admin/permissions/:id", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    if (!(await db.adminDeletePermission(req.params.id))) return fail(reply, 404, "NOT_FOUND", "permissao inexistente");
    await db.audit("permission.revoked", { userId: admin.id, sourceIp: clientIp(req), details: { permission: req.params.id } });
    return reply.code(204).send();
  });

  // Allowed ports ---------------------------------------------------------
  app.get("/api/v1/admin/allowed-ports", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    return { items: await db.listAllowedPorts() };
  });

  app.post("/api/v1/admin/allowed-ports", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const parsed = createAllowedPortSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "payload invalido");
    // Denylist imutavel: 22, 3389, 443, ... nunca entram na allowlist (HR-04).
    const denied = portRejectionReason(parsed.data.port);
    if (denied) return fail(reply, 422, "VALIDATION_FAILED", denied);
    try {
      await db.adminCreateAllowedPort(parsed.data.port, parsed.data.description);
      await db.audit("allowlist.changed", {
        userId: admin.id,
        sourceIp: clientIp(req),
        details: { action: "added", port: parsed.data.port },
      });
      return reply.code(201).send({ port: parsed.data.port });
    } catch (err) {
      return pgError(reply, err);
    }
  });

  app.delete<{ Params: { port: string } }>("/api/v1/admin/allowed-ports/:port", async (req, reply) => {
    const admin = await requireAdmin(req, reply);
    if (!admin) return;
    const port = Number(req.params.port);
    const result = await db.adminDeleteAllowedPort(port);
    if (result === "in_use") return fail(reply, 409, "CONFLICT", "porta em uso por asset ativo");
    if (result === "not_found") return fail(reply, 404, "NOT_FOUND", "porta inexistente");
    await db.audit("allowlist.changed", { userId: admin.id, sourceIp: clientIp(req), details: { action: "removed", port } });
    return reply.code(204).send();
  });

  // Sessions & auditoria --------------------------------------------------
  app.get<{ Querystring: { status?: string; userId?: string; assetId?: string; limit?: string } }>(
    "/api/v1/admin/sessions",
    async (req, reply) => {
      const admin = await requireAdmin(req, reply);
      if (!admin) return;
      const limit = Math.min(Math.max(Number(req.query.limit ?? 100), 1), 500);
      return {
        items: await db.adminListSessions({
          status: req.query.status,
          userId: req.query.userId,
          assetId: req.query.assetId,
          limit,
        }),
      };
    },
  );

  // Gravacao da sessao (Fase 5.1) — admin-only; toda visualizacao e auditada.
  app.get<{ Params: { sessionId: string } }>(
    "/api/v1/admin/sessions/:sessionId/recording",
    async (req, reply) => {
      const admin = await requireAdmin(req, reply);
      if (!admin) return;
      const recordingPath = await db.getRecordingPath(req.params.sessionId);
      if (!recordingPath) return fail(reply, 404, "NOT_FOUND", "sessao sem gravacao");
      let stream: NodeJS.ReadableStream;
      try {
        stream = createReadStream(recordingPath);
      } catch {
        return fail(reply, 404, "NOT_FOUND", "arquivo de gravacao indisponivel");
      }
      await db.audit("recording.viewed", {
        userId: admin.id,
        sessionId: req.params.sessionId,
        sourceIp: clientIp(req),
      });
      reply.header("content-type", "application/octet-stream");
      return reply.send(stream);
    },
  );

  app.get<{ Querystring: { eventType?: string; userId?: string; assetId?: string; page?: string } }>(
    "/api/v1/admin/audit-logs",
    async (req, reply) => {
      const admin = await requireAdmin(req, reply);
      if (!admin) return;
      const limit = 100;
      const page = Math.max(Number(req.query.page ?? 0), 0);
      return {
        items: await db.adminListAuditLogs({
          eventType: req.query.eventType,
          userId: req.query.userId,
          assetId: req.query.assetId,
          limit,
          offset: page * limit,
        }),
      };
    },
  );

  return app;
}
