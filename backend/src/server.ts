import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import cookie from "@fastify/cookie";
import { randomBytes, createHash } from "node:crypto";
import type { Config } from "./config.js";
import type { Db, UserRow } from "./db.js";
import { verifyPassword } from "./auth.js";
import { createSessionSchema, loginSchema } from "./schemas.js";

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

export function buildServer(db: Db, config: Config) {
  const app = Fastify({
    trustProxy: true,
    logger: {
      // HR-06: nenhum segredo em log. Redacao estrutural, nao por disciplina.
      redact: {
        paths: [
          "req.headers.cookie",
          "req.headers.authorization",
          'req.body.password',
          "*.password",
          "*.vncPassword",
          "*.token",
          "*.secret",
        ],
        remove: true,
      },
    },
  });

  app.register(cookie, { secret: config.cookieSecret });

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

  app.get("/healthz", async () => ({ status: "ok" }));

  app.post("/api/v1/auth/login", async (req, reply) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return fail(reply, 400, "INVALID_BODY", "payload invalido");
    const { username, password } = parsed.data;
    const user = await db.findUserByUsername(username);
    const ok = user && user.status === "active" && verifyPassword(password, user.passwordHash);
    if (!ok || !user) {
      await db.audit("auth.login_failed", { sourceIp: clientIp(req), details: { username } });
      return fail(reply, 401, "NOT_AUTHENTICATED", "credenciais invalidas");
    }
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
    };
  });

  app.get("/api/v1/assets", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;
    // A resposta NAO contem IP nem porta — nem para exibicao (HR-01).
    return { items: await db.listAssetsForUser(user.id) };
  });

  app.post("/api/v1/sessions", async (req, reply) => {
    const user = await requireUser(req, reply);
    if (!user) return;

    const parsed = createSessionSchema.safeParse(req.body);
    if (!parsed.success) {
      // host/port ou qualquer campo extra caem aqui (HR-01/02).
      return fail(reply, 400, "INVALID_BODY", "corpo aceita somente assetId");
    }
    const { assetId } = parsed.data;
    const ip = clientIp(req);

    if (!(await db.userCanAccessAsset(user.id, assetId))) {
      await db.audit("session.denied", { userId: user.id, assetId, sourceIp: ip, details: { reason: "no_permission" } });
      return fail(reply, 403, "NOT_AUTHORIZED", "sem permissao no asset");
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
    });
    await db.audit("session.created", { userId: user.id, assetId, sessionId, sourceIp: ip });

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

  return app;
}
