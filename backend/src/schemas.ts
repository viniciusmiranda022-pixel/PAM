import { z } from "zod";

export const loginSchema = z
  .object({
    username: z.string().min(1).max(128),
    password: z.string().min(1).max(1024),
    totp: z.string().regex(/^\d{6}$/).optional(), // exigido se MFA habilitado
  })
  .strict();

export const mfaCodeSchema = z
  .object({ code: z.string().regex(/^\d{6}$/) })
  .strict();

/**
 * Criacao de sessao: SOMENTE assetId (HR-02). `.strict()` faz o contrato
 * rejeitar qualquer campo extra — em especial `host`/`hostname`/`ip`/`port`
 * (HR-01). Este schema e o ponto onde o requisito vira contrato executavel.
 */
export const createSessionSchema = z
  .object({
    assetId: z.string().uuid(),
    justification: z.string().min(1).max(1024).optional(),
  })
  .strict();

export const createAccessRequestSchema = z
  .object({
    assetId: z.string().uuid(),
    justification: z.string().min(3).max(1024),
  })
  .strict();

export const approveAccessRequestSchema = z
  .object({
    windowMinutes: z.number().int().min(1).max(1440),
  })
  .strict();

export const denyAccessRequestSchema = z
  .object({
    note: z.string().max(1024).optional(),
  })
  .strict();

// ───────────────────────── Admin (role: admin) ─────────────────────────

const status = z.enum(["active", "inactive"]);
const role = z.enum(["user", "admin"]);

// Protocolos com adapter oficial (espelha o registry do gateway — PR-16).
// Novos protocolos entram aqui junto com o adapter correspondente (PR-17+).
export const SUPPORTED_PROTOCOLS = ["vnc"] as const;

export const createAssetSchema = z
  .object({
    name: z.string().min(1).max(128),
    description: z.string().max(1024).optional(),
    environment: z.string().min(1).max(64).default("production"),
    protocol: z.enum(SUPPORTED_PROTOCOLS).default("vnc"),
    ipAddress: z.string().ip(),
    port: z.number().int(),
    vncPassword: z.string().min(1).max(1024), // write-only: vai ao cofre
    recordSessions: z.boolean().default(true),
    requestable: z.boolean().default(false),
    requireJustification: z.boolean().default(false),
    tlsRequired: z.boolean().default(false),
  })
  .strict();

export const updateAssetSchema = z
  .object({
    description: z.string().max(1024).optional(),
    environment: z.string().min(1).max(64).optional(),
    protocol: z.enum(SUPPORTED_PROTOCOLS).optional(),
    ipAddress: z.string().ip().optional(),
    port: z.number().int().optional(),
    vncPassword: z.string().min(1).max(1024).optional(), // rotacao
    status: status.optional(),
    recordSessions: z.boolean().optional(),
    requestable: z.boolean().optional(),
    requireJustification: z.boolean().optional(),
    tlsRequired: z.boolean().optional(),
  })
  .strict();

export const createUserSchema = z
  .object({
    username: z.string().min(1).max(128),
    displayName: z.string().min(1).max(256),
    email: z.string().email().optional(),
    password: z.string().min(8).max(1024),
    role: role.default("user"),
  })
  .strict();

export const updateUserSchema = z
  .object({
    displayName: z.string().min(1).max(256).optional(),
    email: z.string().email().optional(),
    password: z.string().min(8).max(1024).optional(),
    role: role.optional(),
    status: status.optional(),
    mfaReset: z.literal(true).optional(), // admin: limpa e desabilita o MFA
  })
  .strict();

export const createGroupSchema = z
  .object({
    name: z.string().min(1).max(128),
    description: z.string().max(1024).optional(),
  })
  .strict();

export const createPermissionSchema = z
  .object({
    assetId: z.string().uuid(),
    userId: z.string().uuid().optional(),
    groupId: z.string().uuid().optional(),
  })
  .strict()
  .refine((v) => (v.userId === undefined) !== (v.groupId === undefined), {
    message: "informe exatamente um entre userId e groupId",
  });

export const createAllowedPortSchema = z
  .object({
    port: z.number().int(),
    description: z.string().min(1).max(256),
  })
  .strict();

export type LoginInput = z.infer<typeof loginSchema>;
export type CreateSessionInput = z.infer<typeof createSessionSchema>;
export type CreateAssetInput = z.infer<typeof createAssetSchema>;
