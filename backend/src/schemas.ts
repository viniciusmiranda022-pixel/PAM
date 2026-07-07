import { z } from "zod";

export const loginSchema = z
  .object({
    username: z.string().min(1).max(128),
    password: z.string().min(1).max(1024),
  })
  .strict();

/**
 * Criacao de sessao: SOMENTE assetId (HR-02). `.strict()` faz o contrato
 * rejeitar qualquer campo extra — em especial `host`/`hostname`/`ip`/`port`
 * (HR-01). Este schema e o ponto onde o requisito vira contrato executavel.
 */
export const createSessionSchema = z
  .object({
    assetId: z.string().uuid(),
  })
  .strict();

// ───────────────────────── Admin (role: admin) ─────────────────────────

const status = z.enum(["active", "inactive"]);
const role = z.enum(["user", "admin"]);

export const createAssetSchema = z
  .object({
    name: z.string().min(1).max(128),
    description: z.string().max(1024).optional(),
    environment: z.string().min(1).max(64).default("production"),
    ipAddress: z.string().ip(),
    port: z.number().int(),
    vncPassword: z.string().min(1).max(1024), // write-only: vai ao cofre
    recordSessions: z.boolean().default(true),
  })
  .strict();

export const updateAssetSchema = z
  .object({
    description: z.string().max(1024).optional(),
    environment: z.string().min(1).max(64).optional(),
    ipAddress: z.string().ip().optional(),
    port: z.number().int().optional(),
    vncPassword: z.string().min(1).max(1024).optional(), // rotacao
    status: status.optional(),
    recordSessions: z.boolean().optional(),
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
