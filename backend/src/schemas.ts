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

export type LoginInput = z.infer<typeof loginSchema>;
export type CreateSessionInput = z.infer<typeof createSessionSchema>;
