-- Fase 5.2 — MFA (TOTP).
-- Executado automaticamente apenas em volumes novos; para um banco existente,
-- aplicar manualmente (idempotente): docs/phase5-mfa.md.
-- mfa_secret guarda o segredo TOTP CIFRADO (enc:v1, mesma cifra do cofre) —
-- nunca em claro no banco.

ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret  text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT false;
