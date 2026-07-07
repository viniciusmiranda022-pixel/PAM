-- Fase 5.1 — gravacao de sessao.
-- Executado automaticamente apenas em volumes novos; para um banco existente,
-- aplicar manualmente (idempotente): docs/phase5-recording.md.

ALTER TABLE assets   ADD COLUMN IF NOT EXISTS record_sessions boolean NOT NULL DEFAULT true;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS recording_path  text;
