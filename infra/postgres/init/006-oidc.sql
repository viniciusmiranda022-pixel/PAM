-- Fase 5.5 — SSO/OIDC.
-- Idempotente; para banco existente, aplicar manualmente: docs/phase5-sso.md.
-- oidc_subject vincula a conta local ao 'sub' do provedor. Usuarios criados por
-- SSO nao tem senha local (password_hash NULL) — nao podem logar por senha.

ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject text UNIQUE;
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
