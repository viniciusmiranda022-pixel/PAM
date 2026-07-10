-- 008 — SAML (PR-15, auth enterprise). Idempotente.
-- Identidade federada via SAML: subject (NameID) unico por usuario, mesmo
-- padrao do oidc_subject (006). Usuarios so-SAML nao tem senha local.
ALTER TABLE users ADD COLUMN IF NOT EXISTS saml_subject text UNIQUE;
