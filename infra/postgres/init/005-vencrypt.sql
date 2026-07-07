-- Fase 5.4 — VeNCrypt (TLS gateway->asset).
-- Idempotente; para banco existente, aplicar manualmente: docs/phase5-vencrypt.md.
-- Quando true, o gateway exige VeNCrypt/X509 ao conectar no asset e cifra o
-- trecho gateway->asset; a autenticacao VNC ocorre dentro do tunel TLS.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS tls_required boolean NOT NULL DEFAULT false;
