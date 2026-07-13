-- 009 — Protocolo do asset (PR-16, adapter registry). Idempotente.
-- Cada asset passa a declarar o protocolo de acesso; o gateway resolve o adapter
-- por este valor. Default 'vnc': todo asset existente e o adapter atual.
-- Novos protocolos (rdp, ssh…) so entram com o adapter correspondente (PR-17+).
ALTER TABLE assets ADD COLUMN IF NOT EXISTS protocol text NOT NULL DEFAULT 'vnc';
