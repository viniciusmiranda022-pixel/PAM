-- Fase 5.3 — Acesso just-in-time (janela de validade, justificativa, aprovacao).
-- Idempotente; para banco existente, aplicar manualmente: docs/phase5-jit.md.

-- Janela de validade nas permissoes (NULL = sem limite).
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS valid_from  timestamptz;
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS valid_until timestamptz;

-- Opt-in por asset: só assets 'requestable' aparecem no catalogo de solicitacao;
-- os demais continuam invisiveis (preserva "usuario ve so o autorizado").
ALTER TABLE assets ADD COLUMN IF NOT EXISTS requestable          boolean NOT NULL DEFAULT false;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS require_justification boolean NOT NULL DEFAULT false;

-- Justificativa registrada na sessao (quando exigida).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS justification text;

CREATE TABLE IF NOT EXISTS access_requests (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    asset_id      uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    justification text NOT NULL,
    status        text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    window_minutes integer,
    decided_by    uuid REFERENCES users (id),
    decided_at    timestamptz,
    decision_note text,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS access_requests_status_idx ON access_requests (status, created_at DESC);
CREATE INDEX IF NOT EXISTS access_requests_user_idx   ON access_requests (user_id, created_at DESC);
