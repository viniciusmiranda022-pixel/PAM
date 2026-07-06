-- PAM VNC-Only — schema inicial (Fase 0)
-- Aplicado automaticamente pelo container postgres no primeiro boot.
-- Racional e invariantes: docs/database-model.md

CREATE TYPE user_role      AS ENUM ('user', 'admin');
CREATE TYPE entity_status  AS ENUM ('active', 'inactive');
CREATE TYPE session_status AS ENUM ('pending', 'active', 'closed', 'failed', 'terminated');

CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text NOT NULL UNIQUE,
    display_name  text NOT NULL,
    email         text UNIQUE,
    password_hash text NOT NULL, -- Argon2id
    role          user_role NOT NULL DEFAULT 'user',
    status        entity_status NOT NULL DEFAULT 'active',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE groups (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_groups (
    user_id  uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_id uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

-- Allowlist de portas VNC (HR-04). O denylist de portas de outros protocolos
-- (22, 3389, 443, ...) é imutável e vive na API — nunca entra nesta tabela.
CREATE TABLE allowed_ports (
    port        integer PRIMARY KEY CHECK (port BETWEEN 1024 AND 65535),
    description text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Assets VNC. A senha NÃO fica neste banco: credential_ref aponta para o cofre.
-- A FK em port torna impossível persistir asset com porta fora da allowlist.
CREATE TABLE assets (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL UNIQUE,
    description    text,
    environment    text NOT NULL DEFAULT 'production',
    ip_address     inet NOT NULL,
    port           integer NOT NULL REFERENCES allowed_ports (port),
    credential_ref text,
    status         entity_status NOT NULL DEFAULT 'active',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Permissão: exatamente um entre user_id e group_id.
CREATE TABLE permissions (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id   uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    user_id    uuid REFERENCES users (id) ON DELETE CASCADE,
    group_id   uuid REFERENCES groups (id) ON DELETE CASCADE,
    granted_by uuid REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((user_id IS NULL) <> (group_id IS NULL)),
    UNIQUE NULLS NOT DISTINCT (asset_id, user_id, group_id)
);

-- Sessões: o token efêmero nunca é persistido em claro — somente o SHA-256.
-- Uso único garantido por UPDATE atômico sobre token_used_at (ver docs).
CREATE TABLE sessions (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          uuid NOT NULL REFERENCES users (id),
    asset_id         uuid NOT NULL REFERENCES assets (id),
    token_hash       bytea NOT NULL UNIQUE,
    token_expires_at timestamptz NOT NULL,
    token_used_at    timestamptz,
    status           session_status NOT NULL DEFAULT 'pending',
    client_ip        inet,
    started_at       timestamptz,
    ended_at         timestamptz,
    end_reason       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (ended_at IS NULL OR end_reason IS NOT NULL)
);

CREATE INDEX sessions_status_idx  ON sessions (status);
CREATE INDEX sessions_user_idx    ON sessions (user_id, created_at DESC);
CREATE INDEX sessions_asset_idx   ON sessions (asset_id, created_at DESC);

-- Auditoria (HR-10) — append-only: o papel de aplicação (criado no
-- provisionamento, senha via secret, fora deste arquivo) recebe apenas
-- SELECT e INSERT nesta tabela; UPDATE/DELETE são negados.
CREATE TABLE audit_logs (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_type text NOT NULL,
    user_id    uuid,
    asset_id   uuid,
    session_id uuid,
    source_ip  inet,
    details    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_logs_event_idx   ON audit_logs (event_type, created_at DESC);
CREATE INDEX audit_logs_session_idx ON audit_logs (session_id);
CREATE INDEX audit_logs_user_idx    ON audit_logs (user_id, created_at DESC);

-- Seed da allowlist: portas VNC padrão. Customizadas entram via API de admin,
-- que valida o denylist imutável antes do INSERT.
INSERT INTO allowed_ports (port, description) VALUES
    (5900, 'VNC display :0'),
    (5901, 'VNC display :1'),
    (5902, 'VNC display :2');
