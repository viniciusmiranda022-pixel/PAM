#!/bin/bash
# 007 — Role de runtime `pam_app` com privilegio minimo (PR-13).
#
# Motivacao: ate aqui backend e gateway conectavam como o DONO do banco, que
# pode tudo — inclusive UPDATE/DELETE em audit_logs. Esta role materializa a
# auditoria append-only prometida no threat model (anti-repudio, HR-10):
#   - audit_logs: somente INSERT e SELECT (nunca UPDATE/DELETE)
#   - demais tabelas: o CRUD que a aplicacao realmente usa
#   - nenhum DDL, nenhum superpoder
#
# Opt-in: so cria a role se PAM_APP_PASSWORD estiver definido no ambiente do
# container ANTES do primeiro boot (initdb). Para um banco ja existente, rode
# este script manualmente:
#   docker compose exec -e PAM_APP_PASSWORD=... postgres \
#     bash /docker-entrypoint-initdb.d/007-app-role.sh
# e aponte DATABASE_URL de backend/gateway para pam_app.
set -euo pipefail

if [ -z "${PAM_APP_PASSWORD:-}" ]; then
  echo "007-app-role: PAM_APP_PASSWORD nao definido — role pam_app nao criada (opcional)."
  exit 0
fi

psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-pam}" -d "${POSTGRES_DB:-pam}" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pam_app') THEN
    CREATE ROLE pam_app LOGIN PASSWORD '${PAM_APP_PASSWORD}';
  ELSE
    ALTER ROLE pam_app WITH LOGIN PASSWORD '${PAM_APP_PASSWORD}';
  END IF;
END
\$\$;

GRANT CONNECT ON DATABASE "${POSTGRES_DB:-pam}" TO pam_app;
GRANT USAGE ON SCHEMA public TO pam_app;

-- CRUD usado pela aplicacao (backend + gateway)
GRANT SELECT, INSERT, UPDATE, DELETE ON
  users, groups, user_groups, assets, permissions, allowed_ports, access_requests
TO pam_app;

-- Sessoes: criadas e atualizadas (token, status, fim), nunca apagadas pela app
GRANT SELECT, INSERT, UPDATE ON sessions TO pam_app;

-- Auditoria APPEND-ONLY: sem UPDATE, sem DELETE, sem TRUNCATE (anti-repudio)
GRANT SELECT, INSERT ON audit_logs TO pam_app;
SQL

echo "007-app-role: role pam_app criada/atualizada com privilegio minimo."
