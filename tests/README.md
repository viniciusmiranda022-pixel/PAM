# tests

Suítes transversais versionadas (os testes unitários vivem dentro de cada
componente: `backend/test`, `gateway/test`). Rodam contra um **Postgres real** e
importam o **build** (`dist`) de backend/gateway.

- `integration/` — fluxo de sessão ponta a ponta (login → criar sessão por
  `assetId` → token efêmero de uso único/TTL, consumido pelo gateway).
- `security/` — testes que travam os hard requirements:
  - **XFF não spoofa o IP de auditoria** (HR-10): `TRUST_PROXY=false` ignora o
    header; `TRUST_PROXY=1` respeita (nginx sobrescreve com `$remote_addr`).
  - **allowlist/denylist por protocolo** (HR-04): porta do denylist recusada na
    API e por FK no banco.
  - **rejeição de `host`/`port`** no start de sessão (HR-01/02).
  - **sentinela de senha** (HR-06): senha nunca aparece nos logs.
  - **auditoria append-only** via role `pam_app` (HR-10): `UPDATE`/`DELETE` em
    `audit_logs` negados.

## Como rodar

Pré-requisitos: backend e gateway **compilados** (`npm run build`) e um Postgres.

```bash
# 1) build (a suíte importa dist/)
(cd ../backend && npm ci && npm run build)
(cd ../gateway && npm ci && npm run build)

# 2) variáveis do banco (exemplo com Postgres local vazio)
export DATABASE_URL=postgres://pam:senha@127.0.0.1:5432/pam
export PAM_APP_URL=postgres://pam_app:apppw@127.0.0.1:5432/pam
export PAM_APP_PASSWORD=apppw
export SCRYPT_N=16384            # KDF barato nos testes (ADR 0002)

# 3) rodar
npm ci && npm test
```

O helper (`helpers/db.ts`) aplica as migrações `infra/postgres/init/*.sql` num
banco vazio e cria a role `pam_app` — o mesmo bootstrap que o CI executa. O
`e2e/` (Playwright: login, abrir sessão VNC, encerrar, kill por admin) contra
noVNC + TigerVNC reais depende de um host com `docker pull` liberado e segue
como pendência (ver [`../docs/function-audit.md`](../docs/function-audit.md)).
