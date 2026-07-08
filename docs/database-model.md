# Modelo de banco de dados

PostgreSQL 16. DDL executável em [`infra/postgres/init/001-schema.sql`](../infra/postgres/init/001-schema.sql)
(aplicado automaticamente pelo Docker Compose). Este documento explica o desenho.

## 1. Diagrama entidade-relacionamento

```text
users ──< user_groups >── groups
  │                          │
  │                          │
  └──< permissions >─────────┘        allowed_ports
            │                               ▲
            ▼                               │ FK (invariante HR-04)
          assets ───────────────────────────┘
            │  credential_ref → cofre (a senha NÃO fica neste banco)
            │
            └──< sessions >── users
                    │
                    ▼
              audit_logs (append-only)
```

## 2. Tabelas e papel de cada uma

| Tabela | Papel | Pontos de segurança |
|---|---|---|
| `users` | contas do portal | `password_hash` Argon2id; `role` (`user`/`admin`); `status` |
| `groups` / `user_groups` | agrupamento para permissões | — |
| `assets` | ativos VNC cadastrados | `port` tem **FK para `allowed_ports`** — é impossível persistir asset com porta fora da allowlist, mesmo por SQL direto; `credential_ref` é um caminho no cofre, nunca a senha |
| `allowed_ports` | allowlist de portas VNC (dado, não código) | seed `5900–5902`; denylist é validada na API antes do INSERT |
| `permissions` | usuário **ou** grupo → asset | `CHECK` garante exatamente um dos dois preenchido |
| `sessions` | ciclo de vida de cada sessão | guarda `token_hash` (nunca o token), TTL, uso único (`token_used_at`), `client_ip`, `status`, `end_reason` |
| `audit_logs` | trilha de auditoria (HR-10) | append-only: `REVOKE UPDATE, DELETE` para o papel da aplicação; `details JSONB` |

## 3. Invariantes garantidas no banco (não só na aplicação)

1. **HR-04 no DDL:** `assets.port REFERENCES allowed_ports(port)` — allowlist não
   é opinião do código, é constraint.
2. **Uso único do token:** consumo via
   `UPDATE sessions SET token_used_at = now() WHERE token_hash = $1 AND token_used_at IS NULL AND token_expires_at > now()`
   — atômico; corrida entre duas conexões resulta em exatamente um vencedor.
3. **Auditoria imutável:** o papel `pam_app` não tem `UPDATE/DELETE` em `audit_logs`.
4. **Sessão consistente:** `CHECK` de transições — `ended_at` exige `end_reason`;
   `status` restrito a `pending|active|closed|failed|terminated`.
5. **Permissão bem-formada:** `CHECK ((user_id IS NULL) <> (group_id IS NULL))`.

## 4. Campos principais de `sessions`

| Coluna | Tipo | Nota |
|---|---|---|
| `id` | uuid PK | `sessionId` da API |
| `user_id` / `asset_id` | uuid FK | quem e o quê |
| `token_hash` | bytea (SHA-256) | token em si nunca é persistido |
| `token_expires_at` | timestamptz | emissão + 30s |
| `token_used_at` | timestamptz null | preenchido no upgrade do WS (uso único) |
| `status` | enum | `pending → active → closed/terminated`; `failed` em erro |
| `client_ip` | inet | IP de origem do usuário (HR-10) |
| `started_at` / `ended_at` | timestamptz | início/fim reais da sessão VNC |
| `end_reason` | text | `client_disconnect`, `admin_terminate`, `idle_timeout`, … |

## 5. O que **não** existe neste banco (por design)

- Nenhuma coluna de credencial do asset — apenas `credential_ref` apontando para o cofre.
- Nenhum token em claro — apenas hash.
- Nenhuma coluna de destino técnico (IP/host/porta/URL/comando) informável pelo
  usuário — o destino é sempre resolvido pelo backend a partir do asset (HR-01/HR-03).
- Coluna `protocol` no asset: **planejada** para o modelo de adapters (PR-16 — ver
  [`adr/0001-pivot-multiprotocolo.md`](adr/0001-pivot-multiprotocolo.md)). Hoje há um
  único protocolo (VNC), então ela ainda não existe; quando entrar, o valor é
  resolvido pelo backend e nunca informado pelo usuário.
