# Fase 5.3 — Acesso just-in-time

Terceiro recurso avançado: acesso privilegiado **temporário e justificado**, com
fluxo de solicitação → aprovação. Da lista da Fase 5: *aprovação de acesso*,
*janela de acesso* e *justificativa obrigatória*.

## O que foi construído

| Peça | Entregue |
|---|---|
| **Janela de validade** | `permissions.valid_from/valid_until`. A autorização (`listAssetsForUser`, `userCanAccessAsset`) só conta a permissão dentro da janela — permissão vencida some sozinha. |
| **Catálogo opt-in** | `assets.requestable` (default `false`). `GET /api/v1/catalog` lista só os assets solicitáveis (sem IP/porta). |
| **Solicitação** | `POST /api/v1/access-requests { assetId, justification }` (asset precisa ser requestable) e `GET /api/v1/access-requests` (minhas). |
| **Aprovação (admin)** | `GET /api/v1/admin/access-requests?status=pending`, `POST /:id/approve { windowMinutes }` (cria permissão com janela `[now, now+window]`, transacional), `POST /:id/deny { note }`. |
| **Justificativa obrigatória** | `assets.require_justification`; `POST /sessions` exige `justification` quando ligada; grava em `sessions.justification` e audita. |
| **UI** | portal: catálogo + "minhas solicitações" + prompt de justificativa no start; admin: aba "Acessos" (aprovar com janela / negar) e flags no cadastro de asset. |

## Decisão: catálogo opt-in preserva a visibilidade

O requisito "usuário vê somente assets autorizados" continua valendo. Um usuário
**não** enxerga assets sem permissão — exceto os que o admin marcou
explicitamente como `requestable`, que aparecem num **catálogo de solicitação**
(nome/descrição, nunca IP/porta). Assets não-solicitáveis permanecem invisíveis.
Assim o just-in-time é **opt-in por asset** e não contradiz a regra padrão.

## Fluxo

```text
usuário → catálogo → solicita (justificativa)  ── access.requested
admin   → fila → aprova (janela N min)          ── access.approved
        → cria permissão [now, now+N]
usuário → vê o asset → abre sessão (justif. se exigida) ── session.created
         (após a janela) permissão expira → asset some, sessão 403
```

Aprovar é **transacional**: marca a solicitação e cria a permissão com janela na
mesma transação. Tudo auditado: `access.requested/approved/denied` e a
justificativa da sessão.

## Verificação (Postgres 16 real)

| Suíte | Cobre | Resultado |
|---|---|---|
| backend unit | validação estrita (session ainda só aceita assetId+justification) | ✅ 27 |
| integração JIT (17) | catálogo isola o requestable, asset oculto permanece invisível, solicitar não-requestable → 403, request→approve cria janela, **justificativa obrigatória** (422 sem / 201 com, gravada), **janela expira → asset some e sessão 403**, deny, 409 em decisão repetida, auditoria | ✅ |

## Migração

`infra/postgres/init/004-jit.sql` (idempotente). Para banco existente:

```bash
docker compose exec postgres psql -U pam -d pam -f /docker-entrypoint-initdb.d/004-jit.sql
```

## Próximo

VeNCrypt (TLS gateway→asset) e SSO/OIDC.
