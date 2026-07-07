# Fase 2 — MVP funcional

Objetivo: transformar a PoC em produto mínimo administrável — cadastro de
assets/usuários, grupos e permissões, e visibilidade operacional de sessões e
auditoria. Login e ciclo de sessão já vieram na Fase 1.

## O que foi construído

| Área | Entregue |
|---|---|
| **Cofre de credenciais (interino)** | Backend cifra a senha VNC com **AES-256-GCM** e a guarda apenas como `credential_ref` (`enc:v1:<nonce>:<ct+tag>`). Texto claro nunca vai ao banco; master key só em env. Gateway decifra no `resolveCredential`. Na Fase 3 entra o Vault sem tocar o resto. |
| **Admin: assets** | `GET/POST/PATCH/DELETE /api/v1/admin/assets`. `vncPassword` é **write-only** (nunca retorna). Porta validada contra allowlist + **denylist imutável**. Delete é soft se houver histórico de sessões. |
| **Admin: usuários** | `GET/POST/PATCH /api/v1/admin/users` (senha via Argon-alvo/scrypt-PoC; hash nunca retorna). |
| **Admin: grupos e permissões** | grupos + membros; permissões por usuário **ou** grupo. |
| **Admin: allowlist de portas** | `GET/POST/DELETE /api/v1/admin/allowed-ports`; recusa a denylist e a faixa fora de 1024–65535; bloqueia remoção de porta em uso por asset ativo. |
| **Admin: sessões e auditoria** | `GET /api/v1/admin/sessions` (filtros) e `GET /api/v1/admin/audit-logs` (filtros + paginação). |
| **UI admin** | `/admin` com abas: ativos, usuários, grupos, permissões, portas, sessões, auditoria. Encerramento de sessão pelo admin. |

## Como os requisitos viram código

- **HR-04 (denylist imutável):** `ports.ts` bloqueia `22, 23, 80, 443, 445, 3389,
  1433, 3306, 5432, 5985/6, 6379, 8080, 8443, 9200, 27017, …` de entrarem na
  allowlist — e, por consequência, de qualquer asset usá-las. A allowlist
  permanece FK no banco.
- **HR-05/06 (senha nunca exposta):** `vncPassword` é write-only na API e cifrada
  no repouso; nenhuma resposta ou log de auditoria a contém (verificado em teste).
- **Autorização:** todas as rotas `/admin/*` exigem perfil `admin` (`requireAdmin`);
  usuário comum recebe 403.

## Decisão: cofre AES-GCM como passo intermediário

A `security-requirements.md §4` prevê Vault na Fase 3. Para a Fase 2, guardar a
senha **cifrada** (AES-256-GCM, master key fora do banco) satisfaz o invariante
"texto claro nunca no banco / nunca em log" e mantém a propriedade write-only,
sem introduzir a operação do Vault ainda. O `credential_ref` já é o seam: trocar
`enc:v1:` por `vault:` na Fase 3 não altera as rotas nem o gateway.

## Evidência de verificação

| Suíte | Cobre | Resultado |
|---|---|---|
| backend unit (12) | validação estrita HR-01/02, denylist de portas, cofre write-only | ✅ |
| gateway unit (20) | RFB/DES, handshakes, `resolveCredential` (env + enc round-trip) | ✅ |
| integração admin (Postgres real, 27) | requireAdmin 403, denylist/allowlist, asset write-only, **cofre e2e (backend cifra → gateway decifra)**, rotação de senha, grupos→permissão→visibilidade, sessões e auditoria, sem senha em log | ✅ |

## Critérios de aceite da Fase 2

- [x] Admin cadastra asset VNC (porta na allowlist; `22`/`3389`/`443` → 422)
- [x] Usuário vê somente assets autorizados (direto e via grupo)
- [x] Asset inativo não aparece
- [x] Usuário inicia e encerra sessão (Fase 1) — admin também encerra
- [x] Usuário não vê a senha em nenhum ponto (write-only + cofre cifrado)
- [x] Sessão registrada em log com usuário, asset, IP, início, fim, status
- [x] Admin lista sessões e auditoria

## Próximo (Fase 3)

HashiCorp Vault no lugar do cofre interino; token/allowlist com testes de corrida
e sentinela de senha no CI (com containers); rate limit; TLS/WSS fim a fim.
