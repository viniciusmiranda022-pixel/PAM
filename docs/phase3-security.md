# Fase 3 — Segurança

Objetivo: deixar a solução minimamente aceitável para ambiente corporativo.
Vários itens já vieram nas fases anteriores (token de uso único + TTL na Fase 1;
allowlist + denylist imutável e cofre write-only na Fase 2); esta fase fecha as
lacunas e **prova** cada garantia com teste.

## O que foi construído nesta fase

| Item | Entregue |
|---|---|
| **Cofre HashiCorp Vault** | Provider `vault:` (KV v2). Backend escreve a senha no Vault e grava só `credential_ref = vault:<path>`; gateway lê no `resolveCredential`. Selecionável por `CREDENTIAL_PROVIDER=enc\|vault` — o mesmo seam dos providers `env:` e `enc:v1:`. |
| **Rate limit** | Login 5/min/IP e criação de sessão 10/min/usuário (janela deslizante em memória); excedente → `429` + auditoria. Configurável. |
| **Bloqueio de host arbitrário (teste)** | Prova de que o gateway recusa destino que não responde banner `RFB`, mesmo em porta permitida — fecha com `4503`, audita `gateway.banner_mismatch`, sessão `failed`. |
| **Sentinela de senha** | Teste que roda o fluxo com uma senha única e garante que ela **não aparece em nenhum log** do backend nem em `audit_logs`. |
| **Compose** | Serviço `vault` (dev, root token fixo, KV `secret/`); variáveis de Vault e rate limit no backend/gateway. |

## Onde cada provider de credencial vive

O gateway resolve `credential_ref` por prefixo — trocar de provider **não muda**
rotas nem o fluxo de sessão:

```text
env:NOME        -> variável de ambiente        (asset de laboratório)
enc:v1:<n>:<b>  -> AES-256-GCM (master key env) (Fase 2, default)
vault:<path>    -> HashiCorp Vault KV v2        (Fase 3)
```

`CREDENTIAL_PROVIDER` controla **como o backend grava** um novo segredo; o
gateway sabe ler os três formatos, então assets antigos continuam funcionando
após a troca.

## Autenticação no Vault

- Lab/dev: token (root token do dev server).
- Produção: **AppRole** com policy de leitura restrita a `secret/data/vnc/*` para
  o gateway e de escrita para o backend. (Substituição direta do `VAULT_TOKEN`.)

## Evidência de verificação

Postgres 16 real + fakes in-process (Vault KV v2, servidor não-VNC), pois o
ambiente de CI não faz `docker pull`.

| Suíte | Cobre | Resultado |
|---|---|---|
| backend unit (16) | validação estrita, denylist, cofre write-only, **rate limiter** | ✅ |
| gateway unit (20) | RFB/DES, handshakes, `resolveCredential` (env/enc/erros) | ✅ |
| integração Fase 3 (12) | **Vault e2e (backend grava → gateway lê)**, rate limit login+sessão, **sentinela de senha** (log + auditoria), **corrida de token** (uso único), **host arbitrário** (banner → 4503 + auditoria) | ✅ |

## Critérios de aceite da Fase 3

- [x] Token expira (Fase 1; reprovado aqui via corrida/expiração)
- [x] Token é de uso único — inclusive sob corrida de 2 conexões
- [x] Senha não aparece no navegador (Fase 1) nem em nenhum log (sentinela)
- [x] Porta não permitida é bloqueada na API, no banco e no gateway
- [x] Asset não autorizado retorna 403 e gera auditoria (Fase 2)
- [x] Gateway recusa destino que não responde banner RFB

## Ainda pendente de ambiente / próximas fases

- Ensaio com **Vault real + noVNC + TigerVNC** via `docker compose --profile app`
  (precisa de host com `docker pull`); passo a passo em `deployment.md`.
- **TLS/WSS fim a fim** já existe na borda (Nginx); mTLS interno e VeNCrypt no
  trecho gateway→asset ficam para a Fase 5.
- AppRole no lugar do token de dev; store externo de auditoria (SIEM).
