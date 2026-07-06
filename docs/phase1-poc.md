# Fase 1 — PoC técnica

Objetivo da fase: **provar o fluxo seguro de ponta a ponta**, com o mínimo de
telas. Nada de dashboard bonito — o núcleo é o controle seguro da sessão VNC.

```text
Portal → login → autorização → criar sessão (só assetId) → token efêmero
→ gateway WebSocket → TCP VNC → asset
```

## O que foi construído

| Componente | Entregue nesta fase |
|---|---|
| `gateway/` | Servidor WS→TCP com **terminação RFB 3.8**: `None` no lado navegador, `VNC Authentication` (DES) no lado asset; consumo atômico do token; validação de banner RFB; re-checagem de allowlist; splice binário; teardown simétrico; auditoria |
| `backend/` | Fastify+Zod: login (cookie assinado), `GET /assets` (sem IP/porta), `POST /sessions` (**somente `assetId`**), `DELETE /sessions/:id`, emissão de token efêmero (hash no banco, TTL 30s), auditoria |
| `frontend/` | Portal mínimo servindo noVNC; login → lista de assets → sessão; token no subprotocolo WS; **sem campo de host/porta** |
| `infra/` | Compose com profile `app`, `lab-vnc` em rede isolada com IP fixo, Nginx TLS/WSS, seed de laboratório |

## Decisões implementadas (e por quê)

- **VNC Authentication sem dependência nativa.** DES simples está desabilitado no
  OpenSSL 3; o gateway calcula a resposta ao challenge via 3DES com a chave
  triplicada (`des-ede3-ecb` com K1=K2=K3=K colapsa para DES simples). Validado
  contra os vetores canônicos do DES — sem vendorizar cripto, sem provider legado.
- **Token no subprotocolo WebSocket**, nunca em URL — não vaza em access log. O
  gateway o consome atomicamente (`UPDATE ... WHERE token_used_at IS NULL`).
- **IP de origem autoritativo** vem do `client_ip` gravado na criação da sessão
  (não do IP da conexão ao gateway, que seria o do Nginx).
- **Provider de credencial como seam**: na Fase 1 é `env:NOME`; a troca pelo Vault
  na Fase 3 não toca o resto do gateway.

## Evidência de verificação

Como o ambiente de CI desta fase não permite `docker pull`, o fluxo foi
verificado com um Postgres 16 local real e um servidor RFB simulado — cobrindo
justamente a lógica que testes unitários não alcançam.

| Suíte | Cobre | Resultado |
|---|---|---|
| `gateway` unit (Vitest, 16) | DES do VNC Auth (vetor canônico), banner RFB, negociação de versão, `assetHandshake` (cliente) e `browserHandshake` (servidor) | ✅ |
| `backend` unit (Vitest, 6) | schema estrito: `host`/`port`/`ip`/`hostname` rejeitados (HR-01/02) | ✅ |
| Integração backend+gateway (Postgres real, 21) | login/authz, assets sem IP/porta, 400 p/ host+port, 403 sem permissão, criação de sessão sem vazar segredo, consumo de token único + TTL, auditoria sem senha | ✅ |
| E2E do gateway (WS↔TCP real, 14) | handshake VNC Auth no asset, `None` no browser, relay do ServerInit, splice bidirecional, reuso de token → close 4401, sessão `active`, auditoria com IP de origem, sem senha em log | ✅ |

Estas suítes de integração/E2E serão portadas para `tests/` e para o CI (com
containers) junto do endurecimento da Fase 3.

## Critérios de aceite da Fase 1

- [x] Usuário abre a tela VNC no navegador (fluxo noVNC ↔ gateway provado no E2E)
- [x] Gateway conecta no asset pela porta 5901 **buscada do banco** (HR-03)
- [x] Usuário não acessa o asset diretamente — `assets_net` isolada (HR-07)
- [x] Senha do asset não trafega ao navegador — handshake `None` (HR-05); E2E confirma
- [x] Não existe biblioteca de RDP/SSH nos lockfiles (HR-09)

> **Pendente de ambiente:** o teste com **noVNC real + TigerVNC real** (via
> `docker compose --profile app up`) precisa de um host com `docker pull`
> liberado. O passo a passo está em [`deployment.md`](deployment.md). A lógica de
> protocolo já está validada contra um servidor RFB simulado.

## Próximo (Fase 2 / Fase 3)

CRUD de assets/usuários/permissões e telas administrativas (Fase 2); token,
allowlist, Vault, rate limit, TLS fim a fim e teste-sentinela de senha em CI
(Fase 3). Ver [`delivery-plan.md`](delivery-plan.md).
