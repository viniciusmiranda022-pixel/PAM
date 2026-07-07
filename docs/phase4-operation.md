# Fase 4 — Administração e operação

Objetivo: permitir operação real. Boa parte da administração (CRUDs, sessões
ativas, encerrar sessão) já veio na Fase 2; esta fase fecha a lacuna operacional
que faltava e adiciona observabilidade.

## O que foi construído nesta fase

| Item | Entregue |
|---|---|
| **Encerramento forçado efetivo** | Antes, `DELETE /sessions/:id` só marcava o banco. Agora o gateway mantém um **registro das sessões ativas** e um **watchdog** que consulta o banco periodicamente; quando o backend marca uma sessão como `terminated`, o gateway **derruba WS + TCP ao vivo**. Kill de admin e "encerrar" do usuário passam a desconectar de fato. |
| **Health check (readiness)** | `GET /healthz` no backend e no gateway reflete o **banco** (`SELECT 1`): `200` ok, `503` degraded. O do gateway também reporta `activeSessions`. Healthchecks de container no compose. |
| **Métricas Prometheus** | `GET /metrics` (formato Prometheus, rede interna). Backend: logins por resultado, sessões criadas, requisições bloqueadas por rate limit. Gateway: sessões iniciadas, encerradas por motivo, e gauge de **sessões ativas**. |
| **Backup do banco** | `scripts/backup-db.sh` (pg_dump comprimido + retenção configurável). |

## Como o encerramento forçado funciona

```text
Admin/usuário         Backend                 Gateway (watchdog a cada 5s)
     │  DELETE /sessions/:id                          │
     │─────────────────▶ UPDATE sessions              │
     │                   status=terminated            │
     │                                    ┌───────────┤ SELECT id FROM sessions
     │                                    │ id ∈ ativos AND status<>'active'
     │                                    ▼
     │                            fecha WS(cliente) + TCP(asset)
     │                            unregister + métrica de sessão encerrada
```

Sem novo canal de rede entre backend e gateway (o backend não fala com o gateway
diretamente): o **banco é o ponto de sincronização**, coerente com o resto da
arquitetura. Intervalo do watchdog configurável (`WATCHDOG_INTERVAL_MS`).

O motivo gravado pelo backend (`admin_terminate` / `user_request`) é preservado —
o gateway apenas derruba os sockets.

## Observabilidade

- `/metrics` **não** é publicado pelo Nginx (o `nginx.conf` só expõe `/`,
  `/api/`, `/gateway/`); fica acessível apenas na rede interna, para o Prometheus.
- Séries principais: `pam_gateway_active_sessions`,
  `pam_gateway_sessions_started_total`, `pam_gateway_sessions_ended_total{reason}`,
  `pam_backend_logins_total{result}`, `pam_backend_rate_limited_total{route}`.

## Evidência de verificação

Postgres 16 real + servidor RFB simulado, in-process (o CI não faz `docker pull`).

| Suíte | Cobre | Resultado |
|---|---|---|
| backend unit (16) | validação, denylist, cofre, rate limiter | ✅ |
| gateway unit (20) | RFB/DES, handshakes, credencial | ✅ |
| integração Fase 4 (10) | **encerramento forçado ao vivo** (backend marca → gateway derruba WS, motivo preservado, registro esvazia), `/healthz` 200/503 refletindo o banco, `/metrics` de backend e gateway | ✅ |

## Critérios de aceite da Fase 4

- [x] Admin vê sessões ativas (Fase 2) e **encerra desconectando o usuário na hora**
- [x] Logs de auditoria consultáveis com filtros (Fase 2)
- [x] Health check reflete o banco (e o gateway reporta sessões ativas)
- [x] Erros são registrados e visíveis (auditoria + métricas)
- [x] Deploy reproduzível documentado (`deployment.md`) + backup do banco

## Pendente de ambiente / próximo (Fase 5)

- Ensaio completo com containers reais (`docker compose --profile app`) precisa de
  host com `docker pull`.
- Health do **cofre** (Vault) e do alcance gateway→asset; store externo de
  auditoria (SIEM); dashboards.
- MFA, SSO (OIDC/SAML), aprovação de acesso, gravação de sessão, VeNCrypt.
