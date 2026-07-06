# Fluxo de sessão VNC

## 1. Fluxo feliz (ponta a ponta)

```text
 Navegador          Backend/Broker           Gateway            Cofre      Asset VNC
    │                     │                     │                 │            │
 1  │── POST /sessions ──▶│                     │                 │            │
    │   { assetId }       │                     │                 │            │
 2  │                     │ valida login,       │                 │            │
    │                     │ permissão, asset    │                 │            │
    │                     │ ativo, porta na     │                 │            │
    │                     │ allowlist           │                 │            │
 3  │                     │ cria session        │                 │            │
    │                     │ (pending) + token   │                 │            │
    │                     │ efêmero (TTL 30s)   │                 │            │
 4  │◀─ 201 {sessionId, ──│                     │                 │            │
    │    wsUrl, token}    │                     │                 │            │
 5  │── WSS upgrade ─────────────────────────▶ │                 │            │
    │   (token)           │                     │                 │            │
 6  │                     │◀── consome token ───│                 │            │
    │                     │    (uso único,      │                 │            │
    │                     │     atômico)        │                 │            │
 7  │                     │                     │── lê senha ────▶│            │
 8  │                     │                     │── TCP connect ──────────────▶│
 9  │                     │                     │  valida banner "RFB 003.008" │
10  │                     │                     │── VNC Auth (DES challenge) ─▶│
11  │◀─ RFB None ─────────────────────────────▶│                 │            │
    │   (handshake sem senha)                   │                 │            │
12  │                     │ session → active    │                 │            │
13  │◀━━━ bytes RFB ━━━━━━━━━━━━━━━━━━━━━━━━━▶│◀━━━ bytes RFB ━━━━━━━━━━━━━━▶│
    │              (splice transparente até o encerramento)       │            │
```

### Detalhe dos passos

| # | Ação | Falha → resultado |
|---|------|-------------------|
| 1 | Frontend envia **somente** `assetId` (HR-02). Payload com `host`/`port` é rejeitado com 400 (validação estrita). | 400 `INVALID_BODY` |
| 2 | Broker confere: usuário autenticado; permissão direta ou via grupo; asset `active`; porta do asset presente na allowlist (defesa em profundidade — o banco já garante por FK). | 401 / 403 `NOT_AUTHORIZED` / 422 `ASSET_INACTIVE` |
| 3 | Cria `sessions(status=pending)`, gera token 256 bits, grava só o hash. Auditoria: `session.created`. | — |
| 4 | Resposta traz `wsUrl` do gateway e o token. O IP/porta do asset **não aparecem** na resposta. | — |
| 5 | noVNC abre WSS contra o gateway com o token. | — |
| 6 | Gateway consome o token: `UPDATE sessions SET token_used_at=now() WHERE token_hash=$1 AND token_used_at IS NULL AND token_expires_at > now()`. 0 linhas afetadas → fecha WS (4401). Auditoria: `session.token_rejected`. | WS close 4401 |
| 7 | Gateway busca a credencial do asset no cofre. Auditoria: `credential.read`. | WS close 4502 |
| 8 | Gateway abre TCP para `(ip, porta)` vindos do banco via sessão — nunca do cliente (HR-03). | WS close 4503, sessão `failed` |
| 9 | Banner ≠ `RFB ` → encerra e audita `gateway.banner_mismatch` (HR-08). | WS close 4503 |
| 10 | Handshake RFB 3.8 com o asset usando `VNC Authentication`; senha nunca é logada (HR-06). | WS close 4504, sessão `failed` |
| 11 | Handshake RFB 3.8 com o navegador usando security type `None` — nenhuma senha no browser (HR-05). | WS close 4400 |
| 12 | Sessão marcada `active`, `started_at=now()`. Auditoria: `session.started`. | — |
| 13 | Pipe binário bidirecional. | — |

## 2. Encerramento

Todos os caminhos convergem para: fechar WS, fechar TCP, `sessions.status` final,
`ended_at=now()`, `end_reason`, evento de auditoria `session.ended`.

| Gatilho | Comportamento | `end_reason` |
|---|---|---|
| Usuário fecha a aba/navegador | WS close → gateway fecha o TCP imediatamente | `client_disconnect` |
| Asset encerra/queda de rede | TCP close/error → gateway fecha o WS | `asset_disconnect` |
| Usuário clica "Encerrar" | `DELETE /sessions/{id}` → broker sinaliza gateway → fecha ambos | `user_request` |
| Admin encerra (kill) | `DELETE /sessions/{id}` por admin → idem | `admin_terminate` |
| Token expirado/reutilizado | WS nunca chega a `active` | `token_invalid` |
| Timeout de inatividade (configurável, Fase 3) | gateway fecha ambos | `idle_timeout` |
| Shutdown do gateway | drain: fecha todas as sessões | `gateway_shutdown` |

**Invariante:** não pode existir socket TCP para asset sem WebSocket vivo
correspondente, nem sessão `active` sem os dois sockets. Watchdog no gateway
reconcilia a cada 30s e força encerramento de órfãos.

## 3. Eventos de auditoria por sessão (HR-10)

Cada sessão produz, no mínimo:

```text
session.created   { userId, assetId, clientIp }
session.started   { sessionId, gatewayInstance }
session.ended     { sessionId, endReason, durationSeconds }
```

E quando aplicável:

```text
session.token_rejected · session.denied (403) · credential.read
gateway.banner_mismatch · gateway.port_blocked · session.terminated_by_admin
```

Falhas também são auditadas — uma tentativa negada deixa rastro igual a uma
sessão bem-sucedida.
