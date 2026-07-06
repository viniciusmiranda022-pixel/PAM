# Contrato de API — v1

## 1. Convenções

- Base path: `/api/v1`. Somente HTTPS.
- Autenticação do portal: cookie de sessão `HttpOnly` + header `X-CSRF-Token` em mutações.
- Corpo JSON com **validação estrita**: campos não previstos ⇒ `400` (é assim que
  HR-01/02 viram contrato — `host`/`port` no start de sessão nunca são aceitos).
- Erros:

```json
{ "error": { "code": "NOT_AUTHORIZED", "message": "..." } }
```

| HTTP | code | Uso |
|---|---|---|
| 400 | `INVALID_BODY` | payload inválido ou com campos extras |
| 401 | `NOT_AUTHENTICATED` | sem login válido |
| 403 | `NOT_AUTHORIZED` | sem permissão no asset / não é admin |
| 404 | `NOT_FOUND` | recurso inexistente |
| 409 | `CONFLICT` | ex.: limite de sessões simultâneas |
| 422 | `VALIDATION_FAILED` | ex.: porta fora da allowlist, asset inativo |
| 429 | `RATE_LIMITED` | rate limit |

## 2. Autenticação

### POST /api/v1/auth/login
```json
{ "username": "vinicius", "password": "•••" }
```
→ `204` + cookie de sessão. Auditoria: `auth.login` / `auth.login_failed`.

### POST /api/v1/auth/logout → `204`

### GET /api/v1/auth/me
```json
{ "id": "uuid", "username": "vinicius", "displayName": "Vinicius", "role": "user" }
```

## 3. Fluxo do usuário

### GET /api/v1/assets — assets autorizados ao usuário logado

```json
{
  "items": [
    { "id": "uuid", "name": "srv-financeiro-01", "description": "…",
      "environment": "production", "status": "active" }
  ]
}
```

> **Nota de segurança:** a resposta **não contém IP nem porta** — nem para
> exibição. O usuário não precisa e não deve conhecer o endereço do asset.
> Assets inativos ou sem permissão não aparecem.

### POST /api/v1/sessions — criar sessão (HR-02: somente `assetId`)

```json
{ "assetId": "uuid-do-asset" }
```

→ `201`:
```json
{
  "sessionId": "uuid",
  "gatewayUrl": "wss://pam.example.com/gateway/vnc/<sessionId>",
  "token": "b64url-256bits",
  "tokenExpiresInSeconds": 30
}
```

Regras: `403` sem permissão · `422` asset inativo ou porta fora da allowlist ·
`409` limite de sessões simultâneas do usuário atingido. A resposta nunca inclui
host/porta/credencial.

### DELETE /api/v1/sessions/{sessionId} → `204`
Dono da sessão ou admin. Encerra WS+TCP no gateway e finaliza a sessão
(`end_reason=user_request` ou `admin_terminate`).

### GET /api/v1/sessions/{sessionId}
```json
{ "sessionId": "uuid", "assetId": "uuid", "status": "active",
  "startedAt": "2026-07-06T14:00:00Z", "endedAt": null, "endReason": null }
```

## 4. Gateway — protocolo WebSocket

### `GET wss://…/gateway/vnc/{sessionId}` (upgrade)

- Token efêmero via subprotocolo: o cliente envia
  `Sec-WebSocket-Protocol: binary, pam.token.<token>`; o gateway responde
  aceitando `binary` e consome o token. Token **nunca** em query string
  (não vaza em access log). O noVNC permite configurar subprotocolos via
  `RFB(..., { wsProtocols })`.
- Após o upgrade: gateway ↔ browser falam **RFB 3.8 com security `None`**;
  gateway ↔ asset com `VNC Authentication` (senha do cofre). Depois do
  `ServerInit`, pipe binário puro.

### Códigos de close do WebSocket

| Código | Significado |
|---|---|
| 1000 | encerramento normal |
| 4400 | handshake RFB inválido do cliente |
| 4401 | token inválido / expirado / já usado |
| 4403 | sessão não está em estado válido |
| 4502 | falha ao obter credencial no cofre |
| 4503 | falha TCP com o asset / banner não-RFB / porta bloqueada |
| 4504 | falha de autenticação VNC com o asset |

## 5. Administração (role `admin`)

### Assets — `/api/v1/admin/assets`

`POST`:
```json
{ "name": "srv-financeiro-01", "description": "…", "environment": "production",
  "ipAddress": "10.10.10.50", "port": 5900, "vncPassword": "•••" }
```
→ `201` com o asset **sem** `vncPassword` (write-only; vai direto ao cofre).
`422` se a porta não estiver na allowlist (`22`, `3389`, `443` etc. jamais passam).

`GET` (lista, com IP/porta — visão admin) · `PATCH /{id}` (inclui rotação de
`vncPassword` e `status: active|inactive`) · `DELETE /{id}` (soft delete se houver
histórico de sessões).

### Usuários, grupos e permissões

```text
POST/GET/PATCH        /api/v1/admin/users          (role: user|admin, status)
POST/GET/DELETE       /api/v1/admin/groups
PUT/DELETE            /api/v1/admin/groups/{id}/members/{userId}
POST/GET/DELETE       /api/v1/admin/permissions    { assetId, userId? | groupId? }
```

### Allowlist de portas — `/api/v1/admin/allowed-ports`

`POST { "port": 5905, "description": "VNC custom fábrica" }` → `201`.
`422 VALIDATION_FAILED` se a porta estiver no denylist imutável ou fora de
`1024–65535`. `GET` lista; `DELETE /{port}` remove (bloqueado se houver asset ativo usando).

### Sessões e auditoria

```text
GET /api/v1/admin/sessions?status=active&userId=&assetId=&from=&to=
GET /api/v1/admin/audit-logs?eventType=&userId=&assetId=&from=&to=&page=
```

Evento de auditoria:
```json
{ "id": "uuid", "eventType": "session.started", "userId": "uuid",
  "assetId": "uuid", "sessionId": "uuid", "sourceIp": "203.0.113.7",
  "details": { "endReason": null }, "createdAt": "2026-07-06T14:00:00Z" }
```

## 6. Operação

```text
GET /healthz            (backend e gateway; sem auth; liveness+readiness)
GET /metrics            (Prometheus; rede interna apenas — Fase 4)
```

## 7. O que este contrato **não** tem (por design)

- Nenhum endpoint aceita `host`, `hostname`, `ip` ou `port` vindos de usuário
  comum (somente admin no CRUD de assets).
- Nenhum endpoint retorna credencial, nem mascarada.
- Nenhum endpoint de conexão para protocolos que não sejam VNC/RFB.
