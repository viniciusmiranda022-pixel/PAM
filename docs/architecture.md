# Arquitetura — VNC Privileged Access Gateway

## 1. Visão geral

O sistema é um **gateway de acesso privilegiado exclusivo para VNC**. Toda a
superfície exposta ao usuário é HTTPS/WSS na porta 443. O único componente com
rota de rede até os assets é o **gateway**, e ele só abre conexões TCP para
`(ip, porta)` de assets cadastrados, com porta em allowlist e sessão válida.

```text
                          ZONA DO USUÁRIO
┌─────────────────────────────────────────────────────────────┐
│  Navegador (HTTPS 443)                                      │
│  ├── Portal web (login, lista de assets)                    │
│  └── noVNC (cliente VNC em JS, fala RFB sobre WebSocket)    │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTPS / WSS (443)
                          ZONA DE APLICAÇÃO (rede app_net)
┌────────────────────────────▼────────────────────────────────┐
│  Reverse Proxy (Nginx)                                      │
│  ├── /            → Frontend (estático)                     │
│  ├── /api/*       → Backend API                             │
│  └── /gateway/*   → VNC Gateway (upgrade WebSocket)         │
├─────────────────────────────────────────────────────────────┤
│  Backend API + Session Broker                               │
│  • autenticação, autorização, assets, permissões            │
│  • criação/validação/encerramento de sessão                 │
│  • emissão de token efêmero (uso único, TTL curto)          │
│  • auditoria                                                │
├──────────────┬─────────────────────────┬────────────────────┤
│  PostgreSQL  │  Cofre de credenciais   │  VNC Gateway       │
│  (estado +   │  (senha VNC dos assets, │  (WS → TCP,        │
│   auditoria) │   nunca vai ao browser) │   terminação RFB)  │
└──────────────┴─────────────────────────┴─────────┬──────────┘
                                                   │ TCP 5900/5901/…
                          ZONA DE ASSETS (rede assets_net — isolada)
┌──────────────────────────────────────────────────▼──────────┐
│  Assets com VNC Server (somente o gateway tem rota até aqui)│
└─────────────────────────────────────────────────────────────┘
```

## 2. Componentes e responsabilidades

| Componente | Responsabilidade | Diretório |
|---|---|---|
| **Frontend Web** | Login, lista de assets autorizados, tela da sessão com noVNC | `frontend/` |
| **noVNC** | Cliente VNC no navegador (RFB sobre WebSocket) | dependência do frontend |
| **Backend API** | Usuários, grupos, permissões, assets, sessões, auditoria | `backend/` |
| **Session Broker** | Módulo do backend: cria/valida/encerra sessão, emite token efêmero | `backend/` |
| **VNC Gateway** | Ponte WebSocket ↔ TCP; terminação do handshake RFB; injeção de credencial | `gateway/` |
| **PostgreSQL** | Assets, usuários, permissões, sessões, allowlist, logs de auditoria | `infra/postgres/` |
| **Cofre (Vault)** | Senha VNC dos assets — write-only pela API, lida só pelo gateway/broker | `infra/vault/` |
| **Reverse Proxy** | TLS, WSS, headers de segurança, rate limit de borda | `infra/nginx/` |

Backend e gateway são **processos separados** desde o início. O gateway é o
componente mais sensível e deve ter superfície mínima: sem framework HTTP além do
upgrade de WebSocket, sem dependência de bibliotecas de outros protocolos (HR-09).

## 3. Zonas de rede

| Rede | Quem participa | Regra |
|---|---|---|
| pública (443) | usuário → nginx | única porta exposta |
| `app_net` | nginx, frontend, backend, gateway, postgres, vault | tráfego interno da aplicação |
| `assets_net` | **somente gateway** e assets VNC | usuário e backend não têm rota (HR-07) |

Em produção, `assets_net` corresponde à VLAN/segmento onde vivem os assets; a
regra permanece: firewall permite `gateway → assets:portas da allowlist` e nada
mais. O Docker Compose local já modela essa separação com duas redes.

## 4. Decisão de arquitetura: terminação do handshake RFB no gateway

**Problema:** se o gateway fosse um túnel byte-a-byte puro (estilo websockify), o
noVNC no navegador faria o handshake de segurança RFB — e precisaria da senha do
asset, violando HR-05.

**Decisão:** o gateway **termina o handshake RFB dos dois lados** e depois faz
splice dos streams:

- **Lado navegador:** o gateway negocia RFB com security type `None`. A
  autenticação do usuário já aconteceu na camada acima (login + token efêmero
  validado no upgrade do WebSocket). Nenhuma senha trafega até o browser.
- **Lado asset:** o gateway executa a autenticação `VNC Authentication`
  (challenge-response DES) usando a senha obtida do cofre.
- Após o `ServerInit`, o gateway vira um pipe binário transparente entre os dois
  lados.

Escopo inicial de protocolo: **RFB 3.8** com security types `None` e
`VNC Authentication (2)`. Outros tipos (Tight, VeNCrypt, RA2…) ficam fora do MVP
e documentados como limitação (ver riscos).

**Validação de banner:** ao abrir o TCP com o asset, o gateway exige que os 12
primeiros bytes sejam `RFB xxx.yyy\n`. Se o destino não fala RFB, a conexão é
encerrada e auditada. Isso impede que o gateway seja usado para alcançar serviços
não-VNC mesmo em porta permitida (defesa extra para HR-08).

## 5. Token efêmero de sessão

| Propriedade | Especificação |
|---|---|
| Formato | opaco, 256 bits aleatórios (CSPRNG), base64url |
| Armazenamento | somente o **hash SHA-256** no banco (coluna `token_hash`) |
| TTL | 30 segundos entre emissão e uso no gateway |
| Uso | **único** — consumido atomicamente no upgrade do WebSocket |
| Vínculo | `session_id` + `user_id` + `asset_id`; qualquer divergência rejeita |
| Revogação | encerrar a sessão invalida o token imediatamente |

O token **não é JWT**: sendo opaco e validado contra o banco, é revogável e o
uso único é garantido por transação (`UPDATE ... WHERE token_used_at IS NULL`).

## 6. Stack tecnológica sugerida

| Camada | Tecnologia | Justificativa |
|---|---|---|
| Linguagem | **TypeScript / Node.js 22 LTS** em todo o projeto | um só toolchain; WebSocket↔TCP é caso natural do Node (streams) |
| Backend API | **Fastify** + **Zod** | leve, schema-first, validação estrita de entrada (rejeita campos extras como `host`/`port`) |
| ORM/Migrations | **Drizzle ORM** + SQL puro para constraints | schema versionado; invariantes críticas ficam em DDL |
| Gateway | **Node + `ws`** apenas; módulo RFB próprio | superfície mínima; handshake RFB 3.8 é um state machine pequeno |
| Frontend | **React + Vite + `@novnc/novnc`** | noVNC é o cliente VNC web de referência |
| Banco | **PostgreSQL 16** | constraints declarativas (allowlist via FK), JSONB para auditoria |
| Cofre | **HashiCorp Vault** (KV v2 + AppRole) na Fase 3; interino: AES-256-GCM com master key fora do banco | caminho incremental sem expor senha em nenhuma fase |
| Reverse proxy | **Nginx** | TLS/WSS, headers, rate limit |
| Senhas de usuário | **Argon2id** | estado da arte para hash de senha |
| Logs | **pino** com `redact` configurado | redação estrutural de segredos (HR-06) — não depende de disciplina do dev |
| Métricas | **prom-client** (formato Prometheus) | Fase 4 |
| Testes | **Vitest** (unit/integration), **Playwright** (e2e) | inclui suíte de testes de segurança automatizada |

Alternativa avaliada: gateway em **Go** (excelente para proxies TCP). Descartada
no início para manter um único toolchain; a separação em processo/diretório
próprio permite reescrever o gateway em Go depois sem tocar no resto.

## 7. O que é proibido implementar (escopo travado)

```text
RDP · SSH · Telnet · SQL · SFTP · VPN · shell remoto · HTTP proxy genérico
qualquer campo de host/porta digitado pelo usuário
qualquer biblioteca cliente de outros protocolos no lockfile
```

CI da Fase 1+ inclui verificação automática: falha se o lockfile contiver
bibliotecas de RDP/SSH/etc. ou se a API aceitar `host`/`port` no start de sessão
(teste de contrato).

## 8. Escalabilidade (nota para depois do MVP)

- Backend é stateless (sessão de login em cookie + estado no Postgres) — escala horizontal trivial.
- Gateway mantém conexões longas; com múltiplas instâncias, o token efêmero é
  validado contra o banco, então **qualquer** instância atende qualquer sessão —
  não há necessidade de sticky session.
- Shutdown do gateway deve drenar: fecha WebSockets com código próprio, marca
  sessões como `terminated` com `end_reason=gateway_shutdown`.
