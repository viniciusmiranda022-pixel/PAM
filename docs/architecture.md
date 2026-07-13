# Arquitetura — PAM Access Gateway

## 1. Visão geral

O sistema é um **gateway de acesso privilegiado multiprotocolo**. Toda a superfície
exposta ao usuário é HTTPS/WSS na porta 443. O único componente com rota de rede
até os assets é o **gateway**, e ele só abre conexões para `(protocolo, ip, porta)`
de assets cadastrados, com porta em allowlist do protocolo e sessão válida.

O acesso a cada protocolo é feito por um **adapter explícito** (Protocol Adapter).
O **VNC (RFB) é o adapter de referência, já implementado**. Novos protocolos
(RDP, SSH…) entram como novos adapters, um por vez — nunca como proxy genérico.

```text
                          ZONA DO USUÁRIO
┌─────────────────────────────────────────────────────────────┐
│  Navegador (HTTPS 443)                                      │
│  ├── Portal web (login, lista de assets)                    │
│  └── Cliente de sessão (ex.: noVNC p/ o adapter VNC)        │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTPS / WSS (443)
                          ZONA DE APLICAÇÃO (rede app_net)
┌────────────────────────────▼────────────────────────────────┐
│  Reverse Proxy (Nginx)                                      │
│  ├── /            → Frontend (estático)                     │
│  ├── /api/*       → Backend API                             │
│  └── /gateway/*   → Gateway (upgrade WebSocket)             │
├─────────────────────────────────────────────────────────────┤
│  Backend API + Session Broker                               │
│  • autenticação, autorização, assets, permissões            │
│  • resolve protocolo + destino + credencial + política      │
│  • criação/validação/encerramento de sessão                 │
│  • emissão de token efêmero (uso único, TTL curto)          │
│  • auditoria                                                │
├──────────────┬─────────────────────────┬────────────────────┤
│  PostgreSQL  │  Cofre de credenciais   │  Protocol Gateway  │
│  (estado +   │  (credencial dos assets,│  Layer             │
│   auditoria) │   nunca vai ao browser) │  ├─ adapter VNC ✅  │
│              │                         │  ├─ adapter RDP 🔜  │
│              │                         │  └─ adapter SSH 🔜  │
└──────────────┴─────────────────────────┴─────────┬──────────┘
                                                   │ TCP (porta do protocolo)
                          ZONA DE ASSETS (rede assets_net — isolada)
┌──────────────────────────────────────────────────▼──────────┐
│  Assets (somente o gateway tem rota até aqui)               │
└─────────────────────────────────────────────────────────────┘
```

## 2. Componentes e responsabilidades

| Componente | Responsabilidade | Diretório |
|---|---|---|
| **Frontend Web** | Login, lista de assets autorizados, tela da sessão com o cliente do protocolo | `frontend/` |
| **Cliente de sessão** | Cliente do protocolo no navegador (ex.: noVNC/RFB sobre WebSocket para o adapter VNC) | dependência do frontend |
| **Backend API** | Usuários, grupos, permissões, assets, sessões, auditoria | `backend/` |
| **Session Broker** | Módulo do backend: resolve protocolo/destino/credencial, cria/valida/encerra sessão, emite token efêmero | `backend/` |
| **Protocol Gateway Layer** | Camada comum do gateway: upgrade WebSocket, consumo de token, resolução de destino/credencial, ciclo de vida, splice, gravação, watchdog, auditoria e **seleção do adapter** pelo `protocol` do asset | `gateway/src/session.ts` |
| **Adapter Registry** | `Map<protocol, adapter>`; resolve o adapter e **recusa** protocolo sem adapter (HR-09) | `gateway/src/adapters/index.ts` |
| **Protocol Adapter** | Fala **um** protocolo dos dois lados (terminação de handshake), injeta credencial no lado do asset. Contrato em `adapters/types.ts` | `gateway/src/adapters/vnc/` (VNC; futuros: `adapters/{rdp,ssh}/`) |
| **PostgreSQL** | Assets, usuários, permissões, sessões, allowlist, logs de auditoria | `infra/postgres/` |
| **Cofre (Vault)** | Credencial dos assets — write-only pela API, lida só pelo gateway/broker | `infra/vault/` |
| **Reverse Proxy** | TLS, WSS, headers de segurança, rate limit de borda | `infra/nginx/` |

Backend e gateway são **processos separados** desde o início. O gateway é o
componente mais sensível e deve ter superfície mínima: sem framework HTTP além do
upgrade de WebSocket, e cada adapter carrega apenas o necessário para falar o seu
protocolo (HR-09).

## 3. Zonas de rede

| Rede | Quem participa | Regra |
|---|---|---|
| pública (443) | usuário → nginx | única porta exposta |
| `app_net` | nginx, frontend, backend, gateway, postgres, vault | tráfego interno da aplicação |
| `assets_net` | **somente gateway** e assets | usuário e backend não têm rota (HR-07) |

Em produção, `assets_net` corresponde à VLAN/segmento onde vivem os assets; a
regra permanece: firewall permite `gateway → assets:portas da allowlist do
protocolo` e nada mais. O Docker Compose local já modela essa separação com duas
redes.

## 4. Decisão de arquitetura: terminação de handshake no adapter

**Problema:** se o gateway fosse um túnel byte-a-byte puro (estilo websockify), o
cliente no navegador faria o handshake de segurança do protocolo — e precisaria da
credencial do asset, violando HR-05.

**Decisão (regra de todo adapter):** o adapter **termina o handshake do protocolo
dos dois lados** e só depois faz splice dos streams. Isso vale para todo protocolo;
o adapter VNC é a materialização de referência:

- **Lado navegador:** o adapter VNC negocia RFB com security type `None`. A
  autenticação do usuário já aconteceu na camada acima (login + token efêmero
  validado no upgrade do WebSocket). Nenhuma credencial trafega até o browser.
- **Lado asset:** o adapter VNC executa a autenticação `VNC Authentication`
  (challenge-response DES) usando a credencial obtida do cofre. Quando o asset
  exige, o trecho é cifrado com VeNCrypt (TLS) antes da autenticação.
- Após o `ServerInit`, o adapter vira um pipe binário transparente entre os lados.

Escopo do adapter VNC: **RFB 3.8** com security types `None`, `VNC Authentication
(2)` e VeNCrypt (subtypes X509). Outros security types RFB (Tight, RA2…) ficam
fora do escopo e são documentados como limitação (ver riscos).

**Validação de handshake:** ao abrir o TCP com o asset, o adapter exige que o
destino realmente fale o protocolo esperado (o adapter VNC exige que os 12
primeiros bytes sejam `RFB xxx.yyy\n`). Se o destino não fala o protocolo, a
conexão é encerrada e auditada. Isso impede que o gateway seja usado para alcançar
serviços diferentes mesmo em porta permitida (defesa extra para HR-08). **Cada
novo adapter deve implementar a validação equivalente para o seu protocolo.**

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

## 6. Stack tecnológica

| Camada | Tecnologia | Justificativa |
|---|---|---|
| Linguagem | **TypeScript / Node.js 22 LTS** em todo o projeto | um só toolchain; WebSocket↔TCP é caso natural do Node (streams) |
| Backend API | **Fastify** + **Zod** | leve, schema-first, validação estrita de entrada (rejeita campos extras como `host`/`port`) |
| Persistência | **PostgreSQL 16** + SQL puro para constraints | schema versionado por migrações; invariantes críticas ficam em DDL |
| Gateway | **Node + `ws`**; adapter de protocolo próprio por protocolo | superfície mínima; o handshake é uma state machine pequena por protocolo |
| Frontend | estático + cliente do protocolo (**`@novnc/novnc`** para o adapter VNC) | noVNC é o cliente VNC web de referência |
| Cofre | **HashiCorp Vault** (KV v2 + AppRole); interino: AES-256-GCM com master key fora do banco | caminho incremental sem expor credencial em nenhuma fase |
| Reverse proxy | **Nginx** | TLS/WSS, headers, rate limit |
| Senhas de usuário | KDF forte (**Argon2id** ou **scrypt** — decisão em ADR no PR-13) | estado da arte para hash de senha |
| Logs | **pino** com `redact` configurado | redação estrutural de segredos (HR-06) — não depende de disciplina do dev |
| Métricas | **prom-client** (formato Prometheus) | operação |
| Testes | **Vitest** (unit/integration), **Playwright** (e2e) | inclui suíte de testes de segurança automatizada |

Alternativa avaliada: gateway/adapters em **Go** (excelente para proxies TCP e para
falar protocolos binários). Mantido em Node no início para um único toolchain; a
separação em processo e por adapter permite reescrever um adapter específico em
outra linguagem depois sem tocar no resto. A **engine de cada novo protocolo**
(implementação própria vs. reuso de um engine externo como `guacd`) é decidida por
adapter, com PoC — ver [`adr/0001-pivot-multiprotocolo.md`](adr/0001-pivot-multiprotocolo.md).

## 7. Regras de escopo (o que continua proibido)

```text
proxy TCP genérico ou encaminhamento de porta arbitrária
qualquer campo de host/porta/URL/comando digitado pelo usuário
qualquer protocolo atendido sem adapter que termine o handshake
credencial do asset trafegando até o navegador
```

Novos protocolos são **bem-vindos**, mas exclusivamente por **adapter explícito**
(HR-09), com threat model, terminação de handshake, validação, gravação, auditoria
e testes próprios. A CI verifica automaticamente: falha se a API aceitar
`host`/`port`/`protocol` no start de sessão (teste de contrato) ou se um caminho de
dados encaminhar bytes a um destino sem passar por um adapter registrado.

## 8. Escalabilidade (nota para depois do MVP)

- Backend é stateless (sessão de login em cookie + estado no Postgres) — escala horizontal trivial.
- Gateway mantém conexões longas; com múltiplas instâncias, o token efêmero é
  validado contra o banco, então **qualquer** instância atende qualquer sessão —
  não há necessidade de sticky session.
- Shutdown do gateway deve drenar: fecha WebSockets com código próprio, marca
  sessões como `terminated` com `end_reason=gateway_shutdown`.
