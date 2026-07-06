# Requisitos de segurança

## 1. Hard requirements (inegociáveis)

Cada requisito tem ID rastreável. PRs que toquem nesses pontos devem referenciar
o ID e incluir teste automatizado correspondente em `tests/security/`.

| ID | Requisito | Como é garantido |
|----|-----------|------------------|
| HR-01 | Usuário nunca informa IP/hostname/porta | Frontend não tem campo; API rejeita payload com esses campos (validação estrita, `additionalProperties: false`) |
| HR-02 | Start de sessão recebe apenas `assetId` | Schema Zod do endpoint; teste de contrato falha se `host`/`port` forem aceitos |
| HR-03 | IP e porta vêm do banco | Gateway só resolve destino via `session → asset`; não existe código que leia destino do cliente |
| HR-04 | Somente portas em allowlist | FK `assets.port → allowed_ports.port` no banco + validação na API + re-checagem no gateway antes do connect |
| HR-05 | Senha VNC nunca chega ao navegador | Terminação RFB no gateway: lado browser negocia `None`; lado asset autentica com credencial do cofre |
| HR-06 | Senha VNC nunca em log | `pino.redact` estrutural; credencial nunca entra em objeto de log; teste de segurança varre logs por segredos semeados |
| HR-07 | Usuário sem rota direta ao asset | Rede `assets_net` isolada — só o gateway participa; em produção, regra de firewall equivalente |
| HR-08 | Gateway não é proxy genérico | Destino só via sessão válida + allowlist + validação de banner `RFB` + uso único do token |
| HR-09 | Nenhum suporte a outros protocolos | Sem bibliotecas RDP/SSH/etc. no lockfile (verificado em CI); sem telas nem endpoints |
| HR-10 | Auditoria completa por sessão | Eventos `session.created/started/ended` com usuário, asset, IP de origem, timestamps e status |

## 2. Protocolos e portas

### Proibido implementar

```text
RDP · SSH · Telnet · SQL · SFTP · VPN · shell remoto · HTTP proxy genérico
acesso por IP/porta digitado pelo usuário
```

### Allowlist de portas (dados, não código)

Tabela `allowed_ports` no banco. Seed inicial: `5900`, `5901`, `5902`.
Portas VNC customizadas são cadastradas por admin **via API**, que aplica um
**denylist imutável em código** — estas portas jamais podem entrar na allowlist:

```text
22, 23, 25, 53, 80, 88, 135, 139, 389, 443, 445, 465, 587, 636,
1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 9200, 27017
```

Regra adicional: porta customizada deve estar em `1024–65535` e fora do denylist.
Toda alteração da allowlist gera auditoria (`allowlist.changed`).

## 3. Autenticação e tokens

| Item | Especificação |
|---|---|
| Login do portal | usuário + senha (Argon2id); cookie de sessão `HttpOnly`, `Secure`, `SameSite=Strict`; CSRF token nas mutações |
| Rate limit | login: 5 tentativas/min/IP + lockout progressivo; criação de sessão: 10/min/usuário |
| Token efêmero | 256 bits CSPRNG, opaco; **hash** no banco; TTL 30s; uso único atômico; vinculado a `session+user+asset` |
| Transporte do token | via subprotocolo WebSocket (`Sec-WebSocket-Protocol`); ver `api-contract.md` §4 — nunca em query string, para não vazar em access log |
| Expiração de sessão de login | 8h absoluta / 30min inatividade (configurável) |

## 4. Cofre de credenciais

- Senha VNC é **write-only** na API de admin: aceita no cadastro/rotação, nunca
  retornada em nenhuma resposta (nem mascarada).
- Armazenamento alvo (Fase 3): HashiCorp Vault KV v2; gateway autentica via
  AppRole com policy de leitura restrita a `vnc/assets/*`.
- Interino (Fases 1–2, só laboratório): AES-256-GCM com master key em variável de
  ambiente — nunca em banco, nunca em log, nunca em commit.
- Toda leitura de segredo gera auditoria `credential.read` com sessão associada.
- Limitação conhecida do protocolo: `VNC Authentication` usa DES com senha
  truncada em 8 caracteres — documentar aos operadores dos assets.

## 5. Logging seguro

- Logger estruturado (pino) com `redact` para os paths `*.password`,
  `*.vncPassword`, `*.secret`, `*.token`, `*.authorization`, `*.cookie`.
- O token efêmero aparece em log apenas como `token_hash` (prefixo de 8 chars).
- Nginx: access log do endpoint do gateway não registra headers de upgrade.
- Teste automatizado (Fase 3): sobe stack com senha-sentinela, executa fluxo
  completo, faz grep da sentinela em **todos** os logs e no tráfego do browser
  (HAR) — qualquer ocorrência falha o build.

## 6. TLS / WSS

- TLS 1.2+ terminado no Nginx; HSTS; certificados via ACME em produção,
  autoassinado no lab.
- WebSocket sempre WSS em qualquer ambiente não-local.
- Headers: `Content-Security-Policy` (sem inline script), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`.
- Trecho gateway → asset: RFB é cleartext por natureza; requisito compensatório é
  segmentação de rede (`assets_net`). Suporte a VeNCrypt/TLS fica no backlog.

## 7. Threat model básico (STRIDE resumido)

| Ameaça | Cenário | Controle |
|---|---|---|
| Spoofing | Reuso/roubo de token efêmero | uso único, TTL 30s, hash no banco, vínculo com sessão/usuário, WSS |
| Tampering | Payload de sessão com `host`/`port` injetado | validação estrita + destino sempre do banco (HR-02/03) |
| Repudiation | Usuário nega acesso realizado | auditoria imutável com IP de origem e timestamps (HR-10) |
| Information disclosure | Senha VNC em browser/log/tráfego | terminação RFB no gateway + redact + teste sentinela (HR-05/06) |
| Denial of service | Flood de criação de sessão / conexões WS | rate limit, limite de sessões simultâneas por usuário, timeouts |
| Elevation of privilege | Gateway usado como proxy para outros serviços internos | allowlist + denylist + banner RFB + rede segregada (HR-08); usuário comum não cadastra asset |
| SSRF via cadastro de asset | Admin malicioso aponta asset para serviço interno não-VNC | cadastro é privilégio de admin + banner RFB no connect + auditoria de cadastro |
| Exfiltração via clipboard VNC | Cópia de dados do asset via `ClientCutText`/`ServerCutText` | flag por asset para desabilitar clipboard no gateway (Fase 3+) |

## 8. Checklist de revisão (usar em toda entrega)

```text
1.  O usuário consegue informar IP ou porta manualmente?            → deve ser NÃO
2.  Existe alguma biblioteca de RDP/SSH no projeto?                 → deve ser NÃO
3.  O gateway consegue acessar host fora dos assets cadastrados?    → deve ser NÃO
4.  A senha VNC aparece no frontend, log ou tráfego do navegador?   → deve ser NÃO
5.  O token da sessão expira?                                       → deve ser SIM
6.  O token é de uso único?                                         → deve ser SIM
7.  Asset não autorizado retorna 403?                               → deve ser SIM
8.  Porta não permitida é bloqueada (API, banco e gateway)?         → deve ser SIM
9.  Fechar o navegador encerra o socket TCP com o asset?            → deve ser SIM
10. Cada sessão (inclusive falhas) gera log de auditoria?           → deve ser SIM
```

Qualquer resposta errada = entrega recusada, mesmo que "funcione".
