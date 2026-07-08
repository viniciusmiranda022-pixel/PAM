# Requisitos de segurança

## 1. Hard requirements (inegociáveis)

Cada requisito tem ID rastreável. PRs que toquem nesses pontos devem referenciar
o ID e incluir teste automatizado correspondente em `tests/security/`.

Estes requisitos são **independentes de protocolo**: valem para o adapter VNC
(implementado) e para qualquer adapter futuro (RDP, SSH…). O pivot de VNC-only
para multiprotocolo (ver [`adr/0001-pivot-multiprotocolo.md`](adr/0001-pivot-multiprotocolo.md))
**não afrouxa** nenhuma garantia: a superfície só cresce sob adapters validados.

| ID | Requisito | Como é garantido |
|----|-----------|------------------|
| HR-01 | Usuário nunca informa destino técnico (IP/hostname/porta/URL/socket/comando) | Frontend não tem campo; API rejeita payload com esses campos (validação estrita, `additionalProperties: false`) |
| HR-02 | Start de sessão recebe apenas `assetId` (+ metadados de governança) | Schema Zod do endpoint; teste de contrato falha se `host`/`port`/`protocol` forem aceitos do cliente |
| HR-03 | Protocolo, IP, porta, credencial e política vêm do backend | Gateway só resolve destino via `session → asset`; não existe código que leia destino do cliente |
| HR-04 | Somente portas em allowlist **por protocolo** | Allowlist e denylist específicas do protocolo no banco + validação na API + re-checagem no gateway antes do connect |
| HR-05 | Credencial do asset nunca chega ao navegador | Terminação de handshake no adapter: o lado do browser nunca recebe a credencial; a autenticação com o asset acontece no gateway |
| HR-06 | Nenhum segredo em log | `pino.redact` estrutural; credencial nunca entra em objeto de log; teste de segurança varre logs por segredos semeados |
| HR-07 | Usuário sem rota direta ao asset | Rede `assets_net` isolada — só o gateway participa; em produção, regra de firewall equivalente |
| HR-08 | Gateway não aceita destino arbitrário | Destino só via sessão válida + allowlist do protocolo + validação de handshake do protocolo + uso único do token |
| HR-09 | Cada protocolo entra por **adapter explícito** | Nunca proxy TCP genérico; cada adapter tem terminação de handshake própria, validação, testes e auditoria (verificado em CI) |
| HR-10 | Auditoria completa por sessão | Eventos `session.created/started/ended` com usuário, asset, **protocolo**, IP de origem, timestamps, status e motivo de encerramento |

## 2. Protocolos e portas

### Modelo de adapters

Cada protocolo suportado é um **adapter explícito** dentro da camada de gateway.
Um adapter só é aceito quando entrega: threat model próprio, terminação de
handshake (o gateway fala o protocolo dos dois lados — nunca um túnel byte-a-byte
que exija a credencial no navegador), validação de que o destino realmente fala
o protocolo esperado, gravação/auditoria e testes específicos.

```text
Proibido em qualquer caso: proxy TCP genérico, encaminhamento de porta arbitrária,
destino (IP/porta/host) informado pelo usuário, credencial trafegando ao navegador.
```

| Protocolo | Adapter | Situação |
|-----------|---------|----------|
| VNC (RFB 3.8) | terminação RFB `None` (browser) / `VNC Authentication` (asset); VeNCrypt opcional | implementado |
| RDP | — | planejado (adapter futuro; engine em aberto — ver ADR) |
| SSH | — | planejado (adapter futuro) |

### Allowlist de portas por protocolo (dados, não código)

Cada protocolo tem sua própria allowlist de portas no banco. Seed inicial do
adapter VNC: `5900`, `5901`, `5902`. Portas customizadas são cadastradas por admin
**via API**, que aplica um **denylist imutável em código** — estas portas jamais
podem entrar em nenhuma allowlist de acesso a asset:

```text
22, 23, 25, 53, 80, 88, 135, 139, 389, 443, 445, 465, 587, 636,
1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 9200, 27017
```

Regra adicional: porta customizada deve estar em `1024–65535` e fora do denylist.
Cada novo adapter define a allowlist padrão do seu protocolo (ex.: SSH `22`, RDP
`3389`) **apenas dentro do escopo daquele adapter** — a liberação de uma porta é
sempre acoplada a um adapter que sabe falar aquele protocolo, nunca a um proxy
cru. Toda alteração da allowlist gera auditoria (`allowlist.changed`).

## 3. Autenticação e tokens

| Item | Especificação |
|---|---|
| Login do portal | usuário + senha (KDF forte; ver nota de KDF abaixo); cookie de sessão `HttpOnly`, `Secure`, `SameSite=Strict`; CSRF token nas mutações. MFA (TOTP) e SSO/OIDC disponíveis. |
| Rate limit | login: 5 tentativas/min/IP + lockout progressivo; criação de sessão: 10/min/usuário |
| Token efêmero | 256 bits CSPRNG, opaco; **hash** no banco; TTL 30s; uso único atômico; vinculado a `session+user+asset` |
| Transporte do token | via subprotocolo WebSocket (`Sec-WebSocket-Protocol`); ver `api-contract.md` §4 — nunca em query string, para não vazar em access log |
| Expiração de sessão de login | 8h absoluta / 30min inatividade (configurável) |

> **Nota de KDF:** o hash de senha local usa **scrypt** (`node:crypto`, N=2^17,
> r=8, p=1 ≈ 128 MiB), com formato auto-descritivo e **rehash transparente** no
> login quando os parâmetros são elevados. Decisão registrada em
> [`adr/0002-kdf-scrypt.md`](adr/0002-kdf-scrypt.md) (Argon2id avaliado e
> rejeitado por exigir dependência nativa). Hash rápido (MD5/SHA sem stretching)
> **nunca** é aceitável.

## 4. Cofre de credenciais

- Credencial do asset é **write-only** na API de admin: aceita no cadastro/rotação,
  nunca retornada em nenhuma resposta (nem mascarada).
- Armazenamento alvo: HashiCorp Vault KV v2; o gateway autentica via AppRole com
  policy de leitura restrita ao caminho do protocolo/asset.
- Interino (laboratório): AES-256-GCM com master key em variável de ambiente —
  nunca em banco, nunca em log, nunca em commit.
- Toda leitura de segredo gera auditoria `credential.read` com sessão associada.
- Limitação conhecida do adapter VNC: `VNC Authentication` usa DES com senha
  truncada em 8 caracteres — documentar aos operadores dos assets. Cada adapter
  documenta as limitações de credencial do seu protocolo.

## 5. Logging seguro

- Logger estruturado (pino) com `redact` para os paths `*.password`,
  `*.vncPassword`, `*.secret`, `*.token`, `*.authorization`, `*.cookie`,
  `*.privateKey`.
- O token efêmero aparece em log apenas como `token_hash` (prefixo de 8 chars).
- Nginx: access log do endpoint do gateway não registra headers de upgrade.
- Teste automatizado: sobe stack com segredo-sentinela, executa fluxo completo,
  faz grep da sentinela em **todos** os logs e no tráfego do browser (HAR) —
  qualquer ocorrência falha o build.

## 6. TLS / WSS

- TLS 1.2+ terminado no Nginx; HSTS; certificados via ACME em produção,
  autoassinado no lab.
- WebSocket sempre WSS em qualquer ambiente não-local.
- Headers: `Content-Security-Policy` (sem inline script), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`.
- **Trecho gateway → asset:** cifrado quando o protocolo/asset permite. Para o
  adapter VNC, o RFB puro é cleartext, então o controle compensatório é a
  segmentação de rede (`assets_net`) **e** o suporte a **VeNCrypt (TLS
  gateway→asset)** já entregue (flag `tls_required` por asset — ver
  [`phase5-vencrypt.md`](phase5-vencrypt.md)). Cada adapter futuro define como
  cifra (ou não) o trecho até o asset e documenta o controle compensatório.

## 7. Threat model básico (STRIDE resumido)

| Ameaça | Cenário | Controle |
|---|---|---|
| Spoofing | Reuso/roubo de token efêmero | uso único, TTL 30s, hash no banco, vínculo com sessão/usuário, WSS |
| Tampering | Payload de sessão com `host`/`port`/`protocol` injetado | validação estrita + destino sempre do banco (HR-02/03) |
| Repudiation | Usuário nega acesso realizado | auditoria imutável com IP de origem, protocolo e timestamps (HR-10) |
| Information disclosure | Credencial em browser/log/tráfego | terminação de handshake no adapter + redact + teste sentinela (HR-05/06) |
| Denial of service | Flood de criação de sessão / conexões WS | rate limit, limite de sessões simultâneas por usuário, timeouts |
| Elevation of privilege | Gateway usado como proxy para outros serviços internos | allowlist por protocolo + denylist + validação de handshake do protocolo + rede segregada (HR-08/HR-09); usuário comum não cadastra asset |
| SSRF via cadastro de asset | Admin malicioso aponta asset para serviço interno que não fala o protocolo | cadastro é privilégio de admin + validação de handshake do protocolo no connect + auditoria de cadastro |
| Exfiltração via clipboard | Cópia de dados do asset via canal de clipboard do protocolo | flag por asset para desabilitar clipboard no adapter |
| Adapter mal-implementado vira túnel cru | Novo adapter encaminha bytes sem terminar o handshake, exigindo credencial no browser | Definition of Done de adapter exige terminação de handshake + revisão de segurança + teste que prova que nenhuma credencial trafega ao browser (HR-05/HR-09) |

## 8. Checklist de revisão (usar em toda entrega)

```text
1.  O usuário consegue informar IP, porta, host, URL ou comando?    → deve ser NÃO
2.  Algum protocolo é atendido por proxy TCP genérico (sem adapter)? → deve ser NÃO
3.  O gateway consegue acessar host fora dos assets cadastrados?    → deve ser NÃO
4.  A credencial do asset aparece no frontend, log ou tráfego?       → deve ser NÃO
5.  O token da sessão expira?                                       → deve ser SIM
6.  O token é de uso único?                                         → deve ser SIM
7.  Asset não autorizado retorna 403?                               → deve ser SIM
8.  Porta fora da allowlist do protocolo é bloqueada (API/banco/gw)? → deve ser SIM
9.  Fechar o navegador encerra a conexão com o asset?               → deve ser SIM
10. Cada sessão (inclusive falhas) gera log de auditoria c/ protocolo? → deve ser SIM
11. (Novo adapter) Ele termina o handshake do protocolo dos dois lados? → deve ser SIM
```

Qualquer resposta errada = entrega recusada, mesmo que "funcione".
