# Plano de entrega por fases

Regra de aceite global: a pergunta nunca é "funcionou?", é **"funcionou sem
violar a arquitetura?"** — usar o checklist de
[`security-requirements.md`](security-requirements.md) §8 em toda revisão.

> **Contexto do pivot:** as Fases 0–5.5 abaixo entregaram o **adapter VNC** e a
> **plataforma comum** (auth, sessão, token, cofre, auditoria, operação). O produto
> passou a ser multiprotocolo por adapter (ver
> [`adr/0001-pivot-multiprotocolo.md`](adr/0001-pivot-multiprotocolo.md)); a
> continuação está no **Roadmap multiprotocolo (PR-12+)** ao fim deste documento.
> Onde se lê "VNC-only" nas fases históricas, entenda "o adapter VNC".

## Fase 0 — Desenho técnico ✅ (este pacote)

Entregáveis: arquitetura, contrato de API, modelo de banco, requisitos de
segurança, fluxo de sessão, riscos, dependências, Docker Compose inicial.

- [x] Arquitetura documentada
- [x] Escopo VNC-only documentado
- [x] Protocolos proibidos documentados
- [x] Fluxo de sessão descrito (pendente de aprovação)
- [x] Modelo de dados descrito (pendente de aprovação)
- [x] Docker Compose inicial com redes segregadas

## Fase 1 — PoC técnica ✅ (ver [`phase1-poc.md`](phase1-poc.md))

**Objetivo:** provar o fluxo seguro de ponta a ponta com o mínimo de telas:
`portal → sessão → token → gateway WS → TCP VNC → asset de laboratório`.

Entregáveis:
- Gateway: upgrade WS, consumo atômico de token, TCP connect, validação de banner
  RFB, terminação RFB (`None` lado browser, `VNCAuth` lado asset via provider de
  credencial `env:*` — cofre real vem na Fase 3).
- Frontend mínimo: página com noVNC que recebe `gatewayUrl+token`.
- Backend mínimo: criação de sessão consultando asset seedado no banco.
- Asset VNC de laboratório no Compose (rede isolada, IP fixo).

Critérios de aceite:
- [x] Usuário abre a tela VNC no navegador (fluxo noVNC ↔ gateway provado no E2E)
- [x] Gateway conecta no asset pela porta buscada do banco (HR-03)
- [x] Usuário não acessa o asset diretamente (rede isolada comprovada)
- [x] Senha do asset não trafega ao navegador (handshake `None`; confirmado no E2E)
- [x] Não existe suporte/biblioteca de RDP/SSH no lockfile

> Verificado com Postgres real + servidor RFB simulado (unit 16+6, integração 21,
> E2E 14 — todos verdes). O ensaio com noVNC+TigerVNC reais requer um host com
> `docker pull` liberado; passo a passo em [`deployment.md`](deployment.md).

## Fase 2 — MVP funcional ✅ (ver [`phase2-mvp.md`](phase2-mvp.md))

Entregáveis: login + cookie (Fase 1), CRUD de usuários, CRUD de assets VNC,
grupos e permissões, cofre de credenciais interino (AES-GCM), criação/encerramento
de sessão, logs, UI administrativa.

Critérios de aceite:
- [x] Usuário vê somente assets autorizados (direto e via grupo)
- [x] Asset inativo não aparece
- [x] Usuário inicia e encerra sessão VNC (admin também encerra)
- [x] Usuário não vê senha em nenhum ponto (write-only + cofre cifrado)
- [x] Sessão é registrada em log com usuário, asset, IP, início, fim, status
- [x] Admin consegue listar sessões (e auditoria)

> Verificado com Postgres real (backend unit 12, gateway unit 20, integração
> admin 27 — todos verdes), incluindo o cofre AES-GCM fim-a-fim (backend cifra →
> gateway decifra). Cadastro de assets/usuários/permissões via `/admin`.

## Fase 3 — Segurança ✅ (ver [`phase3-security.md`](phase3-security.md))

Entregáveis: token efêmero (uso único + TTL, Fase 1), allowlist + denylist
imutável (Fase 2), bloqueio de host arbitrário testado, **HashiCorp Vault**,
rate limit, auditoria completa, teste-sentinela de vazamento de senha. TLS/WSS
na borda (Nginx); mTLS interno e VeNCrypt ficam na Fase 5.

Critérios de aceite:
- [x] Token expira (teste automatizado)
- [x] Token é de uso único (teste de corrida com 2 conexões)
- [x] Senha não aparece no navegador nem em nenhum log (teste sentinela)
- [x] Porta não permitida é bloqueada na API, no banco e no gateway
- [x] Asset não autorizado retorna 403 e gera auditoria
- [x] Gateway recusa destino que não responde banner RFB

> Verificado com Postgres real + fakes in-process (Vault KV v2, servidor
> não-VNC): backend unit 16, gateway unit 20, integração Fase 3 12 — todos
> verdes, incluindo Vault e2e (backend grava → gateway lê) e a sentinela de senha.

## Fase 4 — Administração e operação ✅ (ver [`phase4-operation.md`](phase4-operation.md))

Entregáveis: tela administrativa (Fase 2), sessões ativas, **encerramento forçado
propagado ao gateway**, logs pesquisáveis, `/healthz`, `/metrics` Prometheus,
documentação de deploy, backup do banco.

Critérios de aceite:
- [x] Admin vê sessões ativas
- [x] Admin encerra sessão e o usuário é desconectado imediatamente (watchdog)
- [x] Logs de auditoria consultáveis com filtros
- [x] Health check reflete o banco (gateway também reporta sessões ativas)
- [x] Erros são registrados e visíveis (auditoria + métricas)
- [x] Deploy reproduzível documentado + backup do banco

> Verificado com Postgres real (backend unit 16, gateway unit 20, integração
> Fase 4 10 — todos verdes), incluindo o encerramento forçado derrubando o
> WebSocket ao vivo. Health do cofre (Vault) e store externo de auditoria ficam
> para a Fase 5.

## Fase 5 — Avançado (somente após MVP sólido)

Backlog: MFA · SSO (OIDC/SAML) · aprovação de acesso · janela de acesso ·
justificativa obrigatória · relatórios · alta disponibilidade · VeNCrypt no
trecho gateway→asset.

- **5.1 — Gravação de sessão + playback** ✅ (ver [`phase5-recording.md`](phase5-recording.md)):
  o gateway grava a tela (S→C; sem teclado, por privacidade/HR-06) em formato
  `PAMREC01`; admin assiste no navegador via noVNC em replay. Flag por asset,
  download admin-only e auditado. Verificado (unit 4 + integração 10).
- **5.2 — MFA (TOTP)** ✅ (ver [`phase5-mfa.md`](phase5-mfa.md)): 2FA por TOTP
  (RFC 6238), segredo cifrado no banco, login com `MFA_REQUIRED`, reset por
  admin, tudo auditado. Verificado (unit 11 c/ vetores do RFC + integração 22).
- **5.3 — Acesso just-in-time** ✅ (ver [`phase5-jit.md`](phase5-jit.md)): janela
  de validade nas permissões, catálogo opt-in (`requestable`), solicitação →
  aprovação com janela, justificativa obrigatória por asset. Verificado
  (integração 17).
- **5.4 — VeNCrypt (TLS gateway→asset)** ✅ (ver [`phase5-vencrypt.md`](phase5-vencrypt.md)):
  cifra o trecho gateway→asset com TLS (subtypes X509), autenticação VNC dentro
  do túnel, flag `tls_required` por asset. Verificado (integração 10 com TLS real
  do Node).
- **5.5 — SSO/OIDC** ✅ (ver [`phase5-sso.md`](phase5-sso.md)): Authorization Code
  flow, verificação RS256 do id_token via JWKS (node:crypto), provisionamento e
  vínculo por email, `state`/`nonce`. Verificado (integração 12 com IdP simulado
  e RSA real). **Os três avançados escolhidos estão entregues.**

## Roadmap multiprotocolo (PR-12+)

Com a plataforma comum e o adapter VNC prontos, o produto pivota para
**PAM Access Gateway** multiprotocolo. Cada item é um PR próprio; novos protocolos
entram **um por vez, sempre por adapter explícito** (HR-09), nunca por proxy
genérico. Antes da auditoria de cada função, ver [`function-audit.md`](function-audit.md).

| PR | Objetivo | Escopo | Status |
|----|----------|--------|--------|
| **PR-12** | Pivot documental | constituição, novos HR, ADR, auditoria função-por-função, VNC como 1º adapter | ✅ mergeado |
| **PR-13** | Hardening & CI | IP de origem não-spoofável, remover senhas do seed, CI mínimo, versionar a suíte de integração, usuário DB runtime com privilégio mínimo, KDF (scrypt, ADR 0002) | ✅ mergeado |
| **PR-14** | UI enterprise | portal estilo Fluent; esconder função incompleta; nenhum botão morto | ✅ mergeado |
| **PR-15** | Auth enterprise | consolidar OIDC (PKCE, rotação JWKS, grupo→role); ADFS via OIDC/SAML (ADR 0003); LDAPS → PR-15B | ✅ mergeado |
| **PR-16** | Abstração de protocolo | `protocol` no modelo + **adapter registry** neutro; VNC isolado em `adapters/vnc/`; gateway recusa protocolo sem adapter (ADR 0004) | ✅ mergeado |
| **PR-17** | Primeiro adapter novo — **RDP** | dividido em sub-PRs (abaixo), um adapter por PR, RDP antes de SSH | 🟡 em andamento (17A) |
| **PR-18+** | Adapter SSH | depois do RDP | ⬜ |
| **PR-15B** | LDAPS interno | backlog; não bloqueia o RDP | ⬜ |

### Sub-roadmap do RDP (PR-17)

RDP é grande demais para um PR monolítico; entra por incrementos revisáveis, com
**dois gates empíricos não-circulares** que aceitam coisas diferentes: o **smoke P0**
valida o worker isolado (PR-17B) e **aceita a engine**; o **gate P1** só roda depois
que o produto RDP está completo (PRs 17C–17F) e **aceita o adapter como produto**;
só então o **PR-17G** habilita o RDP em runtime.

| Sub-PR | Objetivo | Status |
|----|----------|--------|
| **PR-17A** | Decisão de engine (ADR 0005 `Accepted — Conditional`, condicionada **ao P0**, com matriz preenchida), threat model ([`threat-models/rdp.md`](threat-models/rdp.md)), runbooks dos gates P0/P1. **Docs-only, zero código.** | 🟢 este PR |
| **PR-17B0** | **Contrato de implementação do worker** ([`adr/0006-rdp-worker-spike.md`](adr/0006-rdp-worker-spike.md) + [`protocols/rdp-worker-spike.md`](protocols/rdp-worker-spike.md)): C++20 + API C do FreeRDP, `rdp-worker/` top-level, UDS-only, proteção de credencial, pinagem/SBOM, CI nativo, scope guard, limites e critérios de aceite. **Docs-only, zero código.** | 🟢 este PR |
| **PR-17B** | **Implementação** do spike isolado: RDP Worker (`privion-rdp-worker-lab`) — **C++20** fino sobre a API C do **FreeRDP 3.28.0 fixado por commit SHA** (`5370fb26…`), em novo top-level `rdp-worker/`; UDS `0600` + peer creds; credencial via fd/secret-file `0400` (`O_NOFOLLOW`+`fstat`); WLog nativo redigido; event loop de sessão + teardown determinístico; build nativo + SBOM (syft) no CI (`rdp-worker-build-test`); scope guard. **Obedece o contrato do PR-17B0.** **Sem** gateway/backend/registry/UI/`SUPPORTED_PROTOCOLS`/`protocol=rdp`/TCP; recusa `PAM_ENV=production` | 🟢 **`rdp-worker-build-test` verde**: pin FreeRDP, build lógico + 8/8 unit tests, **build nativo + 8/8 testes nativos + `--selftest` confirmou FreeRDP 3.28.0**, imagem runtime, SBOM gerado+validado. **Só o P0 (Windows/xrdp) pendente** |
| **Smoke P0** | Gate do **worker isolado** do PR-17B contra **Windows (NLA)** e **xrdp** ([`rdp-smoke-runbook.md`](rdp-smoke-runbook.md)) — **aceita a engine** (ADR 0005 → `Accepted`) e desbloqueia o início do PR-17C | ⛔ fora do sandbox |
| **PR-17C** | Adapter RDP + integração ao broker/registry **em perfil de laboratório**: `SUPPORTED_PROTOCOLS` continua `["vnc"]`, sem UI/rota/asset RDP de produção; exercitado só por testes e perfil de laboratório (que recusa `PAM_ENV=production`) | ⛔ **bloqueado até o smoke P0 verde** |
| **PR-17D** | Segurança/políticas: NLA/CredSSP, validação de certificado, canais virtuais (clipboard/drive/printer **off** por padrão), política por asset | ⬜ |
| **PR-17E** | Cliente web e transporte próprios do PAM (sessão RDP no navegador) | ⬜ |
| **PR-17F** | Gravação, auditoria completa, métricas, encerramento administrativo, resource limits, troubleshooting e operação | ⬜ |
| **Gate P1** | Gate de **integração/segurança end-to-end** do produto completo ([`rdp-integration-p1-runbook.md`](rdp-integration-p1-runbook.md)) — roda **somente após os PRs 17C–17F**; **aceita o adapter como produto** | ⛔ fora do sandbox; **após o PR-17F** |
| **PR-17G** | **Habilitação controlada** do RDP em runtime — **somente aqui** `SUPPORTED_PROTOCOLS = ["vnc", "rdp"]`, após o gate P1 verde | ⛔ **após o gate P1** |

> **Gate não-circular (sequência final):** `PR-17A → PR-17B0 (contrato, docs-only) →
> PR-17B → smoke P0 → PR-17C →
> PR-17D → PR-17E → PR-17F → gate P1 → PR-17G`. O **smoke P0 aceita a engine** (ADR
> 0005 → `Accepted`) e desbloqueia o PR-17C; o **gate P1** só roda depois do PR-17F
> (precisa do cliente web, das políticas, da auditoria completa, do encerramento
> administrativo e da gravação que 17D/17E/17F entregam) e **aceita o adapter como
> produto**. **Política de runtime única:** `SUPPORTED_PROTOCOLS` permanece `["vnc"]`
> até o **PR-17G**; durante 17C–17F o RDP existe apenas em **perfil de laboratório
> explicitamente separado**, que **recusa inicialização quando `PAM_ENV=production`**
> (sem UI RDP pública, sem rota pública de sessão RDP, sem asset RDP na API de
> produção). Só o **PR-17G** — após o P1 verde — muda para `["vnc", "rdp"]`.

Critérios de aceite de um **novo adapter** (PR-17C+):

```text
[ ] Termina o handshake do protocolo dos dois lados (nunca túnel byte-a-byte)
[ ] Nenhuma credencial trafega ao navegador (HR-05) — provado por teste
[ ] Valida que o destino realmente fala o protocolo esperado (HR-08)
[ ] Allowlist de portas específica do protocolo (HR-04)
[ ] Auditoria registra o protocolo em toda sessão (HR-10)
[ ] Gravação/observabilidade equivalente à do adapter VNC, quando aplicável
[ ] Threat model próprio + testes unit/integração/segurança
```

## Épicos (backlog)

| Épico | Objetivo | Fases |
|---|---|---|
| EP01 — Arquitetura Base | estrutura, Docker, documentação | 0–1 |
| EP02 — Frontend Portal | login, dashboard, lista de assets, tela de sessão | 1–2 |
| EP03 — Backend API | usuários, assets, permissões, sessões | 1–2 |
| EP04 — VNC Gateway | WS→TCP, terminação RFB, ciclo de vida da conexão | 1, 3 |
| EP05 — Segurança | token, allowlist, bloqueios, Vault | 3 |
| EP06 — Auditoria | logs de sessão e eventos administrativos | 2–3 |
| EP07 — Administração | CRUDs e telas de operação | 4 |
| EP08 — Operação | health, métricas, deploy, backup | 4 |
| EP09 — Testes | unitário, integração, segurança, e2e | contínuo |

### User stories de referência

```text
EP03 — Como administrador, quero cadastrar um asset VNC com nome, IP, porta e
ambiente, para disponibilizá-lo no portal.
  [ ] Porta precisa estar na allowlist   [ ] IP válido
  [ ] Status active/inactive             [ ] Porta 22/3389/443 → 422

EP03 — Como usuário, quero ver apenas os assets que tenho permissão.
  [ ] Sem permissão → não vê             [ ] Permissão por grupo funciona
  [ ] Asset inativo não aparece

EP04 — Como usuário autorizado, quero abrir sessão VNC pelo navegador.
  [ ] Sessão abre no navegador           [ ] Backend valida token
  [ ] Gateway abre TCP para o asset      [ ] Fechar navegador fecha o TCP

EP05 — Como admin de segurança, quero impedir host/porta arbitrários.
  [ ] API não aceita host/port           [ ] Sessão só aceita assetId
  [ ] Porta vem do banco + allowlist

EP06 — Como auditor, quero saber quem acessou o quê, quando e de onde.
  [ ] Login registrado                   [ ] Criação/início/fim registrados
  [ ] Falhas registradas                 [ ] Leitura de segredo registrada
```

## Definition of Done (por entrega)

```text
[ ] Código revisado
[ ] Testes unitários e de integração criados
[ ] Logs implementados — nenhuma senha em log
[ ] Nenhum host arbitrário aceito
[ ] Porta validada por allowlist
[ ] Documentação atualizada
[ ] Docker build funcionando
[ ] Deploy local reproduzível
[ ] Critérios de aceite da fase validados
[ ] Checklist de segurança (§8) respondido corretamente
```
