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
| **PR-13** | Hardening & CI | IP de origem não-spoofável (nginx `$remote_addr`, `trustProxy` restrito), remover senhas do seed, CI mínimo (typecheck+test+scan de proxy-genérico/deps/segredos), versionar a suíte de integração, usuário DB runtime com privilégio mínimo, decisão de KDF (scrypt, ADR 0002) | 🟢 este PR |
| **PR-14** | UI enterprise | portal estilo Fluent; esconder função incompleta; nenhum botão morto | ⬜ |
| **PR-15** | Auth enterprise | consolidar OIDC; ADFS via OIDC/SAML; LDAPS interno se necessário (nunca LDAP direto exposto à internet) | ⬜ |
| **PR-16** | Abstração de protocolo | `protocol` no modelo de asset + **adapter registry**; VNC vira adapter oficial registrado. Sem novos protocolos ainda | ⬜ |
| **PR-17+** | Novos adapters | um adapter por PR — **RDP primeiro, SSH depois** — cada um com threat model, contrato, terminação de handshake, gravação, auditoria e testes próprios | ⬜ |

Critérios de aceite de um **novo adapter** (PR-17+):

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
