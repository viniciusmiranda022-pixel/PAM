# PAM Access Gateway — Acesso privilegiado por adapter de protocolo

Solução web de **acesso privilegiado (PAM)** com abertura de sessão no navegador.
O usuário autentica em um portal HTTPS, vê somente os ativos autorizados e abre a
sessão **sem nunca conhecer IP, hostname, porta ou credencial** do destino. A
conexão com o asset é feita **exclusivamente** por um gateway controlado pelo
backend, através de um **adapter específico do protocolo** do ativo.

> **Arquitetura multiprotocolo por adapter.** O produto suporta protocolos através
> de **adapters explícitos** — cada protocolo tem um adapter validado, testado e
> auditado. O **VNC (RFB) é o primeiro adapter, já implementado e funcional**.
> Novos protocolos (ex.: RDP, SSH) entram **um por vez, sempre por adapter** —
> **nunca** como proxy TCP genérico. Ver [`docs/adr/0001-pivot-multiprotocolo.md`](docs/adr/0001-pivot-multiprotocolo.md).

## Regra principal

```text
Portal web → autenticação/autorização → criação de sessão (assetId apenas)
→ token efêmero → gateway → adapter do protocolo do asset → asset
```

O usuário **nunca** informa IP, hostname, porta, URL, socket ou comando. O backend
é a fonte de verdade: a partir do `assetId` cadastrado ele resolve **protocolo**,
destino, porta (validada contra a allowlist do protocolo), credencial e política.
O gateway é o único componente com rota de rede até o asset.

## Requisitos inegociáveis (hard requirements)

| ID    | Requisito |
|-------|-----------|
| HR-01 | O usuário nunca informa destino técnico (IP, hostname, porta, URL, socket ou comando) |
| HR-02 | A criação de sessão recebe apenas `assetId` (+ metadados de governança, ex. justificativa) |
| HR-03 | O backend resolve protocolo, IP, porta, credencial e política a partir do asset |
| HR-04 | Somente portas em allowlist **por protocolo** são aceitas |
| HR-05 | A credencial do asset nunca é exibida nem trafega até o navegador |
| HR-06 | Nenhum segredo aparece em log (senha, token, cookie, chave privada, segredo de cofre) |
| HR-07 | O usuário final não tem rota de rede direta até o asset |
| HR-08 | O gateway não aceita destino arbitrário (só o destino resolvido pelo backend para uma sessão válida) |
| HR-09 | Cada protocolo entra por **adapter explícito** — nunca proxy TCP genérico |
| HR-10 | Toda sessão gera auditoria: usuário, asset, **protocolo**, IP de origem, início, fim, status e motivo |

Detalhes e verificação: [`docs/security-requirements.md`](docs/security-requirements.md).

## Adapters de protocolo

| Protocolo | Status | Documento |
|-----------|--------|-----------|
| **VNC (RFB 3.8)** | ✅ implementado — adapter de referência | [`docs/protocols/vnc.md`](docs/protocols/vnc.md) |
| RDP | 🔜 planejado (adapter futuro, um PR próprio) | — |
| SSH | 🔜 planejado (adapter futuro, um PR próprio) | — |

> Um adapter só é considerado pronto após threat model, contrato, terminação de
> handshake própria (nunca túnel byte-a-byte que exija credencial no browser),
> gravação, auditoria e testes específicos. Ver o roadmap em
> [`docs/delivery-plan.md`](docs/delivery-plan.md).

## Documentação

| Documento | Conteúdo |
|-----------|----------|
| [`docs/architecture.md`](docs/architecture.md) | Arquitetura, Protocol Gateway Layer, adapters, zonas de rede, stack |
| [`docs/session-flow.md`](docs/session-flow.md) | Fluxo completo da sessão, terminação de handshake, encerramento |
| [`docs/security-requirements.md`](docs/security-requirements.md) | Hard requirements, threat model, allowlist por protocolo, checklist |
| [`docs/api-contract.md`](docs/api-contract.md) | Contrato REST + protocolo WebSocket do gateway |
| [`docs/database-model.md`](docs/database-model.md) | Modelo de dados e invariantes no banco |
| [`docs/function-audit.md`](docs/function-audit.md) | Auditoria função-por-função: o que funciona x fachada |
| [`docs/protocols/vnc.md`](docs/protocols/vnc.md) | O adapter VNC (RFB) em detalhe |
| [`docs/adr/0001-pivot-multiprotocolo.md`](docs/adr/0001-pivot-multiprotocolo.md) | ADR: pivot de VNC-only para multiprotocolo por adapter |
| [`docs/risks-and-dependencies.md`](docs/risks-and-dependencies.md) | Riscos técnicos e dependências externas |
| [`docs/delivery-plan.md`](docs/delivery-plan.md) | Roadmap, critérios de aceite, épicos, Definition of Done |
| [`docs/deployment.md`](docs/deployment.md) | Ambiente local com Docker Compose |

## Estrutura do repositório

```text
pam/
├── README.md
├── docs/                  # decisões técnicas, ADRs, contratos e auditoria
├── frontend/              # portal web + clientes de sessão (noVNC p/ o adapter VNC)
├── backend/               # API, auth, assets, sessões, política
├── gateway/               # camada de gateway + adapters de protocolo
│   └── src/               # (o adapter VNC vive aqui hoje; futuros: adapters/{rdp,ssh})
├── infra/
│   ├── docker-compose.yml # topologia local (redes isoladas)
│   ├── nginx/             # reverse proxy TLS/WSS
│   └── postgres/init/     # schema inicial
├── scripts/               # seed, run-local, testes de conectividade
└── tests/                 # integração, segurança, e2e
```

## Fases de entrega

| Fase | Objetivo | Status |
|------|----------|--------|
| 0 | Desenho técnico | ✅ |
| 1 | PoC: adapter VNC (noVNC + gateway) + asset de laboratório | ✅ ([`docs/phase1-poc.md`](docs/phase1-poc.md)) |
| 2 | MVP: login, assets, permissões, sessões, logs básicos | ✅ ([`docs/phase2-mvp.md`](docs/phase2-mvp.md)) |
| 3 | Segurança: token efêmero, allowlist, cofre Vault, rate limit, auditoria, TLS/WSS | ✅ ([`docs/phase3-security.md`](docs/phase3-security.md)) |
| 4 | Operação: admin, sessões ativas, kill ao vivo, health, métricas, backup | ✅ ([`docs/phase4-operation.md`](docs/phase4-operation.md)) |
| 5.1 | Gravação de sessão + playback no navegador | ✅ ([`docs/phase5-recording.md`](docs/phase5-recording.md)) |
| 5.2 | MFA (TOTP, RFC 6238) com reset por admin | ✅ ([`docs/phase5-mfa.md`](docs/phase5-mfa.md)) |
| 5.3 | Acesso just-in-time (janela, catálogo, aprovação, justificativa) | ✅ ([`docs/phase5-jit.md`](docs/phase5-jit.md)) |
| 5.4 | VeNCrypt: TLS no trecho gateway→asset (adapter VNC) | ✅ ([`docs/phase5-vencrypt.md`](docs/phase5-vencrypt.md)) |
| 5.5 | SSO/OIDC (Authorization Code, verificação RS256) | ✅ ([`docs/phase5-sso.md`](docs/phase5-sso.md)) |

Todas as entregas acima materializam o **adapter VNC** e a plataforma comum
(auth, sessão, auditoria, operação). O roadmap do pivot multiprotocolo
(hardening, UI enterprise, auth enterprise, adapter registry e novos adapters)
está em [`docs/delivery-plan.md`](docs/delivery-plan.md).

## Subir o ambiente local

```bash
cd infra
cp .env.example .env && ../scripts/gen-certs.sh
# defina COOKIE_SECRET e CREDENTIAL_MASTER_KEY no .env (openssl rand -base64 32)
docker compose --profile app up -d --build
docker compose --profile app run --rm backend node dist/seed.js
```

Abra `https://localhost`. O login de laboratório inicia a sessão no ativo `lab-vnc`
(adapter VNC); o login de admin dá acesso ao painel em `/admin` (cadastro de
assets/usuários/permissões, sessões, auditoria). Passo a passo, isolamento de
rede e testes: [`docs/deployment.md`](docs/deployment.md) ·
[`docs/phase1-poc.md`](docs/phase1-poc.md) · [`docs/phase2-mvp.md`](docs/phase2-mvp.md).

> As credenciais de laboratório são definidas no seed e no `.env` e servem apenas
> para o ambiente local. Nunca use senhas de exemplo em produção.

## Definition of Done

Nenhuma entrega é aceita sem passar por:

- [ ] Código revisado
- [ ] Testes unitários e de integração criados
- [ ] Logs implementados, **nenhum segredo em log**
- [ ] Nenhum destino técnico arbitrário aceito (HR-01/HR-08)
- [ ] Porta validada por allowlist do protocolo
- [ ] Documentação atualizada
- [ ] Docker build funcionando e deploy local reproduzível
- [ ] Critérios de aceite da fase validados
