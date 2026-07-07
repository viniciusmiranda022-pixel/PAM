# PAM VNC-Only — VNC Privileged Access Gateway

Solução web de **acesso privilegiado exclusiva para VNC**. O usuário autentica em um
portal HTTPS, vê somente os ativos VNC autorizados e abre a sessão VNC no navegador
(noVNC). A conexão com o asset é feita **exclusivamente** por um gateway
WebSocket → TCP controlado pelo backend.

> **Isto não é um PAM multiprotocolo.** Não existe — e não existirá — suporte a
> RDP, SSH, Telnet, SQL, SFTP, VPN, shell remoto ou proxy genérico.

## Regra principal

```text
Portal web → autenticação/autorização → criação de sessão (assetId apenas)
→ token efêmero → gateway WebSocket → TCP VNC → asset
```

O usuário **nunca** informa IP, hostname ou porta. O backend resolve o destino a
partir do `assetId` cadastrado, valida a porta contra uma allowlist e o gateway é o
único componente com rota de rede até o asset.

## Requisitos inegociáveis (hard requirements)

| ID    | Requisito |
|-------|-----------|
| HR-01 | O usuário nunca informa IP, hostname ou porta manualmente |
| HR-02 | A API de criação de sessão recebe apenas `assetId` |
| HR-03 | O backend busca IP e porta do asset no banco |
| HR-04 | Somente portas VNC em allowlist são aceitas |
| HR-05 | A senha VNC nunca é exibida nem trafega até o navegador |
| HR-06 | A senha VNC nunca aparece em log |
| HR-07 | O usuário final não tem rota de rede direta até o asset |
| HR-08 | O gateway não pode virar proxy genérico (só assets cadastrados + sessão válida) |
| HR-09 | Nenhuma biblioteca, tela ou endpoint para RDP/SSH/qualquer outro protocolo |
| HR-10 | Toda sessão gera auditoria: usuário, asset, IP de origem, início, fim e status |

Detalhes e verificação: [`docs/security-requirements.md`](docs/security-requirements.md).

## Documentação (Fase 0)

| Documento | Conteúdo |
|-----------|----------|
| [`docs/architecture.md`](docs/architecture.md) | Arquitetura, componentes, zonas de rede, stack tecnológica |
| [`docs/session-flow.md`](docs/session-flow.md) | Fluxo completo da sessão, terminação RFB, encerramento |
| [`docs/security-requirements.md`](docs/security-requirements.md) | Hard requirements, threat model, allowlist, checklist de revisão |
| [`docs/api-contract.md`](docs/api-contract.md) | Contrato REST + protocolo WebSocket do gateway |
| [`docs/database-model.md`](docs/database-model.md) | Modelo de dados e invariantes no banco |
| [`docs/risks-and-dependencies.md`](docs/risks-and-dependencies.md) | Riscos técnicos e dependências externas |
| [`docs/delivery-plan.md`](docs/delivery-plan.md) | Fases, critérios de aceite, épicos, Definition of Done |
| [`docs/deployment.md`](docs/deployment.md) | Ambiente local com Docker Compose |

## Estrutura do repositório

```text
pam/
├── README.md
├── docs/                  # decisões técnicas e documentação (Fase 0)
├── frontend/              # portal web + noVNC            (Fase 1+)
├── backend/               # API, auth, assets, sessões    (Fase 1+)
├── gateway/               # WebSocket → TCP VNC           (Fase 1+)
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
| 1 | PoC: noVNC + gateway WS→TCP + asset de laboratório | ✅ ([`docs/phase1-poc.md`](docs/phase1-poc.md)) |
| 2 | MVP: login, assets, permissões, sessões, logs básicos | ✅ ([`docs/phase2-mvp.md`](docs/phase2-mvp.md)) |
| 3 | Segurança: token efêmero, allowlist, cofre Vault, rate limit, auditoria, TLS/WSS | ✅ ([`docs/phase3-security.md`](docs/phase3-security.md)) |
| 4 | Operação: admin, sessões ativas, kill ao vivo, health, métricas, backup | ✅ ([`docs/phase4-operation.md`](docs/phase4-operation.md)) |
| 5 | Avançado: MFA, SSO, gravação, aprovação, VeNCrypt (fora do MVP) | backlog |

Plano detalhado com critérios de aceite: [`docs/delivery-plan.md`](docs/delivery-plan.md).

## Subir o ambiente local

```bash
cd infra
cp .env.example .env && ../scripts/gen-certs.sh
# defina COOKIE_SECRET e CREDENTIAL_MASTER_KEY no .env (openssl rand -base64 32)
docker compose --profile app up -d --build
docker compose --profile app run --rm backend node dist/seed.js
```

Abra `https://localhost`. Login `poc` / `poc-pass` inicia a sessão VNC no ativo
`lab-vnc`; login `admin` / `admin-pass` dá acesso ao painel em `/admin` (cadastro
de assets/usuários/permissões, sessões, auditoria). Passo a passo, isolamento de
rede e testes: [`docs/deployment.md`](docs/deployment.md) ·
[`docs/phase1-poc.md`](docs/phase1-poc.md) · [`docs/phase2-mvp.md`](docs/phase2-mvp.md).

## Definition of Done

Nenhuma entrega é aceita sem passar por:

- [ ] Código revisado
- [ ] Testes unitários e de integração criados
- [ ] Logs implementados, **nenhuma senha em log**
- [ ] Nenhum host/porta arbitrário aceito
- [ ] Porta validada por allowlist
- [ ] Documentação atualizada
- [ ] Docker build funcionando e deploy local reproduzível
- [ ] Critérios de aceite da fase validados
