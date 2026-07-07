# Plano de entrega por fases

Regra de aceite global: a pergunta nunca é "funcionou?", é **"funcionou sem
violar a arquitetura?"** — usar o checklist de
[`security-requirements.md`](security-requirements.md) §8 em toda revisão.

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

## Fase 4 — Administração e operação

Entregáveis: tela administrativa (assets, usuários, permissões), sessões ativas
em tempo real, encerramento forçado, logs pesquisáveis, `/healthz`, `/metrics`
Prometheus, documentação de deploy, backup do banco.

Critérios de aceite:
- [ ] Admin vê sessões ativas
- [ ] Admin encerra sessão e o usuário é desconectado imediatamente
- [ ] Logs de auditoria consultáveis com filtros
- [ ] Health check reflete banco, cofre e gateway
- [ ] Erros são registrados e visíveis
- [ ] Deploy reproduzível documentado

## Fase 5 — Avançado (somente após MVP sólido)

MFA · SSO (OIDC/SAML) · aprovação de acesso · janela de acesso · justificativa
obrigatória · gravação de sessão + playback · relatórios · alta disponibilidade ·
VeNCrypt no trecho gateway→asset.

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
