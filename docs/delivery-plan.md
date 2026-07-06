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

## Fase 1 — PoC técnica

**Objetivo:** provar o fluxo seguro de ponta a ponta com o mínimo de telas:
`portal → sessão → token → gateway WS → TCP VNC → asset de laboratório`.

Entregáveis:
- Gateway: upgrade WS, consumo de token (versão simplificada), TCP connect,
  validação de banner RFB, terminação RFB (`None` lado browser, `VNCAuth` lado
  asset com senha de variável de ambiente — cofre real vem na Fase 3).
- Frontend mínimo: uma página com noVNC que recebe `gatewayUrl+token`.
- Backend mínimo: endpoint de criação de sessão consultando asset seedado no banco.
- Asset VNC de laboratório no Compose (rede isolada).

Critérios de aceite:
- [ ] Usuário abre a tela VNC no navegador
- [ ] Gateway conecta no asset pela porta 5900 buscada do banco
- [ ] Usuário não acessa o asset diretamente (rede isolada comprovada)
- [ ] Senha do asset não trafega ao navegador (verificado no HAR)
- [ ] Não existe suporte/biblioteca de RDP/SSH no lockfile

## Fase 2 — MVP funcional

Entregáveis: login (Argon2id + cookie), CRUD de usuários, CRUD de assets VNC,
grupos e permissões, criação/encerramento de sessão completos, logs básicos.

Critérios de aceite:
- [ ] Usuário vê somente assets autorizados (direto e via grupo)
- [ ] Asset inativo não aparece
- [ ] Usuário inicia e encerra sessão VNC
- [ ] Usuário não vê senha em nenhum ponto
- [ ] Sessão é registrada em log com usuário, asset, IP, início, fim, status
- [ ] Admin consegue listar sessões

## Fase 3 — Segurança

Entregáveis: token efêmero definitivo (uso único + TTL 30s), allowlist de portas
com denylist imutável, bloqueio de host arbitrário testado, HashiCorp Vault,
rate limit, TLS/WSS fim a fim, auditoria completa, teste-sentinela de vazamento
de senha.

Critérios de aceite:
- [ ] Token expira (teste automatizado)
- [ ] Token é de uso único (teste de corrida com 2 conexões)
- [ ] Senha não aparece no navegador nem em nenhum log (teste sentinela)
- [ ] Porta não permitida é bloqueada na API, no banco e no gateway
- [ ] Asset não autorizado retorna 403 e gera auditoria
- [ ] Gateway recusa destino que não responde banner RFB

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
