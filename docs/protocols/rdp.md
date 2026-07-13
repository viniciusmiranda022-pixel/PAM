# Adapter RDP (rascunho — PLANEJADO, não implementado)

> **Estado: planejado.** Nenhum código RDP existe. `SUPPORTED_PROTOCOLS` continua
> `["vnc"]`; o registry do gateway **recusa** `protocol=rdp` (HR-09). Este
> documento é o rascunho do contrato que o adapter RDP deverá cumprir, produzido
> no PR-17A para guiar os PRs seguintes. Decisão de engine em
> [`../adr/0005-rdp-engine.md`](../adr/0005-rdp-engine.md); ameaças em
> [`../threat-models/rdp.md`](../threat-models/rdp.md).

## Arquitetura alvo (engine própria)

Engine, transporte de sessão e cliente web **próprios** do PAM. FreeRDP entra
apenas como **biblioteca de protocolo de baixo nível**, encapsulada no RDP Worker.

```text
Browser → cliente web próprio do PAM → Session Gateway → adapter RDP → RDP Worker próprio → libfreerdp → asset RDP
        protocolo browser–gateway (nosso)      correlaciona a sessão        egress restrito aos assets
```

- O **navegador nunca fala com o FreeRDP** e **nunca** recebe credencial nem
  parâmetros técnicos do asset (HR-05). Ele fala apenas o **nosso** protocolo
  browser–gateway.
- O **RDP Worker** é nosso: usa `libfreerdp` para falar RDP com o asset, injeta a
  credencial (do cofre), aplica política e emite os eventos de auditoria/gravação.
- Continuam **nossos**: portal, cliente web, protocolo browser–gateway, lifecycle,
  autorização, injeção de credencial, política, auditoria, recording, métricas,
  isolamento e troubleshooting.

## Como o RDP se encaixa no registry

O adapter RDP implementa a mesma interface `ProtocolAdapter`
([`0004-adapter-registry.md`](../adr/0004-adapter-registry.md)) que o VNC. O
`session.ts` continua **agnóstico**: resolve destino/credencial do banco e delega
a terminação ao adapter selecionado por `assets.protocol = 'rdp'`. Sessão segue
por `assetId`; o usuário nunca informa destino técnico. O adapter fala com o **RDP
Worker** (nosso) — nunca um túnel byte-a-byte (HR-09).

## Contrato que o adapter/worker RDP deverá cumprir (aterrissa em PR-17C+)

- **Terminação controlada** dos dois lados; nada de proxy genérico.
- **Destino só do backend:** o worker recebe apenas `(ip, porta, domínio,
  credencial)` resolvidos; nenhum parâmetro vem do cliente.
- **Credencial fora do navegador** (HR-05); NLA/CredSSP negociado no worker/FreeRDP.
- **FreeRDP encapsulado:** o browser nunca alcança o FreeRDP nem o worker
  diretamente; egress do worker restrito aos assets autorizados (HR-07/HR-08).
- **Allowlist por protocolo:** portas RDP (tipicamente `3389`) numa allowlist
  própria do protocolo — a segmentação física da allowlist entra com este adapter
  (era nota do PR-16). `3389` está no denylist da allowlist genérica hoje; passará
  a ser permitida **apenas** sob o adapter RDP validado.
- **Auditoria** com `protocol=rdp` (HR-10); encerramento derruba a conexão ao asset.
- **Gravação:** formato próprio (worker nosso); estratégia definida no PR-17F.

## Sequência de entrega (gate não-circular de dois níveis; não neste PR)

O worker é construído **isolado** antes de qualquer integração, para que o smoke P0
valide um artefato que já existe; e o RDP só é **habilitado em runtime** no PR-17G,
depois que o produto integrado passa no gate P1:

```text
PR-17A (esta decisão) → PR-17B (spike isolado do RDP Worker sobre libfreerdp,
sem gateway/backend/registry/UI/protocol=rdp) → SMOKE P0 (worker, Windows + xrdp) →
PR-17C adapter + broker/registry (perfil de laboratório) →
PR-17D NLA/CredSSP/cert/canais/políticas → PR-17E cliente web e transporte próprio →
PR-17F gravação/auditoria/métricas/operação → GATE P1 (produto integrado end-to-end)
→ PR-17G habilitação controlada do RDP em runtime
```

- **O smoke P0 aceita a engine** (RDP Worker sobre `libfreerdp`) e desbloqueia o
  **início do PR-17C** ([`../rdp-smoke-runbook.md`](../rdp-smoke-runbook.md)) — gate
  do **worker isolado**. Não habilita RDP para usuários.
- **O gate P1 aceita o adapter como produto** e roda **somente após os PRs 17C–17F**
  ([`../rdp-integration-p1-runbook.md`](../rdp-integration-p1-runbook.md)), porque
  depende do cliente web, das políticas, da auditoria completa, do encerramento
  administrativo e da gravação que 17D/17E/17F entregam.
- **Política de runtime única:** `SUPPORTED_PROTOCOLS` permanece **`["vnc"]`** até o
  **PR-17G**. Durante 17C–17F, o RDP existe apenas em **perfil de laboratório
  explicitamente separado**, que **recusa inicialização quando `PAM_ENV=production`**
  — sem UI RDP pública, sem rota pública de sessão RDP, sem asset RDP aceito pela API
  de produção. Só o **PR-17G**, após o P1 verde, muda para `["vnc", "rdp"]`.

A política do transporte gateway↔worker é determinística — ver
[`../adr/0005-rdp-engine.md`](../adr/0005-rdp-engine.md).
