# Runbook — smoke **P0** do RDP Worker isolado + FreeRDP (fora do sandbox)

**Escopo deste runbook: gate P0 — worker isolado.** Ele valida **apenas** o
**RDP Worker do PR-17B** (spike isolado encapsulando `libfreerdp`) contra alvos RDP
reais, **sem** broker, **sem** gateway do produto, **sem** navegador e **sem**
cliente web. Os controles fim-a-fim do produto integrado são provados em outro
gate — o **P1** ([`rdp-integration-p1-runbook.md`](rdp-integration-p1-runbook.md)).

**Por que existe:** o ambiente de desenvolvimento tem `docker pull` bloqueado, o
que impede subir o worker (encapsulando `libfreerdp`) e um alvo RDP real. A decisão
de engine ([`adr/0005-rdp-engine.md`](adr/0005-rdp-engine.md)) fica
**`Accepted — Conditional`** até este smoke rodar, com todos os itens **P0** verdes,
num host com Docker + alvos RDP reais.

**O que este smoke valida:** o **worker do PR-17B** (spike isolado do RDP Worker
sobre `libfreerdp`, sem integração ao produto). O artefato precisa existir antes —
por isso a ordem é `PR-17A (decisão) → PR-17B (worker isolado) → smoke P0 → PR-17C
(integração)`, sem ciclo.

**Gate:** enquanto o smoke P0 não passar, o **PR-17C (adapter + integração ao broker/
registry em perfil de laboratório) fica bloqueado**. Este runbook é o critério
objetivo que **aceita a engine** (ADR 0005 → `Accepted`) e desbloqueia o **início do
PR-17C** (ou reprova o candidato e reabre a decisão de engine entre A e C). **P0
verde não habilita o RDP para usuários** — a prontidão é decidida no **gate P1**
(após o PR-17F) e a habilitação em runtime ocorre só no **PR-17G**.

## Pré-requisitos do host (fora do sandbox)

- Docker com `pull` liberado (ex.: seu notebook).
- Alvo RDP nº 1: **Windows** com **NLA** habilitado.
- Alvo RDP nº 2: **xrdp** (segundo alvo, comportamento diferente do Windows).
- O **RDP Worker isolado + `libfreerdp`** com **versão fixada** (tag/digest do
  worker e versão da `libfreerdp`). O smoke testa o **nosso worker + FreeRDP**,
  nunca guacd.
- Um **harness de laboratório** que injeta no worker o destino `(ip, porta,
  domínio, credencial)` — no P0 **o harness controla o destino** (não há backend
  nem frontend ainda).

## Checklist P0 — worker isolado (todos devem passar)

Tudo aqui é comprovável **só com o worker + FreeRDP + alvo real**:

- [ ] **Versão fixada** (tag/digest do worker + versão da `libfreerdp`; série 3.x —
      2.x proibida) registrados no resultado; build/carga da `libfreerdp` ok.
- [ ] **Conexão contra Windows com NLA** — sessão estabelece (NLA/CredSSP real).
- [ ] **Conexão contra xrdp** (segundo alvo) — sessão estabelece.
- [ ] **Credencial correta** conecta; **credencial incorreta** é recusada e logada
      pelo worker. *(eliminatório P0)*
- [ ] **Certificado confiável** aceito; **certificado não confiável** recusado
      (conforme política do worker/asset). *(eliminatório P0)*
- [ ] **Ausência de segredo nos logs do worker** — grep-sentinela nos logs do
      **worker** (senha/domínio/token/chave): nada. *(eliminatório P0 — escopo
      worker; a prova fim-a-fim, incluindo frontend/gateway/WS/DOM, é do P1)*
- [ ] **Egress do worker restrito** — o worker só alcança os assets+portas RDP
      autorizados; tentativa de sair para outro host/porta falha (nível de rede).
      *(eliminatório P0)*
- [ ] **Destino controlado pelo harness** — o worker conecta **somente** ao destino
      que o harness injeta; ele não expõe endpoint de conexão arbitrária própria.
      *(a prova de que o destino vem do backend, e não do frontend, é do P1)*
- [ ] **Encerramento no worker derruba a conexão ao asset** — sinal de término/
      watchdog do worker fecha a conexão RDP com o alvo. *(eliminatório P0 — o
      encerramento **administrativo pelo produto** é validado no P1)*
- [ ] **Baseline de CPU, RAM e latência** por sessão (1 e N sessões) registrado.
- [ ] **Transporte gateway↔worker conforme a política determinística** (ADR 0005)
      exercitado no harness: mesmo host = Unix Domain Socket + peer credentials;
      outro host = mTLS + rede dedicada + allowlist de origem/egress. **TCP em claro
      deve falhar.**
- [ ] **Revisão de CVEs** da versão fixada da `libfreerdp` — nenhum CVE aplicável
      não mitigado; SBOM do worker gerado. *(eliminatório P0)*

## O que o P0 **não** cobre (permanece UNVERIFIED até o P1)

Um worker isolado **não** tem navegador, broker nem gateway do produto no fluxo, então
estes itens **não podem** ser marcados como comprovados aqui — ficam **UNVERIFIED**
e são responsabilidade do **gate P1**
([`rdp-integration-p1-runbook.md`](rdp-integration-p1-runbook.md)):

- HAR do navegador / frames WebSocket / DOM / `localStorage` / `sessionStorage`;
- logs do **frontend** e do **gateway** do produto (o P0 só cobre os logs do worker);
- **credencial fora do navegador** de ponta a ponta (HR-05);
- **auditoria completa** com usuário, asset e IP de origem (HR-10);
- **início da sessão somente por `assetId`** (HR-01/HR-02);
- **token efêmero de uso único** no broker (correlação sessão↔worker);
- **encerramento administrativo pelo produto** (kill de admin no broker);
- **ausência de rota direta do usuário** ao worker/asset (HR-07);
- **inexistência de parâmetros técnicos controlados pelo frontend** (HR-08).

## Como registrar o resultado

Converter os `UNVERIFIED` de **escopo P0** da **matriz de decisão** da ADR 0005 em
PASS/FAIL e atualizar as notas empíricas (NLA/CredSSP, desempenho) com evidência;
anexar:
- versão/digest do worker + versão da `libfreerdp` + SBOM;
- logs de cada item (sucesso/recusa) do **worker**;
- números de CPU/RAM/latência;
- resultado da revisão de CVEs contra o digest fixado.

Os `UNVERIFIED` de **escopo P1** **não** mudam aqui — só no gate P1.

## Resultado e efeito no status

- **Todos P0 verdes (eliminatórios P0 PASS):** ADR 0005 passa de `Accepted —
  Conditional` para **`Accepted`** (engine aceita); **início do PR-17C** (integração
  em perfil de laboratório) desbloqueado. **O RDP continua desabilitado em runtime**
  (`SUPPORTED_PROTOCOLS` = `["vnc"]`) — a prontidão do produto é decidida no **gate
  P1** (após o PR-17F) e a habilitação em runtime ocorre só no **PR-17G**.
- **Qualquer eliminatório P0 vermelho:** candidato **reprovado**; reabrir a decisão
  (engine própria [A] vs SDK comercial [C]) na ADR 0005, sem iniciar o PR-17C.
