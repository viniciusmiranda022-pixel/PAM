# ADR 0005 — Engine do adapter RDP

- **Status:** **Accepted — Conditional** (candidato preferencial escolhido;
  decisão de **engine** condicionada **apenas ao gate P0** — a matriz de evidências
  e o **smoke P0 real** do worker). O gate **P1** e o **PR-17G** decidem a
  **prontidão/habilitação do produto**, não a escolha da engine.
- **Data:** 2026-07-13
- **Contexto de PR:** PR-17A (spike e decisão de engine RDP — **docs-only**)
- **Relacionado:** [`0001-pivot-multiprotocolo.md`](0001-pivot-multiprotocolo.md),
  [`0004-adapter-registry.md`](0004-adapter-registry.md),
  [`../threat-models/rdp.md`](../threat-models/rdp.md),
  [`../rdp-smoke-runbook.md`](../rdp-smoke-runbook.md),
  [`../rdp-integration-p1-runbook.md`](../rdp-integration-p1-runbook.md).

## Contexto

O PR-16 entregou o registry de adapters com o VNC como primeiro adapter. O RDP é o
próximo protocolo. RDP é muito mais complexo que o RFB (negociação de segurança,
**NLA/CredSSP**, TLS, canais virtuais, bitmaps/codecs). Antes de escrever código,
é preciso **decidir a engine** — com fundamento, não intuição.

Este ADR é a saída do spike. Ele **não** habilita RDP nem toca no gateway.

## Decisão de produto: engine, transporte e cliente próprios

**O PAM Access Gateway terá engine, transporte de sessão e cliente web próprios.**
Não construiremos o produto sobre a arquitetura do Apache Guacamole. Isso é uma
**restrição de produto**, anterior à comparação técnica:

- não queremos dependência arquitetural do **protocolo Guacamole**;
- não queremos exigir **guacd** como serviço na topologia;
- não queremos ser empurrados para **guacamole-common-js** no navegador;
- não queremos aproximar a sessão do desenho de **outro produto**;
- queremos a **nossa própria camada de sessão** (portal, cliente web, protocolo
  browser–gateway, lifecycle, autorização, injeção de credencial, política,
  auditoria, recording, métricas, isolamento e troubleshooting sob nosso controle).

## Arquitetura alvo

```text
Browser → cliente web próprio do PAM → Session Gateway → RDP Worker próprio → libfreerdp → asset RDP
```

- **libfreerdp** (biblioteca de protocolo RDP de baixo nível) fica **encapsulada
  dentro do RDP Worker**. O worker é nosso; ele usa a lib, não o contrário.
- O **navegador nunca fala com o FreeRDP** e **nunca** recebe credencial nem
  parâmetros técnicos do asset (HR-05). O browser fala só o **nosso** protocolo
  com o gateway.
- Continuam **nossos**: portal, cliente web, protocolo browser–gateway, lifecycle
  da sessão, autorização, injeção de credencial, política, auditoria, recording,
  métricas, isolamento e troubleshooting.

## Regra de honestidade desta decisão

- **Hipótese inicial:** **RDP Worker próprio do PAM sobre libfreerdp** é o candidato
  preferencial.
- **Decisão final:** condicionada (a) à matriz de evidências e (b) ao **smoke P0
  real** (runbook), executado contra **o nosso RDP Worker + FreeRDP** — nunca guacd.
- O status só passa de `Accepted — Conditional` para `Accepted` depois do smoke P0
  verde num host com Docker + alvo RDP reais. **Enquanto isso, o PR-17C
  (integração) fica bloqueado.** O smoke **P0 aceita apenas a engine** (o RDP Worker
  sobre `libfreerdp` como implementação de protocolo escolhida) — **não** habilita
  RDP para usuários. A **prontidão do produto** é decidida pelo **gate P1** (após o
  PR-17F) e a **habilitação em runtime** ocorre só no **PR-17G**.

## Correção importante: engine ≠ garantia contra proxy genérico

O RDP Worker **é** um componente que fala protocolo com o asset. O produto só não
vira proxy arbitrário porque **a nossa arquitetura impõe** — independentemente da
engine:

1. o usuário envia somente `assetId` (HR-01/HR-02);
2. o backend resolve protocolo, IP, porta, credencial e política (HR-03);
3. o worker recebe **somente** o destino previamente autorizado;
4. o usuário **não** fornece nenhum parâmetro de conexão (host/porta/domínio);
5. o worker/FreeRDP **não** fica exposto ao navegador nem à rede de usuários;
6. o **egress** do worker é restrito aos assets e às portas RDP autorizados;
7. protocolo desconhecido ou destino divergente é **recusado** (HR-08/HR-09);
8. **não existe** endpoint de conexão arbitrária;
9. cada sessão do broker é **correlacionada** à conexão criada no worker (token
   efêmero de uso único, como no VNC).

Essas nove imposições são condição de aceite do adapter/worker RDP (PR-17B+).

## Candidatos avaliados

| Engine | Descrição | Situação de partida |
|---|---|---|
| **Guacamole / `guacd`** | Reusar o servidor e o protocolo do Apache Guacamole | **REJEITADO por decisão de produto** (restrição arquitetural — ver acima) |
| **A. Engine RDP totalmente própria** | Falar RDP do zero em TS/Node, como o RFB | Avaliar, mas **forte risco de segurança + esforço** (reimplementar NLA/CredSSP/TLS/codecs) |
| **B. RDP Worker próprio sobre `libfreerdp`** | Worker nosso encapsulando a lib FreeRDP | **Candidato preferencial condicional** |
| **C. SDK RDP comercial** | Biblioteca RDP comercial encapsulada no worker | Alternativa **condicionada** a licença, custo, suporte e **independência** |

> `guacd` sai da matriz de pontuação: foi eliminado por **restrição de produto**,
> não por nota. As alternativas técnicas reais são A, B e C.

## Matriz de decisão (pesos explícitos)

Escala: **nota 0–5** por critério; **contribuição = nota × peso** (escala final
0–5). Candidatos técnicos comparados: **A** implementação RDP integral do zero;
**B** RDP Worker próprio sobre `libfreerdp`; **C** SDK RDP comercial. (Guacamole/
`guacd` está **fora da pontuação** — rejeitado por decisão de produto.)

As notas abaixo são **documentais-preliminares**. Critérios de natureza empírica
(compatibilidade real de NLA/CredSSP, desempenho) ficam **UNVERIFIED / pendentes do
smoke P0** — a decisão só vira `Accepted` definitivo após o smoke (ver gate).

### A — Implementação RDP integral do zero

| Critério | Peso | Nota | Contrib. | Evidência · Fonte | Confiança | Status |
|---|---:|---:|---:|---|---|---|
| Segurança e isolamento | 25% | 2 | 0.50 | Reimplementar NLA/CredSSP/TLS/codecs = superfície nova que nós manteríamos · análise interna | Média | documental |
| NLA/CredSSP e compat. RDP | 20% | 1 | 0.20 | CredSSP/NTLM/Kerberos do zero é enorme e propenso a erro · MS-RDPBCGR/MS-CSSP | Média | UNVERIFIED (pendente) |
| Maturidade e manutenção | 15% | 1 | 0.15 | Viramos os únicos mantenedores de um codebase grande · análise interna | Alta | documental |
| Operação/atualização/troubleshoot. | 15% | 2 | 0.30 | Observabilidade total, mas todo bug é nosso · análise interna | Média | documental |
| Cliente web e transporte (próprios) | 10% | 4 | 0.40 | Cliente/transporte já são do PAM em qualquer opção · requisito de produto | Alta | documental |
| Gravação e auditoria | 10% | 4 | 0.40 | Controle total do formato · análise interna | Média | documental |
| Desempenho e escalabilidade | 5% | 2 | 0.10 | Provável desvantagem sem otimização madura · análise interna | Baixa | UNVERIFIED (pendente) |
| **Total preliminar** | | | **2.05** | | | |

### B — RDP Worker próprio sobre `libfreerdp` (preferencial)

| Critério | Peso | Nota | Contrib. | Evidência · Fonte | Confiança | Status |
|---|---:|---:|---:|---|---|---|
| Segurança e isolamento | 25% | 4 | 1.00 | Impl. de protocolo amplamente usada/auditada, encapsulada no nosso worker; há CVEs **e** correções ativas · Security Advisories FreeRDP (ver Baseline) | Média | documental (CVEs a revisar no smoke) |
| NLA/CredSSP e compat. RDP | 20% | 4 | 0.80 | `libfreerdp` implementa NLA/CredSSP, TLS e RDP moderno · repositório oficial FreeRDP (ver Baseline) | Média | UNVERIFIED (compat. real Windows/xrdp no smoke) |
| Maturidade e manutenção | 15% | 5 | 0.75 | Projeto maduro e mantido; `SECURITY.md`: série 3.x suportada; Apache-2.0 · FreeRDP (ver Baseline) | Alta | documental |
| Operação/atualização/troubleshoot. | 15% | 4 | 0.60 | Worker é nosso (bom troubleshooting); lib atualizada por digest fixado + SBOM · análise interna | Média | documental |
| Cliente web e transporte (próprios) | 10% | 4 | 0.40 | Cliente/transporte do PAM; worker↔gateway sob nosso protocolo · requisito de produto | Alta | documental |
| Gravação e auditoria | 10% | 4 | 0.40 | Worker nosso: definimos o que capturar da saída da lib · análise interna | Média | documental |
| Desempenho e escalabilidade | 5% | 4 | 0.20 | Núcleo em C, historicamente performático · projeto FreeRDP | Baixa | UNVERIFIED (baseline no smoke) |
| **Total preliminar** | | | **4.15** | | | |

### C — SDK RDP comercial

| Critério | Peso | Nota | Contrib. | Evidência · Fonte | Confiança | Status |
|---|---:|---:|---:|---|---|---|
| Segurança e isolamento | 25% | 3 | 0.75 | Depende da postura do fornecedor; fonte muitas vezes opaca · avaliação de fornecedor (pendente) | Baixa | UNVERIFIED |
| NLA/CredSSP e compat. RDP | 20% | 4 | 0.80 | SDKs comerciais costumam ter boa compat. · material do fornecedor | Baixa | UNVERIFIED |
| Maturidade e manutenção | 15% | 3 | 0.45 | Pode ser bom, mas há lock-in/EOL e custo · avaliação de fornecedor | Média | documental |
| Operação/atualização/troubleshoot. | 15% | 3 | 0.45 | Caixa-preta para troubleshooting; ciclos de licença · avaliação de fornecedor | Baixa | documental |
| Cliente web e transporte (próprios) | 10% | 3 | 0.30 | SDK pode empurrar componentes de cliente próprios · avaliação de fornecedor | Baixa | UNVERIFIED |
| Gravação e auditoria | 10% | 3 | 0.30 | Ganchos podem ser limitados pelo SDK · avaliação de fornecedor | Baixa | UNVERIFIED |
| Desempenho e escalabilidade | 5% | 4 | 0.20 | Costumam ser otimizados · material do fornecedor | Baixa | UNVERIFIED |
| **Total preliminar** | | | **3.25** | | | |

### Requisitos eliminatórios — por escopo de verificação (P0 / P1)

Todos são impostos pela **nossa** arquitetura (não pela engine). O que muda é
**onde cada um pode virar PASS/FAIL** — e um worker isolado **não** pode provar
controles que só existem no produto integrado:

- **Escopo P0 (worker isolado + alvo RDP real):** verificável já no smoke P0 do
  PR-17B, porque só exige o **RDP Worker + FreeRDP** contra um alvo real (sem
  broker, sem gateway do produto, sem navegador). Ver
  [`../rdp-smoke-runbook.md`](../rdp-smoke-runbook.md).
- **Escopo P1 (produto integrado):** só verificável **depois** que o produto RDP
  está completo — adapter (PR-17C), segurança/políticas (PR-17D), cliente web
  (PR-17E) e gravação/auditoria/operação (PR-17F) — com backend + gateway + cliente
  web + navegador reais no fluxo. Por isso o **P1 roda após o PR-17F**, nunca logo
  após o PR-17C. Ver
  [`../rdp-integration-p1-runbook.md`](../rdp-integration-p1-runbook.md). Enquanto
  o P1 não passar, estes permanecem **UNVERIFIED** e **o RDP não é habilitado em
  runtime**: `SUPPORTED_PROTOCOLS` continua `["vnc"]` até o **PR-17G**.

`Independência arquitetural` é a única avaliável **já agora** (decisão de produto/
licença), sem alvo real.

**Eliminatórios de escopo P0 (worker isolado):**

| Requisito eliminatório (P0) | A. do zero | B. Worker+libfreerdp | C. SDK comercial |
|---|---|---|---|
| NLA/CredSSP real contra Windows **e** xrdp | UNVERIFIED (P0) | UNVERIFIED (P0) | UNVERIFIED (P0) |
| Validação de certificado (confiável aceito / não confiável recusado) | UNVERIFIED (P0) | UNVERIFIED (P0) | UNVERIFIED (P0) |
| Nenhum segredo nos **logs do worker** (HR-06, escopo worker) | UNVERIFIED (P0) | UNVERIFIED (P0) | UNVERIFIED (P0) |
| Encerramento no worker derruba a conexão ao asset (watchdog) | UNVERIFIED (P0) | UNVERIFIED (P0) | UNVERIFIED (P0) |
| Egress do worker restrito aos assets/portas RDP autorizados | UNVERIFIED (P0) | UNVERIFIED (P0) | UNVERIFIED (P0) |
| CVE/SBOM da versão fixada sem vulnerabilidade aplicável não mitigada | UNVERIFIED (P0) | UNVERIFIED (P0) | UNVERIFIED (P0) |

**Eliminatórios de escopo P1 (produto integrado) — permanecem UNVERIFIED até o P1,
um worker isolado não os prova:**

| Requisito eliminatório (P1) | A. do zero | B. Worker+libfreerdp | C. SDK comercial |
|---|---|---|---|
| Credencial fora do navegador (HR-05) — HAR/WS/DOM/storage limpos | UNVERIFIED (P1) | UNVERIFIED (P1) | UNVERIFIED (P1) |
| Sessão iniciada **somente** por `assetId` (HR-01/HR-02) | UNVERIFIED (P1) | UNVERIFIED (P1) | UNVERIFIED (P1) |
| Token efêmero de uso único no broker (correlação sessão↔worker) | UNVERIFIED (P1) | UNVERIFIED (P1) | UNVERIFIED (P1) |
| Auditoria completa: usuário, asset, IP de origem, `protocol` (HR-10) | UNVERIFIED (P1) | UNVERIFIED (P1) | UNVERIFIED (P1) |
| Sem destino controlado pelo frontend — só o backend resolve (HR-08) | UNVERIFIED (P1) | UNVERIFIED (P1) | UNVERIFIED (P1) |
| Encerramento **administrativo pelo produto** derruba a sessão | UNVERIFIED (P1) | UNVERIFIED (P1) | UNVERIFIED (P1) |
| Sem rota direta do usuário ao worker/asset (HR-07) | UNVERIFIED (P1) | UNVERIFIED (P1) | UNVERIFIED (P1) |
| Nenhum segredo em log **fim-a-fim** (frontend + gateway + worker) | UNVERIFIED (P1) | UNVERIFIED (P1) | UNVERIFIED (P1) |

**Eliminatório avaliável já agora (decisão de produto):**

| Requisito eliminatório | A. do zero | B. Worker+libfreerdp | C. SDK comercial |
|---|---|---|---|
| Independência arquitetural | **PASS** | **PASS** | **UNVERIFIED** (risco de licença/lock-in) |

### Resumo e o que depende de cada gate

| Alternativa | Total preliminar | Eliminatórios |
|---|---:|---|
| B. Worker+libfreerdp | **4.15** | independência PASS; P0 e P1 UNVERIFIED (gates) |
| C. SDK comercial | 3.25 | independência UNVERIFIED; P0 e P1 UNVERIFIED |
| A. do zero | 2.05 | independência PASS; P0 e P1 UNVERIFIED (gates) |

- **Depende do smoke P0** (converte os eliminatórios **P0** UNVERIFIED→PASS/FAIL e
  ajusta as notas empíricas): NLA/CredSSP real contra Windows e xrdp; validação de
  certificado; baseline de desempenho/recursos; encerramento worker→asset; egress
  restrito; ausência de segredo nos **logs do worker**; revisão de CVEs/SBOM da
  versão fixada. **Verde aqui desbloqueia o PR-17C (integração), não o runtime.**
- **Depende do P1** (converte os eliminatórios **P1** UNVERIFIED→PASS/FAIL): os
  controles fim-a-fim do produto (credencial fora do navegador, sessão só por
  `assetId`, token de uso único, auditoria completa, sem destino do frontend,
  encerramento administrativo, sem rota direta, sem segredo em log ponta-a-ponta).
  **Só o P1 verde autoriza habilitar o RDP em runtime.**

## Terminologia (precisão)

- O **RDP Worker**, o **transporte** gateway↔worker e o **cliente web** são
  componentes **próprios do PAM**.
- A **implementação do protocolo RDP** é **fornecida pela `libfreerdp`** (Apache-2.0),
  encapsulada no worker. **Não** afirmamos ter desenvolvido o protocolo RDP inteiro.

## Decisão (condicional)

**Candidato preferencial: RDP Worker próprio do PAM encapsulando `libfreerdp`.**
Justificativa: reaproveita a mecânica de protocolo mais sensível (NLA/CredSSP/TLS)
como **biblioteca**, preservando engine, transporte e cliente **próprios** e a
independência arquitetural — sem o serviço/protocolo do Guacamole e sem o lock-in
de um SDK comercial. **Sujeito a:** preenchimento da matriz com evidência e
aprovação no **smoke P0** contra o Worker+FreeRDP. Se falhar um eliminatório ou o
smoke P0, reabrimos entre engine própria e SDK comercial.

## Alternativas rejeitadas

- **Guacamole / `guacd`:** rejeitado por **decisão de produto** (restrição
  arquitetural): acoplaria o PAM ao protocolo/serviço Guacamole e ao
  `guacamole-common-js`, contrariando o objetivo de termos camada de sessão e
  cliente próprios.
- **Engine RDP totalmente própria:** não preferida — o ônus da prova é dela;
  reimplementar NLA/CredSSP/TLS/codecs é risco de segurança e esforço altos.
  Reavaliada só se o Worker+libfreerdp for reprovado.
- **SDK RDP comercial:** alternativa condicionada a licença, custo, suporte e
  independência; reavaliada se o Worker+libfreerdp for reprovado.

## Baseline do FreeRDP (governança da dependência)

| Item | Valor |
|---|---|
| Versão documental avaliada | **FreeRDP 3.28.0** (release estável mais recente, 2026-07-06; "Feature and bugfix release") |
| Licença | **Apache-2.0** (compatível com encapsulamento como biblioteca) |
| Série suportada | **3.x** (`stable-3.0` e `master`) — a série **2.x é PROIBIDA** (fora de suporte, conforme `SECURITY.md`) |
| Versão efetivamente homologada | **pendente do smoke P0** |
| Versão permitida em produção | **digest/artefato fixado** (pin por digest, nunca "latest") |
| Política de atualização | acompanhar advisories; atualizar por PR com re-validação; sem atualização automática para "o mais recente" |
| Política de CVE | **bloquear** release com vulnerabilidade aplicável não mitigada — um CVE aplicável sem correção reprova a versão |
| SBOM | gerar e versionar o SBOM do worker (worker + `libfreerdp` + deps nativas) |
| Dependências nativas relevantes | `libfreerdp` (C) e suas deps de TLS/crypto (ex.: OpenSSL) — entram no SBOM e na política de CVE |

**Fontes oficiais (consultadas em 2026-07-13):**

- Repositório oficial do projeto FreeRDP —
  <https://github.com/FreeRDP/FreeRDP>.
- Release estável **3.28.0** (2026-07-06) e histórico de releases —
  <https://github.com/FreeRDP/FreeRDP/releases>.
- `SECURITY.md` (matriz de suporte: `3.x.x`/`stable-3.0` e `master` **suportados**;
  `2.x.x`/`stable-2.0` e `< 2.0.0` **não suportados**) —
  <https://github.com/FreeRDP/FreeRDP/blob/master/SECURITY.md>.
- Security Advisories oficiais do projeto (base para a política de CVE acima) —
  <https://github.com/FreeRDP/FreeRDP/security/advisories>.

> A versão **3.28.0** e a matriz de suporte 3.x/2.x foram confirmadas nessas fontes
> na data acima. O smoke P0 revalida a versão efetivamente homologada e reexecuta a
> revisão de CVEs/advisories contra o digest fixado — a lista de CVEs muda com o
> tempo, então a checagem é refeita a cada atualização de versão.

## Transporte gateway↔worker (política determinística)

O trecho gateway↔worker é elo sensível. A política **não** é "TLS e/ou rede
isolada"; é determinística por topologia:

- **Worker no mesmo host:** **Unix Domain Socket** com permissões restritas
  (dono/modo) **+ validação da identidade do processo** (peer credentials).
- **Worker em outro container/host:** **mTLS + identidade de serviço + rede
  dedicada + allowlist de origem** (somente o gateway) **e de egress** (somente
  assets e portas RDP autorizados).
- **TCP interno em texto claro (sem autenticação/criptografia) é PROIBIDO.**

Correlação estrita: cada conexão criada no worker é atada à sessão do broker (token
efêmero de uso único), como no VNC.

## Riscos residuais

- **libfreerdp** é dependência nativa (C) — superfície, CVEs e janela de patch a
  acompanhar (ver baseline/SBOM/política de CVE acima); encapsulamento no worker
  reduz o blast radius, não o elimina.
- **Transporte gateway↔worker:** mitigado pela política determinística acima; a
  implementação e o teste ficam no PR-17B (spike) e são validados no smoke P0.
- **Gravação:** `PAMREC01` é orientado a RFB; RDP exige estratégia própria — o
  worker é nosso, então temos liberdade de formato, mas é trabalho do PR-17F.
- Ambiente atual (`docker pull` bloqueado) impede o smoke P0 aqui — daí o status
  condicional e o gate abaixo.

## Condições para virar `Accepted` definitivo (gate não-circular, dois níveis)

Há **dois gates empíricos distintos**, porque um worker isolado não pode provar os
controles do produto integrado. Cada gate valida um artefato que **precisa existir
primeiro**. Por isso a ordem é:

```text
PR-17A (decisão) → PR-17B (worker isolado) → SMOKE P0 (worker) →
PR-17C (adapter + broker/registry, perfil de laboratório) → PR-17D (NLA/CredSSP,
cert, canais, políticas) → PR-17E (cliente web e transporte próprios) →
PR-17F (gravação, auditoria, métricas, lifecycle, operação) → GATE P1 (produto
integrado end-to-end) → PR-17G (habilitação controlada do RDP em runtime)
```

O **P1 vem depois do PR-17F**, porque ele exige justamente o que os PRs 17D/17E/17F
entregam (cliente web, políticas de segurança, auditoria completa, encerramento
administrativo, gravação e operação). Colocar o P1 logo após o PR-17C seria
impossível — não haveria o que testar.

### Gate P0 — aceita a **engine** ([`../rdp-smoke-runbook.md`](../rdp-smoke-runbook.md))

A ADR passa de `Accepted — Conditional` para **`Accepted`** quando o **smoke P0**
rodar contra o **worker do PR-17B**, num host com Docker + alvos RDP reais (Windows
**e** xrdp), com todos os itens P0 verdes e os **eliminatórios de escopo P0 PASS**.
Isso **aceita apenas a engine** (RDP Worker sobre `libfreerdp` como implementação de
protocolo escolhida) e desbloqueia o **início do PR-17C**. **Não** significa que o
RDP está pronto para usuários. O PR-17B **não** toca em gateway/backend/registry/UI
nem habilita `protocol=rdp` — é apenas worker/harness de laboratório.

### Gate P1 — aceita o **adapter como produto** ([`../rdp-integration-p1-runbook.md`](../rdp-integration-p1-runbook.md))

Executado **somente depois dos PRs 17C, 17D, 17E e 17F**, o P1 valida o produto RDP
integrado end-to-end (fluxo por `assetId`; navegador sem credencial nem destino
técnico; backend resolvendo destino/credencial; token de uso único; políticas de
canais; auditoria; encerramento administrativo; isolamento de rede; gravação e
operação; ausência de segredos em todos os componentes).

**Política de runtime — única e determinística (sem "ou"):** até o **PR-17G**,
`SUPPORTED_PROTOCOLS` permanece **`["vnc"]`**. Durante os PRs 17C–17F a integração é
exercitada **apenas por testes e por um perfil de laboratório explicitamente
separado**, que **recusa inicialização quando `PAM_ENV=production`** — sem UI RDP
pública, sem rota pública de sessão RDP e sem asset RDP aceito pela API de produção.
Só **após o gate P1 verde**, o **PR-17G** altera para
`SUPPORTED_PROTOCOLS = ["vnc", "rdp"]` e libera o RDP a usuários.
