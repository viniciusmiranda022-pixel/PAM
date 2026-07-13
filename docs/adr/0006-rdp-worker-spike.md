# ADR 0006 — Contrato de implementação do RDP Worker (PR-17B0)

- **Status:** **Accepted** (contrato congelado; nenhum código escrito nesta ADR)
- **Data:** 2026-07-13
- **Contexto de PR:** **PR-17B0 — RDP Worker implementation contract**
  (**docs-only**: decide **como** o worker será construído e validado). O
  **PR-17B** fica **reservado para a implementação real** do worker isolado
  (C++20 + FreeRDP + CI), que só inicia **após o merge deste contrato** e deve
  **obedecê-lo** — separando contrato e código, o código tem de seguir o desenho
  aprovado, e não o contrário.
- **Relacionado:** [`0005-rdp-engine.md`](0005-rdp-engine.md) (decisão de engine),
  [`../protocols/rdp-worker-spike.md`](../protocols/rdp-worker-spike.md) (desenho),
  [`../threat-models/rdp.md`](../threat-models/rdp.md),
  [`../rdp-smoke-runbook.md`](../rdp-smoke-runbook.md) (gate P0),
  [`../rdp-integration-p1-runbook.md`](../rdp-integration-p1-runbook.md) (gate P1).

## Contexto

A [ADR 0005](0005-rdp-engine.md) decidiu **o quê**: engine = **RDP Worker próprio do
PAM encapsulando `libfreerdp`**, condicionada ao smoke **P0**. Antes de qualquer
código, é preciso decidir **como** o spike será construído e validado, **sem
ultrapassar o escopo aprovado**: o worker encapsula `libfreerdp`, permanece
inacessível ao navegador, e o P0 valida **apenas a engine** — sem habilitar RDP.

Esta ADR (**PR-17B0**) **congela** esse contrato. Ela não implementa o worker — a
implementação é o **PR-17B**, na sequência:

```text
PR-17A   Decisão da engine — mergeado
PR-17B0  Contrato de implementação — docs-only (este PR)
PR-17B   Worker C++20 + FreeRDP + CI
P0       Validação real contra Windows e xrdp
PR-17C   Integração ao broker/registry em laboratório
```

## Decisões congeladas

### 1. Linguagem e binding
**C++20 fino sobre a API C oficial do FreeRDP, com CMake.** Chamada direta a
`libfreerdp`; **RAII** para sessão, sockets e buffers (teardown determinístico);
encapsulamento da dependência nativa num **processo separado**. O código permanece
**pequeno** — sem framework C++ nem abstração genérica de protocolo.

**Proibido:** Node + FFI, `koffi`, Rust neste spike, e **executar `xfreerdp` como
subprocesso** (o worker linka a lib; não terceiriza para um binário cliente).

### 2. Localização
**Novo diretório top-level `rdp-worker/`.** **Não** dentro de
`gateway/src/adapters/`, `backend/`, `frontend/` nem em `infra/docker-compose.yml` —
para que o spike **não** seja interpretado como adapter integrado ou serviço de
produção.

### 3. Aquisição do FreeRDP
**Compilar o FreeRDP 3.28.0 a partir do source oficial fixado** (release estável de
2026-07-06 — ver baseline na ADR 0005). Fixações **obrigatórias**, registradas no
`Dockerfile`/`cmake/FreeRDP.cmake` e verificadas no CI:

- **tag** (`3.28.0`);
- **commit SHA** correspondente à tag;
- **SHA-256** do arquivo de source;
- **imagem-base do builder** por digest;
- **imagem-base do runtime** por digest;
- **dependências nativas** registradas no SBOM.

**Proibido:** `apt install freerdp`, `latest`, `master`, ou qualquer pacote de
distribuição não fixado (pode mudar sem mudança no repositório e não oferece o
controle exigido para homologação).

> **Nota de honestidade:** os valores concretos de commit SHA, SHA-256 do source e
> digests das imagens-base são **registrados na implementação** (no `Dockerfile` e no
> `cmake/FreeRDP.cmake`) e conferidos pelo CI. Esta ADR fixa a **política** e a
> **tag `3.28.0`**; não grava hashes inventados.

### 4. CI
O PR-17B **já** adiciona um job nativo próprio: **`rdp-worker-build-test`**. Ele:

1. constrói a imagem do worker;
2. compila o worker + FreeRDP fixado (warnings tratados como erro);
3. executa os testes unitários;
4. executa `--selftest`;
5. **confirma a versão carregada** do FreeRDP (== 3.28.0 fixado);
6. executa o **teste-sentinela de logs**;
7. **gera o SBOM**;
8. **publica o SBOM** como artifact;
9. **verifica que nenhum runtime do produto referencia `rdp-worker`**.

O **P0 real** (Windows/xrdp) permanece **fora** do CI comum, mas o **build nativo não
pode ser adiado** para o P0 — ele é obrigatório no CI do PR-17B.

**Barreira de escopo:** o `scan-secrets.sh` atual já percorre **todos** os arquivos
versionados (cobre o novo diretório). O `scan-forbidden-deps.sh` atual examina
**apenas** os manifestos Node (backend/gateway/frontend/tests) — **não** protege o
worker nativo. Por isso o PR-17B cria **`scripts/ci/check-rdp-worker-scope.sh`**, que
**falha** quando:

- `SUPPORTED_PROTOCOLS` **não** for exatamente `["vnc"]`;
- gateway, backend ou frontend **importarem/referenciarem** o worker;
- o Compose principal **registrar** o worker;
- aparecer **rota/endpoint/UI pública RDP**;
- o worker abrir **listener TCP**;
- surgir dependência de **Guacamole/`guacd`/cliente Guacamole**.

### 5. Credencial do harness
**Não** usar variável de ambiente, `argv` nem `lab.config` para a senha. A credencial
chega ao harness por **file descriptor herdado** **ou** **secret file `0400`** montado
só para o teste. O arquivo de targets (`lab-targets.example.json`) contém **apenas
dados não secretos** (`targetAlias`, `address`, `port`, `domain`).

Caminho preferencial da credencial:

```text
secret file 0400 → harness → frame protegido na UDS → secure buffer do worker → libfreerdp
```

A senha: não entra em `argv`, env, repositório nem no arquivo de targets; é **lida
uma vez**; transmitida ao worker pela UDS; o **buffer é sobrescrito** após a entrega à
API do FreeRDP; **nunca** aparece em log.

### 6. Auditoria
**Somente eventos técnicos locais de lifecycle.** O PR-17B **não** implementa a
auditoria completa HR-10.

- **Campos permitidos:** `timestamp`, `labJobId`, `targetAlias`, `state`, `result`,
  `reasonCode`, `durationMs`, `workerPid`, `freerdpVersion`.
- **Não simular:** `userId`, `assetId` de produção, `sourceIp` do usuário,
  `approvalId`, `session broker token` — não existem legitimamente no spike; inventá-
  los daria falsa impressão de conformidade. Auditoria completa fica para PR-17F/P1.

## Políticas adicionais (regras absolutas do spike)

- worker/harness **somente** por Unix Domain Socket, modo **0600** + **peer
  credentials**;
- **sem** listener TCP, HTTP, WebSocket ou porta publicada;
- binário **`privion-rdp-worker-lab`** (identidade explícita de laboratório);
- compilação com flag obrigatório **`PRIVION_LAB_ONLY=ON`** — **não existe build de
  produção** do worker neste PR;
- **recusa de inicialização** quando `PAM_ENV=production`;
- `SUPPORTED_PROTOCOLS` permanece `["vnc"]`;
- **sem**: registry, broker, backend, frontend, API pública, suporte de produção,
  destino fornecido por usuário, proxy byte-a-byte, Guacamole.

Arquitetura congelada:

```text
Harness de laboratório
        │  Unix Domain Socket (modo 0600 + peer credentials)
        ▼
Privion RDP Worker — LAB ONLY  (privion-rdp-worker-lab, PRIVION_LAB_ONLY=ON)
        │  API C do FreeRDP
        ▼
libfreerdp 3.28.0 fixado (source por tag + commit SHA + SHA-256)
        ▼
Windows RDP (NLA) / xrdp de laboratório
```

## Escopo

**Dentro (PR-17B):** worker C++20 isolado; carga da `libfreerdp` fixada; config de
lab (targets não secretos); lifecycle da conexão; redação de logs; watchdog;
transporte UDS; allowlist/egress de lab; testes unitários; build reproduzível; SBOM;
job de CI nativo + scope guard; instruções do P0.

**Fora (PR-17B):** adapter RDP no registry; alteração de `SUPPORTED_PROTOCOLS`;
backend aceitando assets RDP; rota/UI pública; WebSocket ao usuário; integração ao
broker; auditoria completa do produto; gravação; execução em produção; host/porta
arbitrários vindos de usuário.

## Impacto HR-01…HR-10

| HR | Como o spike respeita |
|---|---|
| HR-01/02 | worker não aceita destino de "usuário"; só job do harness; sem UI/rota |
| HR-03 | backend é a fonte de verdade → **N/A no spike**; harness é stand-in **documentado**, não o caminho de produto |
| HR-04 | allowlist de lab = só a porta RDP (3389) ao asset |
| HR-05 | credencial via fd/secret-file → UDS → secure buffer → libfreerdp; nunca a browser (não há); nunca logada |
| HR-06 | redação + teste-sentinela; buffer sobrescrito após uso |
| HR-07 | worker em rede interna de lab; sem rota de usuário; egress restrito |
| HR-08 | destino fora da allowlist → recusado (sem destino arbitrário) |
| HR-09 | **não é túnel byte-a-byte**: termina RDP via libfreerdp; **não** está no registry (isso é 17C) |
| HR-10 | eventos técnicos de lifecycle locais; auditoria completa (user/asset/IP) é **17F/P1 — fora** |

## Riscos residuais

- **Binding nativo (`libfreerdp`, C):** superfície/CVEs — mitigado por processo
  isolado, fronteira única (`freerdp_client`), source fixado + SBOM + política de CVE
  (ADR 0005).
- **Logs nativos (WLog) vazando dados:** captura + redação + sentinela.
- **Build reproduzível:** exige host com `docker pull` liberado (o sandbox de dev não
  tem) — por isso o **build nativo roda no CI** (GitHub Actions), não no sandbox.
- **P0 real indisponível aqui:** Windows/xrdp reais ficam no host externo do P0.

## Gate

Concluído o **PR-17B** (código do worker + CI verde, **obedecendo este contrato do
PR-17B0**), o **smoke P0**
([`../rdp-smoke-runbook.md`](../rdp-smoke-runbook.md)) valida o worker contra alvos
reais e **aceita a engine** (ADR 0005 → `Accepted`), desbloqueando o **PR-17C**. O RDP
**não** é habilitado em runtime — isso depende do **gate P1** (após 17F) e do
**PR-17G**.
