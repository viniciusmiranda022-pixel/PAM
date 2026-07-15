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
por isso a ordem é `PR-17A (decisão) → PR-17B0 (contrato, docs-only) → PR-17B
(worker isolado) → smoke P0 → PR-17C (integração)`, sem ciclo.

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
- O worker do PR-17B — **`privion-rdp-worker-lab`** (C++20 sobre a API C do
  **FreeRDP 3.28.0 fixado por source**; contrato em
  [`adr/0006-rdp-worker-spike.md`](adr/0006-rdp-worker-spike.md)). O smoke testa o
  **nosso worker + FreeRDP**, nunca guacd.
- Um **harness de laboratório** que injeta no worker o destino `(ip, porta,
  domínio)` via `lab-targets.json` (não secreto) e a **credencial via fd/secret-file
  `0400`** — no P0 **o harness controla o destino** (não há backend nem frontend
  ainda).

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

## Driver de execução (`run-p0.sh`)

O driver [`rdp-worker/scripts/run-p0.sh`](../rdp-worker/scripts/run-p0.sh)
executa **um** job por cenário e grava uma evidência **sem segredos**. Ele
**não aprova o P0**: grava a evidência e calcula um veredito por cenário; a
aceitação é humana (operador + revisor no
[`rdp-p0-evidence-template.md`](rdp-p0-evidence-template.md)).

**Segredo fora do shell.** A credencial nunca entra em variável de shell, `argv`,
env ou `set -x`. Só o helper
[`p0-evidence-secret-scan.py`](../rdp-worker/scripts/p0-evidence-secret-scan.py)
abre o arquivo `0400` (`O_NOFOLLOW` + `fstat`: arquivo regular, dono == euid, modo
exatamente `0400`, teto de tamanho), lê os bytes internamente e devolve só um
token (`OK` / `CLEAN` / `LEAK_PRESENT`) — nunca a senha, nem em erro. O harness lê
o mesmo arquivo `0400` diretamente para entregá-lo ao worker.

**Sentinela do pacote completo.** O scan de vazamento roda **por último**, depois
de logs, `facts.kv`, `resources.txt`, `manifest.json`, `summary.json` e
`summary.txt` estarem finalizados; ele varre o diretório inteiro e então grava
**apenas** `secret-sentinel.json` (`CLEAN`/`LEAK_PRESENT`). Nenhum outro arquivo
é alterado depois do scan.

**Gate de selftest.** Antes de iniciar qualquer sessão, o driver executa
`worker --selftest` e **recusa (rc 2)** se o selftest falhar, se o worker não for
um build nativo, ou se a versão do FreeRDP não for **exatamente 3.28.0**.

**`PRIVION_EXPECTED_RESULT`** (explícito por cenário; o nome em
`PRIVION_SCENARIO` é só rótulo e nunca influencia o veredito): `connect`,
`auth_reject`, `cert_trusted`, `cert_reject`, `egress_denied`, `watchdog`,
`asset_disconnect`, `network_unreachable`, `terminate`. Coerência exigida:
`terminate` **requer** `PRIVION_SESSION_SECONDS`; `watchdog` e `asset_disconnect`
exigem-no **ausente** (senão a causa do encerramento fica ambígua por construção).

**Códigos de saída do driver (só `PASS` retorna zero):** `0` veredito `PASS` e
sentinela `CLEAN`; `2` pré-condição (env, binário, gate de selftest, credencial
ou alvo inválido — nada foi iniciado); `10` operacional (UDS não surgiu, worker
morreu antes do socket, watchdog do driver); `20` veredito `FAIL`; `25` veredito
`INCONCLUSIVE` (consistente, mas exige confirmação do operador — **nunca**
sucesso); `30` **vazamento** (credencial encontrada no pacote final — parada
dura, sobrepõe qualquer veredito).

### Pré-requisitos de execução (diretório exato)

Execute **a partir de `rdp-worker/`** (o driver resolve os binários por caminho
relativo e grava as evidências em `./p0-evidence/`):

```bash
cd rdp-worker
./scripts/build.sh --native      # produz build-native/privion-rdp-worker-lab
                                 # e build-native/harness/privion-rdp-lab-harness
./build-native/privion-rdp-worker-lab --selftest   # confirma FreeRDP 3.28.0
```

Arquivo de alvo **não secreto** (um por alvo), ex. `lab-targets-win.json`:

```json
{ "address": "10.0.0.21", "port": 3389, "domain": "LAB" }
```

Credencial de laboratório em arquivo `0400` de sua posse (rotacione após o P0):

```bash
umask 077
printf '%s' 'senha-de-laboratorio' > ./cred.0400
chmod 0400 ./cred.0400            # dono == você; sem newline final é aceito
```

### Trust store do certificado (cenários 4 e 5) — mecanismo PROPOSTO

O worker delega a verificação do certificado ao **trust store do OpenSSL** do
processo; o callback do worker só é chamado quando a verificação automática
**falhou**, e então **recusa** (a menos que o *accept-once* de laboratório
`PRIVION_LAB_TOFU_CERT=1` esteja ligado — que **invalida** qualquer veredito de
`cert_trusted`/`cert_reject`).

> **Status: proposto e configurado, ainda não comprovado.** A configuração abaixo
> é a preparação; a **efetividade** (se a combinação FreeRDP/OpenSSL realmente
> consome o caminho configurado, inclusive `SSL_CERT_FILE`) **só é comprovada
> pelos cenários reais 4 e 5**: `TOFU=0` + CA controlada + certificado encadeado
> **aceito** + certificado desconhecido **recusado**. Não afirmar homologação
> antes disso.

- **Build nativo no host:** usa `/etc/ssl/certs` (pacote `ca-certificates` do
  host). Para uma **CA interna de laboratório**, aponte um bundle **read-only**:
  `export SSL_CERT_FILE=/etc/pki/lab-ca.pem` (arquivo somente leitura).
- **Execução na imagem do worker:** a imagem runtime inclui `ca-certificates`
  (ver [`rdp-worker/Dockerfile`](../rdp-worker/Dockerfile)). Para uma CA interna,
  monte o bundle **read-only** (`-v /etc/pki/lab-ca.pem:/etc/pki/lab-ca.pem:ro`)
  e defina `SSL_CERT_FILE=/etc/pki/lab-ca.pem` no ambiente do worker.

Rode os cenários 4 e 5 com `PRIVION_LAB_TOFU_CERT=0`. Anexe a cadeia / impressão
digital observada à evidência; **não** presuma confiança sem a cadeia.

### Execução por cenário

Todos os comandos abaixo assumem `cd rdp-worker` e as variáveis comuns:

```bash
export PRIVION_TARGET_FILE=./lab-targets-win.json   # ou ./lab-targets-xrdp.json
export PRIVION_USERNAME='LAB\labuser'
export PRIVION_CRED_FILE=./cred.0400
```

**1. Windows com NLA (eliminatório):**

```bash
PRIVION_SCENARIO=windows-nla PRIVION_EXPECTED_RESULT=connect \
PRIVION_SESSION_SECONDS=10 PRIVION_MAX_SECONDS=30 \
./scripts/run-p0.sh
```

**2. xrdp (eliminatório):** igual ao (1), com o alvo xrdp:

```bash
PRIVION_TARGET_FILE=./lab-targets-xrdp.json \
PRIVION_SCENARIO=xrdp PRIVION_EXPECTED_RESULT=connect \
PRIVION_SESSION_SECONDS=10 PRIVION_MAX_SECONDS=30 \
./scripts/run-p0.sh
```

**3. Credencial inválida (eliminatório):** use um `cred.0400` com senha errada:

```bash
PRIVION_CRED_FILE=./cred-wrong.0400 \
PRIVION_SCENARIO=cred-invalid PRIVION_EXPECTED_RESULT=auth_reject \
./scripts/run-p0.sh
```

**4. Certificado confiável (eliminatório):** alvo com cert que encadeia no trust
store (ver acima), `TOFU=0` (com `TOFU=1` o driver **reprova** o cenário):

```bash
PRIVION_LAB_TOFU_CERT=0 \
PRIVION_SCENARIO=cert-trusted PRIVION_EXPECTED_RESULT=cert_trusted \
PRIVION_SESSION_SECONDS=10 \
./scripts/run-p0.sh
```

**5. Certificado não confiável (eliminatório):** alvo com cert desconhecido/auto-
assinado, `TOFU=0` (o worker deve recusar):

```bash
PRIVION_LAB_TOFU_CERT=0 \
PRIVION_SCENARIO=cert-untrusted PRIVION_EXPECTED_RESULT=cert_reject \
./scripts/run-p0.sh
```

**6. Host na allowlist (eliminatório):** allowlist derivada do alvo (padrão):

```bash
PRIVION_SCENARIO=host-allowed PRIVION_EXPECTED_RESULT=connect \
PRIVION_SESSION_SECONDS=10 \
./scripts/run-p0.sh
```

**7. Host fora da allowlist (eliminatório):** allowlist aponta para outro host:

```bash
PRIVION_ALLOW_TARGET=192.0.2.99:3389 \
PRIVION_SCENARIO=host-denied PRIVION_EXPECTED_RESULT=egress_denied \
./scripts/run-p0.sh
```

**8. Porta fora da allowlist (eliminatório):** allowlist com a porta errada:

```bash
PRIVION_ALLOW_TARGET=10.0.0.21:3390 \
PRIVION_SCENARIO=port-denied PRIVION_EXPECTED_RESULT=egress_denied \
./scripts/run-p0.sh
```

**9. Encerramento por TERMINATE (eliminatório):** `PRIVION_SESSION_SECONDS` é
**obrigatório** aqui (o harness envia o TERMINATE; sem ele o driver recusa rc 2):

```bash
PRIVION_SCENARIO=terminate PRIVION_EXPECTED_RESULT=terminate \
PRIVION_SESSION_SECONDS=8 PRIVION_MAX_SECONDS=60 \
./scripts/run-p0.sh
```

**10. Watchdog (eliminatório):** `PRIVION_SESSION_SECONDS` deve estar **ausente**
(o driver recusa rc 2 se estiver definido — TERMINATE tornaria a causa ambígua);
watchdog curto:

```bash
unset PRIVION_SESSION_SECONDS
PRIVION_SCENARIO=watchdog PRIVION_EXPECTED_RESULT=watchdog \
PRIVION_MAX_SECONDS=8 \
./scripts/run-p0.sh
```

**11. Desconexão pelo asset (eliminatório):** `PRIVION_SESSION_SECONDS` deve
estar **ausente** (o driver recusa rc 2 se estiver definido); derrube a sessão
**no lado do alvo** durante a janela:

```bash
unset PRIVION_SESSION_SECONDS
PRIVION_SCENARIO=asset-disconnect PRIVION_EXPECTED_RESULT=asset_disconnect \
PRIVION_MAX_SECONDS=60 \
./scripts/run-p0.sh
```

**12. Rede indisponível (diagnóstico — falha fechada):** alvo na allowlist mas
inalcançável; o veredito exige **ausência de `connected`** (falha fechada) e sai
`INCONCLUSIVE` (rc 25) para o operador confirmar a causa de rede no
`worker-stderr.txt`; se conectar, é `FAIL` (rc 20):

```bash
PRIVION_SCENARIO=net-unavailable PRIVION_EXPECTED_RESULT=network_unreachable \
PRIVION_SOCKET_TIMEOUT=15 \
./scripts/run-p0.sh
```

**13. SIGTERM / SIGINT (diagnóstico):** em outro terminal, envie o sinal ao
processo `run-p0.sh` durante a sessão; o driver derruba worker+harness sem deixar
órfãos e remove o socket/`tmpdir` (sai `143`/`130`).

**14. Repetição de N sessões (diagnóstico — baseline):** rode o cenário (1) em
laço `for i in $(seq 1 N)` e agregue `duration_ms_to_connected` (de cada
`summary.json`) e `cpu_user_seconds` / `cpu_system_seconds` /
`worker_peak_rss_kb` / `duration_monotonic_ms` (de cada `resources.txt`).

**15. Ausência de segredo (eliminatório):** confirmado automaticamente em **cada**
execução — o `secret-sentinel.json` (gravado por último, após o pacote completo)
deve ser `CLEAN` em todas; um `LEAK_PRESENT` sai `rc=30` (parada dura).

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

Preencha uma cópia de [`rdp-p0-evidence-template.md`](rdp-p0-evidence-template.md)
(campos começam `PENDENTE`; operador + revisor assinam). Converter os `UNVERIFIED`
de **escopo P0** da **matriz de decisão** da ADR 0005 em PASS/FAIL e atualizar as
notas empíricas (NLA/CredSSP, desempenho) com evidência; anexar:
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
