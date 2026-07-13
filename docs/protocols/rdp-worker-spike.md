# Desenho do RDP Worker (contrato PR-17B0 → implementação PR-17B) — LAB ONLY

> **Estado: contrato congelado (PR-17B0, docs-only), ainda não implementado.**
> Documenta **como** o worker será construído e validado; a **implementação real é o
> PR-17B**, que só inicia após o merge deste contrato e deve obedecê-lo. Decisões em
> [`../adr/0006-rdp-worker-spike.md`](../adr/0006-rdp-worker-spike.md); engine em
> [`../adr/0005-rdp-engine.md`](../adr/0005-rdp-engine.md); ameaças em
> [`../threat-models/rdp.md`](../threat-models/rdp.md). `SUPPORTED_PROTOCOLS`
> permanece `["vnc"]`; o worker é **laboratório**, sem integração ao produto.

## 1. Arquitetura interna

Processo isolado (`privion-rdp-worker-lab`), um job por conexão UDS. Sem porta
pública; a única entrada é o UDS do harness.

```text
harness de laboratório ──UDS(0600 + peer creds)──▶ Privion RDP Worker (LAB ONLY)
                                                     ├─ uds_server      (listener + SO_PEERCRED)
                                                     ├─ config/policy   (destino só do harness; allowlist)
                                                     ├─ credential      (secure_buffer; injeta; nunca loga)
                                                     ├─ freerdp_client  (ÚNICA fronteira com libfreerdp)
                                                     ├─ lifecycle       (connect → session → teardown)
                                                     ├─ watchdog        (terminate → derruba o asset)
                                                     └─ log_redaction   (captura WLog + redige segredos)
                                                              └────▶ libfreerdp 3.28.0 ──▶ asset RDP de lab
```

`freerdp_client` é a **fronteira de encapsulamento**: nenhum outro módulo conhece a
API do FreeRDP, e nada acima do worker alcança a lib.

## 2. Árvore de arquivos (a criar no PR-17B — implementação)

```text
rdp-worker/
├── CMakeLists.txt
├── README.md
├── Dockerfile                      # build reproduzível: bases por digest + FreeRDP 3.28.0 fixado
├── cmake/
│   └── FreeRDP.cmake               # source por tag + commit SHA + SHA-256
├── include/privion/rdp/
│   ├── config.hpp
│   ├── credential.hpp
│   ├── freerdp_client.hpp
│   ├── lifecycle.hpp
│   ├── log_redaction.hpp
│   ├── policy.hpp
│   ├── secure_buffer.hpp
│   └── uds_server.hpp
├── src/
│   ├── main.cpp                    # recusa PAM_ENV=production; abre UDS; aceita 1 job
│   ├── config.cpp
│   ├── credential.cpp
│   ├── freerdp_client.cpp
│   ├── lifecycle.cpp
│   ├── log_redaction.cpp
│   ├── policy.cpp
│   ├── secure_buffer.cpp
│   └── uds_server.cpp
├── harness/
│   ├── CMakeLists.txt
│   ├── main.cpp                    # lê credencial de fd/secret-file 0400; frame protegido na UDS
│   └── lab-targets.example.json    # só dados NÃO secretos
├── tests/
│   ├── lifecycle_test.cpp
│   ├── log_redaction_test.cpp
│   ├── policy_test.cpp
│   ├── secure_buffer_test.cpp
│   └── uds_server_test.cpp
└── scripts/
    ├── build.sh
    ├── generate-sbom.sh
    ├── run-selftest.sh
    └── run-p0.sh

scripts/ci/
└── check-rdp-worker-scope.sh       # barreira anti-integração acidental

docs/
├── adr/0006-rdp-worker-spike.md    # (este PR)
└── protocols/rdp-worker-spike.md   # (este arquivo)
```

## 3. Fluxo de credencial (HR-05/HR-06)

```text
secret file 0400 (ou fd herdado)
      → harness (lê uma vez)
      → frame protegido na UDS
      → secure_buffer do worker
      → API do FreeRDP
      → buffer sobrescrito
```

Regras: a senha **não** entra em `argv`, env, repositório nem no arquivo de targets;
é **lida uma vez**; o `secure_buffer` é **sobrescrito** após a entrega ao FreeRDP;
**nunca** aparece em log (redação + sentinela). Não há navegador no 17B, então a prova
"credencial fora do browser" fim-a-fim continua **UNVERIFIED** (é P1).

## 4. Fluxo de configuração do destino

`lab-targets.example.json` (apenas dados não secretos):

```json
{
  "targetAlias": "windows-nla-lab",
  "address": "192.0.2.10",
  "port": 3389,
  "domain": "LAB"
}
```

O destino `(address, port, domain)` vem **só do harness**; `policy` valida contra a
**allowlist de laboratório** (só o IP do asset + porta 3389). Destino/porta fora da
allowlist → **recusado** (prova P0 de egress restrito / sem destino arbitrário no
nível do worker). "Backend resolve o destino / sem parâmetro do frontend" continua
**P1**.

## 5. Modelo de logs

Log estruturado com **camada de redação**; o **WLog nativo** do FreeRDP é capturado e
roteado para a redação. Campos de auditoria técnica **permitidos**: `timestamp`,
`labJobId`, `targetAlias`, `state`, `result`, `reasonCode`, `durationMs`,
`workerPid`, `freerdpVersion`. Segredos (senha, usuário+domínio, tokens) são
redigidos. **Não simular** `userId`/`assetId`/`sourceIp`/`approvalId`/broker token.

## 6. Política de transporte

- **Só Unix Domain Socket**, modo **0600** + **peer credentials** (`SO_PEERCRED`): só
  o uid do harness conecta.
- **Sem TCP/HTTP/WebSocket/porta publicada.** mTLS/cross-host (ADR 0005) é elo de
  produção → **fora do 17B**.
- Um **job por conexão** (base para o token de uso único do produto, que é 17C+).

## 7. Plano de testes

### CI obrigatório (job `rdp-worker-build-test`)
- build C++ com **warnings tratados como erro**;
- testes unitários;
- UDS com **modo correto** (0600);
- **rejeição de peer não autorizado** (peer credentials);
- recusa de **target fora da allowlist**;
- recusa de **porta diferente** da allowlist;
- **segredo-sentinela ausente** de stdout/stderr/logs;
- **teardown** da máquina de estados;
- **`PAM_ENV=production` recusado**;
- **`--selftest` confirma FreeRDP 3.28.0**;
- **SBOM gerado** (e publicado como artifact);
- **scope guard** verde (`check-rdp-worker-scope.sh`);
- scans atuais verdes (`scan-secrets.sh`, `scan-forbidden-deps.sh`).

### P0 externo (fora do CI comum — [`../rdp-smoke-runbook.md`](../rdp-smoke-runbook.md))
Windows com NLA; xrdp; credencial correta/incorreta; certificado confiável/não
confiável; egress restrito; encerramento worker→asset; ausência de segredo nos logs
do worker; CPU/RAM/latência; CVE/SBOM.

## 8. Critérios de aceite (do PR-17B — a implementação)

```text
[ ] código limitado a rdp-worker/, CI, scripts de escopo e documentação
[ ] C++20 + API C do FreeRDP
[ ] FreeRDP 3.28.0 fixado por source SHA e checksum
[ ] build nativo executado no CI
[ ] testes unitários verdes
[ ] nenhum listener TCP
[ ] somente UDS 0600 + peer credentials
[ ] nenhum segredo em argv, env, config ou logs
[ ] destino limitado à allowlist do laboratório
[ ] PAM_ENV=production recusado
[ ] SUPPORTED_PROTOCOLS permanece ["vnc"]
[ ] nenhum código do produto importa o worker
[ ] nenhum serviço adicionado ao Compose principal
[ ] SBOM publicado
[ ] riscos residuais documentados
[ ] P0 permanece pendente até execução real
```
