# Evidências — smoke **P0** do RDP Worker isolado (PR-17B)

> **Modelo de registro.** Preencha uma cópia deste arquivo por execução do P0.
> **Todos os resultados começam `PENDENTE`.** Nunca marque `PASS` sem anexar a
> evidência correspondente (o diretório `p0-evidence/<cenário>.XXXXXX/` gerado por
> `rdp-worker/scripts/run-p0.sh`). O script **não aprova o P0**: ele grava a
> evidência de um cenário e calcula um veredito por cenário
> (`PASS`/`FAIL`/`INCONCLUSIVE`); a **aceitação do P0** é decisão humana do
> operador + revisor com base nas evidências.
>
> **Escopo.** Valida **apenas** o worker isolado do PR-17B (não o produto
> integrado — isso é o gate **P1**). **P0 verde não habilita o RDP em runtime:**
> `SUPPORTED_PROTOCOLS` permanece `["vnc"]`; o **PR-17C fica bloqueado** até
> **todos os cenários eliminatórios** ficarem `PASS`.

## Identificação da execução

| Campo | Valor |
|---|---|
| Data / hora (UTC) | `PENDENTE` |
| Operador | `PENDENTE` |
| Revisor | `PENDENTE` |
| Host de execução (SO, kernel, CPU, RAM) | `PENDENTE` |
| Imagem do worker (tag/digest) | `PENDENTE` |
| Versão do worker (`--selftest`) | `PENDENTE` |
| Versão da `libfreerdp` (esperado 3.28.0) | `PENDENTE` |
| SHA-256 do binário do worker | `PENDENTE` |
| SHA-256 do binário do harness | `PENDENTE` |
| SBOM anexado (sim/não) | `PENDENTE` |
| Revisão de CVEs da `libfreerdp` fixada | `PENDENTE` |
| Alvo #1 (Windows NLA) — alias | `PENDENTE` |
| Alvo #2 (xrdp) — alias | `PENDENTE` |
| `PRIVION_LAB_TOFU_CERT` usado (0/1 por cenário) | `PENDENTE` |
| Trust store da imagem (ca-certificates / CA bundle read-only) | `PENDENTE` |

> **Regra da credencial de teste:** use uma credencial de laboratório dedicada
> em arquivo `0400`. **Rotacione-a (invalide-a) após concluir o P0.** A credencial
> nunca deve aparecer em nenhum arquivo de evidência — o `secret-sentinel.json`
> de cada execução (gravado por último, após o pacote completo) deve ser `CLEAN`.

## Matriz de cenários

`E` = eliminatório (bloqueia o PR-17C se não ficar `PASS`). `D` = diagnóstico
(registrado, não bloqueia sozinho). Preencha **Resultado (operador)** a partir da
evidência; **Veredito do script** é o campo `verdict` do `summary.json`.

| # | Cenário | `PRIVION_EXPECTED_RESULT` | Tipo | Veredito do script | Resultado (operador) | Diretório de evidência |
|---|---|---|---|---|---|---|
| 1 | Windows com NLA conecta | `connect` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 2 | xrdp conecta | `connect` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 3 | Credencial inválida recusada | `auth_reject` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 4 | Certificado confiável aceito | `cert_trusted` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 5 | Certificado não confiável recusado | `cert_reject` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 6 | Host na allowlist conecta | `connect` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 7 | Host fora da allowlist recusado | `egress_denied` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 8 | Porta fora da allowlist recusada | `egress_denied` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 9 | Encerramento por TERMINATE derruba o asset | `terminate` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 10 | Watchdog encerra a sessão | `watchdog` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 11 | Desconexão pelo asset encerra a sessão | `asset_disconnect` | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 12 | Rede indisponível → falha fechada (sem falso connect) | `network_unreachable` | D | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 13 | SIGTERM / SIGINT encerram sem órfãos | (teardown do driver) | D | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 14 | Repetição de N sessões (baseline CPU/RAM/latência) | `connect` ×N | D | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| 15 | Ausência de segredo nos logs do worker | `secret-sentinel.json` = `CLEAN` em todos | E | `PENDENTE` | `PENDENTE` | `PENDENTE` |

> **Certificado (cenários 4 e 5):** o tipo de teste vem **explicitamente** de
> `PRIVION_EXPECTED_RESULT` (`cert_trusted`/`cert_reject`) — o nome do cenário é
> só rótulo. Um veredito de certificado só é válido com
> `PRIVION_LAB_TOFU_CERT=0`; com `TOFU=1` o script **reprova** (`FAIL`, motivo
> `tofu_voids_cert_*`), independentemente do nome do cenário, pois *accept-once*
> não prova a cadeia. Anexe a cadeia/impressão digital observada. O trust store
> é um mecanismo **proposto** — a efetividade só é comprovada por estes dois
> cenários reais (ver runbook).

## Baseline de recursos (cenário 14)

| Métrica | 1 sessão | N sessões (N=`PENDENTE`) |
|---|---|---|
| Latência até `connected` (ms) — `summary.json` → `duration_ms_to_connected` | `PENDENTE` | `PENDENTE` |
| Pico de RSS do worker (kB) — `resources.txt` → `worker_peak_rss_kb` | `PENDENTE` | `PENDENTE` |
| CPU usuário (s) — `resources.txt` → `cpu_user_seconds` (de `/proc/<pid>/stat` utime/CLK_TCK) | `PENDENTE` | `PENDENTE` |
| CPU sistema (s) — `resources.txt` → `cpu_system_seconds` (stime/CLK_TCK) | `PENDENTE` | `PENDENTE` |
| Duração total monotônica (ms) — `resources.txt` → `duration_monotonic_ms` | `PENDENTE` | `PENDENTE` |

## Preparação

- [ ] Host fora do sandbox com Docker (`pull` liberado), dois alvos RDP reais
      (Windows NLA + xrdp).
- [ ] Imagem do worker construída e `--selftest` confirmando **FreeRDP 3.28.0**.
- [ ] `lab-targets.json` (não secreto) por alvo, com `address` e `port`.
- [ ] Credencial de laboratório em arquivo `0400`, **de posse do operador**.
- [ ] Trust store definido (ver runbook): `ca-certificates` na imagem **ou** CA
      bundle de laboratório montado **read-only** com `SSL_CERT_FILE` —
      **mecanismo proposto**; a efetividade é comprovada pelos cenários 4 e 5.
- [ ] Revisão de CVEs da `libfreerdp` 3.28.0 anexada; SBOM anexado.

## Execução

Comandos completos por cenário: ver
[`rdp-smoke-runbook.md`](rdp-smoke-runbook.md) (seção “Execução por cenário”).
Para cada cenário: rodar `run-p0.sh`, anexar o diretório de evidência, copiar o
`verdict` do `summary.json` para a matriz e decidir o **Resultado (operador)**.

## Troubleshooting

| Sintoma | Interpretação | Ação |
|---|---|---|
| driver sai com `rc=0` | veredito `PASS` e sentinela `CLEAN` (único código de sucesso) | copiar veredito para a matriz |
| driver sai com `rc=2` | pré-condição inválida (env, binário, gate de selftest, credencial, alvo) | ler a mensagem `run-p0: error:` |
| driver sai com `rc=10` | UDS não surgiu / worker morreu antes do socket / watchdog do driver | ler `worker-stderr.txt`; conferir imagem/flags |
| driver sai com `rc=20` | veredito `FAIL` (observado contradiz o esperado) | ler `summary.json` → `reason` |
| driver sai com `rc=25` | veredito `INCONCLUSIVE` — consistente, mas exige confirmação humana; **nunca** tratar como aprovado | confirmar a causa em `worker-stderr.txt` (redigido) e decidir na matriz |
| driver sai com `rc=30` | **VAZAMENTO**: credencial encontrada no pacote final de evidência | **interromper**, tratar como falha de segurança, revisar redação |
| `secret-sentinel.json` = `LEAK_PRESENT` | idem `rc=30` | idem |

## Cleanup

- [ ] Encerrar todos os workers/harness (o driver não deixa órfãos ao sair).
- [ ] Remover os `lab-targets.json` temporários.
- [ ] **Rotacionar/invalidar a credencial de teste `0400`.**
- [ ] Remover os alvos de laboratório efêmeros, se aplicável.

## Retenção

- [ ] Arquivar os diretórios `p0-evidence/*` (com `manifest.json`, `summary.json`,
      `summary.txt`, `secret-sentinel.json`, `worker-selftest.txt`,
      `*-events.jsonl`, `*-stderr.txt`, `resources.txt`, `facts.kv`) junto a
      este registro preenchido.
- [ ] Reter conforme a política de auditoria do PAM; a credencial de teste **não**
      é retida (foi rotacionada).

## Decisão

- **Todos os eliminatórios `PASS` (operador) + segredo `CLEAN` em todos:** ADR
  0005 passa de `Accepted — Conditional` para **`Accepted`**; **início do PR-17C**
  desbloqueado. **RDP continua desabilitado em runtime** (`SUPPORTED_PROTOCOLS` =
  `["vnc"]`); prontidão do produto é decidida no **gate P1** (após o PR-17F) e a
  habilitação em runtime só no **PR-17G**.
- **Qualquer eliminatório `FAIL`:** candidato **reprovado**; reabrir a decisão de
  engine na ADR 0005, sem iniciar o PR-17C.

## Assinatura

| Papel | Nome | Data (UTC) | Assinatura / decisão |
|---|---|---|---|
| Operador | `PENDENTE` | `PENDENTE` | `PENDENTE` |
| Revisor | `PENDENTE` | `PENDENTE` | `PENDENTE` |

> Resultado final do P0 (preenchido pelo revisor): **`PENDENTE`**
> (`APROVADO` desbloqueia o PR-17C · `REPROVADO` reabre a ADR 0005).
