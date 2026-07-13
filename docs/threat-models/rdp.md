# Threat model — adapter RDP

Threat model **específico do RDP**, em arquivo próprio porque **evolui** ao longo
do PR-17B (spike do worker), PR-17C (adapter/registry), PR-17D (autenticação/
segurança), PR-17E (cliente web) e PR-17F (gravação/operação). A
[`../adr/0005-rdp-engine.md`](../adr/0005-rdp-engine.md) **referencia** este
documento, mas foca na decisão de engine.

Estado: **rascunho (PR-17A)** — nenhum código RDP existe ainda. Cada sub-PR
seguinte atualiza a coluna "controle" com o que foi de fato implementado/testado.

## Ativos e superfícies

- **Credencial do asset** (senha/domínio; possível certificado/smartcard) — nunca
  pode chegar ao navegador nem a log (HR-05/HR-06).
- **RDP Worker próprio** (encapsula `libfreerdp`) — componente novo, sensível:
  fala RDP com o asset via a biblioteca; a lib fica encapsulada, o navegador nunca
  a alcança.
- **Transporte gateway ↔ worker** — novo elo; se desprotegido/mal-correlacionado,
  vira o ponto fraco.
- **Sessão do navegador** (cliente web RDP **próprio do PAM**; protocolo
  browser–gateway nosso).
- **Rede de assets** (`assets_net`) — só o gateway/worker alcançam os alvos RDP.

## STRIDE (específico de RDP)

| Ameaça | Cenário RDP | Controle exigido (aterrissa em PR-17x) |
|---|---|---|
| **Spoofing** | Asset RDP falso / MITM no trecho worker→asset | Validar certificado do servidor RDP; NLA/CredSSP; política `tls_required`/cert confiável por asset (17D) |
| **Spoofing** | Reuso do token efêmero para abrir sessão no worker | Token uso-único/TTL, correlação estrita sessão↔conexão do worker (17C) |
| **Tampering** | Usuário injeta host/porta/domínio na conexão do worker | Adapter passa ao worker **somente** o destino resolvido pelo backend; nenhum parâmetro vem do cliente (17C) |
| **Repudiation** | Nega o acesso RDP realizado | Auditoria com `protocol=rdp`, usuário, asset, IP de origem, início/fim/motivo (17F) |
| **Information disclosure** | Credencial/domínio vaza ao navegador ou a log | Credencial fica no gateway/worker/cofre; redação de log; NLA negocia sem expor senha ao browser (17B valida, 17D endurece) — **eliminatório** |
| **Information disclosure** | Canais virtuais (clipboard, drive redirection, impressora) exfiltram dados | Desabilitar por padrão; habilitar por asset com política explícita e auditada (17D/17F) |
| **Denial of service** | Flood de sessões/consumo do worker | Rate limit (já existe), limite de sessões, timeouts, baseline de CPU/RAM do worker (17B baseline, 17F operação) |
| **Elevation of privilege** | Worker usado como proxy para destino arbitrário | Egress do worker restrito a assets+portas RDP autorizados; destino divergente recusado; sem endpoint de conexão arbitrária (17B valida, 17C impõe) — **eliminatório** |
| **Elevation of privilege** | Worker exposto à rede de usuários/navegador | Worker só em rede interna, sem rota do usuário; navegador fala só com o gateway; transporte gateway↔worker determinístico (UDS/mTLS — ADR 0005) (17B/17E) — **eliminatório** |

## Requisitos eliminatórios (herdados dos HR)

Um adapter RDP que falhe **qualquer** um destes é rejeitado, independentemente de
funcionar. Todos são impostos pela **nossa** arquitetura (não pela engine), mas
**onde cada um é provado** difere por gate — um worker isolado não demonstra os
controles do produto integrado:

**Verificáveis no gate P0 — worker isolado** ([`../rdp-smoke-runbook.md`](../rdp-smoke-runbook.md)):

1. **nenhum** segredo nos **logs do worker** (HR-06, escopo worker);
2. worker com **egress restrito** aos assets/portas RDP autorizados (HR-07);
3. encerrar a sessão **no worker** **derruba** a conexão com o asset (HR-10/watchdog);
4. validação de certificado do servidor RDP; NLA/CredSSP real contra alvo.

**Verificáveis só no gate P1 — produto integrado**
([`../rdp-integration-p1-runbook.md`](../rdp-integration-p1-runbook.md)) — permanecem
UNVERIFIED após o P0:

5. credencial **nunca** chega ao navegador — HAR/WebSocket/DOM/storage limpos (HR-05);
6. **nenhum** destino/porta arbitrário — só o resolvido pelo backend, nada do
   frontend (HR-01/03/08);
7. protocolo sem adapter/destino divergente é **recusado** (HR-09);
8. **sem rota direta** do usuário ao worker/asset (HR-07, topologia do produto);
9. **nenhum** segredo em log **fim-a-fim** (frontend + gateway + worker, HR-06);
10. auditoria completa: usuário, asset, IP de origem, `protocol=rdp` (HR-10);
11. **encerramento administrativo pelo produto** derruba a sessão ao vivo (HR-10);
12. sessão iniciada **somente** por `assetId`; token efêmero de uso único (HR-01/02).

O smoke P0 valida os itens 1–4 contra alvo real com o worker do PR-17B e **aceita a
engine**, **antes** da integração (PR-17C). Os itens 5–12 são fechados no **gate
P1**, com o produto integrado e executado **somente após o PR-17F** (precisa do
cliente web, das políticas, da auditoria e do encerramento administrativo que
17D/17E/17F entregam). O RDP só é **habilitado em runtime** no **PR-17G**, após o P1
verde — até lá `SUPPORTED_PROTOCOLS` permanece `["vnc"]`.

## Itens em aberto (a fechar nos sub-PRs)

- Transporte gateway↔worker: **decisão determinística já registrada** na
  [`../adr/0005-rdp-engine.md`](../adr/0005-rdp-engine.md) (mesmo host: Unix Domain
  Socket + peer credentials; outro host: mTLS + rede dedicada + allowlist; TCP em
  claro proibido). **Implementado no PR-17B (worker), validado no smoke P0.**
- Estratégia de gravação do RDP: o RDP Worker é **nosso**, então temos liberdade
  de formato e reprodução (o `PAMREC01` é orientado a RFB e não serve direto) — **17F**.
- Política de canais virtuais (clipboard/drive/printer) por asset — **17D/17F**.
- NLA/CredSSP: matriz de compatibilidade com Windows moderno e xrdp — **smoke P0 + 17D**.
