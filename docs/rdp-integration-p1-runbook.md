# Runbook — gate **P1** de integração e segurança end-to-end do RDP (produto completo)

**Escopo deste runbook: gate P1 — produto integrado.** Ele prova os controles que
**um worker isolado não consegue demonstrar**: os que só existem quando backend +
gateway + cliente web + navegador reais estão no fluxo. O gate do worker isolado é o
**P0** ([`rdp-smoke-runbook.md`](rdp-smoke-runbook.md)); este é o passo **seguinte**.

**Por que existe:** o smoke P0 valida o RDP Worker + FreeRDP contra alvos reais, mas
**sem** navegador, broker ou gateway. Controles como "credencial nunca chega ao
navegador", "sessão só por `assetId`", "token de uso único", "auditoria completa" e
"encerramento administrativo pelo produto" **só podem ser provados com o produto
integrado** — por isso ficam **UNVERIFIED** após o P0 e são fechados aqui.

**Pré-condição:** **P0 verde** (ADR 0005 `Accepted`, engine aprovada) **e** os
**PRs 17C, 17D, 17E e 17F concluídos** — o P1 só pode rodar depois de o produto RDP
estar completo, porque testa justamente o que esses PRs entregam (cliente web,
políticas de segurança, auditoria completa, encerramento administrativo, gravação e
operação). O RDP continua em **perfil de laboratório**, ainda não habilitado em
runtime (ver gate abaixo).

**Gate:** enquanto o P1 não passar, **o RDP não é habilitado para usuários**.
**Política única e determinística (sem "ou"):** `SUPPORTED_PROTOCOLS` permanece
`["vnc"]`; o P1 é executado num **perfil de laboratório explicitamente separado**,
que **recusa inicialização quando `PAM_ENV=production`** (sem UI RDP pública, sem
rota pública de sessão RDP, sem asset RDP aceito pela API de produção). Só **depois
do P1 verde** o **PR-17G** altera para `SUPPORTED_PROTOCOLS = ["vnc", "rdp"]` e expõe
o RDP a usuários comuns.

## Pré-requisitos do host (fora do sandbox)

- Docker com `pull` liberado.
- Stack completa do produto **com os PRs 17C–17F já entregues**: **backend + gateway
  + cliente web do PAM + RDP Worker** (o worker aprovado no P0) + políticas (17D) +
  gravação/auditoria/operação (17F), com `protocol=rdp` ativo **apenas no perfil de
  laboratório** (que recusa `PAM_ENV=production`).
- Alvos RDP reais: **Windows (NLA)** e **xrdp**.
- **Navegador real** (para inspeção de HAR / WebSocket / DOM / storage).
- Um asset RDP cadastrado no backend (destino resolvido **pelo backend**, não pelo
  cliente).

## Checklist P1 — integração e segurança end-to-end (todos devem passar)

Cada item aqui converte um `UNVERIFIED` de **escopo P1** da matriz da ADR 0005 em
PASS/FAIL:

- [ ] **Sessão iniciada somente por `assetId`** — o navegador envia apenas
      `assetId` (+ governança); nenhum IP/host/porta/domínio/credencial parte do
      cliente (HR-01/HR-02). *(eliminatório)*
- [ ] **Backend resolve o destino** — IP, porta, protocolo, credencial e política
      vêm do backend; um destino/parâmetro técnico injetado pelo frontend é
      **ignorado/recusado** (HR-03/HR-08). *(eliminatório)*
- [ ] **Credencial fora do navegador** — inspeção de **HAR**, **frames WebSocket**,
      **DOM**, **`localStorage`** e **`sessionStorage`**: nenhuma senha/segredo/
      domínio. A credencial só existe no backend/worker/cofre (HR-05).
      *(eliminatório)*
- [ ] **Token efêmero de uso único** — o token do broker abre **uma** sessão, é
      consumido atomicamente e não pode ser reusado; a sessão do broker está
      **correlacionada** à conexão criada no worker. *(eliminatório)*
- [ ] **Sem rota direta do usuário** — não há caminho do navegador/rede de usuários
      até o worker nem ao asset; o egress do worker continua restrito (HR-07).
      *(eliminatório)*
- [ ] **Auditoria completa** — a sessão RDP registra usuário, asset, **`protocol=
      rdp`**, IP de origem, início, fim, status e motivo de encerramento (HR-10).
      *(eliminatório)*
- [ ] **Encerramento administrativo pelo produto** — kill de admin / fim de sessão
      no broker **derruba** a conexão RDP no worker ao vivo (watchdog end-to-end),
      e o navegador é desconectado. *(eliminatório)*
- [ ] **Nenhum segredo em log fim-a-fim** — grep-sentinela nos logs do **frontend**,
      do **gateway** e do **worker** simultaneamente: nada (HR-06). *(eliminatório)*
- [ ] **Destino arbitrário recusado** — tentativa de abrir sessão para host/porta
      não autorizados (ou de outra sessão) é recusada em toda a cadeia (HR-08).
      *(eliminatório)*
- [ ] **Recusa de protocolo/adapter divergente** — o registry mantém o comportamento
      do PR-16 para RDP (destino que não fala RDP / adapter ausente é recusado, HR-09).

## Como registrar o resultado

Converter os `UNVERIFIED` de **escopo P1** da matriz da ADR 0005 em PASS/FAIL e
anexar as evidências:
- HAR do navegador + dump de WebSocket/DOM/`localStorage`/`sessionStorage`
  comprovando ausência de segredo;
- registros de auditoria da sessão RDP (usuário, asset, IP, `protocol`);
- prova do encerramento administrativo derrubando a conexão ao vivo;
- saída do grep-sentinela nos três conjuntos de log (frontend/gateway/worker);
- prova da recusa de destino arbitrário e de token reusado.

## Resultado e efeito no status

- **Todos P1 verdes (eliminatórios P1 PASS):** os controles fim-a-fim estão
  provados. **Só então** o **PR-17G** habilita o RDP em runtime —
  `SUPPORTED_PROTOCOLS = ["vnc", "rdp"]`, com UI e rota liberadas. Não há promoção de
  "flag": a única mudança de runtime é a do PR-17G.
- **Qualquer eliminatório P1 vermelho:** o RDP **permanece desabilitado** em
  runtime; corrige-se o controle no produto (PR-17C–17F) e reexecuta-se o P1 antes de
  qualquer exposição a usuários.
