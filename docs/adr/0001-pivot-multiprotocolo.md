# ADR 0001 — Pivot de VNC-only para multiprotocolo por adapter

- **Status:** aceito
- **Data:** 2026-07-08
- **Decisores:** dono do produto
- **Contexto de PR:** PR-12 (documental; nenhuma mudança de código)

> **Nota de supersessão (RDP):** para RDP, esta decisão foi supersedida pelo
> [`0005-rdp-engine.md`](0005-rdp-engine.md), que rejeita Guacamole/`guacd` e
> seleciona condicionalmente um RDP Worker próprio sobre `libfreerdp`. As menções a
> `guacd`/engine externa abaixo são **registro histórico** do estado em 2026-07-08.

## Contexto

O produto foi construído e entregue (Fases 0–5.5) como **PAM VNC-Only**, com a
regra "estritamente VNC-only" travada em documentação, no requisito HR-09
("nenhum suporte a outros protocolos") e prevista para ser travada também em CI.

O dono do produto decidiu **ampliar o escopo para multiprotocolo** (VNC + RDP +
SSH, e potencialmente outros), renomeando o produto para **PAM Access Gateway**.
A motivação é de negócio: um PAM restrito a VNC atende um nicho pequeno; RDP e SSH
são os protocolos de acesso privilegiado mais comuns em ambientes corporativos.

A decisão exige rever a "constituição" do projeto sem sacrificar as propriedades
de segurança que já tornam o produto defensável.

## Decisão

1. **O produto passa a ser multiprotocolo**, organizado em torno de **adapters de
   protocolo explícitos**. Cada protocolo suportado tem um adapter que:
   - termina o handshake do protocolo **dos dois lados** (nunca um túnel
     byte-a-byte que exija a credencial no navegador);
   - valida que o destino realmente fala o protocolo esperado;
   - injeta a credencial no lado do asset, a partir do cofre;
   - registra auditoria e (quando aplicável) gravação.
2. **O VNC (RFB) é rebaixado de "o produto" para "o primeiro adapter"**, já
   implementado e funcional. Seu funcionamento **não muda** com este pivot.
3. **HR-09 é redefinido**: de "nenhum outro protocolo" para **"cada protocolo entra
   por adapter explícito — nunca por proxy TCP genérico"**.
4. **HR-04 é redefinido**: a allowlist de portas passa a ser **por protocolo**.
5. **Novos protocolos entram um por vez, cada um em seu próprio PR**, começando por
   **RDP** e depois **SSH**. Não se implementa RDP/SSH "direto"; primeiro vem a
   abstração de adapter (adapter registry) com o VNC como adapter de referência.

## O que é preservado (núcleo seguro, inegociável)

O pivot **não afrouxa** nenhuma garantia. Continuam valendo, palavra por palavra:

- **HR-01** o usuário nunca informa IP, hostname, porta, URL, socket ou comando;
- **HR-02** a sessão é criada apenas por `assetId` (+ metadados de governança);
- **HR-03** o backend é a fonte de verdade (resolve protocolo, destino, credencial,
  política);
- **HR-05** a credencial nunca vai ao navegador;
- **HR-06** nenhum segredo aparece em log;
- **HR-07** o usuário final não tem rota direta até o asset;
- **HR-08** o gateway não aceita destino arbitrário;
- **HR-10** auditoria completa (agora incluindo o protocolo).

A superfície de ataque só cresce **sob adapters validados**, cada um com threat
model e testes próprios — nunca por relaxamento das regras acima.

## O que muda

| Antes (VNC-only) | Depois (multiprotocolo por adapter) |
|---|---|
| Nome: PAM VNC-Only | Nome: **PAM Access Gateway** |
| HR-09: nenhum outro protocolo | HR-09: adapter explícito por protocolo, nunca proxy genérico |
| HR-04: portas VNC em allowlist | HR-04: allowlist **por protocolo** |
| Gateway ≡ ponte VNC | Gateway ≡ camada comum + adapters (VNC é o 1º) |
| "RDP/SSH proibidos" | RDP/SSH **planejados** como adapters futuros |
| Guacamole/`guacd` proibidos a priori | Permitidos **dentro de um adapter** que preserve HR-01…HR-10 (decisão de engine em aberto) |

## Decisões deixadas em aberto (a resolver com PoC nos PRs de adapter)

- **Engine de cada protocolo:** implementação própria (como o adapter VNC, que fala
  RFB diretamente) **vs.** reuso de um engine externo (ex.: Apache Guacamole/`guacd`
  para RDP) **vs.** SDK específico. Trade-off entre superfície de dependência,
  esforço e fidelidade do protocolo. Decidir por adapter, no PR-16/PR-17, com PoC.
- **Gravação por protocolo:** o formato `PAMREC01` é orientado a tela (RFB). RDP/SSH
  podem exigir formatos/estratégias distintos (ex.: gravação de terminal para SSH).
- **Autenticação enterprise:** LDAP/ADFS entram no PR-15 (via OIDC/SAML/LDAPS),
  ortogonais ao pivot de protocolo.

## Consequências

**Positivas**
- Mercado-alvo muito maior (RDP/SSH são o grosso do acesso privilegiado).
- A arquitetura já favorecia isso: backend resolve destino, gateway é processo
  isolado — introduzir um registry de adapters é evolutivo, não disruptivo.
- As regras de segurança viram genéricas e reutilizáveis por adapter.

**Negativas / custos**
- Mais superfície de ataque e de manutenção (cada adapter é código sensível novo).
- Risco de "parecer pronto" antes de estar (mitigado pela auditoria
  função-por-função em [`../function-audit.md`](../function-audit.md) e pelo
  Definition of Done de adapter).
- Necessidade de validação contra servidores/clients reais (RDP/SSH reais, browser
  real), lacuna que o hardening (PR-13) e os PRs de adapter endereçam.

## Sequência de execução acordada

`PR-12` (este, docs) → `PR-13` hardening & CI → `PR-14` UI enterprise →
`PR-15` auth enterprise → `PR-16` adapter registry (VNC oficializado) →
`PR-17+` novos adapters, um por PR (RDP, depois SSH). Detalhe em
[`../delivery-plan.md`](../delivery-plan.md).

## Alternativas consideradas

- **Manter VNC-only.** Rejeitada: limita o produto a um nicho; o dono decidiu
  ampliar.
- **Adicionar RDP/SSH direto, sem abstração.** Rejeitada: levaria a caminhos de
  código divergentes e ao risco de um deles virar túnel cru. A abstração de adapter
  (com VNC como referência) força o padrão seguro antes de qualquer protocolo novo.
- **Virar um proxy genérico configurável.** Rejeitada frontalmente: violaria
  HR-08/HR-09 e destruiria a proposta de segurança do produto.
