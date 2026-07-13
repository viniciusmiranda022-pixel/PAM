# ADR 0004 — Registry de adapters de protocolo

- **Status:** aceito
- **Data:** 2026-07-10
- **Contexto de PR:** PR-16 (abstração de protocolo)

## Contexto

Até aqui o gateway assumia VNC em todo lugar: `session.ts` fazia a terminação
RFB inline e os módulos `rfb`/`handshake`/`vencrypt` viviam soltos na raiz de
`gateway/src`. Para abrir RDP/SSH em PRs futuros **sem** virar um proxy genérico,
era preciso primeiro extrair a abstração — com o VNC como primeiro adapter — de
forma que qualquer protocolo novo seja obrigado a seguir o mesmo contrato seguro.

## Decisão

1. **Interface `ProtocolAdapter`** (`gateway/src/adapters/types.ts`): cada
   protocolo implementa `connect(ctx)`, que **termina o handshake dos dois
   lados** e devolve o socket efetivo + preâmbulo de gravação. Falha vira
   `AdapterHandshakeError` (evento de auditoria + close code), sem vazar segredo.
   O contrato é **neutro de protocolo**: `types.ts` não importa nada de
   `adapters/vnc/` (inclusive o tipo de TLS é o genérico `AdapterTlsOptions`). A
   dependência vai sempre do adapter para o contrato, **nunca o contrário** — o
   core do registry não conhece detalhes de nenhum protocolo.
2. **Registry** (`gateway/src/adapters/index.ts`): `Map<protocol, adapter>`. O
   gateway resolve o adapter por `assets.protocol`. **Protocolo sem adapter é
   recusado** (`gateway.protocol_unsupported`) — nunca há fallback para proxy
   genérico (HR-08/HR-09).
3. **VNC como adapter completo e isolado** em `gateway/src/adapters/vnc/`
   (`index.ts`, `handshake.ts`, `rfb.ts`, `vencrypt.ts`). Escolha deliberada pelo
   melhor desenho de longo prazo (não pelo menor diff): o VNC deixa de ser um
   wrapper fino sobre arquivos soltos e passa a ser uma unidade fechada, modelo
   para os próximos adapters.
4. **`session.ts` fica agnóstico de protocolo**: token, resolução de
   destino/credencial (sempre do banco — HR-03), conexão TCP, splice, gravação,
   watchdog e auditoria; delega só a terminação ao adapter.
5. **`protocol` no modelo de asset** (migração `009-protocol.sql`, default
   `vnc`); a auditoria de sessão passa a registrar `protocol` (HR-10).

## Comportamento preservado

O VNC funciona **exatamente** como antes: os módulos `rfb`/`handshake`/`vencrypt`
foram **movidos** (git mv), não reescritos — só os caminhos de import mudaram. O
adapter é um invólucro fino que chama as mesmas funções. Provado por: os testes
unitários de RFB/handshake (movidos, seguem verdes) e um e2e in-process novo
(par WebSocket real + asset RFB falso) que completa o handshake e audita
`protocol=vnc`.

Nota de ordenação (negligenciável): a auditoria `gateway.tls_established` agora
ocorre após a terminação completa dos dois lados, em vez de entre o handshake do
asset e o do navegador. O caminho de sucesso e os quatro mapeamentos de falha
(banner/tls/auth/genérico → evento + close code) são idênticos.

## Consequências

- Adicionar um protocolo = adicionar um adapter e registrá-lo; nada em
  `session.ts` muda. Cada adapter é obrigado, por contrato, a terminar o
  handshake (sem túnel cru) e a nunca enviar credencial ao navegador.
- HR-09 deixa de ser convenção e vira estrutura: sem adapter registrado, recusa.
- **Allowlist por protocolo (HR-04):** o adapter declara `defaultPorts`; por ora
  a allowlist física (`allowed_ports`) continua sendo a do VNC. A segmentação
  real por protocolo entra com o primeiro adapter não-VNC (PR-17+).
- Nenhum protocolo novo neste PR. RDP (primeiro) e SSH (depois) entram um por PR.

## Alternativas consideradas

- **Adapter fino reusando os arquivos soltos** (menor diff). Rejeitada pelo dono
  em favor do isolamento completo em `adapters/vnc/` — melhor desenho de longo prazo.
- **Manter tudo inline e ramificar por `if protocol === …`.** Rejeitada: levaria a
  caminhos divergentes e ao risco de um deles virar túnel cru.
