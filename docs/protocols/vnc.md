# Adapter VNC (RFB)

O **VNC** é o primeiro adapter de protocolo do PAM Access Gateway — implementado,
testado e em uso. Este documento o formaliza como adapter de referência: todo
adapter futuro (RDP, SSH…) deve seguir o mesmo padrão de segurança.

## Papel na arquitetura

O adapter VNC vive na camada de gateway (`gateway/src/`). A camada comum cuida do
upgrade WebSocket, do consumo do token efêmero, do ciclo de vida e da gravação; o
adapter cuida de **falar RFB dos dois lados**. Ver
[`../architecture.md`](../architecture.md) §2 e §4.

```text
navegador (noVNC)  ──WSS──▶  gateway [adapter VNC]  ──TCP(+TLS)──▶  asset (VNC server)
     RFB None (sem credencial)          termina o handshake        RFB VNC Authentication
```

## Terminação de handshake (regra HR-05/HR-09)

O adapter **nunca** é um túnel byte-a-byte. Ele termina o handshake RFB dos dois
lados:

- **Lado navegador:** negocia RFB 3.8 com security type **`None`**. A autenticação
  do usuário já aconteceu na camada acima (login + token efêmero validado no
  upgrade). **Nenhuma credencial trafega ao browser.**
- **Lado asset:** executa **`VNC Authentication (2)`** (challenge-response DES) com
  a credencial obtida do cofre. Quando o asset exige, o trecho é cifrado com
  **VeNCrypt (TLS)** antes da autenticação.
- Após o `ServerInit`, o adapter vira um pipe binário transparente.

## Validação de destino (regra HR-08)

Ao abrir o TCP com o asset, o adapter exige que os 12 primeiros bytes sejam
`RFB xxx.yyy\n`. Se o destino não fala RFB, a conexão é encerrada e auditada —
impedindo que o gateway alcance um serviço diferente mesmo numa porta permitida.

## Escopo e limitações

| Item | Situação |
|---|---|
| Versão RFB | 3.8 |
| Security types (browser) | `None` |
| Security types (asset) | `VNC Authentication (2)`; VeNCrypt (subtypes X509) quando `tls_required` |
| Fora de escopo | Tight, RA2, Apple ARD e extensões proprietárias (UltraVNC/RealVNC) |
| Credencial | `VNC Authentication` usa DES com senha **truncada em 8 caracteres** (limitação do protocolo) — documentar aos operadores |
| Cifra gateway→asset | RFB puro é cleartext; controles compensatórios: `assets_net` segregada + VeNCrypt opcional |

## Portas (allowlist do protocolo)

Allowlist padrão do adapter VNC: `5900`, `5901`, `5902`. Portas customizadas são
cadastradas por admin, sempre fora do denylist imutável. Ver
[`../security-requirements.md`](../security-requirements.md) §2.

## Gravação e auditoria

- Gravação opcional por asset no formato `PAMREC01` (orientada a tela; sem teclado,
  por privacidade) — ver [`../phase5-recording.md`](../phase5-recording.md).
- Toda sessão registra em auditoria: usuário, asset, protocolo (`vnc`), IP de
  origem, início, fim, status e motivo (HR-10).

## Onde está no código e como é testado

| Aspecto | Referência |
|---|---|
| Handshake RFB + injeção de credencial | módulos do gateway em `gateway/src/` |
| VeNCrypt (upgrade TLS) | [`../phase5-vencrypt.md`](../phase5-vencrypt.md) |
| Contrato WebSocket / códigos de close | [`../api-contract.md`](../api-contract.md) §4 |
| Estado de verificação (real x fachada) | [`../function-audit.md`](../function-audit.md) — adapter VNC está **PARCIAL**: DES conferido com vetores NIST + RFB simulado; falta smoke test contra TigerVNC e navegador reais |

## Definition of Done deste adapter (referência para os próximos)

```text
[x] Termina o handshake RFB dos dois lados (None no browser, VNC Auth no asset)
[x] Nenhuma credencial trafega ao navegador (HR-05)
[x] Valida que o destino fala RFB antes de seguir (HR-08)
[x] Allowlist de portas específica do protocolo (HR-04)
[x] Auditoria registra o protocolo em toda sessão (HR-10)
[x] Gravação/playback disponível (opcional por asset)
[ ] Smoke test ponta-a-ponta contra TigerVNC + navegador reais  → pendente (PR-13+)
```
