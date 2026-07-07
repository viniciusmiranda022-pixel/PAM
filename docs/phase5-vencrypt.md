# Fase 5.4 — VeNCrypt (TLS gateway→asset)

Segundo dos avançados escolhidos. Fecha uma lacuna que veio sendo sinalizada
desde a Fase 0: o trecho **gateway→asset** era RFB em cleartext (compensado por
segmentação de rede). Com VeNCrypt, esse trecho passa a ser cifrado com TLS, e a
autenticação VNC ocorre **dentro** do túnel.

## O que foi construído

| Peça | Entregue |
|---|---|
| **VeNCrypt no gateway** (`vencrypt.ts`) | Sub-handshake VeNCrypt 0.2, escolha de subtype **X509** (X509Vnc/X509None), upgrade do socket para TLS (`tls.connect({ socket })`), com `socket.unshift` do residual para não perder o ServerHello. |
| **Handshake integrado** (`assetHandshakeTls`) | Quando `tls_required`, exige VeNCrypt (senão falha), faz o upgrade e conduz a autenticação interna (None/VNC Auth) **sobre o TLS**; o splice segue no socket TLS. |
| **Flag por asset** | `assets.tls_required` (default false). O gateway lê no consumo do token. |
| **Config TLS** | `VENCRYPT_CA_FILE` (produção: CA que assina os certificados dos assets) ou `VENCRYPT_INSECURE=true` (lab: aceita autoassinado). |

## Por que só X509 (e não os subtypes anônimos)

Os subtypes `TLSNone/TLSVnc` usam Diffie-Hellman **anônimo**, que o OpenSSL
moderno (e portanto o Node) desabilita por padrão. Os subtypes `X509*` usam um
certificado de servidor real — TLS padrão, sem cifras legadas. Por isso o gateway
oferece/aceita apenas X509, que é também o modo recomendado (autentica o asset).

## Fluxo

```text
gateway ──RFB 3.8──▶ asset
        ◀─ security types [.. 19 ..]
        ── seleciona 19 (VeNCrypt) ──▶
        ◀─ version 0.2 ──  ── 0.2 ──▶  ◀─ ack ──
        ◀─ subtypes [X509Vnc] ──  ── escolhe 261 ──▶
        ═══════════ handshake TLS (cert do asset) ═══════════
        ◀───────── VNC Auth (challenge/DES) DENTRO do TLS ─────────▶
        ◀─ SecurityResult · ServerInit · framebuffer ── (tudo cifrado)
```

Falha explícita: se `tls_required` e o asset **não** oferece VeNCrypt, o gateway
recusa (WS 4503, auditoria `gateway.tls_required_failed`) — não faz downgrade
para cleartext.

## Verificação

TLS **real** do Node contra um servidor VeNCrypt simulado (certificado
autoassinado). O que é exercitado de verdade: seleção do 19, sub-handshake 0.2,
escolha X509Vnc, **handshake TLS real**, **VNC Auth (DES) dentro do túnel**,
ServerInit e framebuffer decifrados, splice sobre TLS.

| Suíte | Resultado |
|---|---|
| gateway unit (caminho RFB simples intacto) | ✅ 24 |
| integração VeNCrypt (10) | seleção 19 → 0.2 → X509Vnc → TLS real → DES no túnel → ServerInit+frame decifrados → sessão active + `gateway.tls_established`; e `tls_required` sem VeNCrypt → 4503 + `gateway.tls_required_failed` | ✅ |

> Ressalva honesta: o framing RFB/VeNCrypt do servidor de teste foi escrito por
> nós a partir da especificação (não há vetores oficiais como no TOTP/DES). A
> camada TLS, essa sim, é a do Node — não um mock. O ensaio contra um servidor
> VNC real com VeNCrypt (TigerVNC `-SecurityTypes VeNCrypt,X509Vnc`) precisa de
> um host com `docker pull`.

## Migração

`infra/postgres/init/005-vencrypt.sql` (idempotente). Para banco existente:

```bash
docker compose exec postgres psql -U pam -d pam -f /docker-entrypoint-initdb.d/005-vencrypt.sql
```

## Próximo

SSO/OIDC — o último dos três escolhidos.
