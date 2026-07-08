# ADR 0002 — KDF de senha local: scrypt (node:crypto)

- **Status:** aceito
- **Data:** 2026-07-08
- **Contexto de PR:** PR-13 (hardening & CI)

## Contexto

Os documentos de segurança prometiam **Argon2id** como KDF-alvo para o hash de
senha local, mas a implementação usava **scrypt** (via `node:crypto`) com
parâmetros de PoC (N=2^14, r=8, p=1 ≈ 16 MiB) — decisão nunca formalizada.
Num produto de segurança, essa divergência entre doc e código precisa de uma
decisão registrada.

## Decisão

**Manter scrypt**, com parâmetros elevados ao patamar recomendado pela OWASP:

| Parâmetro | Valor | Nota |
|---|---|---|
| N | **2^17 (131072)** | ~128 MiB de memória por hash |
| r | 8 | |
| p | 1 | |
| keylen | 64 | |
| salt | 16 bytes CSPRNG | |
| maxmem | 256·N·r | o default do Node (32 MiB) não comporta N=2^17 |

- Formato armazenado **auto-descritivo**: `scrypt$N$r$p$salt$hash` — hashes
  antigos continuam verificáveis.
- **Re-hash transparente:** no login bem-sucedido, hash com parâmetros mais
  fracos que os atuais é re-gerado (`needsRehash` em `backend/src/auth.ts`).
- `SCRYPT_N` permite reduzir custo em ambientes restritos (ex.: CI). **Nunca
  reduzir em produção.**

## Justificativa (scrypt vs Argon2id)

| Critério | scrypt (node:crypto) | Argon2id (lib externa) |
|---|---|---|
| Dependência | **zero** — nativo do Node | `argon2`/`@node-rs/argon2`: build nativo ou binário pré-compilado |
| Superfície de suprimento | nenhuma nova | nova dependência com código nativo num produto de segurança |
| Aceitação | recomendado pela OWASP (com N≥2^17) | primeira recomendação da OWASP |
| Resistência a side-channel | boa | melhor (Argon2id combina resistência a TMTO e side-channel) |
| Build reproduzível | garantido | risco em plataformas sem binário pré-compilado |

O ganho criptográfico marginal do Argon2id não compensa, hoje, o custo de uma
dependência nativa nova — o projeto tem regra explícita de superfície mínima.
Com N=2^17 o scrypt atende o requisito real: inviabilizar ataque de GPU/ASIC a
hashes vazados.

## Consequências

- Custo de CPU/memória por login sobe (~128 MiB, dezenas de ms). Aceitável: o
  login tem rate limit (5/min/IP) e o volume de logins de um PAM é baixo.
- Hashes antigos (N=2^14) permanecem válidos e migram sozinhos no próximo login.
- Revisão futura: se o produto ganhar requisito formal de compliance que exija
  Argon2id (ex.: política corporativa do cliente), este ADR é substituído — o
  formato `$`-prefixado permite convivência dos dois esquemas durante migração.
