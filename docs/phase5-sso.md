# Fase 5.5 — SSO / OIDC

Último dos avançados escolhidos: federação de login via **OpenID Connect**
(Authorization Code flow), compatível com Keycloak, Auth0, Azure AD, Google, etc.
Sem dependência externa: a verificação do `id_token` (RS256) usa `node:crypto`.

## O que foi construído

| Peça | Entregue |
|---|---|
| **Cliente OIDC** (`oidc.ts`) | Discovery (`/.well-known/openid-configuration`, cacheada), `buildAuthUrl`, troca de código no token endpoint, **verificação do id_token**: assinatura RS256 via JWKS (`createPublicKey` a partir do JWK) + `iss`/`aud`/`exp`/`nonce`. |
| **Rotas** | `GET /auth/oidc/login` (gera state+nonce em cookie assinado curto, 302 ao IdP) e `GET /auth/oidc/callback` (valida state, troca código, verifica token, mapeia usuário, cria sessão). `GET /auth/config` diz ao portal se o SSO está ligado. |
| **Mapeamento de usuário** | por `oidc_subject`; senão **vincula** por email a uma conta local existente (preserva role/permissões); senão **provisiona** (`OIDC_AUTO_PROVISION`) um usuário `user` sem senha. |
| **UI** | botão "Entrar com SSO" no portal, exibido só quando o OIDC está configurado. |

## Segurança

- **id_token verificado de verdade:** assinatura RS256 conferida com a chave do
  JWKS (não apenas decodificado), mais `iss`, `aud` (string ou array), `exp` e
  `nonce`. `alg` diferente de RS256 é recusado (evita confusão de algoritmo).
- **CSRF do fluxo:** `state` comparado ao valor guardado em cookie assinado; o
  `nonce` liga o id_token à requisição de login (anti-replay).
- **Usuários só-SSO não têm senha local** (`password_hash` NULL) — não conseguem
  logar por senha; o login por senha rejeita hash nulo.
- **Vínculo por email preserva a conta** (role/permissões/MFA) — o SSO não
  rebaixa um admin existente.
- Tudo auditado: `auth.oidc_provisioned`, `auth.oidc_linked`, `auth.oidc_failed`
  e `auth.login {via: oidc}`.

## Verificação (Postgres real + IdP OIDC simulado in-process)

O IdP de teste usa um par RSA **real** e assina o id_token com RS256; a
verificação é a de produção.

| Suíte | Cobre | Resultado |
|---|---|---|
| backend unit | inalterado | ✅ 27 |
| integração OIDC (12) | discovery→login→callback, **provisionamento**, login repetido sem duplicar, **vínculo por email** (mantém admin), **nonce inválido → 401**, **state inválido → 400**, usuário só-SSO não loga por senha, auditoria | ✅ |

> O ensaio com um IdP **real** (Keycloak/Auth0 em container) precisa de host com
> `docker pull`. A verificação RS256/JWKS e o fluxo são os de produção; só os
> endpoints HTTP do IdP são locais no teste.

## Configuração

```bash
# no infra/.env
OIDC_ISSUER=https://idp.example.com/realms/pam
OIDC_CLIENT_ID=pam-portal
OIDC_CLIENT_SECRET=...
OIDC_REDIRECT_URI=https://pam.example.com/api/v1/auth/oidc/callback
OIDC_AUTO_PROVISION=true   # false exige conta local pré-existente
```

Migração `infra/postgres/init/006-oidc.sql` (idempotente; `oidc_subject` único e
`password_hash` passa a aceitar NULL). Para banco existente:

```bash
docker compose exec postgres psql -U pam -d pam -f /docker-entrypoint-initdb.d/006-oidc.sql
```

## Fim da Fase 5 (os três escolhidos)

Com SSO/OIDC, os três avançados pedidos estão entregues: **5.3 acesso
just-in-time**, **5.4 VeNCrypt**, **5.5 SSO/OIDC**. Backlog remanescente da Fase
5: relatórios, alta disponibilidade (store de sessão compartilhado p/ rate limit
e watchdog multi-instância), janela de acesso com aprovação em duas etapas.
