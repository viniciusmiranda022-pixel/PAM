# ADR 0003 — Autenticação enterprise: OIDC (preferido) + SAML; LDAPS adiado

- **Status:** aceito
- **Data:** 2026-07-10
- **Contexto de PR:** PR-15 (auth enterprise)

## Contexto

O produto já federava login por **OIDC** (Authorization Code, RS256/JWKS via
`node:crypto`). Faltava atender ambientes corporativos reais: ADFS, mapeamento de
grupo→papel, resiliência a rotação de chave e o caso de IdP que só fala SAML.

## Decisão

1. **OIDC é o caminho preferido** e foi **consolidado** (não reescrito):
   - **PKCE S256** no Authorization Code flow.
   - **JWKS com TTL + refresh ao ver `kid` desconhecido** — rotação de chave do
     IdP não derruba mais o login.
   - Método de auth no token endpoint **configurável** (`client_secret_post`
     default, `client_secret_basic` para alguns ADFS).
   - `scope` configurável e **claim de grupos** para mapeamento de papel.
   - Cobre **ADFS 2019+**, **Entra ID/Azure AD**, Keycloak, Auth0, Google.

2. **SAML 2.0 (Service Provider) foi adicionado** para IdPs que só federam por
   SAML (ADFS legado, Shibboleth). A validação de assinatura XML usa a biblioteca
   **`@node-saml/node-saml`** — ver "Sobre a dependência" abaixo.

3. **LDAPS interno fica para o PR-15B** (adiado), não por escopo técnico e sim
   por foco: OIDC/SAML cobrem o acesso federado; LDAPS é um provider distinto
   (bind sobre TLS a um AD interno) e entra isolado, se for necessário. Regra que
   permanece: **nunca LDAP direto exposto à internet** — só LDAPS interno.

## Regra de mapeamento grupo→papel: só eleva

Tanto no OIDC quanto no SAML, um grupo do IdP (`*_ADMIN_GROUP`) **promove** o
usuário a `admin`. A **ausência** do grupo **não rebaixa** automaticamente.
Motivo: uma alteração de claim no IdP (ou um IdP mal configurado) não pode
derrubar o acesso de operação durante um incidente; o rebaixamento é um ato
administrativo explícito (auditado). Toda elevação gera `auth.role_elevated_by_idp`.

## Sobre a dependência (SAML)

Regra do projeto é superfície mínima. Para OIDC isso foi respeitado (zero
dependência — `node:crypto`). Para **SAML abrimos exceção consciente**:

- **Por quê:** validar XML-DSig à mão é um campo minado (canonicalização C14N,
  *signature wrapping*, XXE). Implementar isso à mão num produto de segurança
  seria mais arriscado do que usar uma biblioteca madura.
- **O que:** `@node-saml/node-saml` (base do `passport-saml`), com
  `wantAssertionsSigned`, `audience` restrita ao SP e `validateInResponseTo`.
- **Contenção:** a dependência fica **isolada em `backend/src/saml.ts`**; o resto
  do backend não a conhece. Se o SAML for descartado, remove-se um arquivo e uma
  dependência.

Esta é a primeira dependência de runtime não trivial do backend além de
Fastify/Zod/pg — decisão registrada aqui de propósito.

## Consequências

- ADFS atendido por **dois caminhos** (OIDC moderno e SAML legado); o operador
  liga o que o ambiente dele oferece.
- OIDC fica robusto a rotação de chave e a mais IdPs (basic auth, PKCE).
- Papel pode vir do IdP (elevação), reduzindo administração manual — auditado.
- Uma dependência de runtime nova (SAML), isolada e justificada.
- **Não validado contra ADFS/Entra reais** neste ambiente (sem `docker pull`):
  a verificação é contra IdP OIDC simulado (RSA real, RS256) e IdP SAML simulado
  (assinatura XML real). Ensaio com IdP real fica como pendência, como nos demais
  itens marcados PARCIAL em [`../function-audit.md`](../function-audit.md).

## Anti-replay do SAML e HA

`validateInResponseTo` usa um cache **in-memory** de `InResponseTo`. Em múltiplas
instâncias do backend isso precisa de um store compartilhado (mesma nota de HA já
registrada para rate limit e watchdog). Enquanto single-instance, é suficiente.

## Alternativas consideradas

- **Só OIDC (sem SAML).** Rejeitada: você pediu suporte a ADFS "pelos dois
  caminhos"; ADFS legado às vezes só oferece SAML.
- **SAML à mão (sem dependência).** Rejeitada: risco de segurança maior que o
  ganho de superfície mínima.
- **LDAPS agora.** Adiado ao PR-15B para manter o PR pequeno e revisável.
