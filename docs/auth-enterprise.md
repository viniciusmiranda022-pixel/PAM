# Autenticação enterprise (OIDC / ADFS / SAML)

Como conectar o PAM Access Gateway ao identity provider corporativo. Decisão e
justificativa em [`adr/0003-auth-enterprise.md`](adr/0003-auth-enterprise.md).

O login local (usuário/senha + MFA TOTP) continua funcionando em paralelo; o SSO
é opcional e ligado por variáveis de ambiente. Nenhum segredo (client secret,
PKCE verifier, id_token, assertion) vai ao navegador ou a log (HR-05/HR-06).

## Qual caminho usar

| IdP | Caminho recomendado |
|-----|---------------------|
| **Entra ID / Azure AD** | OIDC |
| **ADFS 2019+** (Windows Server 2019/2022) | OIDC |
| **ADFS 2012 R2 / 2016 legado** | SAML (se o OIDC não estiver habilitado) |
| Keycloak, Auth0, Okta, Google | OIDC |
| Shibboleth e IdPs só-SAML | SAML |

Publicar na internet **sem expor o domínio**: use o IdP corporativo (ADFS/Entra)
como fronteira — o PAM nunca fala LDAP direto com o AD pela internet. LDAPS
interno (quando necessário) é um provider à parte, previsto para o PR-15B.

## OIDC (Authorization Code + PKCE)

```bash
OIDC_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
OIDC_CLIENT_ID=<app-id>
OIDC_CLIENT_SECRET=<secret>
OIDC_REDIRECT_URI=https://pam.example.com/api/v1/auth/oidc/callback
# opcionais
OIDC_TOKEN_AUTH=post          # 'basic' se o IdP exigir client_secret_basic
OIDC_GROUPS_CLAIM=groups      # claim com os grupos do usuário
OIDC_ADMIN_GROUP=PAM-Admins   # grupo que ELEVA a admin (nunca rebaixa)
OIDC_PROVIDER_LABEL=Entra ID  # rótulo do botão
```

No IdP: registre o app com o **redirect URI** acima, habilite o fluxo
Authorization Code, e exponha a claim de grupos (no Entra, "groups" ou "roles").
O cliente usa **PKCE S256** e verifica a assinatura **RS256** contra o JWKS do
issuer, revalidando o JWKS automaticamente quando o IdP roda a chave.

### ADFS via OIDC

ADFS 2019+ tem OpenID Connect. Crie um **Application Group** (Server application +
Web API), use o `OIDC_ISSUER = https://adfs.example.com/adfs`, o client id/secret
gerados e o redirect URI acima. Se o token endpoint exigir autenticação básica,
defina `OIDC_TOKEN_AUTH=basic`.

## SAML 2.0 (ADFS legado / Shibboleth)

```bash
SAML_IDP_ENTRYPOINT=https://adfs.example.com/adfs/ls/
SAML_IDP_CERT=MIIC...            # certificado token-signing do IdP (PEM/base64)
SAML_SP_ISSUER=https://pam.example.com/saml/metadata
SAML_CALLBACK_URL=https://pam.example.com/api/v1/auth/saml/callback
# opcionais
SAML_ADMIN_GROUP=PAM-Admins
SAML_PROVIDER_LABEL=SSO corporativo
```

No ADFS: adicione um **Relying Party Trust** com o entityID `SAML_SP_ISSUER`, o
ACS apontando para `SAML_CALLBACK_URL` (HTTP-POST binding) e regras de claim que
enviem **NameID**, email, nome e (se usar `SAML_ADMIN_GROUP`) o atributo de
grupo. O PAM exige **assertion assinada** e valida `Audience` e `InResponseTo`.

## Mapeamento de usuário (igual nos dois)

1. por identidade federada (`oidc_subject`/`saml_subject`);
2. senão, **vincula por email** a uma conta local existente (preserva
   role/permissões/MFA — o SSO não rebaixa um admin);
3. senão, **provisiona** (`*_AUTO_PROVISION=true`) um usuário `user` sem senha.

Grupo→papel **só eleva** a admin; a ausência do grupo não rebaixa (ADR 0003).
Eventos auditados: `auth.login {via}`, `auth.oidc_*`/`auth.saml_*`,
`auth.role_elevated_by_idp`.
