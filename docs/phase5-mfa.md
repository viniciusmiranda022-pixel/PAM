# Fase 5.2 — MFA (TOTP)

Segundo recurso avançado: autenticação em dois fatores por **TOTP** (RFC 6238),
compatível com Google Authenticator, Aegis, 1Password, etc. Sem dependência
externa — implementado sobre `node:crypto`.

## O que foi construído

| Componente | Entregue |
|---|---|
| **TOTP (`totp.ts`)** | base32 + HOTP/TOTP (HMAC-SHA1, passo 30s, 6 dígitos, janela ±1). Testado contra os **vetores oficiais do RFC 6238**. |
| **Fluxo de conta** | `POST /auth/mfa/setup` (gera segredo + `otpauth://`), `/enable` (confirma com um código), `/disable` (exige código). |
| **Login com 2FA** | senha correta + MFA habilitado → `401 MFA_REQUIRED`; o cliente então reenvia com `totp`. Código inválido → 401. |
| **Recuperação por admin** | `PATCH /admin/users/:id { mfaReset: true }` desabilita e limpa o MFA de quem perdeu o autenticador. |
| **UI** | campo TOTP que aparece no login sob demanda; seção "Segurança da conta" para ativar/desativar; coluna MFA + "Resetar MFA" no painel admin. |

## Segurança

- **Segredo TOTP nunca em claro no banco:** guardado cifrado com AES-256-GCM
  (`enc:v1`, a mesma cifra do cofre; master key só em env). Nunca retorna em
  nenhuma resposta de API depois do setup, e o setup o mostra **uma vez**.
- **`MFA_REQUIRED` é um código próprio** (não um 401 genérico): o frontend revela
  o campo TOTP só depois da senha correta, sem que o backend confirme a senha a
  quem parou na primeira etapa.
- **Enable/disable exigem prova de posse** (um código válido) — ter a sessão
  logada não basta para mexer no MFA.
- **Tudo auditado:** `mfa.setup_started`, `mfa.enabled`, `mfa.disabled`,
  `mfa.reset_by_admin`, e `auth.login_failed` com `reason: totp_invalid`.
- O rate limit de login (Fase 3) continua valendo e conta as tentativas com TOTP.

## Verificação (Postgres real)

| Suíte | Cobre | Resultado |
|---|---|---|
| backend unit — TOTP (11) | vetores do RFC 6238, janela ±1, base32 round-trip, otpauth | ✅ |
| integração MFA (22) | ciclo completo: setup → segredo cifrado → enable → **login exige TOTP** → senha errada nunca passa → disable exige código → **reset por admin** → auditoria → segredo nunca exposto | ✅ |

## Migração

`infra/postgres/init/003-mfa.sql` (idempotente; `mfa_secret` cifrado,
`mfa_enabled`). Para banco existente:

```bash
docker compose exec postgres psql -U pam -d pam -f /docker-entrypoint-initdb.d/003-mfa.sql
```

## Próximo (Fase 5.x)

SSO/OIDC (federar identidade), aprovação de acesso e janela de acesso, VeNCrypt.
