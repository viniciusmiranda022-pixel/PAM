#!/usr/bin/env bash
# scan-secrets.sh — barreira simples contra segredo commitado (HR-06).
# Roda no CI e localmente. Sai !=0 se encontrar indicio de segredo versionado.
set -euo pipefail
cd "$(dirname "$0")/../.."

fail=0
note() { echo "SECRET-SCAN: $1"; fail=1; }

# Arquivos versionados, exceto o proprio scanner e o .env.example (que so tem
# placeholders).
mapfile -t files < <(git ls-files \
  | grep -vE '(^|/)(node_modules|dist)/' \
  | grep -vE 'scripts/ci/scan-secrets\.sh$' \
  | grep -vE '(^|/)\.env\.example$')

# 1) .env real nunca deve ser versionado (.env.example e permitido).
if git ls-files | grep -E '(^|/)\.env($|\.)' | grep -vqE '\.env\.example$'; then
  git ls-files | grep -E '(^|/)\.env($|\.)' | grep -vE '\.env\.example$' || true
  note "arquivo .env versionado"
fi

# 2) Chaves privadas.
if git grep -nI -- '-----BEGIN .*PRIVATE KEY-----' -- "${files[@]}" >/dev/null 2>&1; then
  git grep -nI -- '-----BEGIN .*PRIVATE KEY-----' -- "${files[@]}" || true
  note "chave privada versionada"
fi

# 3) Senhas default do seed nao podem voltar (PR-13 removeu-as).
if git grep -nE "poc-pass|admin-pass" -- "${files[@]}" >/dev/null 2>&1; then
  git grep -nE "poc-pass|admin-pass" -- "${files[@]}" || true
  note "senha default de seed reintroduzida"
fi

# 4) Atribuicao de segredo com valor concreto (nao placeholder) fora de exemplos.
#    Heuristica: NOME_SECRET=... com >=16 chars sem 'troque'/'defina'/'example'.
if git grep -nE '(COOKIE_SECRET|CREDENTIAL_MASTER_KEY|VAULT_TOKEN|OIDC_CLIENT_SECRET|SEED_[A-Z_]*PASSWORD)=[^[:space:]]{16,}' \
     -- "${files[@]}" 2>/dev/null | grep -viE 'troque|defina|example|placeholder|<|\$\{' ; then
  note "possivel segredo concreto versionado"
fi

if [ "$fail" -ne 0 ]; then
  echo "scan-secrets: FALHOU"
  exit 1
fi
echo "scan-secrets: ok"
