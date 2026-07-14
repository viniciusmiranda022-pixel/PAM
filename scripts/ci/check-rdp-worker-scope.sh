#!/usr/bin/env bash
# check-rdp-worker-scope.sh — barreira anti-integração acidental do RDP Worker
# (ADR 0006 §4). O scan-forbidden-deps atual só olha manifestos Node; este script
# protege o worker nativo. Falha (exit != 0) se o spike escapar do laboratório.
set -euo pipefail
cd "$(dirname "$0")/../.."

fail=0
note() { echo "RDP-WORKER-SCOPE: $1"; fail=1; }

# 1) SUPPORTED_PROTOCOLS deve permanecer exatamente ["vnc"].
if ! grep -qE 'SUPPORTED_PROTOCOLS = \["vnc"\] as const;' backend/src/schemas.ts; then
  note 'SUPPORTED_PROTOCOLS não é exatamente ["vnc"] em backend/src/schemas.ts'
fi
if grep -nE 'SUPPORTED_PROTOCOLS[^=]*=[^;]*rdp' backend/src/schemas.ts >/dev/null 2>&1; then
  note 'rdp apareceu em SUPPORTED_PROTOCOLS'
fi

# 2) Nenhum código de produto (gateway/backend/frontend) nem o Compose principal
#    pode referenciar o worker.
if git grep -nE 'rdp-worker|privion-rdp-worker|privion::rdp' -- \
     gateway backend frontend infra/docker-compose.yml >/dev/null 2>&1; then
  echo "--- referências proibidas ao worker ---"
  git grep -nE 'rdp-worker|privion-rdp-worker|privion::rdp' -- \
     gateway backend frontend infra/docker-compose.yml || true
  note 'produto (gateway/backend/frontend) ou Compose principal referencia o worker'
fi

# 3) O worker não pode abrir TCP/HTTP/WebSocket nem porta publicada — só UDS.
#    Casa sinais REAIS de uso (sockets IP, libs http/ws), não a palavra em comentário.
tcp_re='\bAF_INET6?\b|\bSOCK_DGRAM\b|libwebsockets|#include <(microhttpd|civetweb|mongoose)'
if git grep -nE "$tcp_re" -- \
     rdp-worker/src rdp-worker/include rdp-worker/harness >/dev/null 2>&1; then
  echo "--- indício de transporte proibido no worker ---"
  git grep -nE "$tcp_re" -- \
     rdp-worker/src rdp-worker/include rdp-worker/harness || true
  note 'worker aparenta abrir TCP/HTTP/WebSocket (só UDS é permitido)'
fi

# 4) Nenhuma dependência de Guacamole em código/infra (docs citam só a rejeição;
#    o próprio guard é excluído por conter os padrões de busca).
guac_scope=(gateway backend frontend infra scripts rdp-worker
     ':(exclude)scripts/ci/check-rdp-worker-scope.sh' ':(exclude)*.md')
if git grep -niE 'guacd|guacamole' -- "${guac_scope[@]}" >/dev/null 2>&1; then
  echo "--- referência a Guacamole em código/infra ---"
  git grep -niE 'guacd|guacamole' -- "${guac_scope[@]}" || true
  note 'dependência/menção de Guacamole em código/infra'
fi

# 5) O worker é lab-only: guarda de compilação e recusa de produção presentes.
if ! grep -qE '#error .*PRIVION_LAB_ONLY' rdp-worker/src/main.cpp; then
  note 'falta a guarda de compilação #error PRIVION_LAB_ONLY em main.cpp'
fi
if ! grep -qE 'running_in_production' rdp-worker/src/main.cpp; then
  note 'falta a recusa de inicialização em PAM_ENV=production em main.cpp'
fi
if ! grep -qE 'option\(PRIVION_LAB_ONLY .* ON\)' rdp-worker/CMakeLists.txt; then
  note 'PRIVION_LAB_ONLY não está ON por padrão no CMakeLists'
fi

# 6) O worker não pode ser adicionado ao Compose principal como serviço.
if grep -nE '^[[:space:]]+(privion-)?rdp-worker:' infra/docker-compose.yml >/dev/null 2>&1; then
  note 'rdp-worker registrado como serviço no Compose principal'
fi

if [ "$fail" -ne 0 ]; then
  echo "check-rdp-worker-scope: FALHOU"
  exit 1
fi
echo "check-rdp-worker-scope: ok"
