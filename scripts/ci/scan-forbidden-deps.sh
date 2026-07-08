#!/usr/bin/env bash
# scan-forbidden-deps.sh — trava HR-08/HR-09: nenhum proxy TCP generico / tunel
# byte-a-byte. Protocolos entram por ADAPTER explicito, nunca por essas libs.
# Roda no CI e localmente. Sai !=0 se achar dependencia proibida.
set -euo pipefail
cd "$(dirname "$0")/../.."

# Libs que materializam "proxy generico" ou "tunel WS<->TCP sem terminacao de
# handshake" — o oposto do modelo de adapter (HR-09). NAO listamos ssh2/rdp aqui:
# um protocolo novo e permitido DENTRO de um adapter validado (PR-17+).
forbidden='websockify|node-tcp-proxy|tcp-proxy|node-http-proxy|http-proxy-middleware|net-proxy|socksv5|node-portproxy'

fail=0
for pkg in backend gateway frontend tests; do
  for f in "$pkg/package.json" "$pkg/package-lock.json"; do
    [ -f "$f" ] || continue
    if grep -nEi "\"($forbidden)\"" "$f" >/dev/null 2>&1; then
      echo "FORBIDDEN-DEP em $f:"
      grep -nEi "\"($forbidden)\"" "$f" || true
      fail=1
    fi
  done
done

if [ "$fail" -ne 0 ]; then
  echo "scan-forbidden-deps: FALHOU — dependencia de proxy generico detectada (HR-09)."
  exit 1
fi
echo "scan-forbidden-deps: ok"
