#!/usr/bin/env bash
# Gera um certificado TLS autoassinado para o Nginx local (apenas laboratorio).
# Producao usa ACME/PKI interna. Ver docs/security-requirements.md secao 6.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/infra/nginx/certs"
mkdir -p "$DIR"

if [[ -f "$DIR/server.crt" && -f "$DIR/server.key" ]]; then
  echo "Certificado ja existe em $DIR — nada a fazer."
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/server.key" -out "$DIR/server.crt" \
  -days 365 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$DIR/server.key"
echo "Certificado autoassinado gerado em $DIR"
