#!/usr/bin/env bash
# 30-make-ca.sh — Phase 4a: generate a CONTROLLED lab CA, a server certificate
# chained to it (trusted scenario), and an unknown self-signed cert (untrusted
# scenario). Private keys are written 0400. Nothing here is a product secret and
# nothing is committed (tools/p0-lab/.gitignore covers ca/).
#
# The RDP asset must present the generated server cert; the worker verifies it
# against a trust store containing the lab CA (see README + runbook). TOFU stays
# OFF for the certificate scenarios.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"

command -v openssl >/dev/null 2>&1 || die "openssl is required"
CA_DIR="${P0_CA_DIR:-$P0_LAB_DIR/ca}"
XRDP_CN="${P0_XRDP_CN:-${P0_XRDP_TARGET%%:*}}"
XRDP_CN="${XRDP_CN:-xrdp.lab.local}"
mkdir -p "$CA_DIR"; chmod 700 "$CA_DIR"

log "Phase 4a: lab CA + certs -> $CA_DIR (CN=$XRDP_CN)"

# --- lab root CA ---
if [ ! -f "$CA_DIR/lab-ca.crt" ]; then
  openssl genrsa -out "$CA_DIR/lab-ca.key" 4096 2>/dev/null
  chmod 400 "$CA_DIR/lab-ca.key"
  openssl req -x509 -new -nodes -key "$CA_DIR/lab-ca.key" -sha256 -days 30 \
    -subj "/O=PAM P0 Lab/CN=PAM P0 Lab Root CA" -out "$CA_DIR/lab-ca.crt" 2>/dev/null
  log "created root CA (30-day)"
else
  log "root CA already present — reusing"
fi

# --- trusted server cert (chained to the lab CA) ---
cat >"$CA_DIR/server.ext" <<EOF
subjectAltName = DNS:${XRDP_CN}
extendedKeyUsage = serverAuth
EOF
openssl genrsa -out "$CA_DIR/server.key" 2048 2>/dev/null
chmod 400 "$CA_DIR/server.key"
openssl req -new -key "$CA_DIR/server.key" -subj "/O=PAM P0 Lab/CN=${XRDP_CN}" \
  -out "$CA_DIR/server.csr" 2>/dev/null
openssl x509 -req -in "$CA_DIR/server.csr" -CA "$CA_DIR/lab-ca.crt" -CAkey "$CA_DIR/lab-ca.key" \
  -CAcreateserial -days 15 -sha256 -extfile "$CA_DIR/server.ext" \
  -out "$CA_DIR/server.crt" 2>/dev/null
chmod 400 "$CA_DIR/server.key"

# --- untrusted self-signed cert (does NOT chain to the lab CA) ---
openssl req -x509 -newkey rsa:2048 -nodes -days 15 -sha256 \
  -subj "/O=Untrusted/CN=${XRDP_CN}" \
  -keyout "$CA_DIR/untrusted.key" -out "$CA_DIR/untrusted.crt" 2>/dev/null
chmod 400 "$CA_DIR/untrusted.key"

# --- verify chain (evidence) ---
if openssl verify -CAfile "$CA_DIR/lab-ca.crt" "$CA_DIR/server.crt" >/dev/null 2>&1; then
  chain="server.crt chains to lab CA: OK"
else
  chain="server.crt chain verification: FAILED"
fi
if openssl verify -CAfile "$CA_DIR/lab-ca.crt" "$CA_DIR/untrusted.crt" >/dev/null 2>&1; then
  untrusted="untrusted.crt UNEXPECTEDLY verified against lab CA (bad)"
else
  untrusted="untrusted.crt correctly does NOT chain to lab CA: OK"
fi

RUN_DIR="$(p0_run_dir)"
{
  echo "# lab CA / certificates ($(p0_now_utc))"
  echo "ca_dir: $CA_DIR"
  echo "server_cn: $XRDP_CN"
  echo "$chain"
  echo "$untrusted"
  echo "files (private keys are 0400, never committed):"
  # shellcheck disable=SC2012  # controlled lab dir; ls is fine for a listing
  ls -l "$CA_DIR" | awk '{print "  "$1" "$NF}'
  echo
  echo "fingerprints (non-secret):"
  echo "  lab-ca:    $(openssl x509 -in "$CA_DIR/lab-ca.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
  echo "  server:    $(openssl x509 -in "$CA_DIR/server.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
  echo "  untrusted: $(openssl x509 -in "$CA_DIR/untrusted.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
} >"$RUN_DIR/lab-ca.txt"

log "Phase 4a done -> $RUN_DIR/lab-ca.txt"
log "trust store for the worker: point SSL_CERT_FILE (or the container CA bundle) at $CA_DIR/lab-ca.crt for the TRUSTED scenario"
