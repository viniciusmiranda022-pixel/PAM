#!/usr/bin/env bash
# 45-xrdp-cert.sh — install / swap / restore the xrdp server certificate so the
# certificate scenarios are actually PROVEN, not just generated (point #1).
#
#   45-xrdp-cert.sh install   # install the CA-chained (trusted) cert + restart
#   45-xrdp-cert.sh untrusted # swap in the unknown self-signed cert + restart
#   45-xrdp-cert.sh restore   # restore the container's original cert + restart
#
# Works against the xrdp DEFAULT TLS layout (/etc/xrdp/cert.pem, /etc/xrdp/key.pem
# referenced by /etc/xrdp/xrdp.ini). If the image differs, the action is BLOCKED
# (the caller must not run the cert scenario against an unconfigured target).
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"
p0_load_env || true

action="${1:-}"; [ -n "$action" ] || die "usage: 45-xrdp-cert.sh install|untrusted|restore"
eng="$(p0_engine)"; [ -n "$eng" ] || die "no container engine (BLOCKED)"
NAME="${P0_XRDP_CONTAINER:-p0-xrdp}"
CA_DIR="${P0_CA_DIR:-$P0_LAB_DIR/ca}"
CERT="/etc/xrdp/cert.pem"; KEY="/etc/xrdp/key.pem"
BK="/etc/xrdp/.p0-orig"

$eng inspect "$NAME" >/dev/null 2>&1 || die "xrdp container '$NAME' not found — run 40-xrdp-target.sh (BLOCKED)"
contract_ok() { $eng exec "$NAME" sh -c "test -f $CERT && test -f $KEY && test -f /etc/xrdp/xrdp.ini"; }
contract_ok || die "xrdp image does not use the default TLS layout ($CERT/$KEY) — cert scenario BLOCKED"

backup_once() { $eng exec "$NAME" sh -c "test -d $BK || { mkdir -p $BK && cp $CERT $BK/cert.pem && cp $KEY $BK/key.pem; }"; }
restart_xrdp() {
  $eng exec "$NAME" sh -c 'command -v systemctl >/dev/null 2>&1 && systemctl restart xrdp 2>/dev/null || (pkill -x xrdp 2>/dev/null; pkill -x xrdp-sesman 2>/dev/null; sleep 1; (xrdp-sesman || true) >/dev/null 2>&1 & (xrdp || true) >/dev/null 2>&1 &) '
  sleep 2
  $eng exec "$NAME" sh -c '(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ":3389 "' \
    || die "xrdp did not come back up on 3389 after restart (BLOCKED)"
}
put() { # localfile containerpath  (copy without exposing content in argv)
  $eng cp "$1" "$NAME:$2"
}

case "$action" in
  install)
    { [ -f "$CA_DIR/server.crt" ] && [ -f "$CA_DIR/server.key" ]; } || die "run 30-make-ca.sh first (missing server cert/key)"
    backup_once
    put "$CA_DIR/server.crt" "$CERT"; put "$CA_DIR/server.key" "$KEY"
    $eng exec "$NAME" sh -c "chmod 400 $KEY; chmod 444 $CERT"
    restart_xrdp
    log "installed CA-chained (trusted) cert into '$NAME' and restarted xrdp"
    ;;
  untrusted)
    { [ -f "$CA_DIR/untrusted.crt" ] && [ -f "$CA_DIR/untrusted.key" ]; } || die "run 30-make-ca.sh first (missing untrusted cert)"
    backup_once
    put "$CA_DIR/untrusted.crt" "$CERT"; put "$CA_DIR/untrusted.key" "$KEY"
    $eng exec "$NAME" sh -c "chmod 400 $KEY; chmod 444 $CERT"
    restart_xrdp
    log "installed UNTRUSTED cert into '$NAME' and restarted xrdp"
    ;;
  restore)
    if $eng exec "$NAME" sh -c "test -d $BK"; then
      $eng exec "$NAME" sh -c "cp $BK/cert.pem $CERT && cp $BK/key.pem $KEY"
      restart_xrdp
      log "restored the container's original cert"
    else
      warn "no backup found — nothing to restore (was the cert ever swapped?)"
    fi
    ;;
  *) die "unknown action '$action'";;
esac
