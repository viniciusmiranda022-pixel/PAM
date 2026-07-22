#!/usr/bin/env bash
# 40-xrdp-target.sh — Phase 4b: bring up a Linux xrdp target container on an
# INTERNAL network (no published port, no general internet) with a non-privileged
# test user, then VALIDATE it against an explicit readiness contract (point #2).
# If the image does not satisfy the contract, the target is BLOCKED — the script
# never proceeds silently with a non-functional target.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"
p0_load_env || true

eng="$(p0_engine)"; [ -n "$eng" ] || die "no container engine — provide P0_XRDP_TARGET manually and skip this phase (BLOCKED)"
NET="${P0_LAB_NET:-p0-lab-net}"
NAME="${P0_XRDP_CONTAINER:-p0-xrdp}"
XUSER="${P0_XRDP_USER:-labuser}"
CREDF="${P0_XRDP_CRED_FILE:-}"
IMAGE="${P0_XRDP_IMAGE:-}"
RUN_DIR="$(p0_run_dir)"
OUT="$RUN_DIR/xrdp-target.txt"
blocked() { { echo "STATUS: BLOCKED"; echo "reason: $1"; } >>"$OUT"; warn "xrdp target BLOCKED — $1"; exit 0; }

: >"$OUT"
if ! { [ -n "$CREDF" ] && [ -f "$CREDF" ]; }; then blocked "P0_XRDP_CRED_FILE must be a 0400 file with the xrdp test password"; fi
[ -n "$IMAGE" ] || blocked "set P0_XRDP_IMAGE to a trusted image PINNED BY DIGEST you have vetted (not auto-pulled)"

log "Phase 4b: xrdp '$NAME' on internal net '$NET' (engine=$eng, image=$IMAGE)"
$eng network inspect "$NET" >/dev/null 2>&1 || $eng network create --internal "$NET" >/dev/null

tmp_prov="$(mktemp)"; chmod 700 "$tmp_prov"
cat >"$tmp_prov" <<PROV
#!/bin/sh
set -eu
command -v useradd >/dev/null 2>&1 || { echo "CONTRACT_FAIL: no useradd"; exit 41; }
command -v chpasswd >/dev/null 2>&1 || { echo "CONTRACT_FAIL: no chpasswd"; exit 42; }
id "$XUSER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$XUSER"
[ -f /run/xrdp-pass ] || { echo "CONTRACT_FAIL: password file not mounted"; exit 43; }
printf '%s:%s' "$XUSER" "\$(cat /run/xrdp-pass)" | chpasswd
rm -f /run/xrdp-pass
PROV

$eng rm -f "$NAME" >/dev/null 2>&1 || true
# Port NOT published; only reachable inside $NET (container mode worker).
$eng run -d --name "$NAME" --network "$NET" \
  -v "$CREDF":/run/xrdp-pass:ro -v "$tmp_prov":/run/provision.sh:ro \
  "$IMAGE" >/dev/null || { rm -f "$tmp_prov"; blocked "container failed to start from image $IMAGE"; }
prov_rc=0; $eng exec "$NAME" sh /run/provision.sh >>"$OUT" 2>&1 || prov_rc=$?
rm -f "$tmp_prov"
[ "$prov_rc" -eq 0 ] || blocked "provisioning contract failed (rc=$prov_rc; useradd/chpasswd/password mount) — image does not meet the xrdp contract"

# --- explicit readiness contract (point #2) ---
fails=()
$eng exec "$NAME" sh -c 'pgrep -x xrdp >/dev/null 2>&1' || fails+=("xrdp process not running")
$eng exec "$NAME" sh -c 'pgrep -x xrdp-sesman >/dev/null 2>&1' || fails+=("xrdp-sesman (session manager) not running")
$eng exec "$NAME" sh -c '(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ":3389 "' || fails+=("no listener on 3389 inside the container")
$eng exec "$NAME" sh -c 'id '"$XUSER"' >/dev/null 2>&1' || fails+=("test user missing")
# graphical session backend (Xorg/Xvnc/xorgxrdp) — RDP auth to a desktop needs one
$eng exec "$NAME" sh -c 'command -v Xorg >/dev/null 2>&1 || command -v Xvnc >/dev/null 2>&1 || ls /usr/lib/xorg/modules/*xrdp* >/dev/null 2>&1' \
  || fails+=("no graphical backend (Xorg/Xvnc/xorgxrdp) — desktop may be unavailable")

IP="$($eng inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME" 2>/dev/null || true)"
{
  echo "engine: $eng"; echo "container: $NAME"; echo "network: $NET (internal — not published)"
  echo "internal_ip: ${IP:-unknown}"; echo "port: 3389 (in-network only)"
  echo "user: $XUSER (password from 0400 file; not logged)"
  echo "readiness contract:"
  if [ "${#fails[@]}" -eq 0 ]; then echo "  OK — all checks passed"; else printf '  FAIL: %s\n' "${fails[@]}"; fi
} >>"$OUT"

if [ "${#fails[@]}" -ne 0 ]; then blocked "readiness contract not met: ${fails[*]}"; fi
echo "STATUS: READY" >>"$OUT"
echo "SUGGEST: set P0_XRDP_TARGET=${IP:-<ip>}:3389 and P0_WORKER_MODE=container in p0-lab.env" >>"$OUT"
log "Phase 4b READY -> $OUT  (P0_XRDP_TARGET=${IP:-<ip>}:3389, container mode)"
