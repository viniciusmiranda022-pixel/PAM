#!/usr/bin/env bash
# 00-inventory.sh — Phase 1: environment inventory (read-only).
# Discovers OS, virtualization, toolchain and target reachability WITHOUT
# printing any secret. Writes environment-inventory.txt into the run dir.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"

RUN_DIR="$(p0_run_dir)"
OUT="$RUN_DIR/environment-inventory.txt"
p0_load_env || true

have() { command -v "$1" >/dev/null 2>&1 && echo "yes ($(command -v "$1"))" || echo "no"; }

{
  echo "# P0 lab — environment inventory"
  echo "generated_at: $(p0_now_utc)"
  echo
  echo "## host"
  echo "uname: $(uname -a)"
  [ -r /etc/os-release ] && { . /etc/os-release; echo "distro: ${PRETTY_NAME:-unknown}"; }
  echo "arch: $(uname -m)"
  echo "cpus: $(nproc 2>/dev/null || echo '?')"
  if [ -r /proc/meminfo ]; then awk '/MemTotal|MemAvailable/{print tolower($1)" "$2" "$3}' /proc/meminfo; fi
  echo
  echo "## virtualization / containers"
  echo "docker: $(have docker)"
  echo "podman: $(have podman)"
  echo "kvm(/dev/kvm): $([ -e /dev/kvm ] && echo present || echo absent)"
  echo "systemd-detect-virt: $(systemd-detect-virt 2>/dev/null || echo n/a)"
  grep -qi microsoft /proc/version 2>/dev/null && echo "wsl2: likely" || echo "wsl2: no"
  echo
  echo "## toolchain"
  for t in git bash python3 cmake ninja g++ clang++ make openssl ss nft iptables jq curl syft grype trivy; do
    printf '%-10s %s\n' "$t:" "$(have "$t")"
  done
  echo "node: $(node --version 2>/dev/null || echo n/a)"
  echo "freerdp(system): $(xfreerdp --version 2>/dev/null | head -1 || echo 'not installed (worker builds its own pinned 3.28.0)')"
  echo
  echo "## repo build capability (heuristic)"
  echo "native build deps present: $(command -v cmake >/dev/null && command -v ninja >/dev/null && command -v g++ >/dev/null && echo 'likely (cmake+ninja+g++)' || echo 'missing — see 10-repo-validate.sh')"
  echo "container build possible: $(command -v docker >/dev/null || command -v podman >/dev/null && echo yes || echo no)"
  echo
  echo "## network interfaces / routes"
  ip -brief addr 2>/dev/null || ifconfig -a 2>/dev/null || echo "n/a"
  echo "--- default route ---"; ip route 2>/dev/null | grep '^default' || echo "n/a"
  echo
  echo "## lab config presence (values NOT shown)"
  echo "config loaded: ${P0_ENV_LOADED:-0}"
  for v in P0_WIN_TARGET P0_XRDP_TARGET P0_RDP_PORT P0_WIN_USER P0_XRDP_USER \
           P0_CRED_VALID_FILE P0_CRED_INVALID_FILE P0_CA_DIR P0_TRUSTED_CERT P0_UNTRUSTED_CERT; do
    if [ -n "${!v:-}" ]; then echo "$v: SET"; else echo "$v: unset"; fi
  done
  echo
  echo "## target reachability (TCP connect only; no auth, no secrets)"
  for pair in "win:${P0_WIN_TARGET:-}" "xrdp:${P0_XRDP_TARGET:-}"; do
    name="${pair%%:*}"; hostport="${pair#*:}"
    if [ -z "$hostport" ]; then echo "$name: target unset"; continue; fi
    host="${hostport%%:*}"; port="${P0_RDP_PORT:-3389}"
    if command -v nc >/dev/null 2>&1; then
      if nc -z -w3 "$host" "$port" 2>/dev/null; then echo "$name: $host:$port reachable"; else echo "$name: $host:$port UNREACHABLE"; fi
    else
      if timeout 3 bash -c ">/dev/tcp/$host/$port" 2>/dev/null; then echo "$name: $host:$port reachable"; else echo "$name: $host:$port UNREACHABLE"; fi
    fi
  done
} >"$OUT" 2>&1

log "Phase 1 done -> $OUT"
