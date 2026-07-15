#!/usr/bin/env bash
# common.sh — shared helpers for the P0 lab automation (tools/p0-lab/).
# Sourced by every phase script. NO product runtime is touched here.
#
# Safety invariants honoured by all callers:
#   - secrets never enter argv/env/stdout/logs (only 0400 file PATHS are passed);
#   - fail-closed: a phase that cannot run marks BLOCKED/INCONCLUSIVE, never PASS;
#   - residue is measured DIFFERENTIALLY (post minus pre), never absolute counts;
#   - nothing is committed/pushed; artifacts live under an ignored directory.
set -euo pipefail
umask 077
export LC_ALL=C

P0_REPO_ROOT="$(git -C "$(dirname -- "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
export P0_REPO_ROOT
export P0_LAB_DIR="$P0_REPO_ROOT/tools/p0-lab"
export P0_ARTIFACTS_BASE="$P0_LAB_DIR/artifacts/p0"

p0_now_utc()  { date -u +%Y-%m-%dT%H:%M:%SZ; }
p0_stamp()    { date -u +%Y%m%dT%H%M%SZ; }

log()  { printf '[p0-lab] %s\n'      "$*" >&2; }
warn() { printf '[p0-lab] WARN: %s\n' "$*" >&2; }
die()  { printf '[p0-lab] ERROR: %s\n' "$*" >&2; exit 1; }

p0_run_dir() {
  if [ -n "${P0_RUN_DIR:-}" ]; then mkdir -p "$P0_RUN_DIR"; printf '%s\n' "$P0_RUN_DIR"; return 0; fi
  local d; d="$P0_ARTIFACTS_BASE/$(p0_stamp)"
  mkdir -p "$d"; printf '%s\n' "$d"
}

# Record a command's stdout+stderr, exit code and duration; echo the exit code.
# Never use for commands that receive a secret on argv.
p0_run_logged() { # logfile description -- cmd...
  local logf="$1" desc="$2"; shift 2
  [ "$1" = "--" ] && shift
  local start end rc
  start="$(date +%s)"
  printf '### %s\n$ %s\n' "$desc" "$*" >>"$logf"
  set +e; "$@" >>"$logf" 2>&1; rc=$?; set -e
  end="$(date +%s)"
  printf '### exit=%d duration=%ds\n\n' "$rc" "$((end - start))" >>"$logf"
  return "$rc"
}

# Map the run-p0.sh driver exit code to a P0 verdict token.
#   0=PASS  25=INCONCLUSIVE  20/30=FAIL  10=OPERATIONAL  2=BLOCKED
p0_verdict_from_rc() {
  case "$1" in
    0)  echo PASS;;
    25) echo INCONCLUSIVE;;
    20) echo FAIL;;
    30) echo FAIL;;
    10) echo OPERATIONAL;;
    2)  echo BLOCKED;;
    *)  echo UNKNOWN;;
  esac
}

# ── differential residue detection (point #9) ───────────────────────────────
# PID set of THIS user's worker/harness processes, one per line, sorted. Empty
# output (no matches) is normal and must NOT be treated as an error or as "0".
p0_worker_pids() {
  { pgrep -u "$(id -u)" -f 'privion-rdp-worker-lab|privion-rdp-lab-harness' 2>/dev/null || true; } | sort -u
}
p0_worker_tmpdirs() {
  { find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'privion-p0.*' -type d 2>/dev/null || true; } | sort -u
}
# Lines present in $2 (post) but not in $1 (pre). Args are newline-joined strings.
p0_new_lines() { comm -13 <(printf '%s' "$1") <(printf '%s' "$2"); }

# Snapshot processes relevant to leak/orphan detection (no secrets: the worker
# never puts the credential on argv — only the 0400 file path).
p0_snapshot_procs() { # outfile
  # shellcheck disable=SC2009  # need rss/pcpu/nlwp/etimes columns; pgrep can't
  { ps -eo pid,ppid,rss,pcpu,nlwp,etimes,comm,args 2>/dev/null \
      | grep -E 'privion-rdp-worker-lab|privion-rdp-lab-harness|freerdp|xfreerdp|run-p0' \
      | grep -v grep || true; } >"$1"
}
p0_snapshot_sockets() { # outfile
  {
    echo "# unix (privion)"; ss -xp 2>/dev/null | grep -i privion || true
    echo "# tcp"; ss -tanp 2>/dev/null || true
  } >"$1"
}

# ── environment / config ────────────────────────────────────────────────────
p0_load_env() {
  local f="${P0_LAB_ENV:-$P0_LAB_DIR/p0-lab.env}"
  if [ -f "$f" ]; then
    set -a
    # shellcheck disable=SC1090,SC1091
    . "$f"
    set +a
    export P0_ENV_LOADED=1
    log "lab config loaded from $(basename "$f") (values not printed)"
  else
    export P0_ENV_LOADED=0
    warn "no lab config ($f) — external-dependent phases will report BLOCKED"
  fi
}

p0_validate_cred() { # path -> repo helper (never reads the secret in shell)
  python3 "$P0_REPO_ROOT/rdp-worker/scripts/p0-evidence-secret-scan.py" --validate "$1"
}

# ── network route preflight (point #3) ──────────────────────────────────────
# TCP connect probe (no auth). Echoes reachable|unreachable.
p0_tcp_probe() { # host port
  local h="$1" p="${2:-3389}"
  if command -v nc >/dev/null 2>&1; then
    nc -z -w3 "$h" "$p" 2>/dev/null && echo reachable || echo unreachable
  else
    timeout 3 bash -c ">/dev/tcp/$h/$p" 2>/dev/null && echo reachable || echo unreachable
  fi
}

# Decide how the worker must run to reach $host:$port, honouring P0_WORKER_MODE
# (auto|host|container). In 'auto': if the host can TCP-reach the target, use
# host mode; else, if a container runner + lab network exist, use container mode;
# else BLOCKED. Echoes: host | container | blocked:<reason>
p0_resolve_worker_mode() { # host port
  local host="$1" port="$2" mode="${P0_WORKER_MODE:-auto}"
  case "$mode" in
    host)
      [ "$(p0_tcp_probe "$host" "$port")" = reachable ] && { echo host; return; }
      echo "blocked:host mode selected but $host:$port unreachable from host"; return;;
    container)
      p0_container_runner_ready && { echo container; return; }
      echo "blocked:container mode selected but runner image/network missing"; return;;
    auto)
      if [ "$(p0_tcp_probe "$host" "$port")" = reachable ]; then echo host; return; fi
      if p0_container_runner_ready; then echo container; return; fi
      echo "blocked:$host:$port not reachable from host and no container runner (see 41-worker-image.sh)"; return;;
    *) echo "blocked:invalid P0_WORKER_MODE=$mode";;
  esac
}

p0_engine() { command -v docker >/dev/null 2>&1 && { echo docker; return; }; command -v podman >/dev/null 2>&1 && { echo podman; return; }; echo ""; }

p0_container_runner_ready() {
  local eng; eng="$(p0_engine)"; [ -n "$eng" ] || return 1
  "$eng" image inspect "${P0_RUNNER_IMAGE:-p0-lab-runner:local}" >/dev/null 2>&1 || return 1
  "$eng" network inspect "${P0_LAB_NET:-p0-lab-net}" >/dev/null 2>&1 || return 1
  return 0
}
