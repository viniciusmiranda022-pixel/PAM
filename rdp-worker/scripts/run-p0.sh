#!/usr/bin/env bash
# run-p0.sh — drive ONE lab job of the isolated RDP Worker (PR-17B) against a
# REAL RDP target and record tamper-evident, secret-free evidence for the smoke
# P0 (docs/rdp-smoke-runbook.md).
#
# This is a laboratory driver, NOT an automated pass. It records one scenario's
# evidence and computes a per-scenario verdict (PASS / FAIL / INCONCLUSIVE); it
# NEVER declares the P0 approved — that requires ALL eliminatory scenarios green
# plus operator + reviewer sign-off in docs/rdp-p0-evidence-template.md.
#
# The credential NEVER enters the shell: it is validated and leak-scanned only by
# scripts/p0-evidence-secret-scan.py (open O_NOFOLLOW + fstat; the scanner reads
# the bytes internally and returns only CLEAN / LEAK_PRESENT). The credential is
# handed to the worker exclusively by the harness reading the 0400 file itself.
#
# Evidence ordering: process logs -> facts.kv -> resources.txt -> manifest.json/
# summary.json/summary.txt -> FINAL secret scan of the COMPLETE package, which
# then writes ONLY secret-sentinel.json. No other file is modified after the scan.
#
# Inputs (environment):
#   PRIVION_TARGET_FILE     path to a NON-SECRET lab-targets JSON (address, port)
#   PRIVION_USERNAME        login username (not a secret; may be DOMAIN\\user)
#   PRIVION_CRED_FILE       path to a 0400 secret file owned by the caller
#   PRIVION_SCENARIO        label, ^[A-Za-z0-9._-]{1,64}$ (evidence tag only —
#                           it never influences the verdict)
#   PRIVION_EXPECTED_RESULT one of: connect auth_reject cert_trusted cert_reject
#                           egress_denied watchdog asset_disconnect
#                           network_unreachable terminate
#   PRIVION_ALLOW_TARGET    optional addr:port for the worker allowlist; default
#                           derived from PRIVION_TARGET_FILE. Set it DIFFERENT
#                           from the target to exercise egress_denied.
#   PRIVION_SESSION_SECONDS optional positive int; if set the harness holds the
#                           session N s then sends TERMINATE. REQUIRED for
#                           expected=terminate; MUST be unset for
#                           expected=watchdog and expected=asset_disconnect.
#   PRIVION_MAX_SECONDS     worker watchdog seconds (default 30)
#   PRIVION_SOCKET_TIMEOUT  seconds to wait for the worker UDS (default 15)
#   PRIVION_LAB_TOFU_CERT   0 or 1 (default 0). 1 = lab accept-once escape hatch;
#                           it VOIDS any cert_trusted/cert_reject verdict.
#   PRIVION_EVIDENCE_DIR    evidence base dir (default ./p0-evidence)
#   PRIVION_WORKER          worker binary (default build-native/privion-rdp-worker-lab)
#   PRIVION_HARNESS         harness binary (default <worker dir>/harness/privion-rdp-lab-harness)
#
# Hard gate before any session: `worker --selftest` must exit 0 AND confirm a
# NATIVE build with FreeRDP exactly 3.28.0; otherwise the driver refuses (rc 2).
#
# Exit codes (only PASS returns zero):
#   0   ran; verdict PASS; final secret scan CLEAN
#   2   usage / precondition (bad env, missing binary, selftest gate, credential
#       invalid, bad target JSON) — nothing was launched
#   10  runtime/operational failure (worker UDS never appeared, worker died before
#       the socket, or the driver watchdog fired) — result is void, not a verdict
#   20  ran; verdict FAIL (observed outcome contradicts PRIVION_EXPECTED_RESULT)
#   25  ran; verdict INCONCLUSIVE (consistent but needs operator confirmation —
#       NEVER success; a gate must not treat 25 as approved)
#   30  SECRET LEAK: the credential bytes were found in the final evidence
#       package — hard stop (overrides any verdict)
set -euo pipefail
set +x                       # never echo commands (a secret could be on argv)
umask 077                    # new dirs 0700, new files 0600
export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"; readonly SCRIPT_DIR
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"; readonly ROOT_DIR
readonly SCAN_PY="$SCRIPT_DIR/p0-evidence-secret-scan.py"
readonly FREERDP_REQUIRED_VERSION="3.28.0"
readonly EXPECTED_ENUM="connect auth_reject cert_trusted cert_reject egress_denied watchdog asset_disconnect network_unreachable terminate"
readonly DRIVER_MARGIN=30    # driver watchdog = MAX_SECONDS + margin (safety net)

# ── tiny helpers ────────────────────────────────────────────────────────────
log()  { printf 'run-p0: %s\n' "$*" >&2; }
die()  { local code="$1"; shift; printf 'run-p0: error: %s\n' "$*" >&2; exit "$code"; }

require_pos_int() {           # name value max
  local n="$1" v="$2" max="$3"
  case "$v" in ''|*[!0-9]*|0*) die 2 "$n must be a positive integer ($v)";; esac
  [ "$v" -le "$max" ] || die 2 "$n must be <= $max ($v)"
}

# Monotonic milliseconds from /proc/uptime (CLOCK_BOOTTIME): immune to wall-clock
# changes and gives sub-second resolution, unlike `date +%s`.
mono_ms() { awk '{ printf "%.0f", $1 * 1000 }' /proc/uptime; }

# Linux-only liveness: true ONLY if the pid is running (not zombie/dead). Reading
# /proc avoids the kill -0 trap where a not-yet-reaped child looks alive.
proc_alive() {
  local line state
  line=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  state=${line##*') '}       # everything after ") "
  state=${state%% *}         # first token = state char
  case "$state" in Z|X|x|'') return 1;; *) return 0;; esac
}

# ── process/cleanup state ───────────────────────────────────────────────────
tmpdir=''
sock=''
wpid=''
hpid=''
_cleaned=0

# shellcheck disable=SC2329,SC2317  # invoked indirectly via the traps below
cleanup() {
  [ "$_cleaned" = 1 ] && return 0
  _cleaned=1
  # Kill ONLY the PIDs this script started (harness first, then worker). Never
  # pkill/killall. TERM, brief grace, then KILL any straggler; reap each.
  local pid
  for pid in "$hpid" "$wpid"; do
    [ -n "$pid" ] || continue
    kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "$hpid" "$wpid"; do
    [ -n "$pid" ] || continue
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      proc_alive "$pid" || break
      sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [ -n "$sock" ]; then rm -f "$sock" 2>/dev/null || true; fi
  if [ -n "$tmpdir" ]; then rm -rf "$tmpdir" 2>/dev/null || true; fi
}
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
trap 'cleanup; exit 129' HUP

# ── validate the environment (nothing launched yet) ─────────────────────────
[ -f "$SCAN_PY" ] || die 2 "helper not found: $SCAN_PY"
command -v python3 >/dev/null 2>&1 || die 2 "python3 is required"

: "${PRIVION_TARGET_FILE:?set PRIVION_TARGET_FILE to a non-secret lab-targets JSON}"
: "${PRIVION_USERNAME:?set PRIVION_USERNAME}"
: "${PRIVION_CRED_FILE:?set PRIVION_CRED_FILE to a 0400 secret file}"
: "${PRIVION_SCENARIO:?set PRIVION_SCENARIO (evidence label)}"
: "${PRIVION_EXPECTED_RESULT:?set PRIVION_EXPECTED_RESULT ($EXPECTED_ENUM)}"

case "$PRIVION_SCENARIO" in
  *[!A-Za-z0-9._-]*|'') die 2 "PRIVION_SCENARIO must match [A-Za-z0-9._-]{1,64}";;
esac
[ "${#PRIVION_SCENARIO}" -le 64 ] || die 2 "PRIVION_SCENARIO too long (<=64)"

expected=""
for e in $EXPECTED_ENUM; do [ "$PRIVION_EXPECTED_RESULT" = "$e" ] && expected="$e"; done
[ -n "$expected" ] || die 2 "PRIVION_EXPECTED_RESULT must be one of: $EXPECTED_ENUM"

case "$PRIVION_USERNAME" in
  *[[:cntrl:]]*|'') die 2 "PRIVION_USERNAME must be non-empty and control-char free";;
esac
[ "${#PRIVION_USERNAME}" -le 256 ] || die 2 "PRIVION_USERNAME too long (<=256)"

tofu="${PRIVION_LAB_TOFU_CERT:-0}"
case "$tofu" in 0|1) : ;; *) die 2 "PRIVION_LAB_TOFU_CERT must be 0 or 1";; esac

max_seconds="${PRIVION_MAX_SECONDS:-30}"
socket_timeout="${PRIVION_SOCKET_TIMEOUT:-15}"
require_pos_int PRIVION_MAX_SECONDS "$max_seconds" 86400
require_pos_int PRIVION_SOCKET_TIMEOUT "$socket_timeout" 3600

session_seconds="${PRIVION_SESSION_SECONDS:-}"
if [ -n "$session_seconds" ]; then
  require_pos_int PRIVION_SESSION_SECONDS "$session_seconds" 86400
fi

# Expected-result/session coherence: terminate NEEDS the harness to send
# TERMINATE; watchdog/asset_disconnect need it NOT to (else the close cause is
# ambiguous by construction).
case "$expected" in
  terminate)
    [ -n "$session_seconds" ] || die 2 \
      "PRIVION_EXPECTED_RESULT=terminate requires PRIVION_SESSION_SECONDS (the harness must send TERMINATE)";;
  watchdog|asset_disconnect)
    [ -z "$session_seconds" ] || die 2 \
      "PRIVION_EXPECTED_RESULT=$expected requires PRIVION_SESSION_SECONDS unset (TERMINATE must not be sent)";;
esac

[ -f "$PRIVION_TARGET_FILE" ] || die 2 "PRIVION_TARGET_FILE is not a regular file: $PRIVION_TARGET_FILE"

# Worker refuses PAM_ENV=production and would never open the socket; fail fast.
case "${PAM_ENV:-}" in
  production) die 2 "unset PAM_ENV=production — the lab worker refuses to start";;
esac

worker="${PRIVION_WORKER:-$ROOT_DIR/build-native/privion-rdp-worker-lab}"
harness="${PRIVION_HARNESS:-$(dirname -- "$worker")/harness/privion-rdp-lab-harness}"
[ -x "$worker" ]  || die 2 "worker not found/executable: $worker (build with scripts/build.sh --native)"
[ -x "$harness" ] || die 2 "harness not found/executable: $harness"

# Validate the credential file WITHOUT reading it in the shell (regular file,
# owner == euid, mode exactly 0400, size cap). The helper prints only a token.
python3 "$SCAN_PY" --validate "$PRIVION_CRED_FILE" >/dev/null \
  || die 2 "credential file rejected by $SCAN_PY --validate (see message above)"

# Allowlist endpoint: explicit override, else derived from the NON-SECRET target
# JSON (parsed by python; never eval'd). Validated to addr:port before use.
if [ -n "${PRIVION_ALLOW_TARGET:-}" ]; then
  allow_target="$PRIVION_ALLOW_TARGET"
else
  allow_target="$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print("%s:%d" % (str(d["address"]), int(d["port"])))' "$PRIVION_TARGET_FILE")" \
    || die 2 "could not derive addr:port from $PRIVION_TARGET_FILE (need {\"address\",\"port\"})"
fi
case "$allow_target" in
  *[!A-Za-z0-9._:-]*|'') die 2 "allow target has invalid characters: $allow_target";;
esac
allow_port="${allow_target##*:}"
allow_host="${allow_target%:*}"
if [ -z "$allow_host" ] || [ "$allow_host" = "$allow_target" ]; then
  die 2 "allow target must be addr:port: $allow_target"
fi
require_pos_int "allow target port" "$allow_port" 65535

# ── evidence directory (mktemp -d, never -u; 0700) ──────────────────────────
ev_base="${PRIVION_EVIDENCE_DIR:-$PWD/p0-evidence}"
mkdir -p "$ev_base" || die 2 "cannot create evidence base: $ev_base"
chmod 700 "$ev_base" 2>/dev/null || true
evdir="$(mktemp -d "$ev_base/${PRIVION_SCENARIO}.XXXXXX")" || die 2 "mktemp evidence dir failed"
chmod 700 "$evdir"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/privion-p0.XXXXXX")" || die 2 "mktemp tmpdir failed"
chmod 700 "$tmpdir"
sock="$tmpdir/worker.sock"

log "scenario=$PRIVION_SCENARIO expected=$expected allow=$allow_target tofu=$tofu evdir=$evdir"

# ── MANDATORY selftest gate: native worker with FreeRDP exactly 3.28.0 ───────
# Not optional evidence: the P0 refuses to run a logic build, a broken worker,
# or any FreeRDP version other than the pinned one.
selftest_rc=0
"$worker" --selftest >"$evdir/worker-selftest.txt" 2>&1 || selftest_rc=$?
[ "$selftest_rc" -eq 0 ] \
  || die 2 "worker --selftest failed (rc=$selftest_rc; see $evdir/worker-selftest.txt)"
grep -Fq "selftest: native FreeRDP ${FREERDP_REQUIRED_VERSION} confirmed" "$evdir/worker-selftest.txt" \
  || die 2 "worker is not a native build with FreeRDP ${FREERDP_REQUIRED_VERSION} (see $evdir/worker-selftest.txt)"
worker_version="unknown"
IFS= read -r worker_version <"$evdir/worker-selftest.txt" || worker_version="unknown"

worker_sha256="$(sha256sum -- "$worker"  | cut -d' ' -f1)"
harness_sha256="$(sha256sum -- "$harness" | cut -d' ' -f1)"

started_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_ms="$(mono_ms)"

# ── launch exactly one worker; wait for its UDS by the monotonic clock ───────
log "starting worker (watchdog ${max_seconds}s); events are the evidence"
PRIVION_LAB_TOFU_CERT="$tofu" "$worker" \
  --socket "$sock" --allow-target "$allow_target" --max-seconds "$max_seconds" \
  >"$evdir/worker-events.jsonl" 2>"$evdir/worker-stderr.txt" &
wpid=$!

socket_deadline_ms=$(( started_ms + socket_timeout * 1000 ))
until [ -S "$sock" ]; do
  proc_alive "$wpid" || die 10 "worker exited before creating the socket (see worker-stderr.txt)"
  [ "$(mono_ms)" -lt "$socket_deadline_ms" ] || die 10 "worker socket did not appear within ${socket_timeout}s"
  sleep 0.1
done
log "worker socket is up; submitting job via harness"

# ── resource sampling (peak RSS + CPU ticks) ─────────────────────────────────
# VmHWM is peak RSS (monotonic); utime/stime are cumulative CPU ticks — the last
# successful sample before exit is a lower bound. Group redirects so a vanished
# /proc entry cannot print an open error.
peak_rss_kb="unavailable"
utime_ticks=""
stime_ticks=""
sample_worker() {
  local line kb rest
  local -a f
  { while IFS= read -r line; do
      case "$line" in VmHWM:*) kb="${line#VmHWM:}"; kb="${kb//[!0-9]/}"; [ -n "$kb" ] && peak_rss_kb="$kb";; esac
    done <"/proc/$wpid/status"; } 2>/dev/null || true
  line=''
  { IFS= read -r line <"/proc/$wpid/stat"; } 2>/dev/null || true
  if [ -n "$line" ]; then
    rest="${line##*') '}"      # skip "pid (comm) "; utime/stime = tokens 12/13
    read -ra f <<<"$rest"
    if [ "${#f[@]}" -ge 13 ]; then
      utime_ticks="${f[11]}"
      stime_ticks="${f[12]}"
    fi
  fi
}
sample_worker                   # worker is alive here: guarantee >=1 sample

# ── launch exactly one harness; monitor both by the monotonic clock ──────────
harness_args=( --socket "$sock" --target-file "$PRIVION_TARGET_FILE"
               --username "$PRIVION_USERNAME" --cred-file "$PRIVION_CRED_FILE" )
if [ -n "$session_seconds" ]; then
  harness_args+=( --session-seconds "$session_seconds" )
fi
"$harness" "${harness_args[@]}" \
  >"$evdir/harness-stdout.txt" 2>"$evdir/harness-stderr.txt" &
hpid=$!

driver_deadline_ms=$(( started_ms + (max_seconds + DRIVER_MARGIN) * 1000 ))
while proc_alive "$hpid" || proc_alive "$wpid"; do
  sample_worker
  if [ "$(mono_ms)" -ge "$driver_deadline_ms" ]; then
    die 10 "driver watchdog exceeded ($((max_seconds + DRIVER_MARGIN))s); tearing down"
  fi
  sleep 0.2
done

# Capture exit codes SEPARATELY. No `|| true` masking of the main execution:
# a non-zero worker/harness rc is DATA the verdict interprets, not an error to hide.
harness_rc=0; wait "$hpid" 2>/dev/null || harness_rc=$?
worker_rc=0;  wait "$wpid" 2>/dev/null || worker_rc=$?
hpid=''; wpid=''             # reaped; nothing left for cleanup to kill

ended_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
duration_monotonic_ms=$(( $(mono_ms) - started_ms ))

clk_tck="$(getconf CLK_TCK 2>/dev/null)" || clk_tck=""
case "$clk_tck" in ''|*[!0-9]*) clk_tck=100;; esac
cpu_user_seconds="unavailable"
cpu_system_seconds="unavailable"
if [ -n "$utime_ticks" ] && [ -n "$stime_ticks" ]; then
  cpu_user_seconds="$(awk -v t="$utime_ticks" -v hz="$clk_tck" 'BEGIN { printf "%.2f", t / hz }')"
  cpu_system_seconds="$(awk -v t="$stime_ticks" -v hz="$clk_tck" 'BEGIN { printf "%.2f", t / hz }')"
fi

# Resource baseline. Per-session connect latency is durationMs-to-connected in
# the worker events (surfaced in summary.json).
{
  printf 'scenario=%s\n'              "$PRIVION_SCENARIO"
  printf 'cpu_user_seconds=%s\n'      "$cpu_user_seconds"
  printf 'cpu_system_seconds=%s\n'    "$cpu_system_seconds"
  printf 'clk_tck=%s\n'               "$clk_tck"
  printf 'worker_peak_rss_kb=%s\n'    "$peak_rss_kb"
  printf 'duration_monotonic_ms=%s\n' "$duration_monotonic_ms"
  printf 'started=%s\n'               "$started_iso"
  printf 'ended=%s\n'                 "$ended_iso"
  printf 'note=%s\n' "cpu/rss sampled from /proc just before worker exit (lower bound); connect latency is in summary.json (worker events)"
} >"$evdir/resources.txt"

# ── non-secret facts, then verdict + manifest/summary ─────────────────────────
facts="$evdir/facts.kv"
{
  printf 'scenario=%s\n'              "$PRIVION_SCENARIO"
  printf 'expected=%s\n'              "$expected"
  printf 'worker_rc=%s\n'             "$worker_rc"
  printf 'harness_rc=%s\n'            "$harness_rc"
  printf 'worker_path=%s\n'           "$worker"
  printf 'harness_path=%s\n'          "$harness"
  printf 'worker_sha256=%s\n'         "$worker_sha256"
  printf 'harness_sha256=%s\n'        "$harness_sha256"
  printf 'worker_version=%s\n'        "$worker_version"
  printf 'tofu=%s\n'                  "$tofu"
  printf 'allow_target=%s\n'          "$allow_target"
  printf 'session_seconds=%s\n'       "${session_seconds:-unset}"
  printf 'max_seconds=%s\n'           "$max_seconds"
  printf 'socket_timeout=%s\n'        "$socket_timeout"
  printf 'started=%s\n'               "$started_iso"
  printf 'ended=%s\n'                 "$ended_iso"
  printf 'duration_monotonic_ms=%s\n' "$duration_monotonic_ms"
  printf 'peak_rss_kb=%s\n'           "$peak_rss_kb"
  printf 'cpu_user_seconds=%s\n'      "$cpu_user_seconds"
  printf 'cpu_system_seconds=%s\n'    "$cpu_system_seconds"
  printf 'clk_tck=%s\n'               "$clk_tck"
} >"$facts"

verdict="$(python3 "$SCAN_PY" --summarize "$facts" "$evdir")" \
  || die 2 "summarize failed"

chmod 600 "$evdir"/* 2>/dev/null || true

# ── FINAL leak sentinel: scan the COMPLETE package (logs + facts + manifest +
# summaries), then write ONLY secret-sentinel.json. Nothing else is modified
# after this point. Exit: 0 CLEAN, 3 LEAK_PRESENT, 2 validation error.
sentinel="CLEAN"
sc=0
python3 "$SCAN_PY" --scan-final "$PRIVION_CRED_FILE" "$evdir" >/dev/null || sc=$?
case "$sc" in
  0) sentinel="CLEAN";;
  3) sentinel="LEAK_PRESENT";;
  *) die 2 "final secret scan failed (credential validation) rc=$sc";;
esac

log "verdict=$verdict secret_sentinel=$sentinel worker_rc=$worker_rc harness_rc=$harness_rc"
log "evidence: $evdir  (this script does NOT approve the P0 — see summary.txt)"

# ── exit-code mapping (only PASS returns zero; leak overrides everything) ─────
if [ "$sentinel" = "LEAK_PRESENT" ]; then
  exit 30
fi
case "$verdict" in
  PASS)         exit 0;;
  INCONCLUSIVE) exit 25;;
  FAIL)         exit 20;;
  *)            die 2 "unrecognized verdict from summarize: $verdict";;
esac
