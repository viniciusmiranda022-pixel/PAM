#!/usr/bin/env bash
# 50-run-scenario.sh — Phases 5+6: run ONE P0 scenario through the repo driver
# rdp-worker/scripts/run-p0.sh, with DIFFERENTIAL process/socket residue checks
# (point #9), host-or-container execution (point #3), thread/teardown capture,
# and a fail-closed verdict. Appends one JSON record to scenario-results.jsonl.
#
# Execution modes (P0_WORKER_MODE=auto|host|container):
#   host      — native worker binary on this host (routable targets, e.g. the
#               operator's Windows VM).
#   container — worker runs inside the p0-lab-runner image on the lab Docker
#               network (required for the --internal xrdp container, whose IP the
#               host cannot reach). Build it with 41-worker-image.sh.
#
# Required env (driver inputs — see rdp-worker/scripts/run-p0.sh):
#   PRIVION_SCENARIO, PRIVION_EXPECTED_RESULT, PRIVION_TARGET_FILE,
#   PRIVION_USERNAME, PRIVION_CRED_FILE  (+ optional PRIVION_*).
# Optional: SCN_TARGET_HOST/SCN_TARGET_PORT to drive the route/mode decision.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"

RDP="$P0_REPO_ROOT/rdp-worker"
DRIVER="$RDP/scripts/run-p0.sh"
: "${PRIVION_SCENARIO:?set PRIVION_SCENARIO}"
: "${PRIVION_EXPECTED_RESULT:?set PRIVION_EXPECTED_RESULT}"

RUN_DIR="$(p0_run_dir)"
export PRIVION_EVIDENCE_DIR="${PRIVION_EVIDENCE_DIR:-$RUN_DIR/evidence}"
export PRIVION_WORKER="${PRIVION_WORKER:-$RDP/build-native/privion-rdp-worker-lab}"
mkdir -p "$PRIVION_EVIDENCE_DIR"
scn="$PRIVION_SCENARIO"
drvlog="$RUN_DIR/driver-$scn.log"

record() { # verdict rc sentinel residual threads_max wall_ms mode reason
  python3 - "$RUN_DIR/scenario-results.jsonl" "$@" <<'PY'
import json, os, sys
out, verdict, rc, sentinel, residual, threads, wall, mode, reason = sys.argv[1:10]
evsub = os.environ.get("P0_EVSUB", "") or None
rec = {
    "scenario": os.environ["PRIVION_SCENARIO"],
    "expected_result": os.environ["PRIVION_EXPECTED_RESULT"],
    "driver_exit_code": int(rc), "verdict_script": verdict,
    "secret_sentinel": sentinel, "residual_new": int(residual),
    "threads_max": (int(threads) if threads.isdigit() else None),
    "driver_wall_ms": (int(wall) if wall.isdigit() else None),
    "worker_mode": mode, "tofu": os.environ.get("PRIVION_LAB_TOFU_CERT", "0"),
    "allow_target": os.environ.get("PRIVION_ALLOW_TARGET", "(derived)"),
    "evidence_dir": evsub, "reason": reason or None,
    "note": "verdict_script is the driver's mechanical result; PASS of an eliminatory "
            "scenario still needs operator confirmation from worker-stderr.txt",
}
open(out, "a", encoding="utf-8").write(json.dumps(rec) + "\n")
PY
}

# --- fail-closed preconditions ---
if [ ! -x "$PRIVION_WORKER" ] && [ "${P0_WORKER_MODE:-auto}" != container ]; then
  log "scenario '$scn': BLOCKED — native worker not built ($PRIVION_WORKER). Run 10-repo-validate.sh."
  record BLOCKED 2 n/a 0 "" "" host "native worker not built"
  exit 0
fi

# --- resolve execution mode from the target route (point #3) ---
thost="${SCN_TARGET_HOST:-}"; tport="${SCN_TARGET_PORT:-3389}"
mode="host"
if [ -n "$thost" ]; then
  decision="$(p0_resolve_worker_mode "$thost" "$tport")"
  case "$decision" in
    host|container) mode="$decision";;
    blocked:*) log "scenario '$scn': BLOCKED — ${decision#blocked:}"; record BLOCKED 2 n/a 0 "" "" auto "${decision#blocked:}"; exit 0;;
  esac
fi

# --- differential residue baseline (point #9) ---
pids_pre="$(p0_worker_pids)"; tmp_pre="$(p0_worker_tmpdirs)"
p0_snapshot_procs "$RUN_DIR/proc-pre-$scn.txt"; p0_snapshot_sockets "$RUN_DIR/sock-pre-$scn.txt"

# --- thread sampler (best-effort): tracks max NLWP of the worker during the run ---
threads_file="$RUN_DIR/.threads-$scn"; echo 0 >"$threads_file"
( while :; do
    for pid in $(p0_worker_pids); do
      n="$(awk '{print $20}' "/proc/$pid/stat" 2>/dev/null || echo 0)"
      cur="$(cat "$threads_file" 2>/dev/null || echo 0)"
      [ "${n:-0}" -gt "${cur:-0}" ] 2>/dev/null && echo "$n" >"$threads_file"
    done
    sleep 0.3
  done ) & sampler=$!

start_ms="$(awk '{printf "%.0f",$1*1000}' /proc/uptime)"
set +e
if [ "$mode" = container ]; then
  bash "$(dirname -- "$0")/lib/run-driver-container.sh" >"$drvlog" 2>&1
else
  bash "$DRIVER" >"$drvlog" 2>&1
fi
rc=$?
set -e
end_ms="$(awk '{printf "%.0f",$1*1000}' /proc/uptime)"
wall_ms=$(( end_ms - start_ms ))
kill "$sampler" 2>/dev/null || true; wait "$sampler" 2>/dev/null || true
threads_max="$(cat "$threads_file" 2>/dev/null || echo 0)"; rm -f "$threads_file"

p0_snapshot_procs "$RUN_DIR/proc-post-$scn.txt"; p0_snapshot_sockets "$RUN_DIR/sock-post-$scn.txt"
pids_post="$(p0_worker_pids)"; tmp_post="$(p0_worker_tmpdirs)"

# NEW residue attributable to THIS scenario = post-set minus pre-set.
new_pids="$(p0_new_lines "$pids_pre" "$pids_post")"
new_tmp="$(p0_new_lines "$tmp_pre" "$tmp_post")"
residual=0
[ -n "$new_pids" ] && residual=$(( residual + $(printf '%s\n' "$new_pids" | grep -c .) ))
[ -n "$new_tmp" ]  && residual=$(( residual + $(printf '%s\n' "$new_tmp"  | grep -c .) ))
{
  echo "# differential residue for scenario '$scn'"
  echo "new worker/harness pids: ${new_pids:-none}"
  echo "new privion-p0 tmpdirs:  ${new_tmp:-none}"
} >"$RUN_DIR/residue-$scn.txt"

verdict="$(p0_verdict_from_rc "$rc")"
[ "$residual" -gt 0 ] && { warn "scenario '$scn': $residual NEW residual process(es)/tmpdir(s) — orphan FAIL"; verdict=FAIL; }

# Driver's own per-scenario credential-exact sentinel.
evsub="$( { ls -dt "$PRIVION_EVIDENCE_DIR/$scn".*/ 2>/dev/null || true; } | head -n1 )"
export P0_EVSUB="${evsub%/}"
sentinel="unknown"
[ -n "$evsub" ] && [ -f "${evsub}secret-sentinel.json" ] && \
  sentinel="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("result","unknown"))' "${evsub}secret-sentinel.json" 2>/dev/null || echo unknown)"
[ "$sentinel" = "LEAK_PRESENT" ] && verdict=FAIL

record "$verdict" "$rc" "$sentinel" "$residual" "$threads_max" "$wall_ms" "$mode" ""
log "scenario '$scn': mode=$mode exit=$rc verdict=$verdict sentinel=$sentinel residual=$residual threads=$threads_max"
exit 0
