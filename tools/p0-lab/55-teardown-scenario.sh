#!/usr/bin/env bash
# 55-teardown-scenario.sh — automated, controlled teardown scenarios (point #5):
#   sigterm | sigint    — signal the running driver mid-session; expect 143/130
#                         and NO new residual processes/sockets/tmpdirs.
#   asset-disconnect    — drop the TARGET's connectivity mid-session by
#                         disconnecting the xrdp container from the lab network
#                         (controlled, reversible), then evaluate.
#
# These background the driver, wait until it reports "connected" in its own
# events, then apply the teardown — no indefinite manual step. Host mode is used
# for signals (driver runs here); asset-disconnect requires the container target.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"
p0_load_env || true

kind="${1:-}"; [ -n "$kind" ] || die "usage: 55-teardown-scenario.sh sigterm|sigint|asset-disconnect"
RDP="$P0_REPO_ROOT/rdp-worker"
DRIVER="$RDP/scripts/run-p0.sh"
RUN_DIR="$(p0_run_dir)"
export PRIVION_EVIDENCE_DIR="${PRIVION_EVIDENCE_DIR:-$RUN_DIR/evidence}"
export PRIVION_WORKER="${PRIVION_WORKER:-$RDP/build-native/privion-rdp-worker-lab}"
mkdir -p "$PRIVION_EVIDENCE_DIR"
: "${PRIVION_TARGET_FILE:?}"; : "${PRIVION_USERNAME:?}"; : "${PRIVION_CRED_FILE:?}"

scn="$kind"; export PRIVION_SCENARIO="$scn"
case "$kind" in
  sigterm|sigint) export PRIVION_EXPECTED_RESULT=connect;;
  asset-disconnect) export PRIVION_EXPECTED_RESULT=asset_disconnect;;
  *) die "unknown kind '$kind'";;
esac
# Long enough to be mid-session when we act; no TERMINATE for asset-disconnect.
if [ "$kind" = asset-disconnect ]; then unset PRIVION_SESSION_SECONDS
else export PRIVION_SESSION_SECONDS="${PRIVION_SESSION_SECONDS:-30}"; fi
export PRIVION_MAX_SECONDS="${PRIVION_MAX_SECONDS:-60}"
drvlog="$RUN_DIR/driver-$scn.log"

record() { # verdict rc reason
  P0_EVSUB="" python3 - "$RUN_DIR/scenario-results.jsonl" "$1" "$2" "$3" <<'PY'
import json, os, sys
out, verdict, rc, reason = sys.argv[1:5]
open(out, "a").write(json.dumps({
    "scenario": os.environ["PRIVION_SCENARIO"], "expected_result": os.environ["PRIVION_EXPECTED_RESULT"],
    "driver_exit_code": int(rc), "verdict_script": verdict, "secret_sentinel": "see per-scenario",
    "residual_new": int(os.environ.get("P0_RESIDUAL", "0")), "worker_mode": "host",
    "reason": reason,
}) + "\n")
PY
}

[ -x "$PRIVION_WORKER" ] || { record BLOCKED 2 "native worker not built"; exit 0; }
if [ "$kind" = asset-disconnect ]; then
  eng="$(p0_engine)"; [ -n "$eng" ] || { record BLOCKED 2 "asset-disconnect needs a container xrdp target + engine"; exit 0; }
  [ -n "${P0_XRDP_CONTAINER:-}" ] || { record BLOCKED 2 "P0_XRDP_CONTAINER unset"; exit 0; }
fi

pids_pre="$(p0_worker_pids)"; tmp_pre="$(p0_worker_tmpdirs)"

# Background the driver with job control so SIGINT is deliverable (a bg child of a
# non-interactive shell otherwise has SIGINT ignored and cannot be re-trapped).
set +e
set -m
bash "$DRIVER" >"$drvlog" 2>&1 &
dpid=$!
set +m

# Wait until the worker reports "connected" (poll its events), up to ~20s.
connected=0
for _ in $(seq 1 100); do
  if { ls "$PRIVION_EVIDENCE_DIR/$scn".*/worker-events.jsonl 2>/dev/null || true; } | head -1 \
       | xargs -r grep -l '"reasonCode": "connected"' >/dev/null 2>&1; then connected=1; break; fi
  kill -0 "$dpid" 2>/dev/null || break
  sleep 0.2
done

if [ "$connected" = 0 ]; then
  warn "scenario '$scn': never observed 'connected' — INCONCLUSIVE (target/creds?)"
  wait "$dpid" 2>/dev/null; rc=$?; set -e
  record INCONCLUSIVE "${rc:-2}" "no connected event before teardown"
  exit 0
fi

case "$kind" in
  sigterm) kill -TERM "$dpid" 2>/dev/null; expect=143;;
  sigint)  kill -INT  "$dpid" 2>/dev/null; expect=130;;
  asset-disconnect)
    log "dropping asset connectivity: $eng network disconnect $P0_LAB_NET $P0_XRDP_CONTAINER"
    "$eng" network disconnect "${P0_LAB_NET:-p0-lab-net}" "$P0_XRDP_CONTAINER" >/dev/null 2>&1 || warn "network disconnect failed"
    expect=any;;
esac
wait "$dpid" 2>/dev/null; rc=$?
set -e

# Reconnect the asset for subsequent scenarios.
if [ "$kind" = asset-disconnect ]; then
  "$eng" network connect "${P0_LAB_NET:-p0-lab-net}" "$P0_XRDP_CONTAINER" >/dev/null 2>&1 || true
fi

# differential residue
pids_post="$(p0_worker_pids)"; tmp_post="$(p0_worker_tmpdirs)"
new_pids="$(p0_new_lines "$pids_pre" "$pids_post")"; new_tmp="$(p0_new_lines "$tmp_pre" "$tmp_post")"
residual=0
[ -n "$new_pids" ] && residual=$(( residual + $(printf '%s\n' "$new_pids" | grep -c .) ))
[ -n "$new_tmp" ]  && residual=$(( residual + $(printf '%s\n' "$new_tmp"  | grep -c .) ))
export P0_RESIDUAL="$residual"

verdict=INCONCLUSIVE; reason="teardown applied; confirm cause in worker-stderr.txt"
if [ "$residual" -gt 0 ]; then verdict=FAIL; reason="$residual new residual process(es)/tmpdir(s) after teardown"
elif [ "$kind" != asset-disconnect ]; then
  if [ "$rc" = "$expect" ]; then verdict=PASS; reason="driver exited $rc on $kind with no residual"
  else verdict=FAIL; reason="expected exit $expect on $kind, got $rc"; fi
fi
record "$verdict" "$rc" "$reason"
log "scenario '$scn': rc=$rc verdict=$verdict residual=$residual"
exit 0
