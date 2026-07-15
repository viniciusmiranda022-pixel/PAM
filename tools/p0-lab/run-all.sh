#!/usr/bin/env bash
# run-all.sh — fail-closed orchestrator for the P0 lab. Runs every phase possible
# with the current environment and marks the rest BLOCKED (never PASS). Does NOT
# commit/push, change SUPPORTED_PROTOCOLS, or touch the product runtime. Stops for
# genuinely external dependencies only (Windows VM, privilege, missing tools).
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"
p0_load_env || true

P0_RUN_DIR="$(p0_run_dir)"; export P0_RUN_DIR
RESULTS="$P0_RUN_DIR/scenario-results.jsonl"; : >"$RESULTS"
RDP="$P0_REPO_ROOT/rdp-worker"; WORKER="$RDP/build-native/privion-rdp-worker-lab"; D="$P0_LAB_DIR"
log "P0 run dir: $P0_RUN_DIR"

record_blocked() { # scenario expected reason
  python3 - "$RESULTS" "$1" "$2" "$3" <<'PY'
import json, sys
open(sys.argv[1], "a").write(json.dumps({
    "scenario": sys.argv[2], "expected_result": sys.argv[3], "driver_exit_code": 2,
    "verdict_script": "BLOCKED", "secret_sentinel": "n/a", "residual_new": 0,
    "reason": sys.argv[4]}) + "\n")
PY
  warn "scenario '$1': BLOCKED — $3"
}
mk_target() { printf '{"address":"%s","port":%s}\n' "$1" "$2" >"$3"; }

# --- Phases 1-4 ---
bash "$D/00-inventory.sh"    || warn "inventory reported issues"
set +e; bash "$D/10-repo-validate.sh"; PHASE2=$?; set -e
bash "$D/20-discover-lab.sh" || true
command -v openssl >/dev/null 2>&1 && { bash "$D/30-make-ca.sh" || warn "CA generation issues"; }
XRDP_READY=0
if [ -n "${P0_XRDP_IMAGE:-}" ] && [ -n "${P0_XRDP_CRED_FILE:-}" ]; then
  bash "$D/40-xrdp-target.sh" || true
  grep -q '^STATUS: READY' "$P0_RUN_DIR/xrdp-target.txt" 2>/dev/null && XRDP_READY=1
fi
# Container-mode runner image (needed to reach the --internal xrdp container).
if [ "${P0_WORKER_MODE:-auto}" != host ] && [ "$XRDP_READY" = 1 ]; then
  bash "$D/41-worker-image.sh" || warn "runner image build failed — container-mode scenarios may BLOCK"
fi

# --- gate: no native worker / Phase 2 not PASS => everything BLOCKED ---
if { [ ! -x "$WORKER" ] && [ "${P0_WORKER_MODE:-auto}" = host ]; } || [ "${PHASE2:-1}" != 0 ]; then
  warn "worker not built / repo validation not PASS — ALL scenarios BLOCKED"
  for s in host-denied port-denied cert-untrusted cred-invalid windows-nla xrdp cert-trusted \
           terminate watchdog sigterm sigint asset-disconnect network-unreachable; do
    record_blocked "$s" various "native worker unavailable or Phase 2 not PASS (repository-validation.txt)"
  done
  bash "$D/70-sbom-cve.sh" || true
  bash "$D/60-consolidate.sh" || true
  exit 0
fi

RPORT="${P0_RDP_PORT:-3389}"; VALID="${P0_CRED_VALID_FILE:-}"; INVALID="${P0_CRED_INVALID_FILE:-}"
xrdp_host="${P0_XRDP_TARGET%%:*}"; xrdp_port="${P0_XRDP_TARGET##*:}"; [ "$xrdp_port" = "${P0_XRDP_TARGET:-}" ] && xrdp_port="$RPORT"
win_host="${P0_WIN_TARGET%%:*}";   win_port="${P0_WIN_TARGET##*:}";   [ "$win_port" = "${P0_WIN_TARGET:-}" ] && win_port="$RPORT"
CA_DIR="${P0_CA_DIR:-$D/ca}"

# run a driver scenario (50) with target route hints for host/container decision
run_scn() { PRIVION_SCENARIO="$1" PRIVION_EXPECTED_RESULT="$2" SCN_TARGET_HOST="${3:-}" SCN_TARGET_PORT="${4:-$RPORT}" bash "$D/50-run-scenario.sh"; }

if [ -n "${P0_XRDP_TARGET:-}" ] && [ -n "$VALID" ]; then
  mk_target "$xrdp_host" "$xrdp_port" "$P0_RUN_DIR/t-xrdp.json"

  # ---- NEGATIVE controls first ----
  PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
    PRIVION_CRED_FILE="$VALID" PRIVION_ALLOW_TARGET="198.51.100.7:$RPORT" run_scn host-denied egress_denied "$xrdp_host" "$xrdp_port"
  PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
    PRIVION_CRED_FILE="$VALID" PRIVION_ALLOW_TARGET="$xrdp_host:$((xrdp_port + 1))" run_scn port-denied egress_denied "$xrdp_host" "$xrdp_port"

  # cert-untrusted: swap in the unknown cert, TOFU=0, then restore.
  if bash "$D/45-xrdp-cert.sh" untrusted 2>>"$P0_RUN_DIR/cert-ops.log"; then
    PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
      PRIVION_CRED_FILE="$VALID" PRIVION_LAB_TOFU_CERT=0 run_scn cert-untrusted cert_reject "$xrdp_host" "$xrdp_port"
  else
    record_blocked cert-untrusted cert_reject "could not install untrusted cert (see cert-ops.log)"
  fi

  if [ -n "$INVALID" ]; then
    PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
      PRIVION_CRED_FILE="$INVALID" run_scn cred-invalid auth_reject "$xrdp_host" "$xrdp_port"
  else
    record_blocked cred-invalid auth_reject "needs P0_CRED_INVALID_FILE (0400)"
  fi

  # ---- POSITIVE: xrdp connect + trusted cert + teardown family ----
  if bash "$D/45-xrdp-cert.sh" install 2>>"$P0_RUN_DIR/cert-ops.log"; then
    export SSL_CERT_FILE="$CA_DIR/lab-ca.crt"
    PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
      PRIVION_CRED_FILE="$VALID" PRIVION_SESSION_SECONDS=10 run_scn xrdp connect "$xrdp_host" "$xrdp_port"
    PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
      PRIVION_CRED_FILE="$VALID" PRIVION_LAB_TOFU_CERT=0 PRIVION_SESSION_SECONDS=10 run_scn cert-trusted cert_trusted "$xrdp_host" "$xrdp_port"
    PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
      PRIVION_CRED_FILE="$VALID" PRIVION_SESSION_SECONDS=8 run_scn terminate terminate "$xrdp_host" "$xrdp_port"
    PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
      PRIVION_CRED_FILE="$VALID" PRIVION_MAX_SECONDS=8 run_scn watchdog watchdog "$xrdp_host" "$xrdp_port"
    # automated teardown scenarios (signals + asset-disconnect)
    for k in sigterm sigint asset-disconnect; do
      PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
        PRIVION_CRED_FILE="$VALID" bash "$D/55-teardown-scenario.sh" "$k" || true
    done
    bash "$D/45-xrdp-cert.sh" restore 2>>"$P0_RUN_DIR/cert-ops.log" || true
  else
    record_blocked xrdp connect "could not install trusted cert (see cert-ops.log)"
    for s in cert-trusted terminate watchdog sigterm sigint asset-disconnect; do
      record_blocked "$s" various "trusted-cert install failed; xrdp session scenarios blocked"
    done
  fi

  # ---- baseline (CPU/RAM/latency) ----
  N="${P0_BASELINE_COUNT:-20}"
  export SSL_CERT_FILE="$CA_DIR/lab-ca.crt"
  bash "$D/45-xrdp-cert.sh" install 2>>"$P0_RUN_DIR/cert-ops.log" || true
  for i in $(seq -w 1 "$N"); do
    PRIVION_TARGET_FILE="$P0_RUN_DIR/t-xrdp.json" PRIVION_USERNAME="${P0_XRDP_USER:-labuser}" \
      PRIVION_CRED_FILE="$VALID" PRIVION_SESSION_SECONDS=5 run_scn "baseline-$i" connect "$xrdp_host" "$xrdp_port"
  done
  bash "$D/45-xrdp-cert.sh" restore 2>>"$P0_RUN_DIR/cert-ops.log" || true
else
  for s in host-denied port-denied cert-untrusted cred-invalid xrdp cert-trusted terminate watchdog sigterm sigint asset-disconnect; do
    record_blocked "$s" various "needs P0_XRDP_TARGET + P0_CRED_VALID_FILE"
  done
fi

# ---- Windows NLA (operator-provided VM) ----
if [ -n "${P0_WIN_TARGET:-}" ] && [ -n "$VALID" ] && [ -n "${P0_WIN_USER:-}" ]; then
  mk_target "$win_host" "$win_port" "$P0_RUN_DIR/t-win.json"
  PRIVION_TARGET_FILE="$P0_RUN_DIR/t-win.json" PRIVION_USERNAME="$P0_WIN_USER" \
    PRIVION_CRED_FILE="$VALID" PRIVION_SESSION_SECONDS=10 run_scn windows-nla connect "$win_host" "$win_port"
else
  record_blocked windows-nla connect "needs P0_WIN_TARGET (NLA VM) + P0_WIN_USER + P0_CRED_VALID_FILE — OPERATOR PROVIDES WINDOWS"
fi

# ---- network unreachable (fail-closed): allowlisted but unroutable TEST-NET-3 ----
if [ -x "$WORKER" ] || [ "${P0_WORKER_MODE:-auto}" != host ]; then
  mk_target "203.0.113.10" "$RPORT" "$P0_RUN_DIR/t-blackhole.json"
  PRIVION_TARGET_FILE="$P0_RUN_DIR/t-blackhole.json" PRIVION_USERNAME="labuser" \
    PRIVION_CRED_FILE="${VALID:-$INVALID}" PRIVION_ALLOW_TARGET="203.0.113.10:$RPORT" \
    PRIVION_SOCKET_TIMEOUT=8 run_scn network-unreachable network_unreachable "203.0.113.10" "$RPORT" || true
fi

# ---- SBOM + CVE, then consolidate ----
bash "$D/70-sbom-cve.sh" || true
bash "$D/60-consolidate.sh" || true
log "run-all finished. Review $P0_RUN_DIR/evidence-matrix.md, summary.json, resources.txt."
log "P0 is NOT approved here: operator + reviewer must sign docs/rdp-p0-evidence-template.md."
