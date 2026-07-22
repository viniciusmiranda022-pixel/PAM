#!/usr/bin/env bash
# 10-repo-validate.sh — Phase 2: repository validation (offline, no targets).
# Runs the same gates the CI runs for the worker, plus the native build and the
# selftest that the P0 driver requires. Fail-closed: if the build or selftest
# fails, later phases must NOT run scenarios against real targets.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"

RUN_DIR="$(p0_run_dir)"
LOG="$RUN_DIR/repository-validation.txt"
: >"$LOG"
RDP="$P0_REPO_ROOT/rdp-worker"
status=PASS
note_fail() { status=FAIL; warn "$1"; }

log "Phase 2: repository validation -> $LOG"

# --- repository state ---
{
  echo "branch: $(git -C "$P0_REPO_ROOT" branch --show-current)"
  echo "HEAD: $(git -C "$P0_REPO_ROOT" rev-parse HEAD)"
  echo "origin/main: $(git -C "$P0_REPO_ROOT" rev-parse origin/main 2>/dev/null || echo n/a)"
  echo "rdp-worker present: $([ -d "$RDP" ] && echo yes || echo no)"
} >"$RUN_DIR/repository-state.txt"

# --- scope guard + secret/dep scans (same as CI) ---
p0_run_logged "$LOG" "scope guard (check-rdp-worker-scope.sh)" -- \
  bash "$P0_REPO_ROOT/scripts/ci/check-rdp-worker-scope.sh" || note_fail "scope guard failed"
p0_run_logged "$LOG" "scan-secrets.sh" -- \
  bash "$P0_REPO_ROOT/scripts/ci/scan-secrets.sh" || note_fail "scan-secrets failed"
p0_run_logged "$LOG" "scan-forbidden-deps.sh" -- \
  bash "$P0_REPO_ROOT/scripts/ci/scan-forbidden-deps.sh" || note_fail "scan-forbidden-deps failed"

# --- offline P0 driver suite (bash -n, shellcheck if present, stub tests) ---
p0_run_logged "$LOG" "bash -n run-p0.sh" -- bash -n "$RDP/scripts/run-p0.sh" || note_fail "run-p0.sh syntax"
p0_run_logged "$LOG" "python parse secret-scan" -- \
  python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$RDP/scripts/p0-evidence-secret-scan.py" \
  || note_fail "secret-scan syntax"
if command -v shellcheck >/dev/null 2>&1; then
  p0_run_logged "$LOG" "shellcheck" -- shellcheck -x "$RDP/scripts/run-p0.sh" "$RDP/tests/run-p0-script-test.sh" \
    || note_fail "shellcheck findings"
else
  echo "### shellcheck not installed — skipped (CI enforces it)" >>"$LOG"
fi
p0_run_logged "$LOG" "offline stub suite (run-p0-script-test.sh)" -- \
  bash "$RDP/tests/run-p0-script-test.sh" || note_fail "offline stub suite failed"

# --- FreeRDP pin + native build + selftest (the P0 gate) ---
p0_run_logged "$LOG" "pin-freerdp.sh (tag->commit)" -- bash "$RDP/scripts/pin-freerdp.sh" \
  || warn "pin verification failed (see log)"

native_ok=0
if command -v cmake >/dev/null && command -v ninja >/dev/null && command -v g++ >/dev/null; then
  if ( cd "$RDP" && p0_run_logged "$LOG" "native build (build.sh --native)" -- ./scripts/build.sh --native ); then
    native_ok=1
  else
    warn "native build failed on host — try the container path (see README) — Phase 5 BLOCKED"
  fi
else
  warn "native build toolchain missing (need cmake+ninja+g++) — Phase 5 BLOCKED until built"
fi

WORKER="$RDP/build-native/privion-rdp-worker-lab"
if [ "$native_ok" = 1 ] && [ -x "$WORKER" ]; then
  if p0_run_logged "$LOG" "selftest (must confirm native FreeRDP 3.28.0)" -- "$WORKER" --selftest; then
    if grep -q "selftest: native FreeRDP 3.28.0 confirmed" "$LOG"; then
      echo "SELFTEST_GATE: PASS (native FreeRDP 3.28.0)" >>"$LOG"
    else
      note_fail "selftest did not confirm native FreeRDP 3.28.0"
      echo "SELFTEST_GATE: FAIL" >>"$LOG"
    fi
  else
    note_fail "selftest exited non-zero"
  fi
else
  echo "SELFTEST_GATE: BLOCKED (no native worker binary)" >>"$LOG"
  [ "$status" = PASS ] && status=BLOCKED
fi

printf '%s\n' "$status" >"$RUN_DIR/phase2-status.txt"
log "Phase 2 result: $status (native_ok=$native_ok)"
[ "$status" = PASS ]
