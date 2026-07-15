#!/usr/bin/env bash
# run-p0-script-test.sh — offline tests for scripts/run-p0.sh and the
# scripts/p0-evidence-secret-scan.py helper. No FreeRDP, no real RDP target: a
# Python worker stub (real Unix Domain Socket) and a Python harness stub stand in
# for the native binaries via PRIVION_WORKER / PRIVION_HARNESS.
#
# Covered: bash -n, ShellCheck (if present), nominal connect, terminate,
# egress_denied, auth_reject/cert_reject, cert_trusted (TOFU=0/1, scenario name
# deliberately without "cert"), network_unreachable, watchdog, asset_disconnect,
# INCONCLUSIVE→rc 25, missing worker/harness/credential, mode != 0400, wrong
# owner, symlink refused, absent/invalid target JSON, invalid scenario/expected/
# tofu/int, session/expected coherence, selftest gate (fail / logic build /
# wrong FreeRDP version), socket never created, worker dies before the socket,
# expected-vs-observed contradictions (FAIL), final-package leak sentinel
# (present and absent, covering manifest/summary/facts), CPU + monotonic
# duration metrics, socket-wait timeout, SIGINT/SIGTERM teardown, no orphans,
# and tmpdir/socket cleanup.
set -euo pipefail
export LC_ALL=C

SELF_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
RDP_DIR="$(cd -- "$SELF_DIR/.." && pwd)"
DRIVER="$RDP_DIR/scripts/run-p0.sh"
SCAN_PY="$RDP_DIR/scripts/p0-evidence-secret-scan.py"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/p0-script-test.XXXXXX")"
STUB_TAG="p0stub-$$-$RANDOM"
export STUB_TAG
PASS=0
FAIL=0

cleanup_all() {
  # Kill any lingering stub belonging to this test run, then remove WORK.
  local pid
  for pid in $(list_orphans 2>/dev/null || true); do
    kill -KILL "$pid" 2>/dev/null || true
  done
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup_all EXIT

say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }

assert_rc() { # expected actual label
  if [ "$1" = "$2" ]; then ok "$3 (rc=$2)"; else bad "$3 (expected rc=$1, got rc=$2)"; fi
}
assert_contains() { # file needle label
  if grep -Fq -- "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3 (missing '$2' in $1)"; fi
}
assert_absent() { # file needle label
  if grep -Fq -- "$2" "$1" 2>/dev/null; then bad "$3 (unexpected '$2' in $1)"; else ok "$3"; fi
}

# Find processes of THIS test's stubs via their inherited STUB_TAG (reliable even
# though argv is the driver's random socket path).
list_orphans() {
  local p env
  for p in /proc/[0-9]*; do
    # group-redirect so a vanished /proc entry can't print an open error
    { env="$(tr '\0' '\n' <"$p/environ")"; } 2>/dev/null || continue
    printf '%s\n' "$env" | grep -qx "STUB_TAG=$STUB_TAG" && printf '%s\n' "${p#/proc/}"
  done
}

# ── stub binaries ───────────────────────────────────────────────────────────
mk_stubs() {
  cat >"$WORK/stub-worker.py" <<'PY'
#!/usr/bin/env python3
import json, os, socket, sys, time

def emit(**kw):
    kw.setdefault("timestamp", "2026-01-01T00:00:00Z")
    kw.setdefault("labJobId", "stubjob")
    kw.setdefault("workerPid", os.getpid())
    kw.setdefault("freerdpVersion", "3.28.0")
    sys.stdout.write(json.dumps(kw) + "\n")
    sys.stdout.flush()

def selftest():
    mode = os.environ.get("STUB_SELFTEST", "ok")
    if mode == "fail":
        sys.stderr.write("selftest: wipe failed\n")
        return 1
    sys.stdout.write("worker: stub-privion-rdp-worker-lab 0.0.0-stub\n")
    if mode == "logic":
        sys.stdout.write("freerdp: not-linked (expected 3.28.0)\n")
        sys.stdout.write("selftest: logic build (FreeRDP not linked) — native check "
                         "is performed by CI job rdp-worker-build-test\n")
    elif mode == "wrongver":
        sys.stdout.write("freerdp: 3.27.4 (expected 3.28.0)\n")
        sys.stdout.write("selftest: native FreeRDP 3.27.4 confirmed\n")
    else:
        sys.stdout.write("freerdp: 3.28.0 (expected 3.28.0)\n")
        sys.stdout.write("selftest: native FreeRDP 3.28.0 confirmed\n")
    sys.stdout.write("selftest: ok\n")
    return 0

def main():
    mode = os.environ.get("STUB_MODE", "connect")
    sockpath = None
    maxsec = 30
    a = sys.argv[1:]
    i = 0
    while i < len(a):
        if a[i] == "--selftest":
            return selftest()
        elif a[i] == "--socket":
            sockpath = a[i + 1]; i += 2
        elif a[i] == "--max-seconds":
            maxsec = int(a[i + 1]); i += 2
        elif a[i] in ("--allow-target", "--allow-uid"):
            i += 2
        else:
            i += 1
    sys.stderr.write("freerdp: stub worker starting (redacted)\n")
    if mode == "die_before_socket":
        sys.stderr.write("stub: exiting before creating the socket\n")
        return 1
    if mode == "no_socket":
        time.sleep(int(os.environ.get("STUB_NO_SOCKET_SLEEP", "10")))
        return 1
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(sockpath)
    except OSError:
        pass
    s.bind(sockpath)
    s.listen(1)
    s.settimeout(maxsec + 5)
    try:
        conn, _ = s.accept()
    except socket.timeout:
        return 1
    if mode == "egress_denied":
        emit(state="refused", result="refused", reasonCode="egress_denied", durationMs=5)
        conn.close(); s.close(); return 1
    if mode in ("reject", "auth_reject", "cert_reject", "net_unreachable"):
        emit(state="connecting", result="ok", reasonCode="connecting", durationMs=3)
        emit(state="terminated", result="error", reasonCode="freerdp_connect_failed", durationMs=40)
        conn.close(); s.close(); return 1
    # connect-family: connect, watchdog, asset_disconnect
    emit(state="connecting", result="ok", reasonCode="connecting", durationMs=10)
    emit(state="connected", result="ok", reasonCode="connected", durationMs=120)
    if mode == "asset_disconnect":
        time.sleep(0.3)
        emit(state="terminated", result="error", reasonCode="check_event_handles_failed", durationMs=430)
        conn.close(); s.close(); return 1
    conn.settimeout(maxsec)
    try:
        while True:
            data = conn.recv(16)
            if not data or data.strip() == b"TERMINATE":
                break
    except socket.timeout:
        pass  # watchdog fired
    dur = 120 + (maxsec * 1000 if mode == "watchdog" else 900)
    emit(state="terminated", result="ok", reasonCode="closed", durationMs=dur)
    conn.close(); s.close(); return 0

if __name__ == "__main__":
    sys.exit(main())
PY

  cat >"$WORK/stub-harness.py" <<'PY'
#!/usr/bin/env python3
import os, socket, sys, time

def main():
    hmode = os.environ.get("STUB_HARNESS", "")
    sockpath = None
    credfile = None
    session = None
    a = sys.argv[1:]
    i = 0
    while i < len(a):
        if a[i] == "--socket":
            sockpath = a[i + 1]; i += 2
        elif a[i] == "--cred-file":
            credfile = a[i + 1]; i += 2
        elif a[i] == "--session-seconds":
            session = int(a[i + 1]); i += 2
        elif a[i] in ("--target-file", "--username", "--cred-fd"):
            i += 2
        else:
            i += 1
    if hmode == "leak" and credfile:
        # Simulate a buggy component printing the secret; the sentinel must catch it.
        with open(credfile, "rb") as f:
            sys.stdout.write("LEAKED:" + f.read().decode("utf-8", "replace") + "\n")
        sys.stdout.flush()
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(sockpath)
    sys.stderr.write("harness: job submitted (credential not logged)\n")
    if hmode == "error":
        c.close(); return 3
    if session is not None:
        time.sleep(session)
        try:
            c.sendall(b"TERMINATE")
        except OSError:
            pass
        c.close(); return 0
    try:
        while True:
            if not c.recv(16):
                break
    except OSError:
        pass
    c.close(); return 0

if __name__ == "__main__":
    sys.exit(main())
PY
  chmod +x "$WORK/stub-worker.py" "$WORK/stub-harness.py"
}

# ── fixtures ────────────────────────────────────────────────────────────────
mk_fixtures() {
  printf '{"address":"192.0.2.10","port":3389}\n' >"$WORK/target.json"
  printf '{"address":"only-address"}\n'           >"$WORK/target-bad.json"
  printf 's3cr3t-lab-pw-%s' "$RANDOM" >"$WORK/cred"
  chmod 400 "$WORK/cred"
  ln -s "$WORK/cred" "$WORK/cred.symlink"
  printf 'not-really-secret' >"$WORK/cred644"
  chmod 644 "$WORK/cred644"
}

# Base environment for a driver run. Callers export overrides before run_driver.
base_env() {
  export PRIVION_WORKER="$WORK/stub-worker.py"
  export PRIVION_HARNESS="$WORK/stub-harness.py"
  export PRIVION_TARGET_FILE="$WORK/target.json"
  export PRIVION_USERNAME="labuser"
  export PRIVION_CRED_FILE="$WORK/cred"
  export PRIVION_EVIDENCE_DIR="$WORK/ev"
  export PRIVION_MAX_SECONDS="30"
  export PRIVION_SOCKET_TIMEOUT="10"
  unset PRIVION_SESSION_SECONDS PRIVION_ALLOW_TARGET PRIVION_LAB_TOFU_CERT PAM_ENV
  unset STUB_HARNESS STUB_NO_SOCKET_SLEEP STUB_SELFTEST
  export STUB_MODE="connect"
}

DRV_RC=0
run_driver() {
  set +e
  bash "$DRIVER" >"$WORK/driver.out" 2>"$WORK/driver.err"
  DRV_RC=$?
  set -e
}

# Newest evidence dir the driver just created (glob under PRIVION_EVIDENCE_DIR).
# Dir names are controlled (scenario.XXXXXX, no newlines), so ls -t is safe here.
latest_evdir() {
  # shellcheck disable=SC2012  # controlled names; sorting by mtime needs ls -t
  ls -dt "$PRIVION_EVIDENCE_DIR"/*/ 2>/dev/null | head -n1
}

mk_stubs
mk_fixtures

# ── static checks ───────────────────────────────────────────────────────────
say "== static analysis =="
if bash -n "$DRIVER"; then ok "bash -n run-p0.sh"; else bad "bash -n run-p0.sh"; fi
if bash -n "$0";      then ok "bash -n $(basename "$0")"; else bad "bash -n test"; fi
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -x "$DRIVER" "$0"; then ok "shellcheck clean"; else bad "shellcheck findings"; fi
else
  say "  (shellcheck not installed — skipped locally; CI enforces it)"
fi
if python3 -c 'import ast; ast.parse(open("'"$SCAN_PY"'").read())'; then ok "python parse helper"; else bad "python parse helper"; fi

# ── nominal connect (PASS → rc 0) ────────────────────────────────────────────
say "== nominal connect (PASS, CLEAN) =="
base_env; export STUB_MODE="connect"; export PRIVION_SCENARIO="windows-nla"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 0 "$DRV_RC" "connect exits 0"
EV="$(latest_evdir)"
assert_contains "$EV/summary.json" '"verdict": "PASS"' "connect verdict PASS"
assert_contains "$EV/secret-sentinel.json" '"result": "CLEAN"' "final sentinel CLEAN"
for f in manifest.json summary.json summary.txt worker-events.jsonl worker-stderr.txt \
         harness-stdout.txt harness-stderr.txt resources.txt facts.kv \
         worker-selftest.txt secret-sentinel.json; do
  if [ -f "$EV/$f" ]; then ok "evidence has $f"; else bad "evidence missing $f"; fi
done
assert_contains "$EV/summary.txt" "NEVER approves the P0" "summary states it does not approve P0"
# CPU + monotonic duration metrics are real numbers, not placeholders
assert_contains "$EV/resources.txt" "cpu_user_seconds=" "resources has cpu_user_seconds"
assert_contains "$EV/resources.txt" "cpu_system_seconds=" "resources has cpu_system_seconds"
assert_contains "$EV/resources.txt" "duration_monotonic_ms=" "resources has monotonic duration"
assert_absent   "$EV/resources.txt" "cpu_user_seconds=unavailable" "cpu_user_seconds was actually sampled"
assert_contains "$EV/manifest.json" '"cpu_user_seconds"' "manifest has cpu_user_seconds"
assert_contains "$EV/manifest.json" '"duration_monotonic_ms"' "manifest has duration_monotonic_ms"
# final scan is last: nothing in the package is newer than the sentinel
if [ -z "$(find "$EV" -type f ! -name secret-sentinel.json -newer "$EV/secret-sentinel.json" 2>/dev/null)" ]; then
  ok "no evidence file modified after the final scan"
else
  bad "files modified after the final scan"
fi
# no orphaned stubs after a clean run
if [ -z "$(list_orphans)" ]; then ok "no orphaned stubs after clean run"; else bad "orphaned stubs remain"; fi

# ── verdict families ─────────────────────────────────────────────────────────
say "== terminate (PASS via TERMINATE) =="
base_env; export STUB_MODE="connect"; export PRIVION_SCENARIO="terminate"; export PRIVION_EXPECTED_RESULT="terminate"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 0 "$DRV_RC" "terminate exits 0"
assert_contains "$(latest_evdir)/summary.json" "terminate_closed_session" "terminate PASS reason recorded"

say "== egress_denied (PASS) =="
base_env; export STUB_MODE="egress_denied"; export PRIVION_SCENARIO="egress-denied"; export PRIVION_EXPECTED_RESULT="egress_denied"; export PRIVION_ALLOW_TARGET="198.51.100.9:3389"
run_driver; assert_rc 0 "$DRV_RC" "egress_denied exits 0"
assert_contains "$(latest_evdir)/summary.json" '"verdict": "PASS"' "egress_denied verdict PASS"

say "== INCONCLUSIVE always exits 25 =="
base_env; export STUB_MODE="auth_reject"; export PRIVION_SCENARIO="cred-invalid"; export PRIVION_EXPECTED_RESULT="auth_reject"
run_driver; assert_rc 25 "$DRV_RC" "auth_reject INCONCLUSIVE → rc 25"
assert_contains "$(latest_evdir)/summary.json" '"verdict": "INCONCLUSIVE"' "auth_reject verdict INCONCLUSIVE"

base_env; export STUB_MODE="watchdog"; export PRIVION_SCENARIO="watchdog"; export PRIVION_EXPECTED_RESULT="watchdog"; export PRIVION_MAX_SECONDS="2"
run_driver; assert_rc 25 "$DRV_RC" "watchdog INCONCLUSIVE → rc 25"

base_env; export STUB_MODE="asset_disconnect"; export PRIVION_SCENARIO="asset-disconnect"; export PRIVION_EXPECTED_RESULT="asset_disconnect"
run_driver; assert_rc 25 "$DRV_RC" "asset_disconnect INCONCLUSIVE → rc 25"

base_env; export STUB_MODE="net_unreachable"; export PRIVION_SCENARIO="net-unavailable"; export PRIVION_EXPECTED_RESULT="network_unreachable"
run_driver; assert_rc 25 "$DRV_RC" "network_unreachable INCONCLUSIVE → rc 25"
assert_contains "$(latest_evdir)/summary.json" '"connected": false' "network_unreachable: no connected event"
assert_contains "$(latest_evdir)/summary.json" "no_connection_fail_closed" "network_unreachable fail-closed reason"

# ── contradictions → FAIL (rc 20) ───────────────────────────────────────────
say "== contradictions FAIL (rc 20) =="
base_env; export STUB_MODE="reject"; export PRIVION_SCENARIO="c-connect"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 20 "$DRV_RC" "expected connect but rejected → FAIL"
assert_contains "$(latest_evdir)/summary.json" '"verdict": "FAIL"' "connect contradiction verdict FAIL"

base_env; export STUB_MODE="connect"; export PRIVION_SCENARIO="c-egress"; export PRIVION_EXPECTED_RESULT="egress_denied"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 20 "$DRV_RC" "expected egress_denied but connected → FAIL"

base_env; export STUB_MODE="connect"; export PRIVION_SCENARIO="c-auth"; export PRIVION_EXPECTED_RESULT="auth_reject"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 20 "$DRV_RC" "expected auth_reject but connected → FAIL"

base_env; export STUB_MODE="connect"; export PRIVION_SCENARIO="c-net"; export PRIVION_EXPECTED_RESULT="network_unreachable"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 20 "$DRV_RC" "expected network_unreachable but connected → FAIL"

# ── certificate / TOFU guards (explicit expected result, never scenario name) ─
say "== certificate TOFU guards =="
base_env; export STUB_MODE="cert_reject"; export PRIVION_SCENARIO="untrusted-target"; export PRIVION_EXPECTED_RESULT="cert_reject"; export PRIVION_LAB_TOFU_CERT="0"
run_driver; assert_rc 25 "$DRV_RC" "cert_reject tofu=0 → INCONCLUSIVE (rc 25)"
assert_contains "$(latest_evdir)/summary.json" '"verdict": "INCONCLUSIVE"' "cert_reject tofu=0 INCONCLUSIVE"

base_env; export STUB_MODE="cert_reject"; export PRIVION_SCENARIO="plain-neg"; export PRIVION_EXPECTED_RESULT="cert_reject"; export PRIVION_LAB_TOFU_CERT="1"
run_driver; assert_rc 20 "$DRV_RC" "cert_reject tofu=1 → FAIL (scenario name without 'cert')"
assert_contains "$(latest_evdir)/summary.json" "tofu_voids_cert_reject_verdict" "cert_reject tofu=1 reason recorded"

base_env; export STUB_MODE="connect"; export PRIVION_SCENARIO="plain-pos"; export PRIVION_EXPECTED_RESULT="cert_trusted"; export PRIVION_LAB_TOFU_CERT="1"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 20 "$DRV_RC" "cert_trusted tofu=1 → FAIL (scenario name without 'cert')"
assert_contains "$(latest_evdir)/summary.json" "tofu_voids_cert_trust_verdict" "cert_trusted tofu=1 reason recorded"

base_env; export STUB_MODE="connect"; export PRIVION_SCENARIO="trusted-target"; export PRIVION_EXPECTED_RESULT="cert_trusted"; export PRIVION_LAB_TOFU_CERT="0"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 0 "$DRV_RC" "cert_trusted tofu=0 connected → PASS"
assert_contains "$(latest_evdir)/summary.json" "connected_via_verified_trust_chain" "cert_trusted PASS reason recorded"

# ── final-package leak sentinel ───────────────────────────────────────────────
say "== leak sentinel (final package) =="
base_env; export STUB_MODE="connect"; export STUB_HARNESS="leak"; export PRIVION_SCENARIO="leak-pos"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 30 "$DRV_RC" "leaked credential → rc 30"
EV="$(latest_evdir)"
assert_contains "$EV/secret-sentinel.json" '"result": "LEAK_PRESENT"' "final sentinel LEAK_PRESENT"
# only the sentinel is written after the scan
if [ -z "$(find "$EV" -type f ! -name secret-sentinel.json -newer "$EV/secret-sentinel.json" 2>/dev/null)" ]; then
  ok "leak run: nothing modified after the final scan"
else
  bad "leak run: files modified after the final scan"
fi
# and prove the secret token is not echoed by the driver itself
assert_absent "$WORK/driver.out" "s3cr3t-lab-pw" "driver stdout never prints the secret"
assert_absent "$WORK/driver.err" "s3cr3t-lab-pw" "driver stderr never prints the secret"

# ── selftest gate (rc 2, before any session) ──────────────────────────────────
say "== selftest gate =="
base_env; export STUB_SELFTEST="fail"; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"
run_driver; assert_rc 2 "$DRV_RC" "selftest failure → rc 2"
assert_contains "$WORK/driver.err" "selftest" "selftest failure reported"

base_env; export STUB_SELFTEST="logic"; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"
run_driver; assert_rc 2 "$DRV_RC" "logic build (FreeRDP not linked) → rc 2"

base_env; export STUB_SELFTEST="wrongver"; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"
run_driver; assert_rc 2 "$DRV_RC" "FreeRDP != 3.28.0 → rc 2"

# ── precondition / validation failures (rc 2) ───────────────────────────────
say "== precondition failures (rc 2) =="
base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_WORKER="$WORK/nope"
run_driver; assert_rc 2 "$DRV_RC" "missing worker → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_HARNESS="$WORK/nope"
run_driver; assert_rc 2 "$DRV_RC" "missing harness → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_CRED_FILE="$WORK/nope"
run_driver; assert_rc 2 "$DRV_RC" "absent credential → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_CRED_FILE="$WORK/cred644"
run_driver; assert_rc 2 "$DRV_RC" "credential mode != 0400 → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_CRED_FILE="$WORK/cred.symlink"
run_driver; assert_rc 2 "$DRV_RC" "credential symlink refused → rc 2"
assert_contains "$WORK/driver.err" "symlink_refused" "symlink refusal reported by token"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_TARGET_FILE="$WORK/nope.json"
run_driver; assert_rc 2 "$DRV_RC" "absent target file → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_TARGET_FILE="$WORK/target-bad.json"
run_driver; assert_rc 2 "$DRV_RC" "invalid target JSON (no port) → rc 2"

base_env; export PRIVION_SCENARIO="bad name!"; export PRIVION_EXPECTED_RESULT="connect"
run_driver; assert_rc 2 "$DRV_RC" "invalid scenario name → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="bogus"
run_driver; assert_rc 2 "$DRV_RC" "invalid expected result → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_LAB_TOFU_CERT="2"
run_driver; assert_rc 2 "$DRV_RC" "invalid tofu value → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_MAX_SECONDS="0"
run_driver; assert_rc 2 "$DRV_RC" "non-positive max-seconds → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="connect"; export PAM_ENV="production"
run_driver; assert_rc 2 "$DRV_RC" "PAM_ENV=production refused → rc 2"

say "== session/expected coherence (rc 2) =="
base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="terminate"
run_driver; assert_rc 2 "$DRV_RC" "terminate without PRIVION_SESSION_SECONDS → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="watchdog"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 2 "$DRV_RC" "watchdog with PRIVION_SESSION_SECONDS → rc 2"

base_env; export PRIVION_SCENARIO="p"; export PRIVION_EXPECTED_RESULT="asset_disconnect"; export PRIVION_SESSION_SECONDS="1"
run_driver; assert_rc 2 "$DRV_RC" "asset_disconnect with PRIVION_SESSION_SECONDS → rc 2"

# ── socket lifecycle failures (rc 10) ───────────────────────────────────────
say "== socket lifecycle (rc 10) =="
base_env; export STUB_MODE="die_before_socket"; export PRIVION_SCENARIO="s"; export PRIVION_EXPECTED_RESULT="connect"
run_driver; assert_rc 10 "$DRV_RC" "worker dies before socket → rc 10"

base_env; export STUB_MODE="no_socket"; export STUB_NO_SOCKET_SLEEP="10"; export PRIVION_SCENARIO="s"; export PRIVION_EXPECTED_RESULT="connect"; export PRIVION_SOCKET_TIMEOUT="2"
run_driver; assert_rc 10 "$DRV_RC" "socket never appears (timeout) → rc 10"
if [ -z "$(list_orphans)" ]; then ok "no orphaned stubs after socket-timeout teardown"; else bad "orphaned stubs after timeout"; fi

# ── signal teardown + orphan/cleanup checks ─────────────────────────────────
say "== signal teardown (SIGTERM / SIGINT) =="
signal_case() { # signal expected_rc label
  base_env; export STUB_MODE="connect"; export PRIVION_SCENARIO="sig"; export PRIVION_EXPECTED_RESULT="connect"
  export PRIVION_SESSION_SECONDS="30"; export PRIVION_MAX_SECONDS="60"
  set +e
  # Enable job control so the backgrounded driver keeps the DEFAULT SIGINT
  # disposition. A non-interactive shell otherwise sets SIGINT to SIG_IGN for
  # async children (and it cannot be re-trapped), which would mask the driver's
  # INT trap that fires normally under a foreground Ctrl-C.
  set -m
  bash "$DRIVER" >"$WORK/sig.out" 2>"$WORK/sig.err" &
  local dpid=$!
  set +m
  # wait until the worker stub is up (mid-session) before signalling
  local i=0
  while [ "$i" -lt 100 ]; do
    [ -n "$(list_orphans)" ] && break
    sleep 0.1; i=$((i + 1))
  done
  sleep 0.3
  local before; before="$(list_orphans | tr '\n' ' ')"
  kill -"$1" "$dpid" 2>/dev/null
  wait "$dpid"; local rc=$?
  set -e
  assert_rc "$2" "$rc" "$3 driver exit"
  # give the OS a moment to reap the killed children
  local j=0
  while [ "$j" -lt 30 ] && [ -n "$(list_orphans)" ]; do sleep 0.1; j=$((j + 1)); done
  if [ -n "$before" ] && [ -z "$(list_orphans)" ]; then ok "$3 no orphaned stubs after teardown"
  elif [ -z "$before" ]; then bad "$3 could not observe stubs mid-session"
  else bad "$3 orphaned stubs remain: $(list_orphans | tr '\n' ' ')"; fi
}
signal_case TERM 143 "SIGTERM"
signal_case INT  130 "SIGINT"

# tmpdir cleanup: no stray privion-p0.* dirs left behind by any run above
if find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'privion-p0.*' -type d 2>/dev/null | grep -q .; then
  bad "leftover privion-p0.* tmpdir(s) not cleaned up"
else
  ok "no leftover worker tmpdirs"
fi

# ── direct helper checks ──────────────────────────────────────────────────────
say "== helper: p0-evidence-secret-scan.py =="
if python3 "$SCAN_PY" --validate "$WORK/cred" >/dev/null 2>&1; then ok "--validate accepts 0400 owned file"; else bad "--validate rejected a valid file"; fi
if python3 "$SCAN_PY" --validate "$WORK/cred.symlink" >/dev/null 2>&1; then bad "--validate accepted a symlink"; else ok "--validate refuses a symlink"; fi
# wrong owner: only checkable as root (chown to a different, numeric uid)
if [ "$(id -u)" = "0" ]; then
  cp "$WORK/cred" "$WORK/cred-other"; chmod 400 "$WORK/cred-other"; chown 65534 "$WORK/cred-other"
  if python3 "$SCAN_PY" --validate "$WORK/cred-other" >/dev/null 2>&1; then bad "--validate accepted wrong-owner file"; else ok "--validate refuses wrong owner"; fi
else
  say "  (wrong-owner check needs root to chown — skipped on unprivileged CI)"
fi
# scan negative / positive in isolation
mkdir -p "$WORK/evneg"; printf 'no secret here\n' >"$WORK/evneg/a.txt"
if python3 "$SCAN_PY" --scan "$WORK/cred" "$WORK/evneg" | grep -qx CLEAN; then ok "--scan CLEAN when absent"; else bad "--scan not CLEAN"; fi
mkdir -p "$WORK/evpos"; cp "$WORK/cred" "$WORK/tmpcred"; chmod 600 "$WORK/tmpcred"; cat "$WORK/tmpcred" >"$WORK/evpos/leak.txt"
sc=0; python3 "$SCAN_PY" --scan "$WORK/cred" "$WORK/evpos" >/dev/null || sc=$?
assert_rc 3 "$sc" "--scan LEAK_PRESENT exits 3"
# --scan-final covers post-summary files (manifest/summary/facts) and writes the sentinel
mkdir -p "$WORK/evfin"; cat "$WORK/tmpcred" >"$WORK/evfin/manifest.json"
sc=0; python3 "$SCAN_PY" --scan-final "$WORK/cred" "$WORK/evfin" >/dev/null || sc=$?
assert_rc 3 "$sc" "--scan-final catches a leak inside manifest.json"
assert_contains "$WORK/evfin/secret-sentinel.json" '"result": "LEAK_PRESENT"' "--scan-final writes LEAK_PRESENT sentinel"
mkdir -p "$WORK/evfin2"; printf '{"clean":true}\n' >"$WORK/evfin2/manifest.json"
if python3 "$SCAN_PY" --scan-final "$WORK/cred" "$WORK/evfin2" | grep -qx CLEAN; then ok "--scan-final CLEAN on clean package"; else bad "--scan-final not CLEAN"; fi
assert_contains "$WORK/evfin2/secret-sentinel.json" '"result": "CLEAN"' "--scan-final writes CLEAN sentinel"

# ── result ──────────────────────────────────────────────────────────────────
say ""
say "== totals: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
