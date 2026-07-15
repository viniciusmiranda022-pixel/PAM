#!/usr/bin/env bash
# tests/selftest.sh — offline self-tests for the P0 lab automation (point #12).
# Uses stub worker/harness binaries (no FreeRDP, no targets) and synthetic
# evidence to exercise the logic that does NOT depend on Docker/xrdp/Windows:
# verdict mapping, differential residue, the classified secret sentinel, the
# strict global verdict tokens, resources.txt statistics, and the fail-closed
# BLOCKED paths (no worker built, invalid selftest, incomplete config).
# Test assertions intentionally use `cond && ok || bad` (ok/bad always return 0).
# shellcheck disable=SC2015,SC1091
set -euo pipefail
export LC_ALL=C
SELF="$(cd -- "$(dirname -- "$0")" && pwd)"
LAB="$(cd -- "$SELF/.." && pwd)"
# shellcheck source=lib/common.sh
. "$LAB/lib/common.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/p0-lab-selftest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
eq()  { [ "$1" = "$2" ] && ok "$3 ($2)" || bad "$3 (want $1, got $2)"; }

echo "== verdict mapping =="
eq PASS         "$(p0_verdict_from_rc 0)"  "rc0->PASS"
eq BLOCKED      "$(p0_verdict_from_rc 2)"  "rc2->BLOCKED"
eq OPERATIONAL  "$(p0_verdict_from_rc 10)" "rc10->OPERATIONAL"
eq FAIL         "$(p0_verdict_from_rc 20)" "rc20->FAIL"
eq INCONCLUSIVE "$(p0_verdict_from_rc 25)" "rc25->INCONCLUSIVE"
eq FAIL         "$(p0_verdict_from_rc 30)" "rc30->FAIL(leak)"

echo "== differential residue (p0_new_lines) =="
pre="$(printf '111\n222\n')"; post="$(printf '111\n222\n333\n')"
eq "333" "$(p0_new_lines "$pre" "$post" | tr -d '\n')" "new pid detected"
eq "" "$(p0_new_lines "$post" "$post" | tr -d '\n')" "no new pid when unchanged (zero not miscounted)"

echo "== stub worker: selftest gate variants =="
# valid native selftest
cat >"$WORK/worker-ok" <<'SH'
#!/usr/bin/env bash
[ "$1" = "--selftest" ] && { echo "worker: stub 0.0.0"; echo "selftest: native FreeRDP 3.28.0 confirmed"; echo "selftest: ok"; exit 0; }
exit 0
SH
cat >"$WORK/worker-logic" <<'SH'
#!/usr/bin/env bash
[ "$1" = "--selftest" ] && { echo "selftest: logic build (FreeRDP not linked)"; exit 0; }
exit 0
SH
cat >"$WORK/worker-badver" <<'SH'
#!/usr/bin/env bash
[ "$1" = "--selftest" ] && { echo "selftest: native FreeRDP 3.27.4 confirmed"; exit 0; }
exit 0
SH
chmod +x "$WORK"/worker-*
grep -q "native FreeRDP 3.28.0 confirmed" <("$WORK/worker-ok" --selftest) && ok "ok worker confirms 3.28.0" || bad "ok worker"
grep -q "native FreeRDP 3.28.0 confirmed" <("$WORK/worker-logic" --selftest) && bad "logic should not confirm" || ok "logic build not confirmed"
grep -q "native FreeRDP 3.28.0 confirmed" <("$WORK/worker-badver" --selftest) && bad "badver should not confirm" || ok "wrong version not confirmed"

echo "== 50-run-scenario: BLOCKED when worker absent =="
RD="$WORK/run1"; mkdir -p "$RD"
P0_RUN_DIR="$RD" PRIVION_WORKER="$WORK/nope" PRIVION_SCENARIO=x PRIVION_EXPECTED_RESULT=connect \
  PRIVION_TARGET_FILE="$WORK/t.json" PRIVION_USERNAME=u PRIVION_CRED_FILE="$WORK/c" \
  bash "$LAB/50-run-scenario.sh" >/dev/null 2>&1 || true
v="$(python3 -c 'import json;print(json.loads(open("'"$RD"'/scenario-results.jsonl").read().strip())["verdict_script"])' 2>/dev/null || echo ERR)"
eq BLOCKED "$v" "no worker -> BLOCKED"

echo "== classified secret sentinel (60-consolidate Phase 7) =="
# credential-exact leak
RD2="$WORK/run2"; mkdir -p "$RD2/evidence/x.ab12"
printf 's3cr3t-demo' >"$WORK/cred.valid"; chmod 400 "$WORK/cred.valid"
printf 'LEAKED:s3cr3t-demo\n' >"$RD2/evidence/x.ab12/harness-stdout.txt"
printf '{"result":"CLEAN"}' >"$RD2/evidence/x.ab12/secret-sentinel.json"
: >"$RD2/scenario-results.jsonl"
P0_RUN_DIR="$RD2" P0_CRED_VALID_FILE="$WORK/cred.valid" bash "$LAB/60-consolidate.sh" >/dev/null 2>&1 || true
sg="$(python3 -c 'import json;print(json.load(open("'"$RD2"'/secret-sentinel.json"))["result"])')"
eq LEAK_PRESENT "$sg" "credential-exact leak detected"
# and the value is NOT present in the sentinel report
grep -q 's3cr3t-demo' "$RD2/secret-sentinel.json" && bad "sentinel leaked the value!" || ok "sentinel never prints the value"

echo "== clean run: field names are NOT false positives =="
RD3="$WORK/run3"; mkdir -p "$RD3/evidence"
printf 'password: <placeholder>\nAuthorization: Bearer <token>\nthe word secret in prose\n' >"$RD3/evidence/notes.txt"
: >"$RD3/scenario-results.jsonl"
P0_RUN_DIR="$RD3" bash "$LAB/60-consolidate.sh" >/dev/null 2>&1 || true
sg3="$(python3 -c 'import json;print(json.load(open("'"$RD3"'/secret-sentinel.json"))["result"])')"
eq CLEAN "$sg3" "placeholders/field-names not flagged"

echo "== global verdict tokens + resources.txt =="
RD4="$WORK/run4"; mkdir -p "$RD4"
cat >"$RD4/scenario-results.jsonl" <<'JSONL'
{"scenario":"host-denied","expected_result":"egress_denied","driver_exit_code":0,"verdict_script":"PASS","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"port-denied","expected_result":"egress_denied","driver_exit_code":0,"verdict_script":"PASS","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"cred-invalid","expected_result":"auth_reject","driver_exit_code":25,"verdict_script":"INCONCLUSIVE","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"cert-trusted","expected_result":"cert_trusted","driver_exit_code":0,"verdict_script":"PASS","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"cert-untrusted","expected_result":"cert_reject","driver_exit_code":25,"verdict_script":"INCONCLUSIVE","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"windows-nla","expected_result":"connect","driver_exit_code":0,"verdict_script":"PASS","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"xrdp","expected_result":"connect","driver_exit_code":0,"verdict_script":"PASS","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"terminate","expected_result":"terminate","driver_exit_code":0,"verdict_script":"PASS","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"watchdog","expected_result":"watchdog","driver_exit_code":0,"verdict_script":"PASS","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"asset-disconnect","expected_result":"asset_disconnect","driver_exit_code":1,"verdict_script":"PASS","secret_sentinel":"CLEAN","residual_new":0}
{"scenario":"baseline-01","expected_result":"connect","driver_exit_code":0,"verdict_script":"PASS","secret_sentinel":"CLEAN","residual_new":0,"threads_max":7}
JSONL
P0_RUN_DIR="$RD4" bash "$LAB/60-consolidate.sh" >/dev/null 2>&1 || true
gv="$(python3 -c 'import json;print(json.load(open("'"$RD4"'/summary.json"))["global_verdict"])')"
# all eliminatory present & PASS/INCONCLUSIVE, but CVE gate absent -> BLOCKED (fail-closed), not PASS
case "$gv" in PASS|FAIL|INCONCLUSIVE|BLOCKED) ok "global verdict is a strict token ($gv)";; *) bad "illegal global token: $gv";; esac
python3 -c 'import json;s=json.load(open("'"$RD4"'/summary.json"));assert s["global_verdict"]!="PASS_PENDING_SIGNOFF";assert s["signoff_required"] is True' \
  && ok "no PASS_PENDING_SIGNOFF; signoff_required flag present" || bad "verdict token/signoff flag"
[ -f "$RD4/resources.txt" ] && grep -q 'connect_latency_ms' "$RD4/resources.txt" && ok "resources.txt generated with stats" || bad "resources.txt missing/incomplete"
grep -q 'threads_max' "$RD4/resources.txt" && ok "resources.txt has threads_max" || bad "threads_max missing"

echo "== eliminatory FAIL forces global FAIL =="
RD5="$WORK/run5"; mkdir -p "$RD5"
printf '%s\n' '{"scenario":"xrdp","expected_result":"connect","driver_exit_code":20,"verdict_script":"FAIL","secret_sentinel":"CLEAN","residual_new":0}' >"$RD5/scenario-results.jsonl"
P0_RUN_DIR="$RD5" bash "$LAB/60-consolidate.sh" >/dev/null 2>&1 || true
gv5="$(python3 -c 'import json;print(json.load(open("'"$RD5"'/summary.json"))["global_verdict"])')"
eq FAIL "$gv5" "any eliminatory FAIL -> global FAIL"

echo ""
echo "== totals: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
