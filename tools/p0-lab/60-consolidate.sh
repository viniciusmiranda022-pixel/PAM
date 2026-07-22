#!/usr/bin/env bash
# 60-consolidate.sh — Phases 7+8+9: classified secret sentinel (point #8),
# resources.txt with real statistics (point #6), and the evidence matrix + global
# verdict restricted to PASS|FAIL|INCONCLUSIVE|BLOCKED (point #10). The technical
# result is separate from the human sign-off (signoff_required flag); signatures
# record acceptance, they do not change the technical result.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"
p0_load_env || true

RUN_DIR="$(p0_run_dir)"
RESULTS="$RUN_DIR/scenario-results.jsonl"
[ -f "$RESULTS" ] || { warn "no scenario results ($RESULTS)"; : >"$RESULTS"; }

# --- Phase 7: classified secret sentinel over the whole run dir ---
# Distinguishes: private key blocks; a real Authorization/Bearer/token VALUE (not
# a bare field name or placeholder); and the EXACT credential bytes from the lab
# 0400 files (credential-exact, via the repo helper's read_secret path). Reports
# only file/line/class/sanitized-hash — never the matched value.
SENT="$RUN_DIR/secret-sentinel.json"
CREDS_LIST="$RUN_DIR/.creds.list"; : >"$CREDS_LIST"
for v in P0_CRED_VALID_FILE P0_CRED_INVALID_FILE P0_XRDP_CRED_FILE; do
  p="${!v:-}"; [ -n "$p" ] && [ -f "$p" ] && printf '%s\n' "$p" >>"$CREDS_LIST"
done
python3 - "$RUN_DIR" "$SENT" "$CREDS_LIST" <<'PY'
import json, os, re, sys, hashlib, datetime
root, out, creds_list = sys.argv[1:4]

# Load exact credential bytes (never printed; only a salted hash id is emitted).
creds = []
for line in open(creds_list, encoding="utf-8") if os.path.exists(creds_list) else []:
    p = line.strip()
    if not p:
        continue
    try:
        with open(p, "rb") as fh:
            b = fh.read().rstrip(b"\r\n")
        if b:
            creds.append((os.path.basename(p), b, hashlib.sha256(b).hexdigest()[:12]))
    except OSError:
        pass

# pattern split so the literal marker never appears contiguously in source
# (the repo secret-scanner greps tracked files for that exact string).
pk = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE " + rb"KEY-----")
# A real header/token VALUE: key followed by a non-placeholder, >=8-char value.
tokv = re.compile(rb"(?i)\b(authorization|bearer|token|api[_-]?key|secret)\b\s*[:=]\s*([^\s\"'<>]{8,})")
placeholder = re.compile(rb"(?i)(troque|defina|example|placeholder|xxxx|<[^>]+>|\$\{|changeme|your[_-])")

hits = []
skip = {"secret-sentinel.json", ".creds.list"}
for dirpath, _d, files in os.walk(root):
    for name in files:
        if name in skip:
            continue
        p = os.path.join(dirpath, name)
        rel = os.path.relpath(p, root)
        try:
            with open(p, "rb") as fh:
                for i, line in enumerate(fh, 1):
                    if pk.search(line):
                        hits.append({"file": rel, "line": i, "class": "private_key", "id": "-"})
                        continue
                    for bn, b, h in creds:
                        if b in line:
                            hits.append({"file": rel, "line": i, "class": "credential_value", "id": f"{bn}:{h}"})
                    m = tokv.search(line)
                    if m and not placeholder.search(m.group(2)):
                        val = m.group(2)
                        hits.append({"file": rel, "line": i, "class": "token_value",
                                     "id": hashlib.sha256(val).hexdigest()[:12]})
        except OSError:
            continue
# credential_value or private_key => real leak; token_value => review.
hard = [h for h in hits if h["class"] in ("credential_value", "private_key")]
report = {"generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
          "result": "LEAK_PRESENT" if hard else ("REVIEW" if hits else "CLEAN"),
          "hard_hits": len(hard), "total_hits": len(hits), "hits": hits[:300],
          "note": "values never shown; credential_value/private_key => leak, token_value => review. "
                  "Per-scenario secret-sentinel.json is the driver's credential-exact check."}
json.dump(report, open(out, "w"), indent=2)
print(report["result"], report["hard_hits"], report["total_hits"])
PY
rm -f "$CREDS_LIST"
sentinel_global="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["result"])' "$SENT")"

# --- Phase 6: resources.txt with statistics aggregated from the driver evidence ---
python3 - "$RESULTS" "$RUN_DIR" "$RUN_DIR/resources.txt" <<'PY'
import json, os, sys, statistics as st
results_path, run_dir, out = sys.argv[1:4]
recs = [json.loads(l) for l in open(results_path, encoding="utf-8") if l.strip()]
lat, cpu_u, cpu_s, rss, dur, threads, teardown = ([] for _ in range(7))
ok = fail = 0
for r in recs:
    ev = r.get("evidence_dir")
    if r.get("verdict_script") == "PASS": ok += 1
    elif r.get("verdict_script") == "FAIL": fail += 1
    if r.get("threads_max"): threads.append(r["threads_max"])
    if not ev: continue
    sj, rt = os.path.join(ev, "summary.json"), os.path.join(ev, "resources.txt")
    try:
        s = json.load(open(sj)); o = s.get("observed", {})
        if o.get("duration_ms_to_connected") is not None: lat.append(o["duration_ms_to_connected"])
        if o.get("session_active_ms") is not None and r.get("driver_wall_ms"):
            teardown.append(max(r["driver_wall_ms"] - o["session_active_ms"], 0))
    except Exception: pass
    try:
        kv = dict(l.split("=", 1) for l in open(rt) if "=" in l)
        def num(x):
            try: return float(x)
            except: return None
        for k, arr in (("cpu_user_seconds", cpu_u), ("cpu_system_seconds", cpu_s),
                       ("worker_peak_rss_kb", rss), ("duration_monotonic_ms", dur)):
            v = num(kv.get(k, "").strip());
            if v is not None: arr.append(v)
    except Exception: pass

def q(a, p):
    if not a: return None
    a = sorted(a); k = (len(a) - 1) * p; f = int(k); c = min(f + 1, len(a) - 1)
    return round(a[f] + (a[c] - a[f]) * (k - f), 2)
def stats(a):
    if not a: return "n/a"
    return (f"n={len(a)} min={round(min(a),2)} mean={round(sum(a)/len(a),2)} "
            f"median={round(st.median(a),2)} p95={q(a,0.95)} max={round(max(a),2)}")
growth = "n/a"
if len(rss) >= 2: growth = f"{round(rss[-1]-rss[0],2)} kB (first={rss[0]} last={rss[-1]})"

with open(out, "w") as fh:
    fh.write("# P0 resource baseline (aggregated from per-scenario driver evidence)\n")
    fh.write(f"sessions_total: {len(recs)}\nsessions_pass: {ok}\nsessions_fail: {fail}\n")
    fh.write(f"connect_latency_ms: {stats(lat)}\n")
    fh.write(f"cpu_user_seconds: {stats(cpu_u)}\n")
    fh.write(f"cpu_system_seconds: {stats(cpu_s)}\n")
    fh.write(f"worker_peak_rss_kb: {stats(rss)}\n")
    fh.write(f"duration_monotonic_ms: {stats(dur)}\n")
    fh.write(f"threads_max: {stats(threads)}\n")
    fh.write(f"teardown_ms (wall - session_active): {stats(teardown)}\n")
    fh.write(f"rss_growth_first_to_last: {growth}\n")
    fh.write(f"residual_new_total: {sum(r.get('residual_new',0) for r in recs)}\n")
print("resources.txt written")
PY

# --- Phases 8/9: matrix + strict global verdict ---
python3 - "$RESULTS" "$RUN_DIR/evidence-matrix.md" "$RUN_DIR/summary.json" "$sentinel_global" "$RUN_DIR" <<'PY'
import json, sys, datetime, os
results_path, matrix_path, summary_path, sentinel_global, run_dir = sys.argv[1:6]
ELIMINATORY = {
    "windows-nla": "connect", "xrdp": "connect", "cred-invalid": "auth_reject",
    "cert-trusted": "cert_trusted", "cert-untrusted": "cert_reject",
    "host-denied": "egress_denied", "port-denied": "egress_denied",
    "terminate": "terminate", "watchdog": "watchdog", "asset-disconnect": "asset_disconnect",
}
recs = [json.loads(l) for l in open(results_path, encoding="utf-8") if l.strip()]
by = {r["scenario"]: r for r in recs}
rows, missing, fails, inconclusive = [], [], [], []
for scn, exp in ELIMINATORY.items():
    r = by.get(scn)
    if not r:
        missing.append(scn); rows.append((scn, exp, "NOT RUN", "-", "-")); continue
    v, sc = r["verdict_script"], r.get("secret_sentinel", "unknown")
    rows.append((scn, exp, v, str(r["driver_exit_code"]), sc))
    if v == "FAIL" or sc == "LEAK_PRESENT": fails.append(scn)
    elif v in ("INCONCLUSIVE", "OPERATIONAL", "BLOCKED", "UNKNOWN"): inconclusive.append(scn)
extra = [r for r in recs if r["scenario"] not in ELIMINATORY]

# CVE gate (if present) folds into the global result.
cve_gate = None
sp = os.path.join(run_dir, "sbom-cve", "status.json")
if os.path.exists(sp):
    try: cve_gate = json.load(open(sp)).get("gate")
    except Exception: cve_gate = None

# Global verdict restricted to PASS|FAIL|INCONCLUSIVE|BLOCKED.
if sentinel_global == "LEAK_PRESENT" or fails or cve_gate == "FAIL":
    gv = "FAIL"
    reason = ("secret leak" if sentinel_global == "LEAK_PRESENT" else
              (f"eliminatory FAILED: {', '.join(fails)}" if fails else "CVE gate FAIL (critical/high)"))
elif missing or cve_gate in (None, "BLOCKED"):
    gv = "BLOCKED"
    bits = []
    if missing: bits.append(f"eliminatory not run: {', '.join(missing)}")
    if cve_gate in (None, "BLOCKED"): bits.append("SBOM/CVE not completed")
    reason = "; ".join(bits)
elif inconclusive:
    gv = "INCONCLUSIVE"; reason = f"needs operator confirmation from worker-stderr.txt: {', '.join(inconclusive)}"
else:
    gv = "PASS"; reason = "all eliminatory scenarios PASS; sentinel CLEAN; CVE gate PASS"

signoff_required = True  # human operator + reviewer signature is always required

with open(matrix_path, "w", encoding="utf-8") as fh:
    fh.write("# P0 evidence matrix (auto-generated)\n\n")
    fh.write(f"generated_at: {datetime.datetime.utcnow():%Y-%m-%dT%H:%M:%SZ}\n\n")
    fh.write("| # | scenario | expected | verdict | driver rc | sentinel |\n")
    fh.write("|---|----------|----------|---------|-----------|----------|\n")
    for i, (scn, exp, v, rc, sc) in enumerate(rows, 1):
        fh.write(f"| {i} | {scn} | `{exp}` | **{v}** | {rc} | {sc} |\n")
    if extra:
        fh.write("\n### diagnostic / baseline scenarios\n\n")
        for r in extra:
            fh.write(f"- `{r['scenario']}` ({r['expected_result']}) -> {r['verdict_script']} (rc {r['driver_exit_code']})\n")
    fh.write(f"\n## GLOBAL (technical): **{gv}** — {reason}\n\n")
    fh.write(f"CVE gate: {cve_gate or 'n/a'} · secret sentinel (global): {sentinel_global}\n\n")
    fh.write("> Technical result is one of PASS/FAIL/INCONCLUSIVE/BLOCKED. It is SEPARATE from\n"
             "> the human sign-off: even a technical PASS requires operator AND reviewer signatures\n"
             "> in docs/rdp-p0-evidence-template.md (signatures record acceptance; they do not change\n"
             "> the technical result). INCONCLUSIVE is NOT a pass. SUPPORTED_PROTOCOLS stays [\"vnc\"].\n")

json.dump({"generated_at": f"{datetime.datetime.utcnow():%Y-%m-%dT%H:%M:%SZ}",
           "global_verdict": gv, "reason": reason, "signoff_required": signoff_required,
           "secret_sentinel_global": sentinel_global, "cve_gate": cve_gate,
           "eliminatory_missing": missing, "eliminatory_failed": fails,
           "eliminatory_inconclusive": inconclusive, "scenarios": recs,
           "script_approves_p0": False, "runtime_unchanged": 'SUPPORTED_PROTOCOLS=["vnc"]'},
          open(summary_path, "w"), indent=2)
print(gv, "-", reason)
PY

log "Phase 9 done: $RUN_DIR/{evidence-matrix.md,summary.json,resources.txt,secret-sentinel.json}"
