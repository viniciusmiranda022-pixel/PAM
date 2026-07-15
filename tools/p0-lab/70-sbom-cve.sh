#!/usr/bin/env bash
# 70-sbom-cve.sh — Phase: real SBOM + CVE artifacts for the worker (point #7).
# Generates an SBOM of the worker image and scans it for vulnerabilities. If no
# tool is available, the phase is BLOCKED with the exact tool to install — it is
# never silently skipped, and "tool present?" is never mistaken for "scan done".
#
# Policy: CRITICAL or HIGH findings => the CVE gate is FAIL (recorded; the
# operator decides mitigation per the runbook/threat model).
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"
p0_load_env || true

RUN_DIR="$(p0_run_dir)"
OUT="$RUN_DIR/sbom-cve"; mkdir -p "$OUT"
STATUS="$OUT/status.json"
eng="$(p0_engine)"
IMAGE="${P0_WORKER_IMAGE:-${P0_RUNNER_IMAGE:-privion-rdp-worker-lab:ci}}"

record_status() { # sbom_state cve_state gate reason
  python3 - "$STATUS" "$@" <<'PY'
import json, sys
out, sbom, cve, gate, reason = sys.argv[1:6]
json.dump({"sbom": sbom, "cve": cve, "gate": gate, "reason": reason,
           "policy": "FAIL on CRITICAL or HIGH"}, open(out, "w"), indent=2)
PY
}

# --- SBOM ---
sbom_state="BLOCKED"; sbom_file="$OUT/sbom.cyclonedx.json"
if command -v syft >/dev/null 2>&1 && [ -n "$eng" ] && "$eng" image inspect "$IMAGE" >/dev/null 2>&1; then
  if syft "$IMAGE" -o cyclonedx-json="$sbom_file" >/dev/null 2>&1; then
    # Augment + validate with the repo's own tools (adds source-built FreeRDP/WinPR).
    python3 "$P0_REPO_ROOT/rdp-worker/scripts/augment-sbom.py" "$sbom_file" >/dev/null 2>&1 || true
    if python3 "$P0_REPO_ROOT/rdp-worker/scripts/validate-sbom.py" "$sbom_file" >/dev/null 2>&1; then
      sbom_state="OK"
    else
      sbom_state="FAIL"; warn "SBOM missing required native components (freerdp/winpr/openssl/zlib)"
    fi
  fi
elif [ -f "$P0_REPO_ROOT/rdp-worker/sbom.cyclonedx.json" ]; then
  cp "$P0_REPO_ROOT/rdp-worker/sbom.cyclonedx.json" "$sbom_file"; sbom_state="OK (from repo CI artifact)"
fi

# --- CVE scan ---
cve_state="BLOCKED"; gate="BLOCKED"; reason=""
scan_tool=""; command -v grype >/dev/null 2>&1 && scan_tool=grype
[ -z "$scan_tool" ] && command -v trivy >/dev/null 2>&1 && scan_tool=trivy
if [ -n "$scan_tool" ] && [ -n "$eng" ] && "$eng" image inspect "$IMAGE" >/dev/null 2>&1; then
  cve_json="$OUT/cve-$scan_tool.json"
  if [ "$scan_tool" = grype ]; then
    grype "$IMAGE" -o json >"$cve_json" 2>>"$OUT/cve.log" || true
    "$scan_tool" version >"$OUT/cve-tool-version.txt" 2>&1 || true
    counts="$(python3 - "$cve_json" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print("ERR 0 0"); raise SystemExit
sev={}
for m in d.get("matches",[]):
    s=(m.get("vulnerability",{}).get("severity") or "Unknown").upper(); sev[s]=sev.get(s,0)+1
print("OK", sev.get("CRITICAL",0), sev.get("HIGH",0))
PY
)"
  else
    trivy image --format json -o "$cve_json" "$IMAGE" >>"$OUT/cve.log" 2>&1 || true
    "$scan_tool" --version >"$OUT/cve-tool-version.txt" 2>&1 || true
    counts="$(python3 - "$cve_json" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print("ERR 0 0"); raise SystemExit
c=h=0
for r in d.get("Results",[]):
    for v in r.get("Vulnerabilities",[]) or []:
        s=(v.get("Severity") or "").upper()
        c+= s=="CRITICAL"; h+= s=="HIGH"
print("OK", c, h)
PY
)"
  fi
  read -r ok crit high <<<"$counts"
  if [ "$ok" = OK ]; then
    cve_state="OK ($scan_tool: CRITICAL=$crit HIGH=$high)"
    if [ "$crit" -gt 0 ] || [ "$high" -gt 0 ]; then gate=FAIL; reason="CRITICAL=$crit HIGH=$high"; else gate=PASS; reason="no critical/high"; fi
  else
    cve_state="FAIL (could not parse $scan_tool output)"; gate=BLOCKED; reason="scan output unreadable"
  fi
else
  reason="install syft (SBOM) and grype or trivy (CVE), and build/pull the worker image ($IMAGE)"
fi

record_status "$sbom_state" "$cve_state" "$gate" "$reason"
log "SBOM: $sbom_state | CVE: $cve_state | gate: $gate ${reason:+($reason)}"
[ "$gate" = FAIL ] && warn "CVE gate FAIL — see $OUT"
exit 0
