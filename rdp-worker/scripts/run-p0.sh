#!/usr/bin/env bash
# run-p0.sh — drives ONE lab job against a REAL RDP target for the smoke P0
# (docs/rdp-smoke-runbook.md). This is a laboratory aid, NOT an automated pass:
# it requires a native build and a real Windows/xrdp target, and it never claims
# validation on its own — the operator reads the events and fills the runbook.
#
# Usage:
#   PRIVION_TARGET_FILE=./my-target.json \
#   PRIVION_USERNAME=labuser \
#   PRIVION_CRED_FILE=./cred.0400  (mode 0400) \
#   ./scripts/run-p0.sh [path-to-native-worker]
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
worker="${1:-$here/build-native/privion-rdp-worker-lab}"
harness="$(dirname "$worker")/harness/privion-rdp-lab-harness"

: "${PRIVION_TARGET_FILE:?set PRIVION_TARGET_FILE to a lab-targets json (non-secret)}"
: "${PRIVION_USERNAME:?set PRIVION_USERNAME}"
: "${PRIVION_CRED_FILE:?set PRIVION_CRED_FILE to a 0400 secret file}"

if [ ! -x "$worker" ]; then
  echo "run-p0: native worker not found at $worker — build with scripts/build.sh --native" >&2
  exit 1
fi
if [ "$(stat -c '%a' "$PRIVION_CRED_FILE")" != "400" ]; then
  echo "run-p0: credential file must be mode 0400" >&2
  exit 1
fi

# Derive the allowlist entry from the target file (non-secret).
addr="$(grep -oP '"address"\s*:\s*"\K[^"]+' "$PRIVION_TARGET_FILE")"
port="$(grep -oP '"port"\s*:\s*\K[0-9]+' "$PRIVION_TARGET_FILE")"
sock="$(mktemp -u /tmp/privion-p0-XXXX.sock)"

session="${PRIVION_SESSION_SECONDS:-10}"   # deterministic lab session length
maxsec="${PRIVION_MAX_SECONDS:-30}"        # worker watchdog (safety)

echo "run-p0: starting worker (allow ${addr}:${port}, watchdog ${maxsec}s); events are the evidence"
"$worker" --socket "$sock" --allow-target "${addr}:${port}" --max-seconds "$maxsec" &
wpid=$!
# Wait for the socket without a foreground sleep.
i=0; until [ -S "$sock" ] || [ $i -ge 1000 ]; do i=$((i+1)); done
"$harness" --socket "$sock" --target-file "$PRIVION_TARGET_FILE" \
  --username "$PRIVION_USERNAME" --cred-file "$PRIVION_CRED_FILE" \
  --session-seconds "$session" || true
wait "$wpid" || true
echo "run-p0: done — record CPU/RAM/latency and the events in docs/rdp-smoke-runbook.md"
