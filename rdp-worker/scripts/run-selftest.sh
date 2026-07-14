#!/usr/bin/env bash
# run-selftest.sh — runs the worker --selftest. In a native build this confirms
# the linked FreeRDP version matches the pinned baseline (ADR 0006 §4).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
bin="${1:-$here/build/privion-rdp-worker-lab}"
if [ ! -x "$bin" ]; then
  echo "run-selftest: worker binary not found at $bin (build first)" >&2
  exit 1
fi
exec "$bin" --selftest
