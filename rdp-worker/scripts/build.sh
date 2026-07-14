#!/usr/bin/env bash
# build.sh — configure + build the worker. Logic build by default (no libfreerdp,
# runnable offline); pass --native to link the pinned FreeRDP (requires the pin to
# be filled and network access — CI job rdp-worker-build-test).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"

native=OFF
build_dir=build
for a in "$@"; do
  case "$a" in
    --native) native=ON; build_dir=build-native ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

gen=""
command -v ninja >/dev/null 2>&1 && gen="-G Ninja"

# shellcheck disable=SC2086
cmake -S . -B "$build_dir" $gen \
  -DPRIVION_LAB_ONLY=ON \
  -DPRIVION_WITH_FREERDP=$native \
  -DPRIVION_BUILD_TESTS=ON
cmake --build "$build_dir"
echo "build.sh: built ($build_dir, FreeRDP=$native)"
