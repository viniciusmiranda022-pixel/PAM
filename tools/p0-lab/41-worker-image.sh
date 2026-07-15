#!/usr/bin/env bash
# 41-worker-image.sh — build the p0-lab-runner image (worker + harness + driver)
# and ensure the lab network exists, so scenarios can run in container mode when
# the target is the --internal xrdp container. Fail-closed: BLOCKED if no engine.
set -euo pipefail
# shellcheck source=lib/common.sh
. "$(dirname -- "$0")/lib/common.sh"

eng="$(p0_engine)"
[ -n "$eng" ] || die "no container engine (docker/podman) — container mode unavailable; BLOCKED"
img="${P0_RUNNER_IMAGE:-p0-lab-runner:local}"
net="${P0_LAB_NET:-p0-lab-net}"
RUN_DIR="$(p0_run_dir)"
LOG="$RUN_DIR/worker-image-build.log"

log "building runner image '$img' (context=$P0_REPO_ROOT) — this compiles the pinned FreeRDP 3.28.0"
if p0_run_logged "$LOG" "build runner image" -- \
    "$eng" build --platform=linux/amd64 -f "$P0_LAB_DIR/Dockerfile.runner" -t "$img" "$P0_REPO_ROOT"; then
  # readiness: the selftest inside the image must confirm native FreeRDP 3.28.0.
  if "$eng" run --rm --entrypoint /usr/local/bin/privion-rdp-worker-lab "$img" --selftest 2>>"$LOG" \
      | grep -q "selftest: native FreeRDP 3.28.0 confirmed"; then
    "$eng" network inspect "$net" >/dev/null 2>&1 || "$eng" network create --internal "$net" >/dev/null
    echo "RUNNER_IMAGE_READY: $img" >>"$LOG"
    log "runner image ready ($img) + lab network '$net'"
  else
    die "runner image built but selftest did not confirm FreeRDP 3.28.0 — see $LOG (BLOCKED)"
  fi
else
  die "runner image build failed — see $LOG (container mode BLOCKED)"
fi
