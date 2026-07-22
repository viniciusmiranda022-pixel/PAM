#!/usr/bin/env bash
# run-driver-container.sh — run rdp-worker/scripts/run-p0.sh INSIDE the
# p0-lab-runner image, attached to the lab Docker network, so the worker can
# reach the --internal xrdp container (whose IP the host cannot route to).
# Called by 50-run-scenario.sh when P0_WORKER_MODE resolves to 'container'.
#
# The runner image (built by 41-worker-image.sh) contains the native worker +
# harness, run-p0.sh and the secret-scan helper. Nothing is published to the
# host; the credential is a 0400 file bind-mounted read-only (never on argv).
set -euo pipefail
# shellcheck source=lib/common.sh
# shellcheck disable=SC1091
. "$(dirname -- "$0")/common.sh"

eng="$(p0_engine)"; [ -n "$eng" ] || die "no container engine"
img="${P0_RUNNER_IMAGE:-p0-lab-runner:local}"
net="${P0_LAB_NET:-p0-lab-net}"
"$eng" image inspect "$img" >/dev/null 2>&1 || die "runner image '$img' missing — run 41-worker-image.sh"
"$eng" network inspect "$net" >/dev/null 2>&1 || die "lab network '$net' missing — run 40-xrdp-target.sh"

: "${PRIVION_TARGET_FILE:?}"; : "${PRIVION_CRED_FILE:?}"; : "${PRIVION_EVIDENCE_DIR:?}"
mkdir -p "$PRIVION_EVIDENCE_DIR"

# Pass only NON-secret PRIVION_* through -e; the credential goes via a read-only
# mount, and evidence via a read-write mount. TOFU trust store (lab CA) mounted ro.
args=( run --rm --network "$net" --user "$(id -u)":"$(id -g)"
       -v "$PRIVION_TARGET_FILE":/lab/target.json:ro
       -v "$PRIVION_CRED_FILE":/lab/cred.0400:ro
       -v "$PRIVION_EVIDENCE_DIR":/lab/evidence
       -e PRIVION_SCENARIO -e PRIVION_EXPECTED_RESULT -e PRIVION_USERNAME
       -e PRIVION_ALLOW_TARGET -e PRIVION_SESSION_SECONDS -e PRIVION_MAX_SECONDS
       -e PRIVION_SOCKET_TIMEOUT -e PRIVION_LAB_TOFU_CERT
       -e PRIVION_TARGET_FILE=/lab/target.json
       -e PRIVION_CRED_FILE=/lab/cred.0400
       -e PRIVION_EVIDENCE_DIR=/lab/evidence
       -e PRIVION_WORKER=/usr/local/bin/privion-rdp-worker-lab
       -e PRIVION_HARNESS=/usr/local/bin/privion-rdp-lab-harness )
if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "${SSL_CERT_FILE:-}" ]; then
  args+=( -v "$SSL_CERT_FILE":/lab/lab-ca.crt:ro -e SSL_CERT_FILE=/lab/lab-ca.crt )
fi
args+=( "$img" bash /opt/rdp-worker/scripts/run-p0.sh )

exec "$eng" "${args[@]}"
