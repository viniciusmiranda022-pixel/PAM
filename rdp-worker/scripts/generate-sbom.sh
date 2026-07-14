#!/usr/bin/env bash
# generate-sbom.sh — emits a validated CycloneDX SBOM of the FINAL runtime image
# (ADR 0006 / review §3). Requires syft; there is NO minimal fallback, because an
# incomplete SBOM must NOT let the job go green. In CI the SBOM is produced by the
# pinned anchore/sbom-action (see ci.yml); this script is the local equivalent.
#
#   ./scripts/generate-sbom.sh <image-ref> [out.json]
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
image="${1:?usage: generate-sbom.sh <image-ref> [out.json]}"
out="${2:-sbom.cyclonedx.json}"

if ! command -v syft >/dev/null 2>&1; then
  echo "generate-sbom: syft not found — refusing to emit an incomplete SBOM." >&2
  echo "               install a pinned syft (or use the CI action) and re-run." >&2
  exit 1
fi

syft "$image" -o cyclonedx-json="$out"
python3 "$here/scripts/augment-sbom.py" "$out"   # add source-built FreeRDP/WinPR
python3 "$here/scripts/validate-sbom.py" "$out"
echo "generate-sbom: wrote $out"
