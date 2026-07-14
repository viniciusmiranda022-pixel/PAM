#!/usr/bin/env bash
# pin-freerdp.sh — VERIFIES the committed FreeRDP pin (ADR 0006 §3). Does NOT
# resolve or write the pin dynamically (no TOFU at build time).
#
#   ./scripts/pin-freerdp.sh               # verify tag -> committed commit SHA
#   ./scripts/pin-freerdp.sh --print       # show what the tag currently resolves to
#   ./scripts/pin-freerdp.sh --source-hash # download the pinned source URL and
#                                          # print its SHA-256 (run on a TRUSTED
#                                          # HOST WITH HTTP ACCESS; paste the value
#                                          # into cmake/freerdp-pin.cmake)
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
pin="$here/cmake/freerdp-pin.cmake"

tag="$(grep -oP 'set\(FREERDP_GIT_TAG\s+"\K[^"]+' "$pin")"
repo="$(grep -oP 'set\(FREERDP_GIT_REPOSITORY\s+"\K[^"]+' "$pin")"
committed="$(grep -oP 'set\(FREERDP_COMMIT_SHA\s+"\K[^"]+' "$pin")"
version="$(grep -oP 'set\(FREERDP_VERSION\s+"\K[^"]+' "$pin")"

if [ "${1:-}" = "--source-hash" ]; then
  # Reproduce the pinned source hash from the OFFICIAL public release (run on a
  # trusted host). The build itself fetches from the internal mirror, not here.
  official="https://pub.freerdp.com/releases/freerdp-${version}.tar.gz"
  tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
  echo "downloading OFFICIAL release archive: $official" >&2
  echo "(mirror this exact file, unmodified, to the Privion internal artifact repo)" >&2
  curl -fsSL "$official" -o "$tmp"
  echo "FREERDP_SOURCE_SHA256=$(sha256sum "$tmp" | awk '{print $1}')"
  exit 0
fi

remote="$(git ls-remote "$repo" "refs/tags/${tag}^{}" | awk 'NR==1{print $1}')"
[ -n "$remote" ] || remote="$(git ls-remote "$repo" "refs/tags/${tag}" | awk 'NR==1{print $1}')"

if [ "${1:-}" = "--print" ]; then
  echo "tag $tag -> remote commit $remote (committed pin: $committed)"
  exit 0
fi

if [ -z "$remote" ]; then
  echo "pin-freerdp: could not resolve remote commit for tag $tag" >&2
  exit 1
fi
if [ "$remote" != "$committed" ]; then
  echo "pin-freerdp: MISMATCH — tag $tag now points at $remote but the committed" >&2
  echo "             pin is $committed. Investigate (tag moved / tampering)." >&2
  exit 1
fi
echo "pin-freerdp: ok — tag $tag matches committed commit $committed"
