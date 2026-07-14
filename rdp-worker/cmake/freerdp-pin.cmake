# FreeRDP pin (ADR 0006 §3) — defense in depth, three independent controls:
#   * tag              3.28.0
#   * commit SHA       (provenance: the tag dereferences to this commit)
#   * source SHA-256   (byte integrity of the exact archive the build compiles)
#
# The commit SHA was resolved 2026-07-13 via `git ls-remote` on the official repo
# (refs/tags/3.28.0^{}); scripts/pin-freerdp.sh verifies it in CI.
#
# SOURCE ARTIFACT: the OFFICIAL RELEASE tarball
# (https://pub.freerdp.com/releases/freerdp-3.28.0.tar.gz, 11040961 bytes) — NOT
# GitHub's on-demand archive (whose compressed bytes may change). The SHA-256 was
# computed on a trusted host; the build verifies it with URL_HASH BEFORE unpacking
# and fails if the bytes differ. No local file, no dynamic resolution.
#
# The public URL is fetched ONLY at build time of the lab-only worker (in CI); the
# worker at RUNTIME has no internet egress. Mirroring this exact file into a
# Privion-controlled immutable artifact repository (offline/air-gapped builds,
# vendor-availability) is tracked as backlog BLD-ART-01 — required before a
# production release, NOT a blocker for this spike.

set(FREERDP_VERSION        "3.28.0")
set(FREERDP_GIT_TAG        "3.28.0")
set(FREERDP_GIT_REPOSITORY "https://github.com/FreeRDP/FreeRDP.git")
set(FREERDP_COMMIT_SHA     "5370fb26fbf034ecd11d3026b6ad639b5fff493f")
set(FREERDP_SOURCE_URL
    "https://pub.freerdp.com/releases/freerdp-${FREERDP_VERSION}.tar.gz")
set(FREERDP_SOURCE_SHA256
    "61b7c02f64695a0ee883335ffbbce446e119f46bbf3653e1a71bebf6750ffae3")
