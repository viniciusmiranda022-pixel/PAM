#!/usr/bin/env python3
"""Validate a CycloneDX SBOM of the RDP worker runtime image (ADR 0006).

Fails (exit 1) unless the document is CycloneDX and enumerates the native
libraries the worker actually loads. An incomplete SBOM must NOT pass.
"""
import json
import sys

# Each requirement is satisfied if ANY of its aliases appears in a component name.
# FreeRDP/WinPR are source-built (added by augment-sbom.py); OpenSSL ships as the
# dpkg package "libssl3"; zlib as "zlib1g".
REQUIRED = {
    "freerdp": ["freerdp"],
    "winpr": ["winpr"],
    "openssl": ["openssl", "libssl"],
    "zlib": ["zlib"],
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate-sbom.py <sbom.cyclonedx.json>", file=sys.stderr)
        return 2
    doc = json.load(open(sys.argv[1]))
    if doc.get("bomFormat") != "CycloneDX":
        print("validate-sbom: not a CycloneDX document", file=sys.stderr)
        return 1
    names = " ".join(c.get("name", "").lower() for c in doc.get("components", []))
    missing = [req for req, aliases in REQUIRED.items()
               if not any(a in names for a in aliases)]
    if missing:
        print(f"validate-sbom: SBOM missing expected components: {missing}",
              file=sys.stderr)
        return 1
    print(f"validate-sbom: ok — {len(doc.get('components', []))} components; "
          f"required present: {list(REQUIRED)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
