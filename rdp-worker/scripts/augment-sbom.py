#!/usr/bin/env python3
"""Augment a CycloneDX SBOM with the source-built FreeRDP/WinPR components.

FreeRDP and WinPR are compiled from the pinned official source and copied into
the runtime image as shared libraries, so syft (which catalogs package-manager
and known-binary components) does not list them by name. They ARE in the image;
this adds accurate, provenanced entries (version + source URL + commit + SHA-256
from cmake/freerdp-pin.cmake) so the SBOM is complete.

Usage: augment-sbom.py <sbom.cyclonedx.json>
"""
import json
import re
import sys
from pathlib import Path


def read_pin(pin_path: Path) -> dict:
    text = pin_path.read_text()
    def grab(key: str) -> str:
        m = re.search(rf'set\({key}\s+"([^"]+)"', text)
        return m.group(1) if m else ""
    version = grab("FREERDP_VERSION")
    commit = grab("FREERDP_COMMIT_SHA")
    sha256 = grab("FREERDP_SOURCE_SHA256")
    # FREERDP_SOURCE_URL spans two lines; grab the tar.gz literal.
    m = re.search(r'"(https://[^"]+\.tar\.gz)"', text)
    url = (m.group(1).replace("${FREERDP_VERSION}", version) if m else "")
    return {"version": version, "commit": commit, "sha256": sha256, "url": url}


def component(name: str, pin: dict) -> dict:
    return {
        "type": "library",
        "name": name,
        "version": pin["version"],
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "purl": f"pkg:generic/{name}@{pin['version']}",
        "properties": [
            {"name": "privion:source-url", "value": pin["url"]},
            {"name": "privion:source-commit", "value": pin["commit"]},
            {"name": "privion:source-sha256", "value": pin["sha256"]},
            {"name": "privion:build", "value": "from-source"},
        ],
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: augment-sbom.py <sbom.cyclonedx.json>", file=sys.stderr)
        return 2
    sbom_path = Path(sys.argv[1])
    pin = read_pin(sbom_path.parent / "cmake" / "freerdp-pin.cmake")
    doc = json.loads(sbom_path.read_text())
    comps = doc.setdefault("components", [])
    have = {c.get("name", "").lower() for c in comps}
    for name in ("freerdp", "winpr"):
        if name not in have:
            comps.append(component(name, pin))
    sbom_path.write_text(json.dumps(doc, indent=2))
    print(f"augment-sbom: ensured freerdp/winpr {pin['version']} in {sbom_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
