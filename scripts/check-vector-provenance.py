#!/usr/bin/env python3
"""Verify vendored vectors against a recorded, immutable upstream revision."""

import hashlib
import json
import re
from pathlib import Path
from urllib.request import urlopen


def check() -> None:
    spec = Path(__file__).resolve().parents[1] / "spongefish/tests/spec"
    provenance = json.loads((spec / "provenance.json").read_text())
    revision = provenance["revision"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("provenance revision must be a full Git commit ID")
    if provenance["repository"] != "https://github.com/mmaker/draft-irtf-cfrg-sigma-protocols":
        raise ValueError("unexpected specification repository")
    if provenance["directory"] != "poc/vectors":
        raise ValueError("unexpected upstream vector directory")
    expected_files = {
        "fiatShamirShake128Vectors.json",
        "fiatShamirTurboShake128Vectors.json",
    }
    if set(provenance["files"]) != expected_files:
        raise ValueError("provenance must cover both supported suite vector files")
    if {p.name for p in (spec / "vectors").glob("*.json")} != expected_files:
        raise ValueError("vendored vector inventory differs from provenance")

    base = "https://raw.githubusercontent.com/mmaker/draft-irtf-cfrg-sigma-protocols"
    for name, digest in provenance["files"].items():
        local = (spec / "vectors" / name).read_bytes()
        if hashlib.sha256(local).hexdigest() != digest:
            raise ValueError(f"{name}: vendored bytes differ from recorded SHA-256")
        with urlopen(f"{base}/{revision}/poc/vectors/{name}", timeout=30) as response:
            upstream = response.read()
        if upstream != local:
            raise ValueError(f"{name}: vendored bytes differ from upstream {revision}")
        print(f"{name}: SHA-256 and upstream {revision} verified")


if __name__ == "__main__":
    check()
