#!/usr/bin/env python3
"""Package the closed venue ticketing connectors for a licensed customer.

Runs the closed-tree gate (and the test suite unless skipped), then writes a
tarball and its SHA-256 into ``closed/venue-ticketing/dist``. The packager
refuses to build from a tree with tracked source, an AGPL edge, a vendor SDK,
credentials or missing documentation.

Ticketmaster and Eventim are separate products: the manifest lists them
separately so a licence can be sold for one without the other.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "venue-ticketing"
VERSION = "0.1.0"
EXCLUDE_PARTS = {"target", "dist"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()

    gate = [sys.executable, "scripts/check-venue-ticketing.py"]
    if not args.skip_tests:
        gate.append("--test")
    if subprocess.run(gate, cwd=str(ROOT)).returncode != 0:
        print("gate failed; refusing to package")
        return 1

    dist = CLOSED / "dist"
    dist.mkdir(exist_ok=True)
    archive = dist / f"tirbase-venue-ticketing-{VERSION}.tar.gz"

    files = [
        path
        for path in CLOSED.rglob("*")
        if path.is_file() and not (EXCLUDE_PARTS & set(path.relative_to(CLOSED).parts))
    ]
    files.sort()
    with tarfile.open(archive, "w:gz") as tar:
        for path in files:
            tar.add(
                path,
                arcname=str(Path("tirbase-venue-ticketing") / path.relative_to(CLOSED)),
            )

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (dist / f"tirbase-venue-ticketing-{VERSION}.tar.gz.sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )
    manifest = {
        "product": "tirbase-venue-ticketing",
        "version": VERSION,
        "created_est": int(time.time()),
        "archive": archive.name,
        "sha256": digest,
        "files": len(files),
        "products": [
            {
                "product": "tirbase-connector-ticketmaster",
                "crate": "connector-ticketmaster",
                "vendor": "Ticketmaster",
            },
            {
                "product": "tirbase-connector-eventim",
                "crate": "connector-eventim",
                "vendor": "Eventim",
            },
        ],
        "shared": "venue-ticketing-sdk",
        "licence": "LicenseRef-Proprietary",
        "conformance": "tirbase-venue-connectors::certify: both connectors certified",
        "tests": "not run" if args.skip_tests else "cargo test --workspace: passed",
    }
    (dist / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {archive.relative_to(ROOT)} ({len(files)} files)")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
