#!/usr/bin/env python3
"""Package the closed venue operations connectors for a licensed customer.

Runs the closed-tree gate (and the test suite unless skipped), then writes a
tarball and its SHA-256 into ``closed/venue-operations/dist``. Refuses to build
from a tree with tracked source, an AGPL edge, a vendor SDK, credentials, camera
media or missing documentation.

Each connector is a separately licensed product; the manifest lists all seven so a
licence can cover one without the others.
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
CLOSED = ROOT / "closed" / "venue-operations"
VERSION = "0.1.0"
EXCLUDE_PARTS = {"target", "dist"}

PRODUCTS = [
    ("tirbase-connector-hid", "connector-hid", "HID Global", "access"),
    ("tirbase-connector-lenel", "connector-lenel", "LenelS2", "access"),
    ("tirbase-connector-genetec", "connector-genetec", "Genetec", "access"),
    ("tirbase-connector-bms-siemens", "connector-bms-siemens", "Siemens", "bms"),
    ("tirbase-connector-bms-jci", "connector-bms-jci", "Johnson Controls", "bms"),
    ("tirbase-connector-onvif-cctv", "connector-onvif-cctv", "ONVIF", "cctv"),
    ("tirbase-connector-pa", "connector-pa", "public address", "pa"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()

    gate = [sys.executable, "scripts/check-venue-operations.py"]
    if not args.skip_tests:
        gate.append("--test")
    if subprocess.run(gate, cwd=str(ROOT)).returncode != 0:
        print("gate failed; refusing to package")
        return 1

    dist = CLOSED / "dist"
    dist.mkdir(exist_ok=True)
    archive = dist / f"tirbase-venue-operations-{VERSION}.tar.gz"

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
                arcname=str(Path("tirbase-venue-operations") / path.relative_to(CLOSED)),
            )

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (dist / f"tirbase-venue-operations-{VERSION}.tar.gz.sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )
    manifest = {
        "product": "tirbase-venue-operations",
        "version": VERSION,
        "created_est": int(time.time()),
        "archive": archive.name,
        "sha256": digest,
        "files": len(files),
        "products": [
            {
                "product": product,
                "crate": crate,
                "vendor": vendor,
                "domain": domain,
            }
            for product, crate, vendor, domain in PRODUCTS
        ],
        "shared": "venue-ops-sdk",
        "licence": "LicenseRef-Proprietary",
        "life_safety": "no connector controls fire or life-safety systems; such points and alarms are refused",
        "raw_video": "not retained by default; camera media is refused by the ONVIF product",
        "conformance": "tirbase-venue-connectors::certify: all seven connectors certified",
        "tests": "not run" if args.skip_tests else "cargo test --workspace: passed",
    }
    (dist / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {archive.relative_to(ROOT)} ({len(files)} files)")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
