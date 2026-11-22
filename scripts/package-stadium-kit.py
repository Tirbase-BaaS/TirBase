#!/usr/bin/env python3
"""Package the stadium commercial kit.

Builds a watermarked draft archive unless both reviews are approved, in which case
``--release`` is required to produce a release archive. The gate runs first and the
packager refuses to build from an incomplete kit.

Usage:
    python3 scripts/package-stadium-kit.py [--release]
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
KIT = ROOT / "commercial" / "stadium-kit"
DIST = KIT / "dist"
VERSION = "0.1.0"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()

    gate = [sys.executable, "scripts/check-stadium-kit.py"]
    if args.release:
        gate.append("--release")
    if subprocess.run(gate, cwd=str(ROOT)).returncode != 0:
        print("gate failed; refusing to package")
        return 1

    manifest = json.loads((KIT / "manifest.json").read_text(encoding="utf-8"))
    approved = all(
        manifest["reviews"][key]["status"] == "approved"
        for key in ("independent_safety_review", "counsel_review")
    )
    if args.release and not approved:
        print("release requires approved independent safety and counsel reviews")
        return 1

    suffix = "" if approved else "-draft"
    DIST.mkdir(exist_ok=True)
    archive = DIST / f"tirbase-stadium-kit-{VERSION}{suffix}.tar.gz"
    files = sorted(
        path
        for path in KIT.rglob("*")
        if path.is_file() and "dist" not in path.relative_to(KIT).parts
    )
    with tarfile.open(archive, "w:gz") as tar:
        for path in files:
            tar.add(path, arcname=str(Path("tirbase-stadium-kit") / path.relative_to(KIT)))

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (DIST / f"{archive.name}.sha256").write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    delivery = {
        "product": "tirbase-stadium-kit",
        "version": VERSION,
        "created_est": int(time.time()),
        "archive": archive.name,
        "sha256": digest,
        "files": len(files),
        "licence": "proprietary",
        "state": "release" if approved else "draft",
        "contains_source": False,
        "contains_secrets": False,
        "contains_customer_data": False,
        "reviews": {
            key: {
                "status": manifest["reviews"][key]["status"],
                "reviewer": manifest["reviews"][key]["reviewer"],
                "date": manifest["reviews"][key]["date"],
            }
            for key in ("independent_safety_review", "counsel_review")
        },
    }
    (DIST / "delivery-manifest.json").write_text(
        json.dumps(delivery, indent=2) + "\n", encoding="utf-8"
    )

    print(f"wrote {archive.relative_to(ROOT)} ({len(files)} files, state {delivery['state']})")
    print(f"sha256 {digest}")
    if not approved:
        print("DRAFT: watermarked draft; do not present as reviewed or approved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
