#!/usr/bin/env python3
"""Package the closed alert connectors for a licensed customer.

Runs the closed-tree gate (and the tests unless ``--skip-tests``), then writes a
tarball and SHA-256 into ``closed/alerts/dist``. Vault files, environment files,
target directories and build output are never included.
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
CLOSED = ROOT / "closed" / "alerts"
VERSION = "0.1.0"
EXCLUDE_PARTS = {"target", "dist"}
EXCLUDE_SUFFIXES = {".vault.json", ".env"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()

    gate = [sys.executable, "scripts/check-alert-connectors.py"]
    if not args.skip_tests:
        gate.append("--test")
    if subprocess.run(gate, cwd=str(ROOT)).returncode != 0:
        print("gate failed; refusing to package")
        return 1

    dist = CLOSED / "dist"
    dist.mkdir(exist_ok=True)
    archive = dist / f"tirbase-alert-connectors-{VERSION}.tar.gz"
    files = [
        path
        for path in CLOSED.rglob("*")
        if path.is_file()
        and not (EXCLUDE_PARTS & set(path.relative_to(CLOSED).parts))
        and path.name != ".env"
        and not any(path.name.endswith(suffix) for suffix in EXCLUDE_SUFFIXES)
    ]
    files.sort()
    with tarfile.open(archive, "w:gz") as tar:
        for path in files:
            tar.add(path, arcname=str(Path("tirbase-alert-connectors") / path.relative_to(CLOSED)))

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (dist / f"tirbase-alert-connectors-{VERSION}.tar.gz.sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )
    manifest = {
        "product": "tirbase-alert-connectors",
        "version": VERSION,
        "created_est": int(time.time()),
        "archive": archive.name,
        "sha256": digest,
        "files": len(files),
        "crates": ["alert-sdk", "alert-slack", "alert-teams", "alert-pagerduty", "alert-sms", "alert-install"],
        "licence": "LicenseRef-Proprietary",
        "tests": "not run" if args.skip_tests else "cargo test --workspace: passed",
    }
    (dist / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {archive.relative_to(ROOT)} ({len(files)} files)")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
