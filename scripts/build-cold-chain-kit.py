#!/usr/bin/env python3
"""Package the commercial cold-chain kit (CC-23).

The archive contains documents and data only. A `--release` archive is refused unless the
manifest records approved counsel and accredited-assessor reviews; `--draft` always
succeeds but embeds a DRAFT watermark and is named accordingly.

Usage:
    python3 scripts/build-cold-chain-kit.py --draft
    python3 scripts/build-cold-chain-kit.py --release
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = ROOT / "commercial" / "cold-chain-kit"
DIST = ROOT / "dist"
CHECK = ROOT / "scripts" / "check-cold-chain-kit.py"


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--draft", action="store_true")
    mode.add_argument("--release", action="store_true")
    args = parser.parse_args()

    command = [sys.executable, str(CHECK)]
    if args.release:
        command.append("--release")
    check = subprocess.run(command, cwd=ROOT, check=False)
    if check.returncode != 0:
        print("ERROR: kit gate failed; nothing packaged", file=sys.stderr)
        return check.returncode

    manifest = json.loads((KIT / "manifest.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    suffix = "" if args.release else "-DRAFT"
    archive_name = f"tirbase-cold-chain-kit-{version}{suffix}.tar.gz"

    DIST.mkdir(exist_ok=True)
    archive_path = DIST / archive_name
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary) / f"tirbase-cold-chain-kit-{version}{suffix}"
        shutil.copytree(KIT, staging)
        if args.draft:
            (staging / "DRAFT.txt").write_text(
                manifest["delivery"]["draft_watermark"]
                + "\n\nThis archive is a draft. It may not be delivered as a compliance or\n"
                "certification package until counsel and an accredited assessor have\n"
                "reviewed it and manifest.json records both approvals.\n",
                encoding="utf-8",
            )
        with tarfile.open(archive_path, "w:gz") as archive:
            for path in sorted(staging.rglob("*")):
                if path.is_dir():
                    continue
                info = archive.gettarinfo(str(path), arcname=f"{staging.name}/{path.relative_to(staging)}")
                info.uid = 0
                info.gid = 0
                info.mtime = 0
                info.uname = ""
                info.gname = ""
                with path.open("rb") as handle:
                    archive.addfile(info, handle)

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = DIST / "SHA256SUMS"
    checksum_path.write_text(f"{digest}  {archive_name}\n", encoding="utf-8")
    print(f"packaged {archive_path.relative_to(ROOT)}")
    print(f"sha256   {digest}")
    if args.draft:
        print("DRAFT: not for external compliance claims; release packaging is blocked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
