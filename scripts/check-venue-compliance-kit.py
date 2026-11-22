#!/usr/bin/env python3
"""Venue compliance kit packaging gate (ST-13).

Verifies the proprietary kit is deliverable, contains no source/secrets, and
that its retention schedule matches the open schedule. A release archive also
requires an approved privacy/counsel review with reviewer and date.

Usage:
    python3 scripts/check-venue-compliance-kit.py [--release]
"""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = ROOT / "commercial" / "venue-compliance-kit"
OPEN_SCHEDULE = ROOT / "data" / "venue-retention-schedule.csv"

REQUIRED = [
    "LICENSE",
    "README.md",
    "EXCLUSIONS.md",
    "manifest.json",
    "dpia/README.md",
    "dpia/ticket.md",
    "dpia/credential.md",
    "dpia/cctv.md",
    "dpia/access.md",
    "data-flow-map.md",
    "retention-schedule.csv",
    "cctv-retention-and-access.md",
    "subject-access-and-deletion.md",
    "reporting-templates.md",
    "review/privacy-review-record.md",
    "review/review-log.md",
]

ALLOWED_SUFFIXES = {".md", ".csv", ".json", ".txt"}
ALLOWED_NAMES = {"LICENSE"}
CODE_SUFFIXES = {
    ".rs", ".py", ".js", ".mjs", ".ts", ".sh", ".bash", ".wasm", ".so", ".dylib",
    ".dll", ".exe", ".bin", ".o", ".a", ".class", ".jar", ".pem", ".key", ".p12",
}
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{10,}\b"), "API secret key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "GitHub token"),
    (
        re.compile(r"(?i)\b(password|passwd|api[_-]?key|secret)\s*=\s*['\"][^'\"]{8,}"),
        "inline credential",
    ),
]


def check_purity(errors: list[str]) -> int:
    files = 0
    for path in sorted(KIT.rglob("*")):
        if path.is_symlink():
            errors.append(f"{path.relative_to(KIT)}: symlink in kit")
            continue
        if path.is_dir():
            continue
        files += 1
        relative = path.relative_to(KIT)
        if path.name not in ALLOWED_NAMES and path.suffix.lower() not in ALLOWED_SUFFIXES:
            errors.append(f"{relative}: file type {path.suffix or '(none)'} is not deliverable")
            continue
        if path.suffix.lower() in CODE_SUFFIXES:
            errors.append(f"{relative}: source/binary file in kit")
        if path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            errors.append(f"{relative}: executable bit set")
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"{relative}: possible {label}")
    return files


def check_manifest(release: bool, errors: list[str]) -> dict:
    manifest = json.loads((KIT / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("licence") != "proprietary":
        errors.append("manifest: licence must be proprietary")
    reviews = manifest.get("reviews", {})
    record = reviews.get("privacy_counsel", {})
    status = record.get("status")
    if status not in {"pending", "approved", "rejected"}:
        errors.append("manifest: reviews.privacy_counsel.status invalid")
    if status == "approved" and (not record.get("reviewer") or not record.get("date")):
        errors.append("manifest: approved privacy review needs reviewer and date")
    if release and status != "approved":
        errors.append("manifest: a release archive requires an approved privacy review")
    if manifest.get("delivery", {}).get("contains_source"):
        errors.append("manifest: kit claims to contain source")
    if manifest.get("delivery", {}).get("contains_secrets"):
        errors.append("manifest: kit claims to contain secrets")
    return manifest


def check_schedule(errors: list[str]) -> None:
    if not OPEN_SCHEDULE.is_file():
        errors.append("missing open retention schedule")
        return
    if (KIT / "retention-schedule.csv").read_text(encoding="utf-8") != OPEN_SCHEDULE.read_text(
        encoding="utf-8"
    ):
        errors.append("retention-schedule.csv differs from data/venue-retention-schedule.csv")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()

    errors: list[str] = []
    if not KIT.is_dir():
        print(f"ERROR: kit not found at {KIT}", file=sys.stderr)
        return 1
    for relative in REQUIRED:
        if not (KIT / relative).is_file():
            errors.append(f"missing required file: {relative}")
    if "proprietary" not in (KIT / "LICENSE").read_text(encoding="utf-8").lower():
        errors.append("LICENSE: proprietary notice missing")
    for relative in ("dpia/ticket.md", "dpia/credential.md", "dpia/cctv.md", "dpia/access.md"):
        path = KIT / relative
        if path.is_file() and "[ ]" not in path.read_text(encoding="utf-8"):
            errors.append(f"{relative}: no customer completion fields")
    files = check_purity(errors)
    manifest = check_manifest(args.release, errors)
    check_schedule(errors)

    if errors:
        print(f"FAIL: {len(errors)} venue compliance kit problem(s)", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    state = manifest["reviews"]["privacy_counsel"]["status"]
    print(
        f"OK: venue compliance kit is deliverable ({files} files, "
        f"privacy review {state}, no source or secrets)"
    )
    if args.release:
        print("OK: privacy review is approved for release")
    else:
        print("DRAFT: customer completion and privacy/counsel review are required")
    return 0


if __name__ == "__main__":
    sys.exit(main())
