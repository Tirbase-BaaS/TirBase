#!/usr/bin/env python3
"""Gate for the CC-24 closed connector tree.

Proves that the proprietary connectors are not tracked in the open repository,
that no vendor SDK or credential is present, and that the required product
documentation exists. With ``--test`` it also runs the closed test suite.

Exit code 0 means the closed tree is safe to keep beside the open repo. Any
other code is a release blocker.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "connectors"

REQUIRED_DOCS = [
    "README.md",
    "sap.md",
    "odoo.md",
    "tms.md",
    "credentials.md",
    "support.md",
]
REQUIRED_CRATES = ["connector-sdk", "connector-sap", "connector-odoo", "connector-tms"]

EXCLUDE_PARTS = {"target", "dist"}

FORBIDDEN_SUFFIXES = {
    ".jar": "Java vendor SDK/archive",
    ".whl": "Python vendor wheel",
    ".egg": "Python vendor egg",
    ".dll": "native vendor binary",
    ".dylib": "native vendor binary",
    ".so": "native vendor binary",
    ".a": "native vendor library",
    ".jco": "SAP JCo archive",
}
FORBIDDEN_DIRS = {"node_modules", "vendor", "sapjco", "jco", "odoo-addons"}

# Credential-shaped assignments with a non-empty value. Docs mention names only.
CREDENTIAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)client_secret\s*[:=]\s*[\"'][^\"'\s]{6,}"),
    re.compile(r"(?i)password\s*[:=]\s*[\"'][^\"'\s]{4,}"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\-]{12,}"),
    re.compile(r"(?i)TIRBASE_[A-Z_]*(SECRET|KEY|PASSWORD)\s*=\s*(?!…)[^\s]{8,}"),
]


def run(command, cwd=ROOT):
    return subprocess.run(command, cwd=str(cwd), capture_output=True, text=True)


def fail(problems, message):
    problems.append(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="run the closed test suite")
    args = parser.parse_args()

    problems = []
    if not CLOSED.is_dir():
        print("closed connector tree absent; nothing to check (open repo is clean)")
        return 0

    ignored = run(["git", "check-ignore", "-q", "closed/connectors/Cargo.toml"])
    if ignored.returncode != 0:
        fail(problems, "closed/ is not git-ignored; refusing to proceed")

    tracked = run(["git", "ls-files", "closed"])
    if tracked.stdout.strip():
        fail(problems, "closed/ contains tracked files: " + tracked.stdout.strip().splitlines()[0])

    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if "closed/" in manifest:
        fail(problems, "root Cargo.toml references closed/")

    for crate in REQUIRED_CRATES:
        if not (CLOSED / crate / "Cargo.toml").is_file():
            fail(problems, f"missing crate {crate}")
    for doc in REQUIRED_DOCS:
        if not (CLOSED / "docs" / doc).is_file():
            fail(problems, f"missing product document docs/{doc}")
    if not (CLOSED / "LICENSE").is_file():
        fail(problems, "missing proprietary LICENSE")

    for path in CLOSED.rglob("*"):
        if EXCLUDE_PARTS & set(path.relative_to(CLOSED).parts):
            continue
        if path.is_dir():
            if path.name in FORBIDDEN_DIRS:
                fail(problems, f"vendored vendor directory: {path.relative_to(ROOT)}")
            continue
        suffix = path.suffix.lower()
        if suffix in FORBIDDEN_SUFFIXES:
            fail(problems, f"{FORBIDDEN_SUFFIXES[suffix]}: {path.relative_to(ROOT)}")
        if path.stat().st_size > 2_000_000:
            fail(problems, f"unexpected large file in closed tree: {path.relative_to(ROOT)}")
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                fail(
                    problems,
                    f"credential-shaped content in {path.relative_to(ROOT)}: {pattern.pattern}",
                )

    print(f"closed tree: {CLOSED.relative_to(ROOT)}")
    print(f"crates: {', '.join(REQUIRED_CRATES)}")
    print(f"documents: {len(REQUIRED_DOCS)} + LICENSE")

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1

    print("PASS no tracked connector source, no vendor SDK, no credential")

    if args.test:
        result = subprocess.run(
            ["cargo", "test", "--workspace"],
            cwd=str(CLOSED),
            text=True,
        )
        if result.returncode != 0:
            print("FAIL closed connector tests")
            return 1
        print("PASS closed connector tests")

    return 0


if __name__ == "__main__":
    sys.exit(main())
