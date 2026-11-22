#!/usr/bin/env python3
"""Gate for the POS-18 closed delivery-platform connector tree.

Proves that the proprietary Uber Eats, Deliveroo and DoorDash connectors are not
tracked in the open repository, that no vendor SDK, credential or
card-number-shaped fixture is present, that the product documentation exists,
and — with ``--test`` — that the closed conformance and contract suites pass.

Exit code 0 means the closed delivery tree is safe to keep beside the open repo.
Any other code is a release blocker.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "pos-delivery"

REQUIRED_DOCS = [
    "README.md",
    "ubereats.md",
    "deliveroo.md",
    "doordash.md",
    "credentials.md",
    "failure-recovery.md",
    "support.md",
]
REQUIRED_CRATES = [
    "delivery-sdk",
    "delivery-ubereats",
    "delivery-deliveroo",
    "delivery-doordash",
]

EXCLUDE_PARTS = {"target", "dist"}

FORBIDDEN_SUFFIXES = {
    ".jar": "Java vendor SDK/archive",
    ".whl": "Python vendor wheel",
    ".egg": "Python vendor egg",
    ".dll": "native vendor binary",
    ".dylib": "native vendor binary",
    ".so": "native vendor binary",
    ".a": "native vendor library",
    ".xcframework": "iOS vendor SDK",
    ".aar": "Android vendor SDK",
}
FORBIDDEN_DIRS = {
    "node_modules",
    "vendor",
    "ubereats-sdk",
    "deliveroo-sdk",
    "doordash-sdk",
    "Pods",
}

# Credential-shaped assignments with a non-empty value. Docs mention names only.
CREDENTIAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)client_secret\s*[:=]\s*[\"'][^\"'\s]{6,}"),
    re.compile(r"(?i)password\s*[:=]\s*[\"'][^\"'\s]{4,}"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\-]{12,}"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{8,}"),
    re.compile(r"(?i)TIRBASE_[A-Z_]*(SECRET|KEY|PASSWORD|TOKEN)\s*=\s*(?!…)[^\s]{8,}"),
]

DIGIT_RUN = re.compile(r"\d{13,19}")


def run(command, cwd=ROOT):
    return subprocess.run(command, cwd=str(cwd), capture_output=True, text=True)


def luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        value = int(character)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="run the closed test suite")
    args = parser.parse_args()

    problems = []
    if not CLOSED.is_dir():
        print("closed delivery tree absent; nothing to check (open repo is clean)")
        return 0

    ignored = run(["git", "check-ignore", "-q", "closed/pos-delivery/Cargo.toml"])
    if ignored.returncode != 0:
        problems.append("closed/pos-delivery is not git-ignored; refusing to proceed")

    tracked = run(["git", "ls-files", "closed"])
    if tracked.stdout.strip():
        problems.append(
            "closed/ contains tracked files: " + tracked.stdout.strip().splitlines()[0]
        )

    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if "closed/" in manifest:
        problems.append("root Cargo.toml references closed/")

    for crate in REQUIRED_CRATES:
        if not (CLOSED / crate / "Cargo.toml").is_file():
            problems.append(f"missing crate {crate}")
    for doc in REQUIRED_DOCS:
        if not (CLOSED / "docs" / doc).is_file():
            problems.append(f"missing product document docs/{doc}")
    if not (CLOSED / "LICENSE").is_file():
        problems.append("missing proprietary LICENSE")

    for path in CLOSED.rglob("*"):
        relative = path.relative_to(CLOSED)
        if EXCLUDE_PARTS & set(relative.parts):
            continue
        if path.is_dir():
            if path.name in FORBIDDEN_DIRS:
                problems.append(f"vendored directory: {path.relative_to(ROOT)}")
            continue
        suffix = path.suffix.lower()
        if suffix in FORBIDDEN_SUFFIXES:
            problems.append(f"{FORBIDDEN_SUFFIXES[suffix]}: {path.relative_to(ROOT)}")
        if path.stat().st_size > 2_000_000:
            problems.append(f"unexpected large file in closed tree: {path.relative_to(ROOT)}")
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                problems.append(
                    f"credential-shaped content in {path.relative_to(ROOT)}: {pattern.pattern}"
                )
        if path.suffix in {".rs", ".json", ".md", ".toml"}:
            for match in DIGIT_RUN.findall(text):
                if luhn_valid(match):
                    problems.append(
                        f"Luhn-valid card-number-shaped run in {path.relative_to(ROOT)}"
                    )
                    break

    print(f"closed tree: {CLOSED.relative_to(ROOT)}")
    print(f"crates: {', '.join(REQUIRED_CRATES)}")
    print(f"documents: {len(REQUIRED_DOCS)} + LICENSE")

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1

    print("PASS no tracked connector source, no vendor SDK, no credential, no PAN shape")

    if args.test:
        result = subprocess.run(
            ["cargo", "test", "--workspace"],
            cwd=str(CLOSED),
            text=True,
        )
        if result.returncode != 0:
            print("FAIL closed delivery connector tests")
            return 1
        print("PASS closed delivery connector tests")

    return 0


if __name__ == "__main__":
    sys.exit(main())
