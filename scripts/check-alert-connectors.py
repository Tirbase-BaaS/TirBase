#!/usr/bin/env python3
"""Gate for the CC-25 closed alert connector tree.

Proves the Slack, Teams, PagerDuty and SMS connectors are not tracked in the open
repository, contain no provider SDK, no plaintext token or vault file, and ship
the required product documentation. ``--test`` also runs the closed suite.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "alerts"
EXCLUDE_PARTS = {"target", "dist"}

REQUIRED_DOCS = [
    "README.md",
    "slack.md",
    "teams.md",
    "pagerduty.md",
    "sms.md",
    "templates.md",
    "credentials.md",
    "support.md",
]
REQUIRED_CRATES = [
    "alert-sdk",
    "alert-slack",
    "alert-teams",
    "alert-pagerduty",
    "alert-sms",
    "alert-install",
]

FORBIDDEN_SUFFIXES = {
    ".jar": "Java provider SDK",
    ".whl": "Python provider SDK",
    ".dll": "native provider binary",
    ".dylib": "native provider binary",
    ".so": "native provider binary",
    ".p12": "provider certificate bundle",
    ".pfx": "provider certificate bundle",
}
FORBIDDEN_DIRS = {"node_modules", "vendor"}
FORBIDDEN_FILES = {".env", "vault.json", "alerts.vault.json", "token.txt"}

# Real-token shapes and credential assignments. Short synthetic test strings are
# intentionally not matched.
CREDENTIAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"xox[bpars]-[A-Za-z0-9-]{20,}"),
    re.compile(r"xapp-[A-Za-z0-9-]{20,}"),
    re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
    re.compile(r"TIRBASE_ALERT_VAULT_KEY\s*=\s*[0-9a-fA-F]{32,}"),
    re.compile(r"client_secret\s*[:=]\s*[\"'][^\"'\s]{8,}"),
    re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{30,}"),
]


def run(command):
    return subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="run the closed suite")
    args = parser.parse_args()

    if not CLOSED.is_dir():
        print("closed alert tree absent; nothing to check")
        return 0

    problems = []
    if run(["git", "check-ignore", "-q", "closed/alerts/Cargo.toml"]).returncode != 0:
        problems.append("closed/alerts is not git-ignored")
    if run(["git", "ls-files", "closed/alerts"]).stdout.strip():
        problems.append("closed/alerts contains tracked files")
    if "closed/" in (ROOT / "Cargo.toml").read_text(encoding="utf-8"):
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
        if EXCLUDE_PARTS & set(path.relative_to(CLOSED).parts):
            continue
        if path.is_dir():
            if path.name in FORBIDDEN_DIRS:
                problems.append(f"vendored provider directory: {path.relative_to(ROOT)}")
            continue
        if path.name in FORBIDDEN_FILES:
            problems.append(f"forbidden credential file: {path.relative_to(ROOT)}")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            problems.append(
                f"{FORBIDDEN_SUFFIXES[path.suffix.lower()]}: {path.relative_to(ROOT)}"
            )
        if path.stat().st_size > 2_000_000:
            problems.append(f"unexpected large file: {path.relative_to(ROOT)}")
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                problems.append(
                    f"credential-shaped content in {path.relative_to(ROOT)}: {pattern.pattern}"
                )

    print(f"closed tree: {CLOSED.relative_to(ROOT)}")
    print(f"crates: {', '.join(REQUIRED_CRATES)}")
    print(f"documents: {len(REQUIRED_DOCS)} + LICENSE")

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1
    print("PASS no tracked source, provider SDK, plaintext token or vault file")

    if args.test:
        if subprocess.run(["cargo", "test", "--workspace"], cwd=str(CLOSED)).returncode != 0:
            print("FAIL closed alert tests")
            return 1
        print("PASS closed alert tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
