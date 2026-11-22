#!/usr/bin/env python3
"""Gate for the ST-14 closed venue ticketing connector tree.

Proves that the proprietary Ticketmaster and Eventim connectors are not tracked
in the open repository, that they link only the Apache-2.0 venue connector
surface, that no vendor SDK or credential is present, and that the required
product documentation and regression tests exist. With ``--test`` it also runs
the closed suite, including both open-conformance certifications.

Exit code 0 means the closed tree is safe to keep beside the open repository and
ready to package. Any other code is a release blocker.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "venue-ticketing"

REQUIRED_CRATES = ["venue-ticketing-sdk", "connector-ticketmaster", "connector-eventim"]
REQUIRED_DOCS = [
    "README.md",
    "ticketmaster.md",
    "eventim.md",
    "credentials.md",
    "sandbox.md",
    "conformance.md",
    "failure-recovery.md",
    "support.md",
]
REQUIRED_TESTS = {
    "connector-ticketmaster/tests/contract.rs": [
        "ticketmaster_passes_the_open_conformance_suite",
        "revoked_ticket_is_rejected_offline_after_sync",
        "a_replayed_scan_does_not_admit_twice",
    ],
    "connector-eventim/tests/contract.rs": [
        "eventim_passes_the_open_conformance_suite",
        "revoked_ticket_is_rejected_offline_after_sync",
        "a_replayed_scan_does_not_admit_twice",
    ],
}

EXCLUDE_PARTS = {"target", "dist"}
ALLOWED_TIRBASE_DEPS = {"tirbase-venue-connectors", "tirbase-integrations"}

FORBIDDEN_SUFFIXES = {
    ".jar": "Java vendor SDK/archive",
    ".whl": "Python vendor wheel",
    ".egg": "Python vendor egg",
    ".dll": "native vendor binary",
    ".dylib": "native vendor binary",
    ".so": "native vendor binary",
    ".a": "native vendor library",
    ".p12": "certificate container",
    ".pfx": "certificate container",
}
FORBIDDEN_DIRS = {"node_modules", "vendor-sdk", "sdk", "dist-sdk"}

# Credential-shaped assignments with a non-empty value. Docs use placeholders.
CREDENTIAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)client_secret\s*[:=]\s*[\"'][^\"'\s]{6,}"),
    re.compile(r"(?i)password\s*[:=]\s*[\"'][^\"'\s]{4,}"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\-]{12,}"),
    re.compile(r"(?i)TIRBASE_[A-Z_]*(SECRET|KEY|PASSWORD)\s*=\s*(?!…)[^\s]{8,}"),
]


def run(command, cwd=ROOT):
    return subprocess.run(command, cwd=str(cwd), capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="run the closed test suite")
    args = parser.parse_args()

    problems = []

    if not CLOSED.is_dir():
        print("closed venue ticketing tree absent; nothing to check (open repo is clean)")
        return 0

    ignored = run(["git", "check-ignore", "-q", "closed/venue-ticketing/Cargo.toml"])
    if ignored.returncode != 0:
        fail(problems, "closed/ is not git-ignored; refusing to proceed")

    tracked = run(["git", "ls-files", "closed"])
    if tracked.stdout.strip():
        fail(problems, "closed/ contains tracked files: " + tracked.stdout.strip().splitlines()[0])

    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if "closed/" in manifest:
        fail(problems, "root Cargo.toml references closed/")

    workspace = (CLOSED / "Cargo.toml").read_text(encoding="utf-8")
    if "LicenseRef-Proprietary" not in workspace:
        fail(problems, "workspace manifest does not declare the proprietary licence")

    for crate in REQUIRED_CRATES:
        path = CLOSED / crate / "Cargo.toml"
        if not path.is_file():
            fail(problems, f"missing crate {crate}")
            continue
        text = path.read_text(encoding="utf-8")
        if "license.workspace = true" not in text:
            fail(problems, f"{crate} does not inherit the proprietary licence")
    for doc in REQUIRED_DOCS:
        if not (CLOSED / "docs" / doc).is_file():
            fail(problems, f"missing product document docs/{doc}")
    if not (CLOSED / "LICENSE").is_file():
        fail(problems, "missing proprietary LICENSE")

    # The sold connectors are separate products: neither may depend on the other.
    if "connector-eventim" in (CLOSED / "connector-ticketmaster" / "Cargo.toml").read_text(
        encoding="utf-8"
    ):
        fail(problems, "connector-ticketmaster depends on connector-eventim")
    if "connector-ticketmaster" in (CLOSED / "connector-eventim" / "Cargo.toml").read_text(
        encoding="utf-8"
    ):
        fail(problems, "connector-eventim depends on connector-ticketmaster")

    # Regression tests that back the three done criteria must exist by name.
    for relative, tests in REQUIRED_TESTS.items():
        path = CLOSED / relative
        if not path.is_file():
            fail(problems, f"missing test file {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        for name in tests:
            if f"fn {name}(" not in text:
                fail(problems, f"{relative} is missing {name}")

    # Only the Apache-2.0 venue connector surface may be linked.
    lock = CLOSED / "Cargo.lock"
    if not lock.is_file():
        fail(problems, "Cargo.lock is missing; the dependency boundary is unproven")
    else:
        for line in lock.read_text(encoding="utf-8").splitlines():
            match = re.match(r'name = "([^"]+)"', line)
            if not match:
                continue
            name = match.group(1)
            if name.startswith("tirbase-") and name not in ALLOWED_TIRBASE_DEPS:
                fail(problems, f"Cargo.lock reaches a non-Apache-2.0 TirBase crate: {name}")
            if name.startswith("tirbase-venue") and name != "tirbase-venue-connectors":
                fail(problems, f"Cargo.lock reaches the AGPL venue runtime: {name}")

    for path in CLOSED.rglob("*"):
        relative = path.relative_to(CLOSED)
        if EXCLUDE_PARTS & set(relative.parts):
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
        if suffix == ".rs" and not text.startswith("// SPDX-License-Identifier: LicenseRef-Proprietary"):
            fail(problems, f"Rust file without the proprietary SPDX header: {path.relative_to(ROOT)}")
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                fail(
                    problems,
                    f"credential-shaped content in {path.relative_to(ROOT)}: {pattern.pattern}",
                )

    print(f"closed tree: {CLOSED.relative_to(ROOT)}")
    print(f"crates: {', '.join(REQUIRED_CRATES)}")
    print(f"documents: {len(REQUIRED_DOCS)} + LICENSE")
    print(f"TirBase dependencies: {', '.join(sorted(ALLOWED_TIRBASE_DEPS))}")

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1

    print("PASS no tracked connector source, no AGPL edge, no vendor SDK, no credential")

    if args.test:
        result = subprocess.run(["cargo", "test", "--workspace"], cwd=str(CLOSED), text=True)
        if result.returncode != 0:
            print("FAIL closed venue ticketing tests")
            return 1
        print("PASS closed venue ticketing tests and both conformance certifications")

    return 0


def fail(problems, message):
    problems.append(message)


if __name__ == "__main__":
    sys.exit(main())
