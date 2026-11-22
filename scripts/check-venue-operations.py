#!/usr/bin/env python3
"""Gate for the ST-15 closed venue operations connector tree.

Proves the seven proprietary connectors are not tracked in the open repository,
link only the Apache-2.0 venue connector surface, bundle no vendor SDK or
credential, document setup/credentials/failure recovery, and carry the tests that
back the three done criteria: no life-safety control, no duplicated replays, and
open-conformance certification.

With ``--test`` it also runs the closed suite.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "venue-operations"

REQUIRED_CRATES = [
    "venue-ops-sdk",
    "connector-hid",
    "connector-lenel",
    "connector-genetec",
    "connector-bms-siemens",
    "connector-bms-jci",
    "connector-onvif-cctv",
    "connector-pa",
]
REQUIRED_DOCS = [
    "README.md",
    "hid.md",
    "lenel.md",
    "genetec.md",
    "bms.md",
    "cctv.md",
    "pa.md",
    "credentials.md",
    "sandbox.md",
    "conformance.md",
    "failure-recovery.md",
    "support.md",
]
REQUIRED_TESTS = {
    "connector-hid/tests/contract.rs": [
        "hid_passes_the_open_conformance_suite",
        "revoked_credential_is_refused_offline_after_sync",
        "replays_do_not_duplicate_access_decisions",
    ],
    "connector-lenel/tests/contract.rs": [
        "lenel_passes_the_open_conformance_suite",
        "revoked_credential_is_refused_offline_after_sync",
        "replays_do_not_duplicate_access_decisions",
    ],
    "connector-genetec/tests/contract.rs": [
        "genetec_passes_the_open_conformance_suite",
        "revoked_credential_is_refused_offline_after_sync",
        "replays_do_not_duplicate_access_decisions",
    ],
    "connector-bms-siemens/tests/contract.rs": [
        "siemens_passes_the_open_conformance_suite",
        "life_safety_points_and_alarms_are_refused",
        "replays_do_not_duplicate_alarms",
    ],
    "connector-bms-jci/tests/contract.rs": [
        "jci_passes_the_open_conformance_suite",
        "life_safety_points_and_alarms_are_refused",
        "replays_do_not_duplicate_alarms",
    ],
    "connector-onvif-cctv/tests/contract.rs": [
        "onvif_passes_the_open_conformance_suite",
        "onvif_ingestion_keeps_metadata_only",
        "replays_do_not_duplicate_alarm_events",
    ],
    "connector-pa/tests/contract.rs": [
        "pa_passes_the_open_conformance_suite",
        "template_priority_and_audit_are_recorded",
        "replays_do_not_duplicate_announcements",
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
    ".jpg": "camera image or still",
    ".jpeg": "camera image or still",
    ".png": "camera image or still",
    ".mp4": "camera video",
    ".h264": "camera video",
}
FORBIDDEN_DIRS = {"node_modules", "vendor-sdk", "sdk", "snapshots", "media"}

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
        print("closed venue operations tree absent; nothing to check (open repo is clean)")
        return 0

    if run(["git", "check-ignore", "-q", "closed/venue-operations/Cargo.toml"]).returncode != 0:
        problems.append("closed/ is not git-ignored; refusing to proceed")
    tracked = run(["git", "ls-files", "closed"])
    if tracked.stdout.strip():
        problems.append("closed/ contains tracked files: " + tracked.stdout.strip().splitlines()[0])
    if "closed/" in (ROOT / "Cargo.toml").read_text(encoding="utf-8"):
        problems.append("root Cargo.toml references closed/")

    workspace = (CLOSED / "Cargo.toml").read_text(encoding="utf-8")
    if "LicenseRef-Proprietary" not in workspace:
        problems.append("workspace manifest does not declare the proprietary licence")

    for crate in REQUIRED_CRATES:
        path = CLOSED / crate / "Cargo.toml"
        if not path.is_file():
            problems.append(f"missing crate {crate}")
            continue
        if "license.workspace = true" not in path.read_text(encoding="utf-8"):
            problems.append(f"{crate} does not inherit the proprietary licence")
    for doc in REQUIRED_DOCS:
        if not (CLOSED / "docs" / doc).is_file():
            problems.append(f"missing product document docs/{doc}")
    if not (CLOSED / "LICENSE").is_file():
        problems.append("missing proprietary LICENSE")

    # The sold connectors are separate products: no crate may depend on another.
    for crate in REQUIRED_CRATES[1:]:
        text = (CLOSED / crate / "Cargo.toml").read_text(encoding="utf-8")
        for other in REQUIRED_CRATES[1:]:
            if other != crate and other in text:
                problems.append(f"{crate} depends on {other}")

    for relative, tests in REQUIRED_TESTS.items():
        path = CLOSED / relative
        if not path.is_file():
            problems.append(f"missing test file {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        for name in tests:
            if f"fn {name}(" not in text:
                problems.append(f"{relative} is missing {name}")

    # Life-safety refusal must exist in the shared SDK and be exercised by both
    # BMS products, and the CCTV product must refuse media.
    bms = CLOSED / "venue-ops-sdk" / "src" / "bms.rs"
    if not bms.is_file() or "LIFE_SAFETY_MARKERS" not in bms.read_text(encoding="utf-8"):
        problems.append("shared SDK has no life-safety marker list")
    cctv = CLOSED / "venue-ops-sdk" / "src" / "cctv.rs"
    if not cctv.is_file() or "MEDIA_MARKERS" not in cctv.read_text(encoding="utf-8"):
        problems.append("shared SDK has no camera-media refusal")

    lock = CLOSED / "Cargo.lock"
    if not lock.is_file():
        problems.append("Cargo.lock is missing; the dependency boundary is unproven")
    else:
        for line in lock.read_text(encoding="utf-8").splitlines():
            match = re.match(r'name = "([^"]+)"', line)
            if not match:
                continue
            name = match.group(1)
            if name.startswith("tirbase-") and name not in ALLOWED_TIRBASE_DEPS:
                problems.append(f"Cargo.lock reaches a non-Apache-2.0 TirBase crate: {name}")
            if name.startswith("tirbase-venue") and name != "tirbase-venue-connectors":
                problems.append(f"Cargo.lock reaches the AGPL venue runtime: {name}")

    for path in CLOSED.rglob("*"):
        relative = path.relative_to(CLOSED)
        if EXCLUDE_PARTS & set(relative.parts):
            continue
        if path.is_dir():
            if path.name in FORBIDDEN_DIRS:
                problems.append(f"vendored or media directory: {path.relative_to(ROOT)}")
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
        if suffix == ".rs" and not text.startswith(
            "// SPDX-License-Identifier: LicenseRef-Proprietary"
        ):
            problems.append(f"Rust file without the proprietary SPDX header: {path.relative_to(ROOT)}")
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                problems.append(
                    f"credential-shaped content in {path.relative_to(ROOT)}: {pattern.pattern}"
                )

    print(f"closed tree: {CLOSED.relative_to(ROOT)}")
    print(f"crates: {', '.join(REQUIRED_CRATES)}")
    print(f"documents: {len(REQUIRED_DOCS)} + LICENSE")
    print(f"TirBase dependencies: {', '.join(sorted(ALLOWED_TIRBASE_DEPS))}")

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1

    print("PASS no tracked connector source, no AGPL edge, no vendor SDK, no media, no credential")

    if args.test:
        result = subprocess.run(["cargo", "test", "--workspace"], cwd=str(CLOSED), text=True)
        if result.returncode != 0:
            print("FAIL closed venue operations tests")
            return 1
        print("PASS closed venue operations tests and all seven conformance certifications")

    return 0


if __name__ == "__main__":
    sys.exit(main())
