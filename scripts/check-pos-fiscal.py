#!/usr/bin/env python3
"""Gate for the POS-19 closed fiscal-certification tree.

Proves that the proprietary country modules are not tracked in the open
repository, that each has a plan with a named owner, that every module is
blocked in the release manifest, that no module is marked signed off, that no
vendor SDK, credential or card-number-shaped fixture is present, and — with
``--test`` — that the closed suites pass.

Exit code 0 means the tree may stay beside the open repository. It does not
mean any module is certified: certification requires a signed lab report.
"""

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "pos-fiscal"

REQUIRED_CRATES = [
    "fiscal-sdk",
    "fiscal-germany",
    "fiscal-italy",
    "fiscal-france",
    "fiscal-spain",
]

REQUIRED_DOCS = [
    "README.md",
    "germany.md",
    "italy.md",
    "france.md",
    "spain.md",
    "credentials.md",
    "failure-recovery.md",
    "support.md",
    "certification/release-policy.md",
    "certification/evidence-index.md",
    "certification/lab-correspondence.md",
    "certification/claims.md",
    "certification/germany-plan.md",
    "certification/italy-plan.md",
    "certification/france-plan.md",
    "certification/spain-plan.md",
]

PLANS = {
    "germany": "certification/germany-plan.md",
    "italy": "certification/italy-plan.md",
    "france": "certification/france-plan.md",
    "spain": "certification/spain-plan.md",
}

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
    ".pfx": "certificate/private-key container",
    ".p12": "certificate/private-key container",
}
FORBIDDEN_DIRS = {
    "node_modules",
    "vendor",
    "tse-sdk",
    "rt-sdk",
    "nf525-sdk",
    "verifactu-sdk",
    "Pods",
}

# Credential-shaped assignments with a non-empty value. Docs mention names only.
CREDENTIAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)client_secret\s*[:=]\s*[\"'][^\"'\s]{6,}"),
    re.compile(r"(?i)password\s*[:=]\s*[\"'][^\"'\s]{4,}"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\-]{12,}"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{8,}"),
    re.compile(
        r"(?i)TIRBASE_[A-Z_]*(SECRET|KEY|PASSWORD|TOKEN)\s*=\s*(?!…)[^\s]{8,}"
    ),
]

DIGIT_RUN = re.compile(r"\d{13,19}")
STUB = re.compile(r"\b(todo!|unimplemented!)\s*\(")
AGPL_CRATES = ["tirbase-pos", "tirbase-core", "tirbase-drivers", "tirbase-gateway"]


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
        print("closed fiscal tree absent; nothing to check (open repo is clean)")
        return 0

    ignored = run(["git", "check-ignore", "-q", "closed/pos-fiscal/Cargo.toml"])
    if ignored.returncode != 0:
        problems.append("closed/pos-fiscal is not git-ignored; refusing to proceed")

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
    if not (CLOSED / "release-manifest.toml").is_file():
        problems.append("missing release-manifest.toml")

    release = CLOSED / "release-manifest.toml"
    if release.is_file():
        data = tomllib.loads(release.read_text(encoding="utf-8"))
        modules = data.get("modules", {})
        if set(modules) != set(PLANS):
            problems.append(
                "release manifest must name exactly: " + ", ".join(sorted(PLANS))
            )
        for name, plan_path in PLANS.items():
            entry = modules.get(name, {})
            if entry.get("status") != "blocked":
                problems.append(f"{name}: release status is not blocked")
            if entry.get("signed_off") is not False:
                problems.append(f"{name}: signed_off must be false without a lab report")
            if entry.get("certificate_id"):
                problems.append(f"{name}: certificate id set without a signed report")
            if entry.get("report_reference"):
                problems.append(f"{name}: report reference set without a signed report")
            if not entry.get("owner"):
                problems.append(f"{name}: release manifest has no owner")
            plan_file = CLOSED / "docs" / plan_path
            if not plan_file.is_file():
                problems.append(f"{name}: missing plan docs/{plan_path}")
                continue
            plan_text = plan_file.read_text(encoding="utf-8")
            if "**Owner:**" not in plan_text:
                problems.append(f"{name}: plan has no Owner line")
            if "blocked" not in plan_text:
                problems.append(f"{name}: plan is not marked blocked")

    evidence = (CLOSED / "docs" / "certification" / "evidence-index.md").read_text(
        encoding="utf-8"
    )
    for prefix in ("DE-E1", "IT-E1", "FR-E1", "ES-E1"):
        if prefix not in evidence:
            problems.append(f"evidence index is missing {prefix}")

    claims = (CLOSED / "docs" / "certification" / "claims.md").read_text(
        encoding="utf-8"
    )
    if "no approved claims" not in claims.lower():
        problems.append("claims matrix does not state that no claim is approved")

    correspondence = (
        CLOSED / "docs" / "certification" / "lab-correspondence.md"
    ).read_text(encoding="utf-8")
    if "no correspondence has been sent" not in correspondence.lower():
        problems.append("lab correspondence log does not state that none was sent")

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
                if len(set(match)) == 1:
                    continue
                if luhn_valid(match):
                    problems.append(
                        f"Luhn-valid card-number-shaped run in {path.relative_to(ROOT)}"
                    )
                    break
        if path.suffix == ".rs" and STUB.search(text):
            problems.append(f"stub left in module: {path.relative_to(ROOT)}")

    for path in CLOSED.rglob("Cargo.toml"):
        text = path.read_text(encoding="utf-8")
        for crate in AGPL_CRATES:
            if re.search(rf"(?m)^\s*{re.escape(crate)}\s*=", text):
                problems.append(f"AGPL dependency {crate} in {path.relative_to(ROOT)}")

    print(f"closed tree: {CLOSED.relative_to(ROOT)}")
    print(f"crates: {', '.join(REQUIRED_CRATES)}")
    print(f"documents: {len(REQUIRED_DOCS)} + LICENSE + release manifest")
    print("release state: every module blocked, no signed_off, no certificate id")

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1

    print(
        "PASS no tracked fiscal source, no AGPL dependency, no vendor SDK, "
        "no credential, no PAN shape"
    )
    print("PASS every module has a plan, owner, blocked release state and incomplete evidence")

    if args.test:
        result = subprocess.run(
            ["cargo", "test", "--workspace", "--no-fail-fast"],
            cwd=str(CLOSED),
            text=True,
        )
        if result.returncode != 0:
            print("FAIL closed fiscal module tests")
            return 1
        print("PASS closed fiscal module tests")

    return 0


if __name__ == "__main__":
    sys.exit(main())
