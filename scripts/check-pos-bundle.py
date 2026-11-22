#!/usr/bin/env python3
"""Release gate for the POS-20 closed PCI evidence and device bundle tree.

Proves that the proprietary bundle is not tracked in the open repository, that
every PCI requirement maps to an indexed artifact whose file exists, that no
uncertified device carries an approval identifier, that every pending
attestation is honestly pending, and that the reviewed release state is a sales
hold. It also rejects credentials, card-number-shaped fixtures and vendor SDK
binaries.

Exit code 0 means the tree may stay beside the open repository. It does not mean
the bundle is certified or saleable: real approval, scan and assessment evidence
must come from outside this repository.
"""

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "pos-bundle"

REQUIRED_CRATES = ["bundle-sdk"]

REQUIRED_DATA = [
    "Cargo.toml",
    "LICENSE",
    "bundles/retail-bundle.toml",
    "catalog/devices.toml",
    "catalog/attestations.toml",
    "pci/requirements.toml",
    "pci/evidence-index.toml",
    "pci/asv-scan-register.toml",
    "config/baseline.toml",
    "release-manifest.toml",
]

REQUIRED_DOCS = [
    "README.md",
    "bundle.md",
    "sales-hold.md",
    "support.md",
    "configuration-baseline.md",
    "hardening-guide.md",
    "secure-development.md",
    "change-management.md",
    "access-control.md",
    "physical-security.md",
    "security-programme.md",
    "supplier-management.md",
    "security-awareness.md",
    "incident-response.md",
    "forensic-readiness.md",
    "attestation-tracking.md",
    "pci/scope.md",
    "pci/data-flow.md",
    "pci/segmentation.md",
    "pci/key-management.md",
    "pci/logging.md",
    "pci/asv-scans.md",
    "pci/penetration-testing.md",
    "pci/requirement-map.md",
    "pci/evidence-index.md",
]

PRINCIPAL_REQUIREMENTS = {str(number) for number in range(1, 13)}

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
    "stripe-sdk",
    "adyen-sdk",
    "sumup-sdk",
    "Pods",
}

# Credential-shaped assignments with a non-empty value. Docs mention names only.
CREDENTIAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)client_secret\s*[:=]\s*[\"'][^\"'\s]{6,}"),
    re.compile(r"(?i)password\s*[:=]\s*[\"'][^\"'\s]{4,}"),
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\-]{12,}"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{8,}"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{8,}"),
    re.compile(
        r"(?i)TIRBASE_[A-Z_]*(SECRET|KEY|PASSWORD|TOKEN)\s*=\s*(?!…)[^\s]{8,}"
    ),
]

DIGIT_RUN = re.compile(r"\d{13,19}")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
STUB = re.compile(r"\b(todo!|unimplemented!)\s*\(")
AGPL_CRATES = ["tirbase-pos", "tirbase-core", "tirbase-drivers", "tirbase-gateway"]

ARTIFACT_PREFIXES = ("docs/", "pci/", "config/", "catalog/", "bundles/")
ARTIFACT_STATES = {
    "prepared",
    "reviewed",
    "accepted",
    "pending",
    "not_applicable",
    "missing",
}


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


def load(relative: str):
    return tomllib.loads((CLOSED / relative).read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="run the closed test suite")
    args = parser.parse_args()

    problems = []
    if not CLOSED.is_dir():
        print("closed POS bundle tree absent; nothing to check (open repo is clean)")
        return 0

    ignored = run(["git", "check-ignore", "-q", "closed/pos-bundle/Cargo.toml"])
    if ignored.returncode != 0:
        problems.append("closed/pos-bundle is not git-ignored; refusing to proceed")

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
    for relative in REQUIRED_DATA:
        if not (CLOSED / relative).is_file():
            problems.append(f"missing data file {relative}")
    for doc in REQUIRED_DOCS:
        if not (CLOSED / "docs" / doc).is_file():
            problems.append(f"missing product document docs/{doc}")

    if problems:
        # The remaining checks need the files to exist.
        for problem in problems:
            print(f"FAIL {problem}")
        return 1

    # --- PCI requirement coverage -----------------------------------------
    evidence = load("pci/evidence-index.toml")
    artifacts = {row["id"]: row for row in evidence.get("artifacts", [])}
    if len(artifacts) != len(evidence.get("artifacts", [])):
        problems.append("duplicate artifact id in pci/evidence-index.toml")

    for artifact_id, row in artifacts.items():
        path = row.get("path", "")
        if not path.startswith(ARTIFACT_PREFIXES):
            problems.append(f"{artifact_id}: path is outside the allowed tree")
        if not (CLOSED / path).is_file():
            problems.append(f"{artifact_id}: evidence file {path} does not exist")
        status = row.get("status")
        if status not in ARTIFACT_STATES:
            problems.append(f"{artifact_id}: unknown status {status!r}")
        if status == "accepted":
            if not row.get("accepted_by"):
                problems.append(f"{artifact_id}: accepted without an assessor")
            if not SHA256.match(row.get("evidence_sha256", "")):
                problems.append(f"{artifact_id}: accepted without a SHA-256")
        if status == "not_applicable" and not row.get("note"):
            problems.append(f"{artifact_id}: not_applicable without a justification")

    requirements = load("pci/requirements.toml")
    rows = requirements.get("requirements", [])
    ids = {row["id"] for row in rows}
    if ids != PRINCIPAL_REQUIREMENTS:
        problems.append(
            "requirements must be exactly the twelve principal ids; got "
            + ", ".join(sorted(ids))
        )
    for row in rows:
        named = row.get("artifacts", [])
        if not named:
            problems.append(f"requirement {row['id']} maps to no artifact")
        for artifact_id in named:
            if artifact_id not in artifacts:
                problems.append(
                    f"requirement {row['id']} names unknown artifact {artifact_id}"
                )

    mapped = {artifact for row in rows for artifact in row.get("artifacts", [])}
    if not mapped & {"EV-ASV", "EV-ASV-REGISTER", "EV-PENTEST"}:
        problems.append("requirement 11 does not name the ASV/penetration evidence")

    # --- Device catalog -----------------------------------------------------
    catalog = load("catalog/devices.toml")
    devices = {row["id"]: row for row in catalog.get("devices", [])}
    if not devices:
        problems.append("catalog contains no device row")
    if len(devices) != len(catalog.get("devices", [])):
        problems.append("duplicate device id in catalog/devices.toml")

    certified = []
    for device_id, row in devices.items():
        state = row.get("certification_state")
        cert_id = row.get("certification_id", "")
        if state in {"certified", "withdrawn"}:
            if not cert_id:
                problems.append(f"{device_id}: {state} without an approval identifier")
            if not row.get("approval_body"):
                problems.append(f"{device_id}: {state} without an approval body")
            if not row.get("approval_on"):
                problems.append(f"{device_id}: {state} without an approval date")
            if state == "certified":
                certified.append(device_id)
        elif cert_id:
            problems.append(
                f"{device_id}: records approval id {cert_id!r} while {state}"
            )
        for version in row.get("firmware", []):
            if any(character in version for character in "*xX^~<>=, ") or not version:
                problems.append(f"{device_id}: firmware {version!r} is not an exact version")
        if not row.get("firmware"):
            problems.append(f"{device_id}: no firmware listed")
        if not row.get("countries"):
            problems.append(f"{device_id}: no sale country listed")
        for country in row.get("countries", []):
            if not re.fullmatch(r"[A-Z]{2}", country):
                problems.append(f"{device_id}: invalid country {country!r}")

    # --- Bundle -------------------------------------------------------------
    bundle = load("bundles/retail-bundle.toml")
    for line in bundle.get("devices", []):
        device = devices.get(line.get("device_id", ""))
        if device is None:
            problems.append(f"bundle names unknown device {line.get('device_id')}")
            continue
        if line.get("firmware") not in device.get("firmware", []):
            problems.append(
                f"{device['id']}: bundle pins unapproved firmware {line.get('firmware')!r}"
            )
        if line.get("quantity", 0) < 1:
            problems.append(f"{device['id']}: bundle quantity is zero")
    for country in bundle.get("countries", []):
        for device_id, device in devices.items():
            if country not in device.get("countries", []):
                problems.append(f"{device_id}: not approved for bundle country {country}")
    for document in bundle.get("documentation", []):
        if not (CLOSED / document).is_file():
            problems.append(f"bundle ships missing document {document}")
    if set(bundle.get("required_attestation_kinds", [])) < {"aoc", "asv_scan"}:
        problems.append("bundle does not require both the AOC and ASV attestations")

    # --- Attestations -------------------------------------------------------
    book = load("catalog/attestations.toml")
    seen = set()
    verified = 0
    pending = 0
    for row in book.get("attestations", []):
        attestation_id = row.get("id", "")
        if attestation_id in seen:
            problems.append(f"duplicate attestation id {attestation_id}")
        seen.add(attestation_id)
        subject = row.get("subject", "")
        prefix, _, subject_id = subject.partition(":")
        if prefix == "bundle":
            if subject_id != bundle.get("id"):
                problems.append(f"{attestation_id}: unknown bundle subject {subject!r}")
        elif prefix == "device":
            if subject_id not in devices:
                problems.append(f"{attestation_id}: unknown device subject {subject!r}")
        else:
            problems.append(f"{attestation_id}: malformed subject {subject!r}")
        if row.get("issued_on", "") >= row.get("expires_on", ""):
            problems.append(f"{attestation_id}: expiry is not after issue")
        status = row.get("status")
        if status == "verified":
            verified += 1
            if not row.get("signatory"):
                problems.append(f"{attestation_id}: verified without a signatory")
            if not SHA256.match(row.get("evidence_sha256", "")):
                problems.append(f"{attestation_id}: verified without a SHA-256")
            if not row.get("evidence_path"):
                problems.append(f"{attestation_id}: verified without an evidence path")
        elif status in {"pending", "withdrawn"}:
            if status == "pending":
                pending += 1
            if row.get("evidence_sha256"):
                problems.append(
                    f"{attestation_id}: {status} record carries an evidence hash"
                )
            if row.get("signatory"):
                problems.append(f"{attestation_id}: {status} record carries a signatory")
        else:
            problems.append(f"{attestation_id}: unknown status {status!r}")

    if not certified and verified:
        problems.append("verified attestation exists while no device is certified")
    if certified and not verified:
        problems.append("certified device exists without a verified attestation")
    if pending == 0 and not certified:
        problems.append("no certified device and no pending attestation: state is unclear")

    # --- Reviewed release state --------------------------------------------
    release = load("release-manifest.toml")
    expected_hold = not certified or pending > 0
    sales_status = release.get("sales_status")
    if expected_hold and sales_status != "hold":
        problems.append(
            "release manifest says saleable while the catalog or attestations are incomplete"
        )
    if expected_hold:
        if release.get("signed_off") is not False:
            problems.append("release signed off while the bundle is not saleable")
        if release.get("certificate_id"):
            problems.append("certificate id set without verified evidence")
        if not release.get("sales_hold_reasons"):
            problems.append("sales hold has no recorded reason")
    elif sales_status != "saleable":
        problems.append("all evidence is current but the release manifest is still on hold")
    if not release.get("reviewed_by"):
        problems.append("release manifest has no reviewer")

    if not (CLOSED / release.get("bundle_manifest", "")).is_file():
        problems.append("release manifest points at a missing bundle manifest")
    if not (CLOSED / release.get("evidence_index", "")).is_file():
        problems.append("release manifest points at a missing evidence index")

    # --- Tree hygiene -------------------------------------------------------
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
    print(f"documents: {len(REQUIRED_DOCS)}")
    print(
        f"evidence: {len(artifacts)} artifacts, "
        f"{sum(1 for row in artifacts.values() if row.get('status') == 'pending')} pending"
    )
    print(f"devices: {len(devices)} rows, {len(certified)} certified")
    print(f"attestations: verified={verified}, pending={pending}")

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1

    print("PASS every PCI requirement maps to an indexed artifact whose file exists")
    print("PASS no uncertified device carries an approval id; strict firmware and countries")
    print("PASS pending attestations carry no signature or hash; release is a reviewed hold")
    print("PASS no tracked closed source, vendor SDK, credential, stub or PAN shape")

    if args.test:
        result = subprocess.run(
            ["cargo", "test", "--workspace", "--no-fail-fast"],
            cwd=str(CLOSED),
            text=True,
        )
        if result.returncode != 0:
            print("FAIL closed POS bundle tests")
            return 1
        print("PASS closed POS bundle tests")

        status = subprocess.run(
            [
                "cargo",
                "run",
                "--quiet",
                "--bin",
                "pos-bundle",
                "--",
                "status",
                "--root",
                ".",
                "--as-of",
                release.get("as_of", ""),
            ],
            cwd=str(CLOSED),
            capture_output=True,
            text=True,
        )
        if status.returncode != 0:
            print("FAIL pos-bundle status did not run")
            print(status.stderr.strip())
            return 1
        if "sales state: HOLD" not in status.stdout:
            print("FAIL release is marked on hold but the computed gate is not HOLD")
            print(status.stdout.strip())
            return 1
        print("PASS computed gate agrees with the reviewed hold")

    return 0


if __name__ == "__main__":
    sys.exit(main())
