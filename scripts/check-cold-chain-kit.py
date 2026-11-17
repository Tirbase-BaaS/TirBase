#!/usr/bin/env python3
"""Cold-chain commercial kit gate (CC-23).

Verifies that the proprietary kit is deliverable without exposing source or secrets and
that every control has an evidence link or an explicit gap.

Checks:
  * required layout and the proprietary licence notice;
  * CSV schema integrity (exact headers, no ragged rows);
  * every control row resolves to an existing evidence file, an existing gap, or a
    same-kit checklist anchor;
  * every referenced gap id exists; every sensor row has a certificate reference or a gap;
  * the calibration uncertainty budget recomputes and stays below the acceptance limits;
  * no source code, binaries, symlinks, keys, tokens or environment files in the kit;
  * review state in manifest.json: a release archive requires approved counsel and
    accredited-assessor records with a reviewer and date.

Usage:
    python3 scripts/check-cold-chain-kit.py [--release]
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = ROOT / "commercial" / "cold-chain-kit"

REQUIRED = [
    "LICENSE",
    "README.md",
    "EXCLUSIONS.md",
    "manifest.json",
    "audit-kit/control-to-evidence.csv",
    "audit-kit/gaps.csv",
    "audit-kit/SOP-01-temperature-monitoring.md",
    "audit-kit/SOP-02-excursion-and-disposition.md",
    "audit-kit/SOP-03-calibration-and-verification.md",
    "audit-kit/SOP-04-alarm-response.md",
    "audit-kit/SOP-05-data-integrity-and-records.md",
    "audit-kit/checklists.md",
    "audit-kit/retention-guidance.md",
    "iec62443/SL2-SL3-dossier.md",
    "iec62443/zones.csv",
    "iec62443/conduits.csv",
    "iec62443/requirements.csv",
    "cra/technical-file.md",
    "cra/risks.csv",
    "sensors/certified-sensor-list.csv",
    "calibration/procedure.md",
    "calibration/uncertainty-budget.csv",
    "calibration/acceptance-criteria.csv",
    "licensing/OEM-LICENCE-TEMPLATE.md",
    "licensing/24x7-SLA-TEMPLATE.md",
    "review/counsel-review-record.md",
    "review/assessor-review-record.md",
    "review/review-log.md",
]

HEADERS = {
    "audit-kit/control-to-evidence.csv": [
        "control_id",
        "framework",
        "requirement",
        "control",
        "evidence",
        "owner",
        "status",
    ],
    "audit-kit/gaps.csv": [
        "gap_id",
        "description",
        "why_it_is_not_closed",
        "interim_control",
        "owner",
        "target",
        "severity",
    ],
    "iec62443/zones.csv": [
        "zone_id",
        "zone_name",
        "assets",
        "sl_target",
        "trust_boundary",
        "notes",
    ],
    "iec62443/conduits.csv": [
        "conduit_id",
        "from_zone",
        "to_zone",
        "protocol",
        "authentication",
        "integrity",
        "confidentiality",
        "requirement_ids",
    ],
    "iec62443/requirements.csv": [
        "requirement_id",
        "standard",
        "fr",
        "requirement_summary",
        "sl2",
        "sl3",
        "status",
        "evidence",
        "gap_id",
        "notes",
    ],
    "cra/risks.csv": [
        "risk_id",
        "threat",
        "affected_asset",
        "likelihood",
        "impact",
        "mitigation",
        "residual_risk",
        "maps_to",
    ],
    "sensors/certified-sensor-list.csv": [
        "device_class",
        "vendor_model",
        "transport",
        "supported_firmware_range",
        "kit_reference_implementation",
        "certificate_reference",
        "status",
        "notes",
    ],
    "calibration/uncertainty-budget.csv": [
        "component",
        "type",
        "value_c",
        "distribution",
        "divisor",
        "standard_uncertainty_c",
        "notes",
    ],
    "calibration/acceptance-criteria.csv": [
        "transport",
        "acceptance_limit_c",
        "expanded_uncertainty_c",
        "pass",
        "notes",
    ],
}

ALLOWED_SUFFIXES = {".md", ".csv", ".json", ".txt"}
ALLOWED_NAMES = {"LICENSE", "SHA256SUMS"}
CODE_SUFFIXES = {
    ".rs", ".py", ".js", ".mjs", ".ts", ".sh", ".bash", ".wasm", ".so", ".dylib",
    ".dll", ".exe", ".bin", ".o", ".a", ".class", ".jar", ".pem", ".key", ".p12",
}
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{10,}\b"), "API secret key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "GitHub token"),
    (re.compile(r"(?i)\b(password|passwd|api[_-]?key|secret)\s*=\s*['\"][^'\"]{8,}"), "inline credential"),
]


def resolve_evidence(kit: Path, reference: str) -> bool:
    reference = reference.strip()
    if not reference:
        return False
    if reference.startswith("GAP-"):
        return True  # existence is checked against the gap register separately
    if "#" in reference:
        reference = reference.split("#", 1)[0]
    candidates = [ROOT / reference, kit / reference, kit / "audit-kit" / reference]
    return any(candidate.is_file() for candidate in candidates)


def read_csv(kit: Path, relative: str, errors: list[str]) -> list[dict[str, str]]:
    path = kit / relative
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        expected = HEADERS[relative]
        if reader.fieldnames != expected:
            errors.append(f"{relative}: header {reader.fieldnames} != expected {expected}")
            return []
        rows: list[dict[str, str]] = []
        for line, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                errors.append(f"{relative}:{line}: ragged row (check unquoted commas)")
                continue
            rows.append(row)
        return rows


def check_purity(kit: Path, errors: list[str]) -> int:
    files = 0
    for path in sorted(kit.rglob("*")):
        if path.is_symlink():
            errors.append(f"{path.relative_to(kit)}: symlink in kit")
            continue
        if path.is_dir():
            continue
        files += 1
        relative = path.relative_to(kit)
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


def check_kits(errors: list[str]) -> dict[str, int]:
    controls = read_csv(KIT, "audit-kit/control-to-evidence.csv", errors)
    gaps = read_csv(KIT, "audit-kit/gaps.csv", errors)
    requirements = read_csv(KIT, "iec62443/requirements.csv", errors)
    risks = read_csv(KIT, "cra/risks.csv", errors)
    sensors = read_csv(KIT, "sensors/certified-sensor-list.csv", errors)
    budget = read_csv(KIT, "calibration/uncertainty-budget.csv", errors)
    acceptance = read_csv(KIT, "calibration/acceptance-criteria.csv", errors)
    read_csv(KIT, "iec62443/zones.csv", errors)
    read_csv(KIT, "iec62443/conduits.csv", errors)

    gap_ids = {row["gap_id"] for row in gaps}
    for row in controls:
        reference = row["evidence"].strip()
        if not reference:
            errors.append(f"{row['control_id']}: empty evidence")
            continue
        for item in reference.split(";"):
            item = item.strip()
            if not item:
                continue
            if item.startswith("GAP-") and item not in gap_ids:
                errors.append(f"{row['control_id']}: unknown gap {item}")
            elif not item.startswith("GAP-") and not resolve_evidence(KIT, item):
                errors.append(f"{row['control_id']}: evidence does not resolve: {item}")

    statuses = {"met", "partial", "gap", "not-required"}
    for row in requirements:
        if row["status"] not in statuses:
            errors.append(f"{row['requirement_id']}: status {row['status']!r}")
        if row["status"] in {"met", "partial"} and not row["evidence"].strip():
            errors.append(f"{row['requirement_id']}: {row['status']} without evidence")
        for item in row["evidence"].split(";"):
            item = item.strip()
            if item and not resolve_evidence(KIT, item):
                errors.append(f"{row['requirement_id']}: evidence does not resolve: {item}")
        if row["gap_id"].strip() and row["gap_id"].strip() not in gap_ids:
            errors.append(f"{row['requirement_id']}: unknown gap {row['gap_id']}")

    for row in sensors:
        certificate = row["certificate_reference"].strip()
        if not certificate:
            errors.append(f"{row['device_class']}: no certificate reference or gap")
        elif certificate.startswith("GAP-") and certificate not in gap_ids:
            errors.append(f"{row['device_class']}: unknown gap {certificate}")

    for row in risks:
        if not row["maps_to"].strip():
            errors.append(f"{row['risk_id']}: no control mapping")

    combined = math.sqrt(
        sum(float(row["standard_uncertainty_c"]) ** 2 for row in budget)
    )
    expanded = round(2 * combined, 3)
    limits = [float(row["acceptance_limit_c"]) for row in acceptance]
    if not limits:
        errors.append("calibration/acceptance-criteria.csv: no acceptance limits")
    elif expanded > min(limits):
        errors.append(f"uncertainty budget expanded {expanded} exceeds acceptance {min(limits)}")
    for row in acceptance:
        if row["pass"].strip().lower() == "true" and expanded > float(row["acceptance_limit_c"]):
            errors.append(f"{row['transport']}: budget {expanded} > limit {row['acceptance_limit_c']}")

    return {
        "controls": len(controls),
        "gaps": len(gaps),
        "requirements": len(requirements),
        "risks": len(risks),
        "sensors": len(sensors),
        "expanded_uncertainty_c": expanded,
    }


def check_reviews(release: bool, errors: list[str]) -> dict:
    manifest = json.loads((KIT / "manifest.json").read_text(encoding="utf-8"))
    reviews = manifest.get("reviews", {})
    for name in ("counsel", "assessor"):
        record = reviews.get(name, {})
        if record.get("status") not in {"pending", "approved", "rejected"}:
            errors.append(f"manifest reviews.{name}.status invalid")
        if record.get("status") == "approved":
            if not record.get("reviewer") or not record.get("date"):
                errors.append(f"reviews.{name} approved without reviewer and date")
        if release and record.get("status") != "approved":
            errors.append(
                f"reviews.{name} is {record.get('status')!r}: a release archive needs approval"
            )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release",
        action="store_true",
        help="require approved counsel and assessor reviews (release archive)",
    )
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

    counts = check_kits(errors)
    files = check_purity(KIT, errors)
    manifest = check_reviews(args.release, errors)

    if errors:
        print(f"FAIL: {len(errors)} problem(s) in the cold-chain kit", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        "OK: cold-chain kit is deliverable "
        f"({counts['controls']} controls, {counts['gaps']} gaps, "
        f"{counts['requirements']} IEC requirements, {counts['risks']} risks, "
        f"{counts['sensors']} device classes, {files} files, "
        f"expanded uncertainty {counts['expanded_uncertainty_c']} C)"
    )
    if args.release:
        print("OK: counsel and assessor reviews are approved")
    else:
        print(
            "DRAFT: counsel and assessor reviews are "
            f"{manifest['reviews']['counsel']['status']} / "
            f"{manifest['reviews']['assessor']['status']}; release archive is blocked"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
