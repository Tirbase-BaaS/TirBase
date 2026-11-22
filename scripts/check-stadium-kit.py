#!/usr/bin/env python3
"""Stadium commercial kit gate (ST-16).

Verifies the proprietary kit is deliverable: no source, secrets or customer data;
every hazard has an owner, a mitigation and resolvable evidence; every hazard is
covered by a safety requirement; the authority, integrator, managed-operations and
hardware parts are complete and usable without source access.

A draft passes the default check. ``--release`` additionally requires an approved
independent safety review and an approved counsel review, with reviewer, date and
no open findings.

Usage:
    python3 scripts/check-stadium-kit.py [--release]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIT = ROOT / "commercial" / "stadium-kit"

REQUIRED = [
    "LICENSE",
    "README.md",
    "EXCLUSIONS.md",
    "manifest.json",
    "safety/hazard-log.csv",
    "safety/risk-assessment.md",
    "safety/safety-requirements.md",
    "safety/evidence-index.md",
    "safety/gate-failure-modes.md",
    "safety/independent-review-plan.md",
    "safety/safety-case-report.md",
    "insurance/system-description.md",
    "insurance/controls.md",
    "insurance/incident-history.md",
    "insurance/auditability.md",
    "insurance/evidence-index.md",
    "authority/capacity-report-template.md",
    "authority/incident-report-template.md",
    "authority/lockdown-report-template.md",
    "integrator/training.md",
    "integrator/exam.md",
    "integrator/badge.md",
    "integrator/badge-registry.csv",
    "integrator/recertification.md",
    "integrator/commissioning-checklist.md",
    "managed-ops/monitoring.md",
    "managed-ops/on-call.md",
    "managed-ops/incident-command.md",
    "managed-ops/change-management.md",
    "managed-ops/sla.md",
    "hardware/certified-controllers.md",
    "hardware/readers.md",
    "hardware/spares.md",
    "hardware/firmware-support.md",
    "hardware/eol-policy.md",
    "hardware/bom-template.csv",
    "review/safety-review-record.md",
    "review/counsel-review-record.md",
    "review/review-log.md",
]

ALLOWED_SUFFIXES = {".md", ".csv", ".json", ".txt"}
ALLOWED_NAMES = {"LICENSE"}
CODE_SUFFIXES = {
    ".rs", ".py", ".js", ".mjs", ".ts", ".sh", ".bash", ".wasm", ".so", ".dylib",
    ".dll", ".exe", ".bin", ".o", ".a", ".class", ".jar", ".pem", ".key", ".p12",
    ".jpg", ".jpeg", ".png", ".mp4", ".pdf",
}
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{10,}\b"), "API secret key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "GitHub token"),
    (re.compile(r"(?i)\b(password|passwd|api[_-]?key|secret)\s*=\s*['\"][^'\"]{8,}"), "inline credential"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"), "customer email address"),
]

HAZARD_COLUMNS = [
    "hazard_id", "area", "hazard", "cause", "effect", "severity", "likelihood",
    "risk_score", "owner", "mitigation", "mitigation_ref", "evidence_ref",
    "residual_severity", "residual_likelihood", "residual_risk", "status",
]
HAZARD_STATUS = {"open", "mitigated", "accepted", "closed"}
REVIEW_KEYS = ("independent_safety_review", "counsel_review")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def check_purity(errors: list[str]) -> int:
    files = 0
    for path in sorted(KIT.rglob("*")):
        if "dist" in path.relative_to(KIT).parts:
            continue
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
            errors.append(f"{relative}: source/binary/media file in kit")
        if path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            errors.append(f"{relative}: executable bit set")
        text = read(path)
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"{relative}: possible {label}")
    return files


def resolves(reference: str) -> bool:
    reference = reference.split("#", 1)[0].strip()
    if not reference:
        return False
    return (KIT / reference).is_file() or (ROOT / reference).is_file()


def check_hazards(errors: list[str], requirements: str, failure_modes: str) -> dict:
    path = KIT / "safety" / "hazard-log.csv"
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    if not rows:
        errors.append("hazard-log.csv: no hazards")
        return {}
    header = list(rows[0].keys())
    if header != HAZARD_COLUMNS:
        errors.append(f"hazard-log.csv: header mismatch; expected {','.join(HAZARD_COLUMNS)}")

    hazard_ids: set[str] = set()
    for line, row in enumerate(rows, start=2):
        hazard_id = (row.get("hazard_id") or "").strip()
        if not re.fullmatch(r"H-\d{2}", hazard_id):
            errors.append(f"hazard-log.csv:{line}: invalid hazard id {hazard_id!r}")
            continue
        if hazard_id in hazard_ids:
            errors.append(f"hazard-log.csv:{line}: duplicate hazard id {hazard_id}")
        hazard_ids.add(hazard_id)
        for field in ("area", "hazard", "cause", "effect", "owner", "mitigation", "mitigation_ref"):
            if not (row.get(field) or "").strip():
                errors.append(f"hazard-log.csv:{line}: {hazard_id} has no {field}")
        try:
            severity = int(row["severity"])
            likelihood = int(row["likelihood"])
            risk = int(row["risk_score"])
            residual = int(row["residual_risk"])
            residual_severity = int(row["residual_severity"])
            residual_likelihood = int(row["residual_likelihood"])
        except (KeyError, TypeError, ValueError):
            errors.append(f"hazard-log.csv:{line}: {hazard_id} has a non-numeric risk field")
            continue
        for value in (severity, likelihood, residual_severity, residual_likelihood):
            if not 1 <= value <= 5:
                errors.append(f"hazard-log.csv:{line}: {hazard_id} score outside 1..5")
        if risk != severity * likelihood:
            errors.append(f"hazard-log.csv:{line}: {hazard_id} risk_score is not severity × likelihood")
        if residual != residual_severity * residual_likelihood:
            errors.append(f"hazard-log.csv:{line}: {hazard_id} residual_risk is not severity × likelihood")
        if residual > severity * likelihood:
            errors.append(f"hazard-log.csv:{line}: {hazard_id} residual risk exceeds the unmitigated risk")
        if (row.get("status") or "") not in HAZARD_STATUS:
            errors.append(f"hazard-log.csv:{line}: {hazard_id} has an invalid status")
        if not resolves(row.get("evidence_ref") or ""):
            errors.append(
                f"hazard-log.csv:{line}: {hazard_id} evidence_ref does not resolve: {row.get('evidence_ref')!r}"
            )
        for reference in re.findall(r"SR-\d{2}", row.get("mitigation_ref") or ""):
            if f"| {reference} |" not in requirements:
                errors.append(f"hazard-log.csv:{line}: {hazard_id} cites unknown {reference}")
        if hazard_id not in requirements:
            errors.append(f"safety-requirements.md: {hazard_id} is not covered by any requirement")
        if hazard_id not in failure_modes:
            errors.append(f"safety/gate-failure-modes.md: {hazard_id} is not addressed")

    for reference in sorted(set(re.findall(r"H-\d{2}", failure_modes))):
        if reference not in hazard_ids:
            errors.append(f"safety/gate-failure-modes.md cites unknown hazard {reference}")
    return {"hazards": len(hazard_ids)}


def check_parts(errors: list[str], requirements: str) -> None:
    checklist = read(KIT / "integrator" / "commissioning-checklist.md")
    if checklist.count("- [ ]") < 20:
        errors.append("commissioning-checklist.md: too few verifiable checks")
    for reference in sorted(set(re.findall(r"SR-\d{2}", checklist))):
        if f"| {reference} |" not in requirements:
            errors.append(f"commissioning-checklist.md cites unknown {reference}")
    if "| Signature |" not in checklist:
        errors.append("commissioning-checklist.md: no signature block")

    for name in ("capacity", "incident", "lockdown"):
        template = read(KIT / "authority" / f"{name}-report-template.md")
        if "- [ ]" not in template and "| Field | Entry |" not in template:
            errors.append(f"authority/{name}-report-template.md: no completion fields")
        if "| Signature |" not in template:
            errors.append(f"authority/{name}-report-template.md: no signature block")

    exam = read(KIT / "integrator" / "exam.md")
    if "80%" not in exam or "pass mark" not in exam.lower():
        errors.append("integrator/exam.md: no pass mark")
    training = read(KIT / "integrator" / "training.md")
    if training.count("| ") < 10 or "Practical requirements" not in training:
        errors.append("integrator/training.md: modules or practical requirements incomplete")
    badge = read(KIT / "integrator" / "badge.md")
    for state in ("active", "suspended", "expired", "revoked"):
        if state not in badge:
            errors.append(f"integrator/badge.md: registry state {state} missing")
    recert = read(KIT / "integrator" / "recertification.md")
    if "24 months" not in recert:
        errors.append("integrator/recertification.md: no 24-month cycle")
    registry = read(KIT / "integrator" / "badge-registry.csv")
    if "badge_id,holder,organisation,level,issued_est,expires_est,exam_score,status" not in registry:
        errors.append("integrator/badge-registry.csv: header mismatch")

    for name in ("monitoring", "on-call", "incident-command", "change-management", "sla"):
        if len(read(KIT / "managed-ops" / f"{name}.md")) < 800:
            errors.append(f"managed-ops/{name}.md: too thin to operate from")
    sla = read(KIT / "managed-ops" / "sla.md")
    for severity in ("S1", "S2", "S3", "S4"):
        if severity not in sla:
            errors.append(f"managed-ops/sla.md: no {severity} target")

    controllers = read(KIT / "hardware" / "certified-controllers.md")
    if "pending" not in controllers:
        errors.append("hardware/certified-controllers.md: certification state missing")
    firmware = read(KIT / "hardware" / "firmware-support.md")
    if "24 months" not in firmware or "EOL" not in firmware:
        errors.append("hardware/firmware-support.md: support window or EOL missing")
    eol = read(KIT / "hardware" / "eol-policy.md")
    if "12 months" not in eol:
        errors.append("hardware/eol-policy.md: no notice/deviation window")
    bom = read(KIT / "hardware" / "bom-template.csv")
    if "support_status" not in bom:
        errors.append("hardware/bom-template.csv: no support status column")

    incident = read(KIT / "insurance" / "incident-history.md")
    if "No production incidents are recorded" not in incident:
        errors.append("insurance/incident-history.md: must state the honest pilot history")
    audit = read(KIT / "insurance" / "auditability.md")
    if "Append-only" not in audit:
        errors.append("insurance/auditability.md: no append-only statement")

    safety_case = read(KIT / "safety" / "safety-case-report.md")
    if "Not an approved safety case" not in safety_case:
        errors.append("safety/safety-case-report.md: must state it is not an approved safety case")
    plan = read(KIT / "safety" / "independent-review-plan.md")
    if "Not yet reviewed" not in plan:
        errors.append("safety/independent-review-plan.md: must state the review is outstanding")


def check_manifest(release: bool, errors: list[str]) -> dict:
    manifest = json.loads(read(KIT / "manifest.json"))
    if manifest.get("licence") != "proprietary":
        errors.append("manifest: licence must be proprietary")
    for key in ("contains_source", "contains_secrets", "contains_customer_data"):
        if manifest.get(key) is not False:
            errors.append(f"manifest: {key} must be false")
    if manifest.get("usable_without_source") is not True:
        errors.append("manifest: usable_without_source must be true")

    reviews = manifest.get("reviews", {})
    for key in REVIEW_KEYS:
        record = reviews.get(key, {})
        status = record.get("status")
        if status not in {"pending", "approved", "rejected"}:
            errors.append(f"manifest: reviews.{key}.status invalid")
            continue
        if status == "approved":
            for field in ("reviewer", "organisation", "date"):
                if not record.get(field):
                    errors.append(f"manifest: approved {key} needs {field}")
            if int(record.get("findings_open", 0) or 0) != 0:
                errors.append(f"manifest: approved {key} has open findings")
            record_path = KIT / record.get("record", "")
            if record_path.is_file() and "NOT REVIEWED" in read(record_path):
                errors.append(f"manifest: {key} approved but its record is unsigned")
        if release and status != "approved":
            errors.append(f"manifest: a release requires approved {key}")

    statuses = {reviews.get(key, {}).get("status") for key in REVIEW_KEYS}
    if statuses != {"approved"} and manifest.get("status") != "draft":
        errors.append("manifest: status must be draft while a review is not approved")
    if statuses != {"approved"} and "DRAFT" not in read(KIT / "README.md"):
        errors.append("README.md: draft must be marked DRAFT")
    return manifest


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
    if "proprietary" not in read(KIT / "LICENSE").lower():
        errors.append("LICENSE: proprietary notice missing")
    if "life-safety" not in read(KIT / "LICENSE").lower():
        errors.append("LICENSE: safety notice missing")

    requirements = read(KIT / "safety" / "safety-requirements.md")
    failure_modes = read(KIT / "safety" / "gate-failure-modes.md")
    files = check_purity(errors)
    stats = check_hazards(errors, requirements, failure_modes)
    check_parts(errors, requirements)
    manifest = check_manifest(args.release, errors)

    if errors:
        print(f"FAIL: {len(errors)} stadium kit problem(s)", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    reviews = manifest["reviews"]
    states = ", ".join(f"{key} {reviews[key]['status']}" for key in REVIEW_KEYS)
    print(
        f"OK: stadium kit is deliverable ({files} files, {stats['hazards']} hazards with "
        f"owner/mitigation/evidence, no source/secrets/customer data; {states})"
    )
    if args.release:
        print("OK: independent safety review and counsel review are approved for release")
    else:
        print("DRAFT: independent safety review and counsel review are outstanding")
    return 0


if __name__ == "__main__":
    sys.exit(main())
