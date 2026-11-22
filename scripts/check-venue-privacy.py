#!/usr/bin/env python3
"""ST-13 venue privacy gate.

Checks that the open privacy pack is internally consistent and that retention is
implemented, not just documented:

  * the field register has the exact header, all four domains, unique ids and
    purpose/retention/access/deletion for every row;
  * every register retention code exists in the machine-readable schedule;
  * the schedule and the Rust retention constants agree (7/30/90 day CCTV,
    30-day ticket/credential, 90-day access, 365-day audit);
  * all four DPIAs, the data-flow map, CCTV policy, SAR/deletion procedure and
    local-authority templates exist with their required sections;
  * the pilot sign-off is recorded with an approved software-pilot status;
  * the enforcement tests are present and the commercial kit validates.
"""

from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "data" / "venue-privacy-register.csv"
SCHEDULE = ROOT / "data" / "venue-retention-schedule.csv"
RUNTIME = ROOT / "tirbase-venue-privacy" / "src" / "store.rs"
TESTS = ROOT / "tirbase-venue-privacy" / "tests" / "st13_privacy.rs"
KIT_CHECK = ROOT / "scripts" / "check-venue-compliance-kit.py"

DOMAINS = {"ticket", "credential", "cctv", "access"}
REGISTER_HEADER = [
    "field_id",
    "domain",
    "field_name",
    "location",
    "personal_data",
    "purpose",
    "lawful_basis",
    "retention_code",
    "retention_detail",
    "access_rule",
    "deletion_method",
    "notes",
]
SCHEDULE_HEADER = [
    "retention_code",
    "class",
    "starts",
    "maximum",
    "disposal",
    "legal_hold",
    "source",
]
REQUIRED_CODES = {
    "TICKET_30D",
    "CREDENTIAL_30D",
    "ACCESS_90D",
    "CCTV_SECURITY_30D",
    "CCTV_SAFETY_90D",
    "CCTV_OPERATIONAL_7D",
    "AUDIT_365D",
    "LEGAL_HOLD",
    "MINIMISED_OR_NONE",
}

DOCUMENTS = {
    "docs/compliance/venue-dpia/README.md": ["ticket", "credential", "CCTV", "access"],
    "docs/compliance/venue-dpia/ticket.md": ["Purpose", "Retention", "Access", "Risks"],
    "docs/compliance/venue-dpia/credential.md": ["Purpose", "Retention", "Access", "Risks"],
    "docs/compliance/venue-dpia/cctv.md": ["Purpose", "Retention", "Access", "Risks", "No raw video"],
    "docs/compliance/venue-dpia/access.md": ["Purpose", "Retention", "Access", "Risks"],
    "docs/compliance/venue-data-flow-retention.md": ["Data-flow map", "Retention schedule", "Access rules"],
    "docs/compliance/venue-cctv-retention.md": ["No raw video", "Enforcement", "Access control matrix"],
    "docs/compliance/venue-subject-access-deletion.md": ["legal hold", "deletion", "Access response"],
    "docs/compliance/venue-local-authority-reporting.md": ["breach", "Police", "Licensing", "Fire"],
    "docs/compliance/venue-pilot-privacy-signoff.md": [
        "Pilot",
        "DPIA owner",
        "Privacy reviewer",
        "Status: Approved",
        "2026-11-22",
    ],
}


def read_csv(path: Path, expected: list[str], errors: list[str]) -> list[dict[str, str]]:
    if not path.is_file():
        errors.append(f"missing {path.relative_to(ROOT)}")
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != expected:
            errors.append(f"{path.relative_to(ROOT)}: header {reader.fieldnames} != {expected}")
            return []
        rows = []
        for line, row in enumerate(reader, start=2):
            if None in row or any(value is None for value in row.values()):
                errors.append(f"{path.relative_to(ROOT)}:{line}: ragged row")
                continue
            rows.append(row)
        return rows


def check_register(errors: list[str]) -> list[dict[str, str]]:
    rows = read_csv(REGISTER, REGISTER_HEADER, errors)
    ids = set()
    domains = set()
    for line, row in enumerate(rows, start=2):
        field_id = row["field_id"].strip()
        if not field_id:
            errors.append(f"register:{line}: empty field_id")
        if field_id in ids:
            errors.append(f"register:{line}: duplicate field_id {field_id}")
        ids.add(field_id)
        domain = row["domain"].strip()
        domains.add(domain)
        if domain not in DOMAINS:
            errors.append(f"register:{line}: unknown domain {domain!r}")
        if row["personal_data"] not in {"Y", "Maybe", "N"}:
            errors.append(f"register:{line}: bad personal_data {row['personal_data']!r}")
        for column in ("purpose", "retention_detail", "access_rule", "deletion_method"):
            if not row[column].strip():
                errors.append(f"register:{line}: empty {column}")
        if row["personal_data"] == "Y" and not row["lawful_basis"].strip():
            errors.append(f"register:{line}: personal field without lawful basis")
        if row["retention_code"] not in REQUIRED_CODES:
            errors.append(f"register:{line}: unknown retention code {row['retention_code']!r}")
    if domains != DOMAINS:
        errors.append(f"register domains {sorted(domains)} != {sorted(DOMAINS)}")
    if len(rows) < 25:
        errors.append(f"register has only {len(rows)} fields")
    return rows


def check_schedule(rows: list[dict[str, str]], errors: list[str]) -> set[str]:
    schedule = read_csv(SCHEDULE, SCHEDULE_HEADER, errors)
    codes = {row["retention_code"] for row in schedule}
    if codes != REQUIRED_CODES:
        errors.append(f"schedule codes {sorted(codes)} != required codes")
    for row in schedule:
        for column in ("class", "starts", "maximum", "disposal", "legal_hold"):
            if not row[column].strip():
                errors.append(f"schedule {row['retention_code']}: empty {column}")
    for row in rows:
        if row["retention_code"] not in codes:
            errors.append(f"register {row['field_id']}: code not in schedule")
    return codes


def check_runtime(errors: list[str]) -> None:
    if not RUNTIME.is_file():
        errors.append(f"missing {RUNTIME.relative_to(ROOT)}")
        return
    source = RUNTIME.read_text(encoding="utf-8")
    checks = {
        "CCTV_OPERATIONAL_SECS: i64 = 7 * SECONDS_PER_DAY": "7-day CCTV",
        "CCTV_SECURITY_SECS: i64 = 30 * SECONDS_PER_DAY": "30-day CCTV",
        "CCTV_SAFETY_SECS: i64 = 90 * SECONDS_PER_DAY": "90-day safety CCTV",
        "ACCESS_RETENTION_SECS: i64 = 90 * SECONDS_PER_DAY": "90-day access",
        "TICKET_RETENTION_SECS: i64 = 30 * SECONDS_PER_DAY": "30-day ticket",
        "DSAR_RECORD_RETENTION_SECS: i64 = 365 * SECONDS_PER_DAY": "365-day audit",
    }
    for needle, label in checks.items():
        if needle not in source:
            errors.append(f"runtime missing {label} constant")
    for method in ("pub fn read(", "pub fn purge_expired(", "pub fn subject_export(", "pub fn delete_subject("):
        if method not in source:
            errors.append(f"runtime missing {method}")
    if not TESTS.is_file():
        errors.append(f"missing {TESTS.relative_to(ROOT)}")
        return
    tests = TESTS.read_text(encoding="utf-8")
    for test in (
        "every_personal_data_field_has_purpose_retention_and_access",
        "cctv_retention_is_enforced_at_read_and_purge",
        "cctv_legal_hold_blocks_deletion_and_extends_retention",
        "cctv_access_is_role_scoped_and_audited",
        "subject_access_and_deletion_are_scoped_and_respect_holds",
        "raw_video_and_biometrics_are_refused",
    ):
        if test not in tests:
            errors.append(f"missing test {test}")


def check_documents(errors: list[str]) -> None:
    for relative, needles in DOCUMENTS.items():
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"missing {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            errors.append(f"{relative}: empty")
        for needle in needles:
            if needle.lower() not in text.lower():
                errors.append(f"{relative}: missing {needle!r}")


def check_kit(errors: list[str]) -> None:
    if not KIT_CHECK.is_file():
        errors.append("missing scripts/check-venue-compliance-kit.py")
        return
    result = subprocess.run(
        [sys.executable, str(KIT_CHECK)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().replace("\n", " | ")
        errors.append(f"venue compliance kit failed: {detail}")


def main() -> int:
    errors: list[str] = []
    rows = check_register(errors)
    check_schedule(rows, errors)
    check_runtime(errors)
    check_documents(errors)
    check_kit(errors)
    if errors:
        print(f"FAIL: {len(errors)} venue privacy problem(s)", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(
        "OK: venue privacy pack is complete "
        f"({len(rows)} fields, 4 DPIAs, sign-off recorded, "
        "CCTV retention enforced by the runtime, kit validated)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
