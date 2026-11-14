# Auditor Guide (TirBase)

For security/compliance auditors reviewing controls and evidence.

## Evidence sources (in-repo)

- Threat model and invariants: `docs/THREAT_MODEL.md`, `docs/system-invariants.md`, `docs/adversary-scenarios.md`.
- Security programme: `docs/SECURITY_PROGRAM.md`, `SECURITY.md`, `docs/security-findings.md`.
- Compliance aids (non-certifying): `docs/compliance/cra-annex-i-checklist.md`, `docs/compliance/iec62443-gap-analysis.md`, `docs/compliance/vulnerability-handling.md`, `docs/compliance/support-period-policy.md`, DPIA templates and data protection procedures (F-15).
- Audit logs: hash-chained security event log; verification via `tirbase-admin verify-log` (and export tools). See `docs/observability.md`, `docs/security-event-catalog.md`.
- SBOM/VEX/signing/provenance: release workflows and artifacts (`.github/workflows/sbom.yml`, `sign.yml`, `docs/releases/*`).

## What to verify (suggested checklist)

- [ ] Signed profiles/policies in use; deny-all posture when absent (documented behavior).
- [ ] Role separation and M-of-N controls for sensitive operations (lockdown exit, policy loosening paths as designed).
- [ ] Security event chain integrity verification performed on sample exports.
- [ ] Backup/restore tested and documented (`docs/runbooks/restore.md`).
- [ ] Dependency and vulnerability handling processes followed (`docs/compliance/vulnerability-handling.md`, `docs/releases/dependency-review.md`).

## Limitations

- TirBase provides evidence aids, not certifications. CRA/IEC 62443 checklists are internal aids unless separately validated by qualified assessors.
- Physical security, OS hardening, and network segregation are deployment responsibilities.

## Contact

For coordinated disclosure, follow `SECURITY.md`. For audit access arrangements, use the project’s agreed customer engagement process.
