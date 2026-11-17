# SOP-05 — Data integrity, records and audit trail

**Owner:** Quality. **Reference:** `retention-guidance.md`, `docs/reporting.md`,
`docs/auditor-guide.md`.

## 1. Principles (ALCOA+)

Records must be attributable, legible, contemporaneous, original, accurate, complete,
consistent, enduring and available. The runtime enforces this by design; this SOP defines
the operator's duties.

| Attribute | Operator duty |
| --- | --- |
| Attributable | Named accounts only; no shared logins; e-signature reasons recorded |
| Legible | Exports rendered from stored records, not retyped |
| Contemporaneous | Clocks synchronised; no back-dating; corrections by new record |
| Original | Source readings and ledger entries retained, not summarised-only |
| Accurate | Calibration valid; drift checked; corrections traceable |
| Complete | No deleted excursions or gaps; outages recorded |
| Consistent | Unique ids; no duplicate lots; sequence continuity verified |
| Enduring | Retention per guidance; backups verified by restore test |
| Available | Audit export produced on request; access controlled |

## 2. Record types and custody

1. **Primary records:** readings, excursion records, calibration records, ledger entries.
   These are append-only; corrections are new records that reference the original.
2. **Exports:** signed report exports with a manifest. Verify the signature and digest on
   receipt; keep the manifest with the export.
3. **Audit chain:** never pruned. Verify the chain after restore, after an upgrade and at
   each internal audit. Record the verification result.

## 3. Access and changes

1. Grant the minimum role required. Review access quarterly and on leaver events.
2. Configuration changes require the change-control checklist, a named approver and a
   rollback plan.
3. Administrative actions are logged and reviewed monthly.

## 4. Backup and restore

1. Back up the gateway database and the evidence exports on the site's schedule.
2. Test a restore at least quarterly on non-production hardware. A backup is only proven
   when a restore has been verified.
3. After any restore, run the audit-chain verification and record the outcome.

## 5. Audit support

Provide auditors with: the control-to-evidence map, the relevant SOPs, the retention
policy, exports for the audit period, and verification results for the chain and
signatures. Do not provide source code or secrets; provide rendered evidence.
