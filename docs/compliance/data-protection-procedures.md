# Data Protection Procedures (F-15)

> Complements DPIA templates (`dpia-templates.md`) and runbooks. This document describes **procedures**; operators must map them to local law (GDPR, sector rules) and customer contracts.

## 1. Principles

- **Purpose limitation:** collect/process only fields documented in the per-field register (§2).
- **Minimization:** avoid free-text PII in command payloads and logs; use IDs and redaction.
- **Integrity of audit chains:** security event logs are hash-chained (PrimaryLedger). Deletion of individual chain entries is **not permitted** without breaking verifiability; use **redaction/pseudonymization** and **legal hold** exceptions as below.
- **Defence in depth:** encryption in transit (mTLS/TLS), optional DB-at-rest encryption (SQLCipher feature) where deployed.

## 2. Per-field register (template — “every personal-data field has a purpose, retention, and access rule”)

For each deployment, maintain a table like:

| Field (logical) | Location (system/table/log) | Personal data? (Y/N/Maybe) | Purpose | Lawful basis (template) | Retention | Access roles | Deletion/redaction method | Notes |
|-----------------|-----------------------------|----------------------------|---------|-------------------------|-----------|--------------|---------------------------|-------|
| operator_display_name | external IAM / ticketing | Y | Support attribution | Contract/legitimate interests | Per org policy | Admin, Support (scoped) | Delete in source system | Not stored on edge by default |
| actor_did | security_log.actor_did | Maybe (pseudonymous) | Audit attribution | Legal obligation/legitimate interests | Matches log retention + legal hold | Auditor, Security | Pseudonymize export (`security_log_export` salted) or retain until hold lifted | Hash chain anchors integrity |
| site_name | vertical_api.cold_chain_sites.name | Maybe | Operations | Contract | Until site deleted or retention policy | Operator roles per API | Soft-delete + purge workflow (documented) | Avoid personal names |
| customer_email (if added) | POS extension (example) | Y | Receipts/loyalty | Consent/contract | e.g. 30 days post-transaction unless tax law requires longer | Restricted | Purge job + legal hold check | **Must** be added to this register before use |

**Rule:** any new field that is or may be personal data MUST be added to this register before deployment/pilot.

## 3. Retention

- **Default operational data:** define per customer (e.g. 90 days hot, archive per policy). Document in deployment runbook.
- **Security event log:** retained to satisfy audit/legal requirements; export and archive per `docs/runbooks/storage-retention-dr.md` patterns. Redacted exports may be produced for long-term retention with less sensitivity.
- **Backups:** follow backup retention schedule; backups containing personal data are in scope for the same deletion requests where technically feasible (document exceptions, e.g. encrypted offline backups under legal hold).

## 4. Data residency

- Document where gateways, databases, backups, and export artifacts are stored (country/region, cloud provider region).
- For mesh/cloud sync, document data flows and any cross-border transfers; record safeguards (contractual, SCCs) in the DPIA record.
- **Configuration:** operators should set deployment location labels in inventory; this repo does not enforce residency automatically except by deployment topology.

## 5. Subject access requests (SAR) / data subject rights

1. **Intake:** log request (ticket ID), identity verification steps (per org policy), scope (which systems/tenants).
2. **Discovery:** identify stores (edge SQLite, exports, backups, external systems). Use tenant scoping and audit logs.
3. **Response:** provide copy/export in a common format where feasible; explain limitations (e.g. hash-chained entries cannot be altered without detection — offer redacted views where appropriate).
4. **Timelines:** follow applicable law (e.g. GDPR one month) and contract SLAs.

## 6. Deletion and erasure

- **Preferred:** soft-delete + scheduled purge jobs for application tables where business rules allow, with verification logs.
- **Hash-chained security logs:** do **not** rewrite history. Options:
  - Stop including new personal data (mitigation going forward).
  - Produce redacted exports for disclosure; retain original under access controls and legal hold rules.
  - If erasure is legally required and no lawful exception applies, document the conflict and seek legal counsel; technical mitigation may be limited to key rotation + redaction of future exports (record decision).
- **Backups:** deletion from backups may require key destruction or documented retention exceptions under legal hold; record in the SAR/deletion log.

## 7. Legal hold

- When a legal hold is active, **suspend** scheduled purges and deletions for in-scope data/accounts.
- Implement via operational flag/checklist in the deployment runbook (no automatic legal-hold engine in core unless specified). Record hold ID, scope, start/end dates, and approver.
- Legal hold overrides normal retention/deletion until lifted and documented.

## 8. Audit chain integrity notes

- `Applied_Effects_Ledger` and security event chains are designed for tamper evidence. Any procedure that would mutate past entries requires explicit security review and is generally prohibited in production.
- Exports for legal purposes should include verification instructions (e.g. `tirbase-admin verify-log` where applicable).

## 9. Review cadence

- Review this register and procedures at least annually or when adding new data fields/vertical features.
