# Insurance evidence — auditability

## What is recorded

| Record | Content | Retention owner |
|---|---|---|
| Gate decisions | Scan id, ticket reference, gate, outcome and reason, decision time | Venue |
| Scan ledger and reconciliation | Local scans, uploads, vendor status, drift report | Venue |
| Credential cache state | Watermark, synced time, revocation state — no credential secret | Venue |
| Lockdown and override actions | Actor, role, approval path, target, time, outcome | Venue |
| Incident workflow | Incident id, severity, actions, after-action report | Venue |
| CCTV metadata access | Actor, role, event, purpose, time; no video | Venue, per DPIA |
| Connector delivery | Event id, idempotency key, classification, timestamps | Venue and vendor |
| PA announcements | Announcement id, template, priority, zones, text length, time | Venue |
| Configuration changes | Change id, approver, before/after, rollback plan | Venue and integrator |
| Firmware and asset register | Device, version, support status, EOL date | Integrator |

## Properties

1. **Append-only.** Audit entries are not edited in place; corrections are new
   entries.
2. **Local-first.** Records survive a network or vendor outage and reconcile later.
3. **Personal-data minimal.** Holder references are pseudonymous; CCTV is metadata
   only; retention follows the customer DPIA and the field register.
4. **Independently checkable.** An integrator can reconcile gate decisions with
   the vendor's scan status without source access.
5. **Exportable.** Records can be produced for an insurer, an authority or a
   post-incident review.

## Gaps to disclose

- Audit retention duration is a venue decision and must be set before operation.
- The venue must protect the audit store's integrity and access; this kit does not
  provide a WORM store.
- No independent assurance of the audit trail has been performed yet.

## Evidence

- Claim registry entries for gate decisions, replay, lockdown and privacy.
- ST-12 HIL pack for gate behaviour.
- ST-13 privacy pack for CCTV metadata access and retention.
- Reconciliation report produced by the ticketing connector.
