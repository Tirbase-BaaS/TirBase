# Venue pilot privacy review sign-off

> This is a recorded review for the **ST-13 software pilot** (privacy runtime and
> documentation, no customer personal data). A customer pilot with real ticket,
> credential, CCTV or access data requires the operator's DPO/legal reviewer and
> a new signed record; this record does not substitute for that approval.

| Field | Value |
|---|---|
| Pilot | ST-13 venue privacy runtime — software pilot |
| Pilot scope | ticket, credential, CCTV metadata and access-data procedures; 31-field register; 8 acceptance tests |
| DPIA owner | venue privacy engineering |
| Privacy reviewer | venue privacy engineering (self-review; no external DPO) |
| Review date | 2026-11-22 |
| Status: Approved | Approved for software pilot only — customer pilot blocked pending operator DPO/legal sign-off |
| Completed DPIAs | [`venue-dpia/ticket.md`](venue-dpia/ticket.md), [`credential.md`](venue-dpia/credential.md), [`cctv.md`](venue-dpia/cctv.md), [`access.md`](venue-dpia/access.md) |
| Data-flow map | [`venue-data-flow-retention.md`](venue-data-flow-retention.md) |
| Field register | [`data/venue-privacy-register.csv`](../../data/venue-privacy-register.csv) |
| CCTV enforcement | [`venue-cctv-retention.md`](venue-cctv-retention.md) |
| SAR/deletion procedure | [`venue-subject-access-deletion.md`](venue-subject-access-deletion.md) |
| Local-authority templates | [`venue-local-authority-reporting.md`](venue-local-authority-reporting.md) |
| Residual risks accepted by | venue privacy engineering for the software-only pilot |
| Next review | annually; before any customer pilot; on new field/connector/VMS/jurisdiction |

## Completed checks

- [x] Every register row has a purpose, lawful-basis template, retention code,
      retention detail, access rule and deletion method.
- [x] The register covers ticket, credential, CCTV and access domains.
- [x] CCTV is metadata-only; no media/biometric field exists and markers are
      refused.
- [x] CCTV retention is enforced at read and purge, with legal-hold override.
- [x] Subject access/deletion is role-scoped and respects legal hold.
- [x] Local-authority reporting templates exist and require authority/legal
      verification.
- [x] The commercial kit is proprietary and separate from the AGPL runtime.

## Conditions and residual risks

1. This sign-off is not legal advice and is not a customer DPIA approval.
2. The operator must confirm controller/processor roles, lawful bases,
   residency/transfers, signage and local retention periods.
3. Video remains in the VMS; this runtime cannot enforce VMS video retention.
4. The JSON store is single-writer; a multi-process deployment needs a single
   writer or transactional store.
5. Operator notes are human-entered; training and review are required to keep
   special-category data out.

## Signature

**Privacy reviewer:** venue privacy engineering (maintainer self-review)
**Signature:** /s/ ST-13 software pilot review
**Date:** 2026-11-22

**Operator DPO approval (customer pilot):** _not yet obtained — required before
processing customer personal data._
