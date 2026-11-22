# Venue data-flow map and retention schedule (ST-13)

This document is the data-flow and retention baseline for ticket, credential,
CCTV and access data. It is deliberately field-level: the authoritative list is
[`data/venue-privacy-register.csv`](../../data/venue-privacy-register.csv),
with one row per field and a purpose, lawful-basis template, retention code,
retention detail, access rule and deletion method.

> Local counsel/DPO must confirm the lawful basis and local statutory periods.
> The table is a baseline, not legal advice.

## 1. Data-flow map

```text
                        ┌──────────────────────────────┐
 Ticket issuer/scanner  │ ticket_id + holder_ref       │
                        │ (+ name/email transient)     │
                        └──────────────┬───────────────┘
                                       │ presentation
                                       ▼
 ┌───────────────┐   verify    ┌──────────────────┐   decision   ┌───────────────┐
 │ Credential /  │────────────▶│ Access decision  │─────────────▶│ Gate controller│
 │ holder device │             │ (ST-03/ST-04)    │              │ / turnstile    │
 └───────────────┘             └────────┬─────────┘              └───────┬───────┘
                                        │ scan/decision metadata         │ audit
                                        ▼                                ▼
                              ┌──────────────────────┐          ┌──────────────────┐
                              │ Privacy preparation  │          │ Restricted audit │
                              │ names/emails removed │          │ 365-day records  │
                              │ holder pseudonymised │          └──────────────────┘
                              └──────────┬───────────┘
                                         │ redacted event
                                         ▼
                         ┌──────────────────────────────┐
                         │ Ticketing/access connectors  │
                         │ (no raw video; no secrets)   │
                         └──────────────────────────────┘

 Camera/VMS/alarm ──metadata only──▶ CctvStore (7/30/90 days)
      (video stays in VMS)                 │
                                           ├─ role-scoped read + access log
                                           ├─ legal hold → suspend deletion
                                           └─ privacy officer export/delete

 Subject request ──▶ privacy officer ──▶ field-scoped export / deletion
                                           └─ legal hold report + audit record
```

**Boundaries**

- No raw video enters TirBase. `CctvEvent` has no frame/clip/thumbnail/embedding
  field; media and biometric markers are refused. A VMS remains the video
  controller if video is used.
- No biometric or special-category processing is part of this baseline.
- Names/emails are transient scanner input, removed before connector delivery;
  they are not stored by the venue runtime.
- Cloud sync/connectors are optional. The deployment must add the destination,
  transfer mechanism and processor to its DPIA before enabling them.

## 2. Retention schedule

The machine-readable schedule is
[`data/venue-retention-schedule.csv`](../../data/venue-retention-schedule.csv).

| Code | Class | Starts | Maximum | Disposal | Hold |
|---|---|---|---|---|---|
| `TICKET_30D` | ticket/scan | event | 30 days | delete ticket/scan metadata | overrides |
| `CREDENTIAL_30D` | credential | revocation/expiry | 30 days | delete credential metadata; reason to audit | overrides |
| `ACCESS_90D` | access decision | decision | 90 days | delete decision; retain restricted attribution | overrides |
| `CCTV_SECURITY_30D` | CCTV security/anomaly | event | 30 days | `CctvStore::purge_expired` | overrides |
| `CCTV_SAFETY_90D` | CCTV safety | event | 90 days | `CctvStore::purge_expired` | overrides |
| `CCTV_OPERATIONAL_7D` | CCTV operational | event | 7 days | `CctvStore::purge_expired` | overrides |
| `AUDIT_365D` | audit/DSAR | closure | 365 days | delete restricted audit record | overrides |
| `LEGAL_HOLD` | legal hold | hold start | until release + matter closure | delete after release/closure | n/a |
| `MINIMISED_OR_NONE` | minimised | collection | not retained | delete at source; never forward | no |

### Retention rules

1. The retention clock starts at the event/decision/closure time shown above, not
   at ingestion.
2. At the maximum, data is deleted or irreversibly de-identified. A legal hold
   suspends disposal for the hold's scope.
3. Backups follow the same schedule where technically feasible; if an encrypted
   backup cannot be selectively edited, record the exception and delete on the
   next restore/rotation.
4. Exports are copies and inherit the source retention. Do not keep an export
   longer than its source without a new purpose and access rule.
5. The field register is the source of truth. A new field is not deployable
   until its row has purpose, retention and access.

## 3. Access rules

| Role | Ticket | Credential | Access | CCTV |
|---|---|---|---|---|
| venue operator | admission metadata | no | lane/outcome | operational metadata only |
| security operator | scan metadata | no | decision metadata | security/anomaly/operational metadata |
| safety officer | no | no | decision metadata | safety/security metadata |
| auditor | read all | read all | read all | read all metadata; no export/delete |
| privacy officer | DSAR only | DSAR only | DSAR/audit | all metadata; export/delete/hold |
| venue manager | operational | no | operational | operational metadata only |

Access is venue-scoped. The CCTV store additionally enforces the matrix in
[`venue-cctv-retention.md`](venue-cctv-retention.md) and records every action.

## 4. Residency and transfers

The default deployment is local at the venue. Record the country/region of the
gateway, database, backups and exports, plus any cloud anchor, connector or
support access. A cross-border transfer needs a lawful transfer mechanism and a
DPIA update before enablement. The commercial venue compliance kit includes a
customer transfer addendum.

## 5. Review triggers

Review this map and the schedule when a field, connector, VMS, camera purpose,
retention period, legal basis, subprocessor or jurisdiction changes — and at
least annually. A review that changes a field also changes the register and the
DPIA pack before deployment.
