# Customer CCTV metadata retention and access

The open runtime enforces metadata retention. This kit adds the customer-specific
operating decisions.

## 1. Retention decisions

| Class | Baseline ceiling | Customer choice | Approved by |
|---|---|---|---|
| operational | 7 days | [ ] | [ ] |
| security/access anomaly | 30 days | [ ] | [ ] |
| safety | 90 days | [ ] | [ ] |

Justify any shorter period. A longer period requires a new DPIA/lawful-basis
review; do not silently exceed the runtime ceiling.

## 2. Access approvals

| Role | Customer post-holder | Approved |
|---|---|---|
| security operator | [ ] | [ ] |
| safety officer | [ ] | [ ] |
| auditor | [ ] | [ ] |
| privacy officer | [ ] | [ ] |
| venue manager | [ ] | [ ] |

## 3. Operating checks

- Purge owner and cadence: [ ] daily [ ] other: [ ]
- Access-log review owner/frequency: [ ]
- Legal-hold approver: [ ]
- State-file encryption/backup: [ ]
- VMS video retention (separate): [ ]

## 4. Enforced controls

- Reads after the deadline fail unless an active hold applies.
- Purge removes expired metadata and reports held events.
- Export/delete are privacy-officer-only and hold-aware.
- No raw video or biometric field is accepted.
- Every access, hold, export, delete and purge is audited.

## 5. Customer sign-off

- [ ] Retention classes approved
- [ ] Role holders named
- [ ] VMS/video boundary documented
- [ ] Purge and access-review owners assigned
- [ ] Legal-hold procedure tested
- DPO/legal reviewer: [ ]
- Date/signature: [ ]
