# Customer subject access and deletion runbook

This is the customer-facing operation sheet. The open procedure and legal-hold
rules are in `docs/compliance/venue-subject-access-deletion.md`.

## 1. Intake

- Request channel: [ ]
- Request log location: [ ]
- Identity verification: [ ]
- Statutory deadline: [ ]
- DPO/counsel escalation: [ ]

## 2. Search

| Store | Search key | Owner |
|---|---|---|
| ticket/scan | ticket id/holder ref | [ ] |
| credential | credential id/holder ref | [ ] |
| access/audit | decision id/holder ref | [ ] |
| CCTV metadata | pseudonymous subject ref | [ ] |
| backups/exports | backup catalogue | [ ] |

## 3. Export

```bash
venue-privacy --state <state-file> --actor <privacy-officer> \
  --role privacy_officer --venue <venue> export <subject-ref>
```

- Redact third-party data: [ ]
- Explain pseudonyms/codes: [ ]
- Secure channel: [ ]
- Withholdings and legal basis: [ ]

## 4. Delete

```bash
venue-privacy --state <state-file> --actor <privacy-officer> \
  --role privacy_officer --venue <venue> delete <subject-ref> <request-id>
```

- [ ] Unheld metadata deleted
- [ ] Held events reported, not deleted
- [ ] Legal hold id recorded: [ ]
- [ ] Exports/caches purged
- [ ] Backup exception recorded: [ ]
- [ ] Closure record retained 365 days

## 5. Legal hold

A hold overrides deletion. Do not release a hold to satisfy a request. Escalate
to counsel; tell the requester that deletion is restricted without revealing
privileged detail.

## 6. Closure

- Request id: [ ]
- Response date: [ ]
- Reviewer: [ ]
- Attachments: [ ]
