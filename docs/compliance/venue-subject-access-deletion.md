# Venue subject access and deletion procedure (ST-13)

This procedure covers ticket, credential, access and CCTV metadata. It respects
an active legal hold: a hold suspends deletion but does not hide the request or
the fact that data is retained.

## 1. Intake and clock

1. Record the request in the privacy request log with a `request_id`. Do not put
   the subject's name or other payload in the request id.
2. Confirm the requester's identity using the operator's identity-verification
   standard. Do not collect more identity data than verification needs.
3. Confirm scope: which venue(s), which domains, and whether the request is
   access, correction, deletion or restriction.
4. Start the statutory clock (for example one month under GDPR/UK GDPR) and
   record the due date. Record any lawful extension and tell the requester.
5. If the request is manifestly unfounded or excessive, do not silently refuse;
   record the legal basis for refusal and tell the requester about remedies.

## 2. Discovery

Search all stores that may hold the subject data:

| Domain | Search key | Notes |
|---|---|---|
| ticket | ticket id, pseudonymous holder ref, issuer reference | Names/emails are external; do not invent a match. |
| credential | credential id, pseudonymous holder ref | Never export a private key (the venue does not hold one). |
| access | decision/scan id, pseudonymous holder ref | Operator attribution may need third-party redaction. |
| CCTV | `CctvStore::subject_export` by pseudonymous subject ref | Metadata only; no video. |
| audit | request id, actor id; legal-hold register | Audit entries may be retained under legal obligation. |
| backups/exports | backup catalogue and export log | Record whether retrieval is technically feasible. |

If a field is not in the [register](../../data/venue-privacy-register.csv), it
must not be in scope. Add undocumented stores to the register before processing
the request.

## 3. Access response

Use the privacy officer role:

```bash
venue-privacy --state /var/lib/tirbase/venue-privacy.json \
  --actor dpo-1 --role privacy_officer --venue venue-1 \
  export <pseudonymous-subject-ref>
```

The export contains:

- retained metadata for that subject only;
- active legal holds covering those events;
- a note when held events are included beyond normal retention.

Before sending:

- remove another person's data, confidential security detail and operator
  personal data that is not the requester's;
- explain stable codes and pseudonyms;
- do not disclose the deployment pseudonymisation salt or another subject's
  identifier;
- state any data withheld and the legal basis, including a legal hold;
- provide the response in a secure, encrypted channel.

Video is **not** in this runtime. If the operator's VMS holds video, the VMS
controller handles that part under its own procedure.

## 4. Deletion and legal hold

Use the privacy officer role:

```bash
venue-privacy --state /var/lib/tirbase/venue-privacy.json \
  --actor dpo-1 --role privacy_officer --venue venue-1 \
  delete <pseudonymous-subject-ref> <request-id>
```

The result reports:

| Result | Meaning |
|---|---|
| `deleted` | Event metadata removed from the store. |
| `retained_under_hold` | Event kept because a subject/event/venue hold covers it. |
| `legal_holds` | Active hold ids and reasons for the retention. |

Rules:

1. **A legal hold wins.** Do not release or bypass a hold to satisfy a deletion
   request. Tell the requester that deletion is restricted, without disclosing
   privileged detail.
2. Delete unheld events now; do not wait for the retention sweep.
3. Retain the deletion report and audit record, not the deleted payload, for
   `AUDIT_365D`.
4. Purge derived exports and caches. If an encrypted backup cannot be edited,
   record the exception and suppress the data on restore.
5. If a hash-chained audit ledger contains the subject, do not rewrite the
   chain. Redact exports, restrict access, or apply the documented
   erasure-conflict review; record the decision.
6. Re-run `purge` after a hold is released if the data is past its retention
   deadline.

### Hold-aware decision table

| Situation | Access request | Deletion request |
|---|---|---|
| No hold | return retained metadata | delete unheld data |
| Subject hold | return metadata and disclose hold | keep and report hold |
| Event hold | return event metadata only if requester is the subject; otherwise redact | keep that event and report |
| Venue hold | return the subject's metadata | keep all in-scope events and report |
| Hold released | normal retention applies | delete if past deadline; otherwise normal schedule |

## 5. Audit and closure

Record in the privacy request log:

- request id, date received, due date, verification method;
- domains searched, stores/backups checked;
- export date/channel or deletion report;
- legal holds encountered, without privileged content;
- redactions and refusals with legal basis;
- responder and approver;
- closure date and requester communication.

Retain the request record for `AUDIT_365D`. Do not retain the exported dataset
longer than the source purpose requires.

## 6. Escalation

Escalate to the venue DPO/legal counsel when: identity is uncertain; the request
touches another person's data; a hold is active; a backup cannot be edited; the
request is from a regulator/police; or deletion conflicts with a legal
obligation. Use
[`venue-local-authority-reporting.md`](venue-local-authority-reporting.md) for
external requests.
