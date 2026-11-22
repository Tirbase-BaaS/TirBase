# DPIA — venue ticketing data

**Domain:** ticket · **Register fields:** `ticket.*` · **Status:** baseline
complete for software pilot; operator localisation required.

## 1. Description of processing

Ticket scans establish whether a presented admission right is valid at a lane.
The scanner may supply a holder reference, name and email. The venue runtime
uses the ticket and scan metadata; names and emails are removed before any
connector delivery. Ticket data is not used for CCTV analytics, biometrics or
payment processing.

**Data flow**

```text
ticket issuer / scanner
  └─ ticket_id + holder_ref (+ name/email, transient) + gate + time
       → access decision (ST-03/ST-04)
       → scan records (30 days) + access decisions (90 days)
       → privacy preparation: name/email removed, holder_ref pseudonymised
       → ticketing connector (if enabled) / venue audit
```

## 2. Necessity and proportionality

| Question | Assessment |
|---|---|
| Is the data necessary? | Yes for admission, replay defence and dispute handling. |
| Is it proportionate? | Yes with minimisation: name/email are not retained by the runtime and are never forwarded. |
| Could fewer people be identified? | The holder reference is pseudonymised at the venue boundary. |
| Is the data used for a new purpose? | No. Re-use for marketing, CCTV or analytics is out of scope. |

## 3. Fields, purpose, retention and access

| Register field | Purpose | Retention | Access |
|---|---|---|---|
| `ticket.ticket_id` | Validate admission right | 30 days after scan event | venue operator, auditor |
| `ticket.holder_ref` | Correlate repeat scans without exposing scanner reference | 30 days after scan event | security operator, auditor |
| `ticket.holder_name` | Support/dispute only | not retained; delete at source | not exposed after privacy preparation |
| `ticket.holder_email` | Receipt/support only | not retained; delete at source | not exposed after privacy preparation |
| `ticket.scan_id` | Idempotency and replay defence | 30 days after scan event | security operator, auditor |
| `ticket.gate_id` | Lane attribution | 30 days after scan event | venue operator, auditor |
| `ticket.occurred_est` | Timeline and replay window | 30 days after scan event | security operator, auditor |
| `ticket.direction` | Entry/exit reconciliation | 30 days after scan event | venue operator, auditor |

## 4. Recipients and transfers

The venue operator, gate/security staff and auditors. A ticketing connector may
receive the redacted scan event under the connector contract; no name, email or
raw scanner reference is delivered. No cloud transfer by default.

## 5. Risks and mitigations

| Risk | Likelihood/impact | Mitigation | Residual |
|---|---|---|---|
| Ticket id linked to a named person in an external system | Medium/high | Keep ticket ids out of CCTV notes and free text; pseudonymise holder references; restrict exports | Medium — external issuer remains in scope |
| Over-retention after an event | Medium/medium | 30-day ticket and 90-day access register codes; scheduled deletion; audit exports | Low |
| Name/email copied into a connector payload | Low/high | Privacy preparation removes direct identifiers; tests assert absence | Low |
| Replay or duplicate admission | Medium/medium | Scan id idempotency and decision log | Low |

## 6. Data-subject rights

Subject access and deletion use the scope in
[`venue-subject-access-deletion.md`](../venue-subject-access-deletion.md).
Ticket records are normally matched by the issuer's holder reference, not by
name. Where a legal hold covers a dispute, deletion is suspended and reported.

## 7. Outcome

**Approved for software pilot only.** The processing is necessary and
proportionate with the stated minimisation. A customer pilot requires the
operator's DPO/legal confirmation of lawful basis, issuer contract, retention
and transfer position, plus the pack sign-off.

| Sign-off field | Value |
|---|---|
| DPIA owner | venue privacy engineering |
| Operator DPO | _to be completed by customer_ |
| Review date | 2026-11-22 (baseline) |
| Next review | annually or on field/integration change |
