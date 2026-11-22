# DPIA — venue access decisions

**Domain:** access · **Register fields:** `access.*` · **Status:** baseline
complete for software pilot; operator localisation required.

## 1. Description of processing

Access decisions record whether a ticket or credential was admitted at a gate,
the lane/time, the outcome, and the authenticated operator or system that acted.
They are used for admission integrity, replay defence, incident investigation
and audit. Access decisions do not include video, biometrics, payment data or
special-category data.

**Data flow**

```text
ticket/credential presentation
  └─ access decision: decision_id + ticket_id + holder_ref + gate + outcome + time
       → gate controller / audit (90 days)
       → operator attribution (365 days restricted audit)
       → privacy preparation for connectors
       → subject access / deletion request (privacy officer)
```

## 2. Necessity and proportionality

| Question | Assessment |
|---|---|
| Is the data necessary? | Yes: the venue must prove a gate decision and defend against replay. |
| Is it proportionate? | Yes: a decision record is smaller than a full ticket/identity record; direct identifiers are omitted. |
| Is operator attribution necessary? | Yes for misuse investigation and accountability; restricted to audit/security roles. |
| Is profiling used? | No automated profiling or biometric matching. |
| Are children's data processed? | Potentially, as ticket holders; the operator must apply its child/vulnerable-person safeguards. |

## 3. Fields, purpose, retention and access

| Register field | Purpose | Retention | Access |
|---|---|---|---|
| `access.decision_id` | Prove decision/replay defence | 90 days | security operator, auditor |
| `access.ticket_id` | Explain admission | 90 days | security operator, auditor |
| `access.holder_ref` | Correlate pseudonym | 90 days | security operator, auditor |
| `access.gate_id` | Lane attribution | 90 days | venue operator, auditor |
| `access.outcome` | Audit admission/refusal | 90 days | security operator, auditor |
| `access.operator_actor_id` | Attribution | 365 days restricted audit | auditor, security administrator |
| `access.decided_est` | Timeline | 90 days | security operator, auditor |
| `access.dsar_request_id` | Prove request handled | 365 days | privacy officer, auditor |

## 4. Recipients and transfers

Venue operators, security, safety officers and auditors. Connectors receive only
redacted access decisions; no holder name/email is forwarded. No cloud transfer
by default. An external access-control platform must be included in the
operator's processor list.

## 5. Risks and mitigations

| Risk | Likelihood/impact | Mitigation | Residual |
|---|---|---|---|
| Refusal pattern reveals sensitive inference | Medium/medium | Restrict outcome detail; no reason beyond stable code; short retention | Medium — context remains |
| Operator attribution used for performance monitoring | Medium/medium | Access limited to audit/security; purpose limitation; works council/employment review by operator | Medium — customer policy |
| Ticket/credential linkage | Medium/high | Pseudonymous holder reference; no name/email; no CCTV notes | Low |
| Replay/duplicate decision | Medium/medium | Idempotency, decision log, gate state verification | Low |
| Over-retention | Medium/low | 90-day access retention; 365-day restricted audit | Low |
| Cross-venue access | Low/high | Venue-scoped actor checks | Low |

## 6. Data-subject rights

The privacy officer can export or delete a subject's retained access metadata
using the pseudonymous holder reference. Audit attribution may be retained under
a legal obligation or legal hold; deletion reports what was retained and why. A
request does not rewrite gate history or a hash-chained audit ledger.

## 7. Outcome

**Approved for software pilot only.** The processing is necessary for admission
integrity and proportionate with the stated retention/access controls. A
customer pilot requires the operator to confirm employment/works-council
implications of operator attribution, child/vulnerable-person safeguards and
local retention rules.

| Sign-off field | Value |
|---|---|
| DPIA owner | venue privacy engineering |
| Operator DPO | _to be completed by customer_ |
| Review date | 2026-11-22 (baseline) |
| Next review | annually or on access/audit change |
