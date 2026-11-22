# DPIA — venue credential data

**Domain:** credential · **Register fields:** `credential.*` · **Status:** baseline
complete for software pilot; operator localisation required.

## 1. Description of processing

A credential authorises a holder to use a gate. The venue runtime stores a
credential identifier, a pseudonymous holder reference, public verification
material and lifecycle state. It does not store the holder's private key, raw
biometric template, name, email or payment data. Revocation prevents further
admission and is retained for audit.

**Data flow**

```text
enrolment (operator / issuer)
  └─ credential_id + holder_ref + public key + validity
       → access controller verifies presentation
       → status / revocation event
       → audit record (365 days for revocation reason)
       → credential metadata purge 30 days after revocation or expiry
```

## 2. Necessity and proportionality

| Question | Assessment |
|---|---|
| Is the data necessary? | Yes: the gate must verify the credential and honour revocation. |
| Is it proportionate? | Yes: public verification material only; no secret or biometric template. |
| Could a shared identifier be avoided? | Holder references are pseudonymous; credential ids are deployment-scoped. |
| Is biometric processing used? | No. Biometric markers are refused by the venue privacy and CCTV paths. |

## 3. Fields, purpose, retention and access

| Register field | Purpose | Retention | Access |
|---|---|---|---|
| `credential.credential_id` | Authorise/revoke access | 30 days after revocation/expiry | security administrator, auditor |
| `credential.holder_ref` | Link credential to authorised holder | 30 days after revocation/expiry | security administrator, auditor |
| `credential.public_key` | Verify presentation | 30 days after revocation/expiry | security administrator |
| `credential.status` | Deny revoked/expired credentials | 30 days after revocation/expiry | security administrator, auditor |
| `credential.issued_est` | Validity window | 30 days after revocation/expiry | security administrator |
| `credential.revoked_reason` | Audit withdrawal | 365 days restricted audit | auditor, security administrator |

## 4. Recipients and transfers

Venue security administrators, gate controllers and auditors. No credential
secret leaves the holder device. If a credential issuer is external, the
issuer/venue contract must define controller/processor roles and revocation
exchange. No cloud transfer by default.

## 5. Risks and mitigations

| Risk | Likelihood/impact | Mitigation | Residual |
|---|---|---|---|
| Credential theft or sharing | Medium/high | Revocation, replay defence, gate audit; no private key at venue | Medium — holder device controls remain |
| Holder re-identification | Medium/medium | Pseudonymous holder reference; no name/email; restricted admin access | Low |
| Biometric creep | Low/high | No biometric field; media/biometric markers refused and tested | Low |
| Stale credentials after revocation | Medium/high | Revocation status checked before admission; audit reason retained | Low |
| Over-retention of expired credentials | Medium/low | 30-day post-revocation purge; register code | Low |

## 6. Data-subject rights

Access and deletion follow
[`venue-subject-access-deletion.md`](../venue-subject-access-deletion.md).
Deletion removes credential metadata; a revocation reason may be retained under
a legal/audit basis with restricted access. Private keys are never in the venue
store and cannot be exported by it.

## 7. Outcome

**Approved for software pilot only.** No special-category or biometric data is
processed. A customer pilot requires the operator/issuer to confirm the lawful
basis, credential lifecycle, revocation exchange and retention, and to sign the
pilot record.

| Sign-off field | Value |
|---|---|
| DPIA owner | venue privacy engineering |
| Operator DPO | _to be completed by customer_ |
| Review date | 2026-11-22 (baseline) |
| Next review | annually or on credential/issuer change |
