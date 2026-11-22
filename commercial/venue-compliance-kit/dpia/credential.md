# Customer DPIA — credential data

## 1. Context
- Customer/venue: [ ]
- Credential issuer/technology: [ ]
- Controller/processor allocation: [ ]
- Lawful basis: [ ] contract [ ] legitimate interests [ ] legal obligation [ ] other: [ ]

## 2. Scope and fields
| Field id | Purpose | Retention code | Access role | Customer addition? |
|---|---|---|---|---|
| `credential.credential_id` | [ ] | `CREDENTIAL_30D` | [ ] | [ ] |
| `credential.holder_ref` | [ ] | `CREDENTIAL_30D` | [ ] | [ ] |
| `credential.public_key` | [ ] | `CREDENTIAL_30D` | [ ] | [ ] |
| `credential.revoked_reason` | [ ] | `AUDIT_365D` | [ ] | [ ] |

## 3. Flow and boundaries
- Enrolment system: [ ]
- Revocation path: [ ]
- Does the venue hold a private key? [ ] no (baseline) [ ] yes — stop; redesign
- Biometrics used? [ ] no (baseline) [ ] yes — separate high-risk DPIA required
- External issuer/transfer: [ ]

## 4. Retention and rights
- 30-day post-revocation purge confirmed: [ ]
- Revocation audit retention: [ ]
- DSAR key: credential id/holder ref: [ ]
- Legal hold understood: [ ]

## 5. Risks
| Risk | Mitigation | Residual | Owner |
|---|---|---|---|
| Credential sharing/theft | [ ] | [ ] | [ ] |
| Re-identification | [ ] | [ ] | [ ] |
| Stale revocation | [ ] | [ ] | [ ] |

## 6. Outcome
- [ ] Approved [ ] Approved with conditions [ ] Rejected
- Conditions: [ ]
- DPO/legal reviewer: [ ]
- Date/signature: [ ]
