# Security Findings Tracker (External Crypto Review & Pentest)

> **[CLAIM-54.3]** — **Planned** (tracker established; external cryptographic review and penetration test have not been completed as of 2026-11-11).

This document tracks findings from the external cryptographic review (`docs/crypto-review-scope.md`) and penetration test (`docs/pentest-scope.md`), including severity, status, remediation, and verification.

## Engagement status

| Engagement | Status | Scope | Report / evidence |
|---|---|---|---|
| External cryptographic review | **Not started** (no external review completed) | `docs/crypto-review-scope.md` | — |
| External penetration test | **Not started** (no external penetration test completed) | `docs/pentest-scope.md` (failure modes 1, 2, 5) | — |

## Gate for public security claims

- **Policy (PV-29.3):** No **HIGH** or **CRITICAL** finding may remain unresolved before any public security claim that relies on the reviewed/tested controls.
- **Current state:** No externally reported findings exist because no external review/pentest has been completed. Therefore there are **0 unresolved HIGH** and **0 unresolved CRITICAL** external findings recorded. This is **not** evidence that no such issues exist; it reflects pending external assessment.
- **`CLAIMS.md` impact:** Per CLAIM-54.4, `CLAIMS.md` must be updated after review/testing to reflect any claims modified by findings. No external findings have modified claims to date.

## Findings log

| ID | Source | Component / area | Severity (C/H/M/L/I) | Status (Open / In progress / Resolved / Accepted risk) | Summary | Affected claims / PV | Remediation | Verification / evidence | Owner | Target date |
|---|---|---|---|---|---|---|---|---|---|---|
| _None recorded_ | — | — | — | — | No external findings recorded (engagements pending). | — | — | — | — | — |

## Severity and status definitions

- **Critical (C):** Direct, reliable compromise of safety/security boundary or key material with high impact.
- **High (H):** Significant control bypass or impactful exploit with realistic preconditions.
- **Medium (M):** Limited bypass, defense-in-depth gap, or exploit requiring stronger preconditions.
- **Low (L):** Minor issue or hard-to-exploit weakness.
- **Informational (I):** Hardening/clarity recommendation.
- **Resolved:** Fix implemented and verified (test/review evidence linked). **Accepted risk:** Explicitly accepted with rationale and approver (time-bounded where possible).

## Update procedure

1. Add each external finding as a new row with a unique ID and link to the source report section/artifact.
2. Record remediation (PR/commit), verification evidence, and any `CLAIMS.md`/doc updates required.
3. Re-evaluate public-claim readiness: block claims if any HIGH/CRITICAL remains Open/In progress.
4. After each engagement, update the engagement status table and, if applicable, `CLAIMS.md` per CLAIM-54.4.
