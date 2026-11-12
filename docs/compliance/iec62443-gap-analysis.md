# IEC 62443-4-1 / 4-2 Gap Analysis (Evidence Aid)

> **Disclaimer (cannot-claim-compliance):** This document is an internal evidence aid only. It does **not** constitute, claim, or imply certification, conformity assessment, or compliance with IEC 62443 (including IEC 62443-4-1 and IEC 62443-4-2), or any other standard or regulation. No external publication, customer representation, or regulatory submission may be made using this document without prior review and written approval by qualified legal counsel.

**Release reviewed against:** `<fill at release>` 
**Last reviewed (UTC):** `<YYYY-MM-DD>` 
**Scope:** TirBase gateway/guard/core components relevant to secure product development lifecycle (4-1 oriented) and component technical security capabilities (4-2 oriented) as implemented in this repository.

## Method

- This is a **gap analysis**, not an audit report or certification package.
- Ratings: `Implemented (evidence)`, `Partial`, `Gap`, `N/A` (with rationale).
- Evidence should reference repository artifacts (code, tests, CI, docs). Formal SDL artifacts outside this repo (organizational policies, training records, supplier contracts) are typically `Gap/N/A` here and must be maintained by the organization.

## A. IEC 62443-4-1 (secure development lifecycle practices) — high-level mapping

| Practice (summary) | TirBase evidence in-repo | Rating | Gaps / actions |
|---|---|---|---|
| Security management / governance | `SECURITY.md`, security event catalog, threat model/invariants docs, claims-driven verification | Partial | Formal SDL policy, roles/RACI, training records, and management review evidence are external/organizational |
| Security requirements | `requirements.md` (PV-*), `tasks.md`, `CLAIMS.md`, adversary scenarios | Partial | Requirements traceability to released baselines should be formalized per release |
| Secure by design | Deny-by-default guard pipeline, signed ops/profiles, least-privilege boundaries, mode/lockdown controls | Partial | Formal threat/risk reviews per feature and design sign-off records not fully codified |
| Secure implementation | Rust safety posture, typed events/errors, fail-closed paths, lint/deny/audit gates in CI | Partial | Coding standards/training and secure code review checklists should be formalized |
| Security verification & validation testing | Unit/integration/property/fuzz/mutation/benchmark/gate checks, adversary/failure scenarios | Partial | Coverage of hardware-in-the-loop and full system validation depends on lab procedures/releases |
| Management of security-related issues | Vulnerability handling/support docs, dependency review, SBOM/VEX/signing/reproducibility workflows | Partial | PSIRT tooling, SLAs, customer notification workflows, and case records are operational processes |
| Security update management | Signed artifacts/provenance, attestation/update mechanisms, documented support period | Partial | End-to-end update delivery, rollback comms, and field deployment governance need operational evidence |
| Security guidelines / documentation | Operational docs (root ceremony, token schema, packaging, failure-injection catalog, reference hardware/perf baselines) | Partial | User/admin hardening guides and secure deployment baselines should be versioned per release |

## B. IEC 62443-4-2 (component technical security requirements) — selected capability mapping

| FR / area (summary) | Relevant TirBase capabilities (evidence) | Rating | Gaps / actions |
|---|---|---|---|
| FR 1 Identification and authentication control | Device/issuer identities (DIDs/keys), signed commands/tokens, enrollment/epoch controls, role-based authorization | Partial | Component-level IAC conformance levels and authenticator lifecycle evidence not formally assessed |
| FR 2 Use control | Role/target/parameter scope checks, policy/envelope enforcement, per-issuer controls, command admission stages | Partial | Granular use-control SL-C targets and administrative role separation need formal mapping |
| FR 3 System integrity | Signed artifacts/profiles/bundles, hash-chained security log + checkpoints, tamper detection, anti-replay/rollback protections | Partial | Boot/runtime integrity measurements and platform trust-chain claims depend on deployment/hardware |
| FR 4 Data confidentiality | Optional SQLCipher-at-rest, TLS for remote/cloud comms, key material handling/zeroization practices | Partial | Confidentiality controls vary by deployment configuration; not all paths uniformly encrypted/authenticated by default |
| FR 5 Restricted data flow | Explicit ingress paths, mTLS-only remote admin, outbound-only cloud posture, peer transport controls | Partial | Network segmentation/zoning and conduit requirements are system/deployment responsibilities |
| FR 6 Timely response to events | Typed security events, mode transitions, lockdown/restricted handling, export/verify tooling, rate limiting | Partial | Centralized monitoring/SIEM integration and response runbooks are deployment-specific |
| FR 7 Resource availability | Bounded queues/caches, rate limits, reconciliation/recovery logic, watchdog/crash-loop concepts in design/runtime controls | Partial | Availability SL targets and resilience validation on reference/field hardware require ongoing evidence |

## C. Prioritized gaps

| Priority | Gap | Rationale | Recommended action | Owner | Target |
|---|---|---|---|---|---|
| P1 | Organizational SDL evidence not in-repo | 4-1 requires process/governance artifacts beyond code | Maintain external SDL evidence package; link release-reviewed summaries | TBD | TBD |
| P1 | SL-C targets not defined per deployment/component | 4-2 assessment depends on target security levels and context | Define intended SL-C(s) and environment assumptions per product profile | TBD | TBD |
| P2 | Deployment hardening/segmentation guidance incomplete | FR4/FR5/FR7 depend on system integration | Publish versioned deployment and hardening guides; validate on reference hardware | TBD | TBD |
| P2 | Hardware-backed assurance evidence limited | TPM/secure element, physical protections, and HIL validation vary | Expand Level 2/TPM test evidence and lab procedures per release | TBD | TBD |

## Review checklist (per release)

- [ ] Evidence links sampled and verified for `Implemented/Partial` items
- [ ] New security-relevant changes mapped to affected FR/practice rows
- [ ] Gaps updated with owners/targets or explicit risk acceptance
- [ ] Legal/certification experts consulted before any external use

---
*Evidence aid only. Not a compliance or certification claim. External publication requires prior legal counsel review.*
