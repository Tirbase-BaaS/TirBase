# CRA Annex I Checklist (Evidence Aid)

> **Disclaimer (cannot-claim-compliance):** This document is an internal evidence aid only. It does **not** constitute, claim, or imply certification, conformity assessment, or compliance with the EU Cyber Resilience Act (CRA), Annex I, or any other standard or regulation. No external publication, customer representation, or regulatory submission may be made using this document without prior review and written approval by qualified legal counsel.

**Release reviewed against:** `<fill at release>` 
**Last reviewed (UTC):** `<YYYY-MM-DD>` 
**Owner:** `<name/team>`

## Scope and method

- Source requirements: EU CRA Annex I (Part I essential cybersecurity requirements; Part II vulnerability handling where applicable).
- Method: checklist mapping to TirBase implementation artifacts, tests, and operational controls. Each item must cite evidence (code path, test, CI workflow, or procedure) or be marked `Gap/Planned`.
- Status values: `Met (evidence)`, `Partial`, `Gap/Planned`, `N/A (with rationale)`.

## Annex I Part I — Essential cybersecurity requirements (mapping)

| Ref | Requirement (summary) | TirBase mapping / evidence | Status | Evidence / notes |
|---|---|---|---|---|
| I.1(a) | Secure-by-default configuration; reduce attack surface | Deny-all command posture without signed profile (PV-11.5), explicit config validation, mTLS-only remote admin, no inbound cloud listener | Partial | `tirbase-gateway/src/config.rs`, `tirbase-gateway/src/main.rs`, `tirbase-gateway/src/admin_remote.rs`, PV-11.x tests |
| I.1(b) | Protect against unauthorised access (authN/authZ) | Signed command admission pipeline, Biscuit token binding, role registry, epoch/revocation checks | Partial | `tirbase-guard/src/admit.rs`, `tirbase-guard/src/command.rs`, `tirbase-core/src/auth/`, guard tests |
| I.1(c) | Confidentiality of stored/transmitted/processed data where relevant | SQLCipher feature path for DB-at-rest (optional), TLS for remote/cloud paths, secret handling via `secrecy`/zeroize | Partial | `tirbase-gateway` `sqlcipher` feature, `tirbase-gateway/src/cloud.rs`, `docs/root-ceremony.md` |
| I.1(d) | Integrity of stored/transmitted data, commands, programs, configuration | Signed operations/profiles/bundles, hash-chained security log, CBOR/domain separation | Partial | `tirbase-guard/src/signed_operation.rs`, `tirbase-gateway/src/security_log.rs`, profile/policy verification |
| I.1(e) | Minimise data (incl. personal data) | GDPR salted commitments for personal fields in security log chain; pseudonymized export support | Partial | `tirbase-gateway/src/security_log.rs`, `tirbase-gateway/src/security_log_export.rs`, CLAIM-27.x |
| I.1(f) | Protect availability / resilience (incl. DoS mitigation) | Rate limits, quotas, bounded queues/caches, degraded/restricted modes, crash-loop escalation controls | Partial | admit pipeline rate limits, quarantine/queue bounds, `node_mode`/lockdown paths |
| I.1(g) | Minimise negative impact on other services/devices | Least-privilege driver isolation posture, scoped tokens/roles, bounded network behaviour | Partial | driver isolation modules, role-scoped admission |
| I.1(h) | Limit attack surface, including external interfaces | Local-only health/metrics defaults, peer-credential admin socket, explicit trust roots | Partial | `tirbase-gateway/src/config.rs`, `admin.rs`, `health.rs`, `metrics.rs` |
| I.1(i) | Reduce impact via exploitation-mitigation mechanisms (segmentation, least privilege, etc.) | Guard/driver separation, unforgeable `ActuationPermit`, mode transitions, anti-replay/epoch/lease controls | Partial | `tirbase-guard/src/permit.rs`, `tirbase-guard/src/driver_proxy.rs`, AEF/lease/replay stores |
| I.1(j) | Record and/or monitor relevant internal activity, incl. access | Hash-chained security events, checkpoints, tamper detection, exports/verification | Partial | `tirbase-gateway/src/security_log.rs`, `tirbase-admin verify-log/export-log` |
| I.1(k) | Address vulnerabilities without delay (updates/mitigations) | Signed update/attestation flows, release SBOM/VEX/signing/reproducibility workflows (supply-chain evidence) | Partial | `.github/workflows/sbom.yml`, `sign.yml`, `reproducibility.yml`, self-update/attestation code paths |
| I.2 | Secure-by-default, secure updates, vulnerability handling process support | Documented vulnerability handling and support period (companion docs), release gates | Partial | `docs/compliance/vulnerability-handling.md`, `docs/compliance/support-period-policy.md` |

## Gaps and follow-ups

| ID | Gap | Planned action | Owner | Target |
|---|---|---|---|---|
| CRA-GAP-001 | Formal conformity assessment mapping incomplete | Complete per-release evidence review with legal/product | TBD | TBD |
| CRA-GAP-002 | User-facing security update/notification procedures not fully documented | Align support policy with operational runbooks | TBD | TBD |

## Review record

- [ ] Evidence links verified for this release
- [ ] Gaps triaged and accepted/mitigated
- [ ] Legal review completed before any external use

---
*Evidence aid only. Not a compliance or certification claim. External publication requires prior legal counsel review.*
