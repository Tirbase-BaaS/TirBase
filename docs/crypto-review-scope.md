# External Cryptographic Review Scope

> **Status:** Scope defined; external cryptographic review **not yet completed** (as of 2026-11-11). This document is the review charter, not a review report.
>
> **[CLAIM-54.1]** — **Planned** (scope artifact exists; no external review has been performed and no external findings have been adjudicated).

## Purpose

Define the scope for an independent cryptographic/security review of TirBase security-critical primitives before any public security claim that depends on their correctness. The review covers design, implementation, key/secret handling, domain separation, and misuse resistance of the components below.

## In-scope components

| Component | Scope (what to review) | Primary code/docs |
|---|---|---|
| **Biscuit token handling** | Token minting/verification, root CA key registration and trust, role/caveat binding, attenuation semantics, expiry evaluation against `now_est`, revocation-ID handling, token parsing/validation boundaries, and resistance to confused-deputy or scope-relaxation misuse. | `tirbase-core/src/auth/` (Biscuit/token/command-token/root-CA paths), `tirbase-guard/src/guard.rs`, `tirbase-guard/src/admit.rs`, `docs/token-schema.md`, `docs/api/gateway-admin-openapi.yaml` |
| **`FixedPointValue` guard path** | Canonical fixed-point representation at the guard boundary, float-ingress rejection (NaN/±∞/−0 normalization), unit-ID/canonical-exponent enforcement, i128 comparison arithmetic for envelope bounds, drift/rate checks, and non-finite/overflow rejection behavior. | `tirbase-types/src/fixed_point.rs` (and related types), `tirbase-guard/src/admit.rs`, `tirbase-guard/src/envelope.rs`, `tirbase-guard/src/guard.rs`, `docs/unit-registry.md` |
| **`TimeRatchet`** | Authenticated-time estimate (`now_est`), monotonic ratchet persistence/floor, reboot/boot-id handling, beacon validation/max-forward-jump and M-of-N jump authorization, freshness state (`Verified`/`Unverified`) and challenge-nonce gating for critical parameters, and resistance to time-anchor poisoning/rollback. | `tirbase-guard/src/time.rs`, `tirbase-gateway/src/time_anchor.rs`, `tirbase-gateway/src/guard.rs`, `tirbase-core/src/traits.rs` (`TimeSource`), `docs/freshness-policy.md` |
| **WASM sandbox isolation (migrations)** | `DeterministicWasmProfile` validation, float/SIMD/threads/host-clock/host-randomness prohibition, fuel metering/limits, execution-profile/version binding, shadow-copy execution and postcondition handling, expand/contract enforcement, cancellation, and post-execution revocation checks. | `tirbase-core/src/migration/` (WASM sandbox/runner), migration validation/quarantine paths, `docs/design-notes/` (migration/determinism notes), `tirbase-sim` migration scenarios (e.g. S8/S9) |
| **Hash-chained security event log** | Append-only hash chain construction, checkpoint signing/verification cadence, boot tamper/tail-truncation detection and mode transitions, segment handling/recovery, external checkpoint anchoring, GDPR salted-commitment handling, export/evidence-bundle integrity claims, and rate-limiting/suppression behavior. | `tirbase-gateway/src/security_log.rs`, `tirbase-guard`/gateway event emission sites, `tirbase-admin/src/cmd/{export,verify_log}.rs`, `docs/security-event-catalog.md`, `docs/runbooks/tamper.md` |

## Out of scope (for this review)

- Safety certification (no SIL claims) and physical safety-instrumented systems.
- Compromise of a fully rooted host OS, physical attacks on hardware, or bypass paths directly to legacy controllers outside TirBase.
- Non-cryptographic product/UX concerns not affecting the above security properties.
- Third-party dependencies except as they affect the in-scope components (dependency CVE posture is covered by supply-chain processes).

## Review method and deliverables (expected)

- **Method:** design review, targeted source audit of in-scope paths, and adversarial test-case review/reproduction where feasible against `tirbase-sim` and integration tests.
- **Deliverables:** written findings with severity, affected component, reproduction/impact rationale, recommended remediation, and verification evidence for fixes.
- **Severity handling:** findings tracked in `docs/security-findings.md`; no HIGH or CRITICAL finding may remain unresolved before any public security claim relying on the reviewed components (PV-29.3).

## Evidence and limitations

- **External review status:** not completed. No external reviewer, report, or finding disposition is asserted here.
- **Internal evidence (not a substitute for external review):** scenario/invariant coverage in `tirbase-sim` (S1–S35, INV checks) and crate integration/property tests for guard, time, policy, CRDT hardening, and migration paths (see `docs/adversary-scenarios.md`, `docs/system-invariants.md`, and `CLAIMS.md` for mapped coverage).
- **Claim hygiene:** `CLAIMS.md` must be updated after review to reflect any claims modified by findings (CLAIM-54.4). Until then, review-dependent claims remain **Planned**.

## References

- `docs/THREAT_MODEL.md`
- `docs/token-schema.md`
- `docs/unit-registry.md`
- `docs/security-event-catalog.md`
- `docs/adversary-scenarios.md`
- `docs/system-invariants.md`
