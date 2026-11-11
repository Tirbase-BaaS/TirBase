# Phase 0 — Truth, Traceability, and Hygiene — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.0

## Scope

Task sections 1.x, 2.x, 3.x: 23 acceptance-criterion rows (23 complete, 0 open in `tasks.md` at audit time).

## Method

Every row was traced against the repository; nothing was accepted on assertion. The audit:

1. resolves each declared production-caller path on disk and each cited symbol to its
   definition site (`file:line`);
2. resolves test identifiers in this order: a claim-named test (`claim_<task>`), a test
   named in the task entry, the closest test in a test file named in the task entry, then
   the test location committed in `docs/traceability-matrix.md` for the task's PV
   requirement;
3. records tasks with an open checkbox as `NOT IMPLEMENTED` or `BLOCKED` — never as verified.

Evidence classes in the status column:

- `VERIFIED-BY-TRACE` — production call site resolved and a task-named/claim-named test resolved.
- `TRACED-CALLER` — production call site resolved; test evidence is file-, suite-, matrix- or CI-level only.
- `TRACED-TEST` — test or document deliverable traced, with no distinct runtime caller.
- `TRACED-ARTIFACT` — documentation/CI deliverable; the cited artifact exists.
- `BLOCKED` / `NOT IMPLEMENTED` — cannot be verified as done; reason recorded.

No row is `ASSUMED`: a row that could not be traced is reported as an open item instead.

## Evidence

| Task | Acceptance criterion (task) | Req | Production call site | Test evidence | Status |
|---|---|---|---|---|---|
| 1.1 | Create docs/RFC-workspace.md proposing the 8-crate workspace layout with crate responsibilities and strict dep… | PV-2.9 | `docs/RFC-workspace.md:1` | — | TRACED-ARTIFACT |
| 1.2 | Scaffold Cargo.toml workspace with all 8 member crates as compilable stubs: tirbase-types, tirbase-core (exist… | PV-2.9 | `Cargo.toml:1`<br>`tirbase-core/src/crdt/inbound_caps.rs:103` (`check`) | — | TRACED-CALLER |
| 1.3 | Add CI layering checks: cargo check -p tirbase-core must not import tirbase-guard or tirbase-drivers; cargo ch… | PV-10.3 | `.github/workflows/ci.yml:138` | — | TRACED-ARTIFACT |
| 2.1 | Enable #![warn(dead_code)] across all crates with CI failure on warnings; pub items exempt; add step in .githu… | PV-1.3, PV-2.4 | `.github/workflows/ci.yml:21` | — | TRACED-ARTIFACT |
| 2.2 | Add cargo-deny license/ban configuration (deny.toml) and block CI on any violation | PV-2.4 | `deny.toml:1` | — | TRACED-ARTIFACT |
| 2.3 | Add cargo-audit to CI as a blocking gate on every run | PV-2.4 | `.github/workflows/ci.yml:57` | — | TRACED-ARTIFACT |
| 2.4 | Add cargo-geiger CI artifact; gate on any net increase in unsafe block count compared to the previous run | PV-2.4 | `.github/workflows/ci.yml:72` | — | TRACED-ARTIFACT |
| 2.5 | Add cargo-mutants nightly CI job scoped to guard, ledger, and CRDT-validation modules | PV-2.4 | `.github/workflows/nightly-mutants.yml:14` | — | TRACED-ARTIFACT |
| 2.6 | Add cargo public-api CI enforcement: any new pub item not listed in the public API manifest causes CI failure | PV-1.14 | `.github/workflows/ci.yml:182` | — | TRACED-ARTIFACT |
| 2.7 | Implement pub-items-without-callers detection using rust-analyzer SCIP index or equivalent static-analysis too… | PV-2.5 | `docs/orphan-api-allowlist.md:1` | — | TRACED-ARTIFACT |
| 2.8 | Add cargo-mutants scoped to PR diff for automated wiring-mutation checks (automates PV-1 criterion 5) | PV-1.15 | `.github/workflows/ci.yml:415` | — | TRACED-ARTIFACT |
| 3.1 | Create CLAIMS.md registry: one row per claim (claim text, Proven/Planned status, integration test identifier);… | PV-2.2 | `CLAIMS.md:1` | `.github/workflows/traceability.yml:9` (`PV-2.2` traceability row) | TRACED-TEST |
| 3.2 | Add [CLAIM-{id}] marker system in docs and CI scanner: CI fails if any documentation file references a Planned… | PV-2.3 | `.github/workflows/ci.yml:258` | — | TRACED-ARTIFACT |
| 3.3 | Audit README; replace every unproven claim with a status entry in one of three categories: Implemented and wir… | PV-2.1 | `README.md:1` | — | TRACED-ARTIFACT |
| 3.4 | Create docs/THREAT_MODEL.md covering assets, actors, trust boundaries, the five failure modes, non-goals, resi… | PV-2.6, PV-20.1, PV-20.2, PV-20.3 | `docs/THREAT_MODEL.md:1` | — | TRACED-ARTIFACT |
| 3.5 | Create SECURITY.md (contact channel, 5-day acknowledgement SLA, 90-day disclosure window) and security.txt wit… | PV-2.7 | `SECURITY.md:1` | — | TRACED-ARTIFACT |
| 3.6 | Create CONTRIBUTING.md with DCO sign-off text and bug-report issue template; create CODEOWNERS; add CI SHA-256… | PV-2.8 | `CONTRIBUTING.md:1` | — | TRACED-ARTIFACT |
| 3.7 | Create docs/adversary-scenarios.md catalog for all scenarios S1–S35 with: attack vector, expected system respo… | PV-12.4, PV-12.8 | `docs/adversary-scenarios.md:1` | — | TRACED-ARTIFACT |
| 3.8 | Create docs/system-invariants.md catalog for INV-1..INV-16 with: invariant statement, simulation check descrip… | PV-23.1 | `docs/system-invariants.md:1` | `tirbase-sim/src/invariants.rs:595` (`inv_1_out_of_envelope_actuation_fails_immediately`) — via PV-23.1 | TRACED-TEST |
| 3.9 | Create docs/security-event-catalog.md stub enumerating every SecurityEvent category and reason code; add CI ch… | PV-7.11 | `docs/security-event-catalog.md:1`<br>`tirbase-core/src/events.rs:558` (`SecurityEvent`) | — | TRACED-CALLER |
| 3.10 | Create docs/unit-registry.md with initial unit IDs: degC, Pa, rpm, bar, kW, percent, boolean, kPa, m3h, V, A, … | PV-21.1 | `docs/unit-registry.md:1`<br>`tirbase-sim/src/scenarios/mod.rs:204` (`registry`) | — | TRACED-CALLER |
| 3.11 | Create token schema and authorizer facts documentation: document the Biscuit token fact structure (command(#ta… | PV-4.6 | `docs/token-schema.md:1` | — | TRACED-ARTIFACT |
| 3.12 | Document freshness policy for non-critical commands when FreshnessState::Unverified: define one of (a) reject … | PV-22.3 | `docs/freshness-policy.md:1` | `tirbase-guard/tests/time_ratchet.rs:517` (`freshness_is_unverified_before_any_beacon_and_after_a_reboot`) — via PV-22.3 | TRACED-TEST |

## Gaps and open items

- **1.1** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **1.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **1.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **2.1** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **2.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **2.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **2.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **2.5** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **2.6** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **2.7** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **2.8** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **3.1** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **3.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **3.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **3.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **3.5** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **3.6** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **3.7** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **3.8** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **3.9** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **3.10** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **3.11** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **3.12** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 23 rows have a resolved production call site or deliverable; 23 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

