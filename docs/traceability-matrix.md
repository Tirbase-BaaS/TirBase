# Traceability Matrix (PV Requirements → Design, Tests, Locations)

> **[CLAIM-56.2]** — **Proven** (matrix maintained; CI verifies every named test/location path exists via `scripts/check-traceability-matrix.sh`).

This matrix maps each PV requirement to its design section(s), test type, and test/file location. It consolidates the authoritative traceability table in `.kiro/specs/tirbase-master-enhancement/design.md` (§ "Traceability Matrix") and adds explicit coverage for PV-29 (external review scope/findings) and PV-30 (operator runbooks).

## CI verification

- scripts/check-traceability-matrix.sh docs/traceability-matrix.md fails if any named path in the **Test Location** column does not exist in the repository (files or directories). Workflow references must resolve to .github/workflows/<file>.

## Consolidated matrix (from design.md)

| PV Requirement | Design Section(s) | Test Type | Test Location |
|---|---|---|---|
| PV-1.4 | §4.5 (guard pipeline), §Testing Strategy | integration test (two CoreHandle instances) | tirbase-guard/tests/integration.rs |
| PV-1.11 | §Error Handling (failure modes), §4.6 (NodeMode) | integration test (crash → restart, crash-loop → LOCKDOWN) | tirbase-gateway/tests/crash_recovery.rs |
| PV-2.2 | §4.18 (CI pipeline), CLAIMS.md | CI gate (claim shape, status, production caller, and cited evidence) | `.github/workflows/ci.yml` (`claims-check` job), `scripts/check-claims.sh`, `scripts/check-claims-schema.py` |
| PV-2.4 | §4.18 (CI pipeline) | CI gate (cargo-deny, cargo-audit, cargo-geiger, cargo-mutants) | .github/workflows/deny.yml, .github/workflows/geiger.yml, .github/workflows/mutants.yml |
| PV-3.1 | §4.3 (KeyProvider), §4.12 (auth matrix) | unit test (role separation) | `tirbase-guard/tests/auth_matrix.rs` |
| PV-3.3 | §4.12 (token schema, auth matrix tests) | unit tests (auto-generated from AUTHORIZATION_MATRIX, P19) | `tirbase-guard/tests/auth_matrix.rs` |
| PV-3.4 | §4.11 (TrustRootRecord) | unit test (k=1 warning, k-of-n rotation) | `tirbase-guard/tests/trust_root.rs` |
| PV-3.6 | §4.3 (KeyProvider trait) | unit test (file-backed, TPM2/PKCS#11 stubs) | tirbase-guard/tests/key_provider.rs |
| PV-3.7 | §4.3 (zeroize on drop) | unit test (ZeroizeOnDrop derive) | tirbase-guard/tests/key_provider.rs |
| PV-3.8 | §4.2 (TimeSource trait) | unit test (no direct clock calls via clippy lint) | tirbase-core/tests/time_source.rs |
| PV-3.12 | §4.2 (clippy::disallowed_methods) | CI gate (clippy lint) | .github/workflows/clippy.yml |
| PV-3.14 | §4.3 (enrollment nonce store) | unit test (bounded retention, purge) | `tirbase-guard/tests/enrollment.rs` |
| PV-4.3 | §4.4 (ActuationPermit, bypass-proof) | compile-fail (trybuild) | `tirbase-guard/tests/compile_fail/` |
| PV-4.4 | §4.4 (compile-fail tests) | compile-fail (trybuild, all 3 ingress paths) | `tirbase-guard/tests/compile_fail/` |
| PV-4.5 | §Data Models (EnvelopeProfile, ParameterSpec) | unit test (profile validation) | `tirbase-guard/tests/envelope_profile.rs` |
| PV-4.6 | §4.5 (Stage 11), §4.12 (token schema) | property-based (P5) | tirbase-guard/tests/properties.rs |
| PV-4.7 | §4.5 (Stage 13, drift), §DB Schema (drift_rate_history) | property test (drift window enforcement) | tirbase-guard/tests/properties.rs |
| PV-4.8 | §4.7 (PolicyLifecycle, anti-rollback) | property-based (P15), adversary (S6) | tirbase-guard/tests/properties.rs, `tirbase-sim/scenarios/S06.toml` |
| PV-4.10 | §4.7 (policy loosening M-of-N) | integration test (loosening requires M-of-N + timelock) | tirbase-guard/tests/policy.rs |
| PV-4.11 | §4.7 (classify_bundle) | property-based (P6), proptest offline | tirbase-guard/tests/properties.rs, tirbase-guard/tests/policy.rs |
| PV-4.13 | §4.6 (NodeMode, five-state) | integration test (LOCKDOWN entry/exit, M-of-N) | tirbase-guard/tests/mode.rs |
| PV-4.15 | §4.6 (watchdog, crash-loop) | integration test (systemd watchdog, crash-loop → LOCKDOWN) | tirbase-gateway/tests/watchdog.rs |
| PV-4.16 | §4.5 (Stage 15, quorum) | unit test (M-of-N for critical params) | tirbase-guard/tests/properties.rs |
| PV-4.17 | §4.5 (simulate API) | unit test (dry-run returns exact rejection) | tirbase-guard/tests/simulate.rs |
| PV-4.20 | §4.4 (ingress convergence), §4.5 (pipeline) | compile-fail (trybuild, all 3 ingress paths converge) | `tirbase-guard/tests/compile_fail/` |
| PV-4.21 | §4.4 (socketpair), §4.14 (driver isolation) | integration test (SO_PEERCRED, seccomp) | `tirbase-guard/tests/driver_isolation.rs` |
| PV-5.1 | §4.8 (AppliedEffectsLedger), §DB Schema | integration test (Actuating-first, WAL, synchronous=FULL) | tirbase-guard/tests/effects_ledger.rs |
| PV-5.2 | §4.5 (Stage 16, Actuating before dispatch) | integration test (fsync before dispatch) | tirbase-guard/tests/effects_ledger.rs |
| PV-5.3 | §4.8 (boot reconciliation), §5.5 (sequence diagram) | integration test (read_back on boot, 30s timeout) | tirbase-guard/tests/effects_ledger.rs |
| PV-5.4 | §Testing Strategy (kill-at-every-step) | failpoint tests (fail crate at every write boundary) | tirbase-guard/tests/kill_at_every_step.rs |
| PV-5.5 | §4.8 (AntiReplayWindow) | property-based (P7, P8), adversary (S3, S20) | tirbase-guard/tests/properties.rs, `tirbase-sim/scenarios/S03.toml`, `tirbase-sim/scenarios/S20.toml` |
| PV-5.6 | §4.8 (idempotency keys) | property-based (P10), adversary (S29) | tirbase-guard/tests/properties.rs, `tirbase-sim/scenarios/S29.toml` |
| PV-5.7 | §4.8 (persist seq/idempotency) | integration test (power-loss survival) | tirbase-guard/tests/effects_ledger.rs |
| PV-5.8 | §4.8 (SingleWriterLease) | property-based (P9), adversary (S21) | tirbase-guard/tests/properties.rs, `tirbase-sim/scenarios/S21.toml` |
| PV-5.8a | §4.8 (lease preemption, revocation release, renewal cap) | property test (preemption, cap, cooldown) | tirbase-guard/tests/properties.rs |
| PV-5.9 | §4.8 (mismatch event), §DB Schema | unit test (mismatch within timeout, fail-safe trigger) | tirbase-guard/tests/effects_ledger.rs |
| PV-5.11 | §4.8 (retry semantics) | unit test (Failed → new command accepted, Unknown blocks) | tirbase-guard/tests/effects_ledger.rs |
| PV-5.12 | §4.8 (pruning, multi-param rejection) | unit test (90-day/1M cap, multi-param rejected) | tirbase-guard/tests/effects_ledger.rs |
| PV-6.1 | §4.9 (CRDT hardening, validate_start_op) | property-based (P16), characterization+regression | tirbase-core/tests/crdt_hardening.rs |
| PV-6.2 | §4.9 (characterization + regression tests) | integration tests | tirbase-core/tests/crdt_hardening.rs |
| PV-6.3 | §4.9 (InboundCaps) | unit test (all caps enforced) | tirbase-core/tests/crdt_hardening.rs |
| PV-6.4 | §4.9 (QuarantineReasonCode) | unit test (first-match-wins ordering) | tirbase-core/tests/crdt_hardening.rs |
| PV-6.5 | §4.9 (memory budgets) | unit test (cache metrics observable) | tirbase-core/tests/crdt_hardening.rs |
| PV-6.6 | §4.9 (fuzz targets), §Testing Strategy | fuzz smoke pass (≤60s per target) | `fuzz/fuzz_targets/` |
| PV-6.7 | §4.9 (quarantine stores) | property-based (P20), adversary (S25) | tirbase-core/tests/quarantine.rs, `tirbase-sim/scenarios/S25.toml` |
| PV-6.8 | §4.9 (fuzz target registry CI rule) | CI gate (every parser has a fuzz target) | .github/workflows/fuzz-registry.yml |
| PV-7.1 | §4.10 (SecurityEvent typed records) | unit test (replaces eprintln, typed fields) | tirbase-guard/tests/security_log.rs |
| PV-7.2 | §4.10 (hash-chain) | property-based (P18) | tirbase-guard/tests/properties.rs |
| PV-7.3 | §4.10 (checkpoints every 100 events or 60s) | unit test (checkpoint cadence) | tirbase-guard/tests/security_log.rs |
| PV-7.4 | §4.10 (tamper detection), §5.6 (sequence diagram) | integration test (interior break, torn tail) | tirbase-guard/tests/security_log_tamper.rs |
| PV-7.6 | §4.10 (rate limit, ring buffer) | unit test (100/s per category, 10k ring) | tirbase-guard/tests/security_log.rs |
| PV-7.7 | §4.10 (export CBOR/JSON, pseudonymization) | unit test (chain-verifiable raw, disclaimer on pseudonymized) | tirbase-guard/tests/security_log.rs |
| PV-7.8 | §4.10 (evidence bundle) | integration test (signed archive) | tirbase-guard/tests/security_log.rs |
| PV-7.9 | §4.10 (mesh sync) | integration test (append-only, retry 30s) | tirbase-guard/tests/security_log.rs |
| PV-7.10 | §4.10 (external checkpoint anchoring) | integration test (discrepancy → tail-truncation) | tirbase-guard/tests/security_log.rs |
| PV-7.11 | §4.10 (event catalog) | CI gate (every emitted event in catalog) | .github/workflows/event-catalog.yml |
| PV-7.12 | §4.10 (event sync rate limits) | unit test (500 events/min per peer) | tirbase-guard/tests/security_log.rs |
| PV-7.13 | §4.10 (retention bound) | unit test (90 days/1 GB, background rotation) | tirbase-guard/tests/security_log.rs |
| PV-8.1 | §4.13 (wasmi, migration determinism) | property-based (P12), cross-arch CI | tirbase-core/tests/migration_determinism.rs, .github/workflows/cross-arch.yml |
| PV-8.2 | §4.13 (DeterministicWasmProfile) | unit test (wasmparser rejects NaN/SIMD/threads) | tirbase-core/tests/migration_sandbox.rs |
| PV-8.2a | §4.13 (ExecutionProfileVersion, float prohibition) | unit test (version mismatch → quarantine, float → reject) | tirbase-core/tests/migration_sandbox.rs |
| PV-8.3 | §4.13 (fuel exhaustion) | unit test (quarantine, no partial application) | tirbase-core/tests/migration_sandbox.rs |
| PV-8.4 | §4.13 (shadow copy, postconditions) | integration test (postcondition failure → discard) | tirbase-core/tests/migration_sandbox.rs |
| PV-8.5a | §4.13 (expand-then-contract) | unit test (add+remove → reject) | tirbase-core/tests/migration_sandbox.rs |
| PV-8.6 | §4.13 (cancellation) | unit test (interrupt at fuel-check, state intact) | tirbase-core/tests/migration_sandbox.rs |
| PV-8.7 | §4.13 (post-execution revocation check) | unit test (revoked author → reject result) | tirbase-core/tests/migration_sandbox.rs |
| PV-8.9 | §4.13 (staged rollout primitives) | unit test (canary ring, signed rollback) | tirbase-core/tests/migration_sandbox.rs |
| PV-9.1 | §DB Schema (state inventory) | CI annotation check | .github/workflows/state-inventory.yml |
| PV-9.2 | §4.8 (ICO persistence) | integration test (restart-recovery, fields identical) | tirbase-core/tests/persistence.rs |
| PV-9.3 | §DB Schema (Primary vs Derived) | integration test (corruption → restricted mode) | tirbase-core/tests/persistence.rs |
| PV-9.4 | §DB Schema (schema migrations at boot) | integration test (ascending order, idempotent) | tirbase-core/tests/persistence.rs |
| PV-9.5 | §Testing Strategy (power-loss failpoint tests) | failpoint tests (logical-dump equivalence) | tirbase-core/tests/persistence.rs |
| PV-9.8 | §4.3 (MonotonicCounterTrait), §4.15 (epoch) | integration test (Level 1/2, epoch bump, LOCKDOWN on rollback) | `tirbase-guard/tests/epoch.rs` |
| PV-10.1 | §4.14 (DriverTrait codec) | unit test (each operation, 5000ms timeout) | `tirbase-drivers/tests/driver_trait.rs` |
| PV-10.2 | §4.14 (DeviceModel) | unit test (no params → reject) | tirbase-drivers/tests/device_model.rs |
| PV-10.3 | §Architecture (CI check) | CI gate (no core imports from drivers) | .github/workflows/layering.yml |
| PV-10.4 | §4.14 (seccomp, landlock, fail-closed) | integration test (isolation-failure, 2s timeout) | tirbase-drivers/tests/isolation.rs |
| PV-10.7 | §4.14 (reference drivers) | integration test (Modbus FC 03/04/06/16, MQTT TLS, cold-room) | tirbase-drivers/tests/modbus.rs, tirbase-drivers/tests/mqtt.rs, tirbase-drivers/tests/cold_room.rs |
| PV-11.1 | §4.16 (gateway binary) | integration test (TOML config, sd_notify, health, metrics) | tirbase-gateway/tests/gateway.rs |
| PV-11.2 | §4.16 (admin API) | integration test (SO_PEERCRED, mTLS remote, endpoints) | tirbase-gateway/tests/admin_api.rs |
| PV-11.5 | §4.16 (no profile → reject all) | unit test (NoProfile error, no sockets) | tirbase-gateway/tests/gateway.rs |
| PV-12.1 | §4.17 (simulator), adversary scenarios | adversary scenario suite | `tirbase-sim/scenarios/` |
| PV-12.2 | §4.17 (seed on failure) | unit test (seed printed to stdout) | `tirbase-sim/tests/scenario_runner.rs` |
| PV-12.3 | §4.17 (deterministic models) | property test (bit-identical from same seed) | `tirbase-sim/tests/determinism.rs` |
| PV-12.7 | §Testing Strategy (cargo-mutants) | CI gate (≥80% kill rate) | .github/workflows/mutants.yml |
| PV-12.8 | §Adversary Scenario Catalog (S19–S25) | adversary scenarios | `tirbase-sim/scenarios/S19.toml`, `tirbase-sim/scenarios/S20.toml`, `tirbase-sim/scenarios/S21.toml`, `tirbase-sim/scenarios/S22.toml`, `tirbase-sim/scenarios/S23.toml`, `tirbase-sim/scenarios/S24.toml`, `tirbase-sim/scenarios/S25.toml` |
| PV-13 | §(RFC-verifier reference) | document review | `docs/RFC-verifier.md` |
| PV-14.1 | §4.18 (SBOM) | CI gate (CycloneDX + VEX attached to release) | `.github/workflows/sbom.yml` |
| PV-14.2 | §4.18 (cosign signing) | CI gate (keyless OIDC signing) | `.github/workflows/sign.yml` |
| PV-14.3 | §4.18 (reproducibility) | CI gate (two builds, hash compare) | `.github/workflows/reproducibility.yml` |
| PV-15.3 | §Testing Strategy (Criterion benchmarks) | CI gate (instruction-count regression via iai-callgrind) | .github/workflows/benchmarks.yml |
| PV-15.4 | §Testing Strategy (flash-write budget) | unit test (group-commit batching, HIGH/CRITICAL bypass) | tirbase-gateway/tests/flash_budget.rs |
| PV-15.5 | §Testing Strategy (virtual-time soak) | CI soak test (72h simulated in 2h wall-clock) | `tirbase-sim/tests/soak.rs` |
| PV-16.1 | §4.19 (demo pack format), §Adversary Scenario Catalog (S1–S3) | integration test (cold-chain demo, observed output within 120s) | `tirbase-demo/cold-chain/run.sh` |
| PV-16.2 | §4.19 (demo pack format) | integration test (each vertical demo, run.sh produces output) | `tirbase-demo/energy-edge/run.sh`, tirbase-demo/water/run.sh, tirbase-demo/logistics/run.sh, tirbase-demo/buildings/run.sh, tirbase-demo/remote-ops/run.sh, `tirbase-demo/defense-logistics/run.sh` |
| PV-16.3 | §4.19 (demo pack format) | integration test (per-pack adversary scenario automated test) | `tirbase-sim/scenarios/` |
| PV-17.1 | §4.16 (Gateway admin API), §4.18 (CI pipeline) | CI gate (OpenAPI-generated TS SDK, WASM surface diff) | .github/workflows/sdk-parity.yml |
| PV-17.2 | §4.18 (CI pipeline) | CI gate (mdBook site generated) | .github/workflows/docs.yml |
| PV-17.4 | §4.18 (changelog) | document review (changelog updated before release tag) | `CHANGELOG.md` |
| PV-18 | §Data Models (schema parser), §Architecture | property-based (P13) | tirbase-core/tests/schema_parser.rs |
| PV-20.1 | §4.6 (NodeMode), §(THREAT_MODEL reference) | document review | `docs/THREAT_MODEL.md` |
| PV-20.2 | §(THREAT_MODEL reference) | document review (exclusion list) | `docs/THREAT_MODEL.md` |
| PV-20.3 | §(THREAT_MODEL reference) | document review (owner-decision list) | `docs/THREAT_MODEL.md` |
| PV-20.4 | §4.11 (TrustRootRecord, k=1 warning) | unit test (k=1 startup diagnostic warning emitted) | `tirbase-guard/tests/trust_root.rs` |
| PV-20.5 | §4.12 (Biscuit token schema), §4.16 (admin API) | unit test (long-TTL token emits startup warning) | tirbase-guard/tests/token_ttl_warning.rs |
| PV-25 | §4.13 (DeterministicWasmProfile — PV-8.2/8.2a), §4.16 (flash-wear — PV-15.4) | see PV-8.2, PV-8.2a, PV-15.4 rows | tirbase-core/tests/migration_sandbox.rs, tirbase-gateway/tests/flash_budget.rs |
| PV-19.1 | §Data Models (ConvergentState) | property-based (P11) | tirbase-core/tests/properties.rs |
| PV-21.1 | §4.1 (FixedPointValue) | property-based (P2, P3, P4) | tirbase-types/tests/fixed_point.rs |
| PV-21.2 | §4.5 (Stage 10, unit mismatch) | unit test (no unit tag → reject, wrong unit → reject) | tirbase-guard/tests/properties.rs |
| PV-22.1 | §4.3 (now_est model) | unit test (now_est formula, no direct clock) | `tirbase-guard/tests/time_ratchet.rs` |
| PV-22.2 | §4.3 (TimeRatchet persisted floor) | property-based (P17) | tirbase-guard/tests/properties.rs |
| PV-22.3 | §4.5 (Stage 9, freshness + challenge nonce) | unit test (UNVERIFIED → challenge required, RD-10 policy) | `tirbase-guard/tests/time_ratchet.rs` |
| PV-22.5 | §4.3 (TimeRatchet, advance) | property-based (P14), adversary (S23) | tirbase-guard/tests/properties.rs, `tirbase-sim/scenarios/S23.toml` |
| PV-23.1 | §System Invariants Catalog | simulation tick checks (INV-1..16) | `tirbase-sim/src/invariants.rs` |
| PV-24.1 | §4.5 (coarse/fine rejection mapping) | unit test (mapping completeness in CI) | tirbase-types/tests/rejection_mapping.rs |
| PV-24.2 | §4.5 (Stage 14, per-issuer rate limit) | unit test (10 cmd/s, retry-after) | tirbase-guard/tests/rate_limiter.rs |
| PV-24.3 | §4.16 (Guard status API) | integration test (self-query, cross-issuer needs Auditor) | tirbase-gateway/tests/admin_api.rs |
| PV-26.1 | §4.17 (formal models) | model check (TLA+/Quint) | `formal/policy_lifecycle.tla`, `formal/command_freshness.tla` |
| PV-26.3 | §Testing Strategy (loom/shuttle) | concurrency test | tirbase-guard/tests/concurrency.rs |
| PV-26.4 | §Testing Strategy (kani proof) | model check (kani) | `formal/kani_envelope_arith.rs` |
| PV-27.2 | §Testing Strategy (HIL test suite) | HIL integration test (maintainer-triggered) | `tests/hil/` |
| PV-28.1 | §4.3 (TimeAnchorService) | unit test (broadcast cadence) | `tirbase-gateway/tests/time_anchor.rs` |
| PV-29.1 | §Phase 19 (external crypto review scope) | document review (scope artifact) | `docs/crypto-review-scope.md` |
| PV-29.2 | §Phase 19 (pentest scope) | document review (scope artifact) | `docs/pentest-scope.md` |
| PV-29.3 | §4.18 (security findings tracking) | document review (findings tracker; no HIGH/CRITICAL unresolved before public claims) | `docs/security-findings.md` |
| PV-29.4 | §Phase 19 (claims hygiene after review) | document review (`CLAIMS.md` updated post-review if findings modify claims) | `CLAIMS.md`, `docs/security-findings.md` |
| PV-30.1 | §Phase 20 (operator runbooks) | runbook validation (procedures documented) | `docs/runbooks/lockdown.md`, `docs/runbooks/tamper.md`, `docs/runbooks/restore.md`, `docs/runbooks/key-compromise.md`, `docs/runbooks/crash-loop.md`, `docs/runbooks/time-anchor-failure.md` |
| PV-30.2 | §Phase 20 (runbook content: commands/outputs/rollback) | document review | `docs/runbooks/lockdown.md`, `docs/runbooks/tamper.md`, `docs/runbooks/restore.md`, `docs/runbooks/key-compromise.md`, `docs/runbooks/crash-loop.md`, `docs/runbooks/time-anchor-failure.md` |
| PV-30.3 | §Phase 20 (runbook verification) | simulated-fault runbook verification (`tirbase-sim`) | `tirbase-sim/tests/runbook_fault_verification.rs` |
| Req 1.4 (Property 1) — no PV ID; mapped to the core-protocol requirement | §Property 1 Cross-Build State Convergence (`.kiro/specs/tirbase-core-protocol/design.md`) | CI gate (native vs real-WASM deterministic state hash) | `scripts/cross-build-parity.sh`, `tirbase-core/src/parity_probe.rs`, `tirbase-core/src/tests/properties.rs` |
| Req 9.1, 9.3 (Property 7) — no PV ID; mapped to the core-protocol requirement | §Requirement 9 (Revocation): partial-delta accumulation, threshold enforcement, fail-closed negatives | integration test (two Swarm-backed `CoreHandle` instances) | `tirbase-core/src/api/revocation_saturate_mesh_tests.rs` |
| Req 17.1, 20.5 (Property 15) — no PV ID; mapped to the core-protocol requirement | §Requirement 17 (Schema Identification and Forward Compatibility), §Requirement 20 (Schema Parser) | property test (schema hash determinism) | `tirbase-core/src/tests/properties.rs` |
| Req 3.4, 12, 16 — no PV ID; mapped to the core-protocol requirements | §Requirement 3.4 (Compaction_Policy), §Requirement 12 (Delta Transmission Scheduling), §Requirement 16 (Cloud Ledger Integration) | integration test (real-mesh DRR byte floors, per-table compaction, outbound queue bound) | `tirbase-core/src/api/drr_compaction_queue_tests.rs` |
| Req 10, 11, 19 — no PV ID; mapped to the core-protocol requirements | §Requirement 10 (Causal Contamination Engine), §Requirement 11 (Contamination Resolution), §Requirement 19 (Non-Destructive Migration Recovery) | integration test (real-mesh contamination, composite ICO, Side-Car replay) | `tirbase-core/src/api/contamination_mesh_tests.rs` |
| Req 5, 6 — no PV ID; mapped to the core-protocol requirements | §Requirement 5 (Peer-to-Peer Mesh Networking), §Requirement 6 (Session Cryptography) | integration test (real-mesh fragmentation, multi-hop relay, 0-RTT resumption and key rotation) | `tirbase-core/src/api/network_wiring_mesh_tests.rs` |
| S1–S35 | §Adversary Scenario Catalog | adversary scenario suite | `tirbase-sim/scenarios/` |
| INV-1..16 | §System Invariants Catalog | simulation tick checks | `tirbase-sim/src/invariants.rs` |

## Claim → production caller → evidence (F-02)

`CLAIMS.md` is the authority for what is Proven, implemented-but-unwired, or Planned. This
section maps the CI machinery that keeps it honest. Every path here is checked by
`scripts/check-traceability-matrix.sh`.

| Claim | Production caller | Evidence (test / CI gate) | Remove-the-caller negative proof |
|---|---|---|---|
| CLAIM-3.1 | n/a — docs/CI deliverable | `scripts/check-claims.sh`, `scripts/check-claims-schema.py`, `.github/workflows/ci.yml` (`claims-check`) | n/a (gate) |
| CLAIM-3.4, 3.8, 3.9, 3.10, 3.12 | n/a — docs/CI deliverable | `scripts/check-docs-claims.sh`, `docs/THREAT_MODEL.md`, `docs/system-invariants.md`, `docs/security-event-catalog.md`, `docs/unit-registry.md`, `docs/freshness-policy.md` | n/a (docs gate) |
| CLAIM-35.7 | `tirbase-gateway/src/main.rs`, `tirbase-gateway/src/command_ingress/mesh.rs`, `tirbase-gateway/src/cloud.rs`, `tirbase-core/src/api/mod.rs` | `tirbase-gateway/tests/mesh_command_ingress.rs`, `tirbase-gateway/tests/command_ingress.rs` | n/a (delivery only; admission is the guard pipeline) |
| CLAIM-14.2 | `tirbase-guard/src/admit.rs` | `tirbase-guard/tests/admit_pipeline.rs` (`claim_14_2_stage0_pre_auth_rate_limit`) | `docs/security-critical-callers.toml` (`CLAIM-14.2`) |
| CLAIM-20.1 | `tirbase-guard/src/anti_replay.rs` | `tirbase-guard/tests/anti_replay_proptest.rs` | `docs/security-critical-callers.toml` (`CLAIM-20.1`) |
| CLAIM-G1.9 | `tirbase-core/src/migration/mod.rs` | `tirbase-core/src/api/mod.rs` (`migration_mid_flight_revocation_two_core_handle_instances`) | `docs/security-critical-callers.toml` (`CLAIM-G1.9`) |
| CLAIM-G1.11 | `tirbase-core/src/auth/revocation.rs` | `tirbase-core/src/api/revocation_saturate_mesh_tests.rs` | `docs/security-critical-callers.toml` (`CLAIM-G1.11`) |
| all Proven rows | see the `Production Caller` column in `CLAIMS.md` | see the `Test or CI Gate` column in `CLAIMS.md` | `scripts/reverse-proof.py` (nightly, `.github/workflows/reverse-proof.yml`) |

Release-level status and known limitations are recorded in `docs/releases/v0.1.0.md`.

## Notes

- **PV-29.1–29.4:** External crypto review/pentest engagements are **not completed**; scope and findings-tracking artifacts exist and no HIGH/CRITICAL external findings are recorded (see `docs/security-findings.md`). Any public security claim relying on reviewed components remains gated on completion and claim updates.
- **PV-30.1–30.3:** Runbook procedures are verified against simulated faults via `tirbase-sim/tests/runbook_fault_verification.rs` (and referenced scenario modules/tests).
- Where a named path is a directory or a general test file covering multiple subcases, the row indicates the owning location; CI enforces existence of every backticked path token in this document.
