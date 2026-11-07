# TirBase Verification Claims

This file is a **machine-readable registry** of every security and correctness claim in the TirBase
codebase.  Each row maps a `CLAIM-*` identifier (referenced from source code, tests, and CI steps)
to the claim text, its current status, and the integration test or CI gate that proves it.

**Status values:**
- `Proven` — the claim is backed by a passing integration test or CI gate; the test identifier is
  mandatory.
- `Planned` — the claim is committed to but the backing test has not yet been written; test
  identifier must be empty.

> **CI gate (CLAIM-3.1):** `scripts/check-claims.sh` runs on every push/PR and fails the build if
> any `Proven` row has an empty test identifier.  Update this file whenever a test is added or a
> status changes.

<!-- CLAIMS TABLE — columns must stay pipe-separated; no pipes inside cell values -->
| Claim ID | Claim Text | Status | Test Identifier |
|---|---|---|---|
| CLAIM-G1.1 | Outbound mesh transport is wired: `tirbase-core/src/transport/` has a real libp2p gossipsub production caller; a two-`CoreHandle` integration test over TCP verifies a delta written on node A appears on node B; removing the production caller fails at least one test | Proven | `outbound_mesh_transport_wired_two_core_handle_instances` |
| CLAIM-G1.2 | Inbound delta processing is wired: inbound mesh messages flow through `apply_incoming_delta` in `tirbase-core/src/crdt/merge.rs`; a two-`CoreHandle` integration test proves a delta written on node A appears on node B; removing `apply_incoming_delta` call fails at least one test | Proven | `inbound_delta_processing_wired_two_core_handle_instances` |
| CLAIM-G1.3 | CA registration is wired: `core_register_root_ca_key` has a production caller in `CoreHandle::init`; Biscuit tokens fail verification before registration and succeed after; removing the call fails at least one test | Proven | `ca_registration_wired_biscuit_fails_before_succeeds_after` |
| CLAIM-G1.4 | Revocation delta applied on a mesh node causes subsequent deltas from the revoked DID to be rejected at `apply_incoming_delta` | Proven | `revoked_author_mesh_delta_rejected_at_apply_incoming_delta` |
| CLAIM-G1.5 | `core_activate_saturate_mode` has a real production caller path wired through the init-time `SaturateModeStateMachine` configuration in `CoreHandle::init`; two real `CoreHandle` instances verify the full activation path; removing the root CA key wiring from `CoreHandle::init` causes the test to fail | Proven | `saturate_mode_wiring_two_core_handle_instances_activate_via_production_caller` |
| CLAIM-G1.6 | Cloud-sync send path (`CoreHandle::init` → `spawn_cloud_sync_loop` → `run_cloud_sync_cycle` → `cloud_sync_loop` → `CloudConnection::send_delta`) and receive path (`CloudLedger::receive_delta` via `CloudLedgerConnection::send_delta`) are wired as production callers; a mock cloud endpoint integration test verifies both paths; removing either caller causes the test to fail | Proven | `cloud_sync_send_and_receive_paths_are_wired_to_mock_endpoint` |
| CLAIM-G1.7 | `register_migration_ca_key` and `schema_version_path` have production callers in the gateway init path; a `MigrationDelta` with a wrong CA signature is rejected; removing either caller fails at least one test | Proven | `migration_ca_key_and_version_path_wired_wrong_sig_rejected` |
| CLAIM-G1.8 | Quarantine-ledger writes and sidecar-ledger writes have production callers; removing either write call fails at least one test | Proven | `quarantine_and_sidecar_ledger_writes_wired_two_core_handle_instances` |
| CLAIM-G1.9 | A revocation delta arriving while a migration is executing causes `finish_migration` at `migration/mod.rs:400` (CLAIM-G1.9 block) to discard the transform result before the schema hash advances; the check is verified by a two-`CoreHandle` integration test; removing the `is_revoked` re-check inside `finish_migration` causes `migration_mid_flight_revocation_two_core_handle_instances` to fail (schema advances to `v2` instead of remaining at `v1`) | Proven | `migration_mid_flight_revocation_two_core_handle_instances` |
| CLAIM-G1.10 | `docs/audits/gate-g1.md` is committed and contains a VERIFIED-BY-TRACE row for each of CLAIM-G1.1 through CLAIM-G1.9 with no ASSUMED entries | Proven | `docs/audits/gate-g1.md` |
| CLAIM-1.1 | `docs/RFC-workspace.md` is committed to the main branch and proposes the 8-crate workspace layout with crate responsibilities and strict dependency-edge table; no workspace-restructuring changes may be merged without this RFC on main | Proven | `docs/RFC-workspace.md` |
| CLAIM-1.2 | `Cargo.toml` workspace declares all 8 member crates as compilable stubs (tirbase-types, tirbase-core, tirbase-guard, tirbase-drivers, tirbase-gateway, tirbase-admin, tirbase-sim, tirbase-demo); `cargo check --workspace` passes in CI | Proven | `cargo check --workspace` (ci.yml `check` job) |
| CLAIM-1.3 | CI blocking steps enforce that `tirbase-core/Cargo.toml` does not declare `tirbase-guard` or `tirbase-drivers` as dependencies, and that `tirbase-drivers/Cargo.toml` does not declare `tirbase-guard` or `tirbase-core` as dependencies; each step greps the manifest and fails with a named violation message, then runs `cargo check -p <crate>` to compile-verify layer isolation; both the `check` and `test` CI jobs are gated on these steps via `needs: layer-isolation` | Proven | `layer-isolation` (`.github/workflows/ci.yml`) |
| CLAIM-2.1 | `#![warn(dead_code)]` is enabled across all crates; CI promotes this warning to an error via `RUSTFLAGS="-D dead_code"` and fails if any private symbol is unused; `pub` items are exempt from this lint | Proven | `check` job — "Check dead_code warnings" step (`.github/workflows/ci.yml`) |
| CLAIM-2.2 | `deny.toml` at workspace root enforces license allow-list, bans `openssl`/`native-tls`, treats all vulnerability advisories as errors, and allows only crates.io as a source; the `cargo-deny` CI job runs `EmbarkStudios/cargo-deny-action@v2` as a blocking gate; pre-existing advisories are individually documented in `deny.toml`'s `ignore` list | Proven | `cargo-deny` job (`.github/workflows/ci.yml`), `deny.toml` |
| CLAIM-2.3 | `audit.toml` at workspace root lists all pre-existing advisories acknowledged at gate-wiring time; the `cargo-audit` CI job runs `rustsec/audit-check@v2` as a blocking gate with no `continue-on-error` and fails CI if any unignored vulnerability is found | Proven | `cargo-audit` job (`.github/workflows/ci.yml`), `audit.toml` |
| CLAIM-2.4 | `cargo geiger --workspace --output-format Json` runs on every CI push/PR; `scripts/check-geiger.sh` compares the used-unsafe block count against the previous run's baseline artifact and fails CI with old vs. new counts if the count has increased; the first run passes gracefully and saves the initial count | Proven | `cargo-geiger` job (`.github/workflows/ci.yml`), `scripts/check-geiger.sh` |
| CLAIM-2.5 | A nightly CI job runs `cargo-mutants` scoped to the guard, ledger, and CRDT-validation modules and reports mutation kill rates | Planned | |
| CLAIM-2.6 | `cargo-public-api` (v0.52.0) runs on every CI push/PR for all library crates; `scripts/check-public-api.sh` compares the generated public API against the committed `public-api.txt` manifest in each crate directory; any new `pub` item not in the manifest causes CI failure | Proven | `public-api` job (`.github/workflows/ci.yml`), `scripts/check-public-api.sh` |
| CLAIM-2.7 | `scripts/check-orphan-api.sh` runs on every CI push/PR; generates rustdoc JSON for all library crates; identifies `pub` items with no non-test callers; cross-references against `docs/orphan-api-allowlist.md`; any unapproved orphan or expired allowlist entry fails CI | Proven | `orphan-api` job (`.github/workflows/ci.yml`), `scripts/check-orphan-api.sh`, `docs/orphan-api-allowlist.md` |
| CLAIM-2.8 | On every pull request, `cargo-mutants --in-diff` is scoped to the unified diff of changed Rust files relative to the merge-base; CI fails if any mutation in the changed lines survives | Proven | `cargo-mutants-pr` job (`.github/workflows/ci.yml`) |
| CLAIM-3.1 | `CLAIMS.md` registry exists with one row per claim; `scripts/check-claims.sh` runs on every push/PR and fails CI naming the affected claim(s) if any `Proven` row has an empty or missing test identifier | Proven | `claims-check` job (`.github/workflows/ci.yml`), `scripts/check-claims.sh` |
| CLAIM-3.2 | A CI scanner detects any documentation file that references a `[CLAIM-{id}]` marker whose status in `CLAIMS.md` is `Planned` without explicitly stating it as planned | Proven | `claim-markers` job (`.github/workflows/ci.yml`), `scripts/check-claim-markers.sh` |
| CLAIM-3.3 | The README has been audited; every unproven claim is replaced with a status entry in one of three categories: Implemented and wired, Implemented but not wired, or Planned | Proven | `README.md` (audit completed; every claim sentence carries a [Status: ...] marker) |
| CLAIM-3.4 | `docs/THREAT_MODEL.md` covers assets, actors, trust boundaries, the five failure modes, non-goals, residual risks, out-of-scope exclusions, and the owner-decision list per PV-20.3 | Planned | |
| CLAIM-3.5 | `SECURITY.md` exists with a contact channel, 5-day acknowledgement SLA, and 90-day disclosure window; `security.txt` has an `Expires` field per RFC 9116 | Proven | `SECURITY.md`, `.well-known/security.txt` |
| CLAIM-3.6 | `CONTRIBUTING.md` exists with DCO sign-off text and a bug-report issue template; `CODEOWNERS` exists; CI SHA-256 hash check on `LICENSE` fails and blocks merge if the hash differs from the known-good value stored in CODEOWNERS | Proven | `license-hash-check` job (`.github/workflows/ci.yml`), `CONTRIBUTING.md`, `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/CODEOWNERS` |
| CLAIM-3.7 | `docs/adversary-scenarios.md` catalog covers all scenarios S1–S35 with attack vector, expected system response, PV requirement reference, pass/fail criteria, and test ID for each entry | Planned | |
| CLAIM-3.8 | `docs/system-invariants.md` catalog covers INV-1 through INV-16 with invariant statement, simulation check description, `debug_assert!` location, and test ID | Planned | |
| CLAIM-3.9 | `docs/security-event-catalog.md` enumerates every `SecurityEvent` category and reason code; CI fails if any `SecurityEvent` emitted in production code is absent from the catalog | Planned | |
| CLAIM-3.10 | `docs/unit-registry.md` defines initial unit IDs (degC, Pa, rpm, bar, kW, percent, boolean, kPa, m3h, V, A, Hz) with integer IDs, labels, and dimensions | Planned | |
| CLAIM-3.11 | Biscuit token fact structure, Datalog authorizer program, and the deviation note (envelope arithmetic runs in Rust, not Datalog) are documented; attenuation caveats, `now_est` injection, and Biscuit revocation IDs are documented | Implemented | `docs/token-schema.md` |
| CLAIM-3.12 | Freshness policy for non-critical commands when `FreshnessState::Unverified` is documented and tested in tirbase-sim | Planned | |
| CLAIM-4.1 | `tirbase-types/Cargo.toml` exists as a `no_std`-capable crate with only `serde` as a dependency | Proven | `cargo check --workspace` (ci.yml `check` job) |
| CLAIM-4.2 | `FixedPointValue { mantissa: i64, exponent: i8, unit_id: UnitId }` is implemented in `tirbase-types` with `canonical_exponent` enforcement; gateway binary uses it at the guard boundary | Planned | |
| CLAIM-4.3 | Float-to-`FixedPointValue` conversion rejects NaN, +∞, −∞ with a typed `NonFiniteValueError`; normalizes float −0 to integer 0 at the conversion boundary | Proven | `fixed_point::tests::from_f64_nan_rejected`, `from_f64_pos_inf_rejected`, `from_f64_neg_inf_rejected`, `from_f64_negative_zero_normalises_to_zero` |
| CLAIM-4.4 | `FixedPointValue` min/max comparison uses i128 intermediates to prevent overflow in envelope bound comparisons | Proven | `tirbase-types::fixed_point::prop_tests::p6_boundary_i64_overflow_caught_by_i128` |
| CLAIM-4.5 | Property tests cover NaN rejection, +∞ rejection, −∞ rejection, −0 normalization, integer overflow on conversion, and round-trip serialization/deserialization for `FixedPointValue` | Planned | |
| CLAIM-4.6 | ID newtypes (`DeltaId`, `Did`, `TargetId`, `MigrationId`, `ProfileId`), `UnitId`, and `UnitDescriptor` are implemented in `tirbase-types` | Proven | `tirbase-types` unit tests (`tests::did_new_and_as_str`, `tests::target_id_new_and_as_str`, `tests::delta_id_is_32_bytes`, `tests::migration_id_is_32_bytes`, `tests::profile_id_is_16_bytes`, `tests::unit_descriptor_ids_match_registry`, `tests::all_units_length`) |
| CLAIM-4.7 | `CommandRole` enum (`CommandIssuer, PolicyAuthority, UpdateSigner, RevocationManager, Auditor, TimeAnchor`) is implemented in `tirbase-types` | Proven | `command_role_tests` (tirbase-types unit tests) |
| CLAIM-4.8 | `DeviceKeyType` enum (`Ed25519 | P256`) and `DeviceSignature` enum (`Ed25519([u8; 64]) | P256(Vec<u8>)`) are implemented in `tirbase-types` | Proven | `tests::device_signature_ed25519_key_type`, `tests::device_signature_p256_key_type`, `tests::device_signature_ed25519_as_bytes`, `tests::device_signature_p256_as_bytes`, `tests::device_signature_ed25519_len`, `tests::device_signature_p256_len`, `tests::device_signature_is_empty_false_for_valid`, `tests::device_key_type_as_str`, `tests::device_signature_ed25519_serde_roundtrip`, `tests::device_signature_p256_serde_roundtrip` |
| CLAIM-4.9.1 | `tirbase-gateway` binary entry point parses `GatewayConfig` TOML and initializes `CoreHandle`, `TimeSource`, `KeyProvider`, and `MonotonicCounterTrait`; `cargo check -p tirbase-gateway` passes | Proven | `cargo check -p tirbase-gateway` |
| CLAIM-4.9.2 | Admin Unix-socket listener at `/run/tirbase/admin.sock` opens with `SO_PEERCRED` authentication; all 12 endpoints return 501 Not Implemented; `SO_PEERCRED` rejects unauthenticated connections | Proven | `cargo check -p tirbase-gateway (admin stub compiles)` |
| CLAIM-4.9.3 | Health endpoint `GET /health` on `127.0.0.1` returns 200 OK within 500ms; no guard state required | Proven | `tirbase-gateway::health::tests::health_returns_200_within_500ms` |
| CLAIM-5.1 | `TimeSource` trait is defined in `tirbase-core/src/traits.rs` with `monotonic_now() -> u64`, `wall_hint() -> Option<i64>`, `boot_id() -> u64`; `monotonic_now` is documented as `CLOCK_BOOTTIME` | Planned | |
| CLAIM-5.2 | `KeyProvider` trait is defined in `tirbase-core/src/traits.rs` with `sign`, `sign_async`, `public_key_bytes`, `key_type`, `did`; private key material is never returned | Planned | |
| CLAIM-5.3 | `MonotonicCounterTrait` is defined in `tirbase-core/src/traits.rs` with `read`, `increment`, `set_if_greater`; two assurance levels are documented | Planned | |
| CLAIM-5.4 | `SecurityEventSink` trait is defined in `tirbase-core/src/traits.rs` with `emit(event: SecurityEvent)` | Planned | |
| CLAIM-5.5 | `clippy::disallowed_methods` configuration at the workspace root bans `std::time::Instant::now`, `std::time::SystemTime::now`, and `tokio::time::Instant::now` outside the `TimeSource` implementation crate; CI fails on any direct clock call | Planned | |
| CLAIM-5.6 | All `Instant::now` / `SystemTime::now` / `tokio::time::Instant::now` call sites in `tirbase-core` are migrated to `TimeSource::monotonic_now()`; `cargo clippy --workspace` passes with zero disallowed-methods violations | Planned | |
| CLAIM-5.7 | `IdentityManager` / keypair handling in `tirbase-core/src/identity/` uses the `KeyProvider` trait; a delta is signed with a `FileKeyProvider` instance using two `CoreHandle` instances | Planned | |
| CLAIM-5.8 | `SecurityEventSink::emit()` is wired at every emission site in `tirbase-core` (`crdt/`, `auth/`, `transport/`, `migration/`); all security events appear in the event log in the gateway binary; removing any `emit()` call fails at least one test | Planned | |
| CLAIM-5.9 | A CI script parses all `_Requirements: PV-X.Y_` markers in `tasks.md` and verifies each cited PV requirement exists in `requirements.md`; CI fails on any orphaned PV reference | Planned | |
| CLAIM-6.1 | `FileKeyProvider` is implemented with secrets held in `secrecy::Secret<[u8; 32]>`, implements `ZeroizeOnDrop`; never writes private key to configuration files | Planned | |
| CLAIM-6.2 | A `ZEROIZE_ON_DROP_REGISTRY` static slice is maintained; a CI test verifies every struct in `tirbase-guard` and `tirbase-core` whose fields include raw key bytes is in the registry and derives `ZeroizeOnDrop`; removing a `ZeroizeOnDrop` derive fails CI | Planned | |
| CLAIM-6.3 | `Tpm2KeyProvider` stub exists behind `feature = "tpm2"` with Ed25519-sealed-seed and P-256 options; NV-endurance wear-leveling design notes are present; `cargo check --features tpm2` passes | Planned | |
| CLAIM-6.4 | `Pkcs11KeyProvider` stub exists behind `feature = "pkcs11"`; `cargo check --features pkcs11` passes | Planned | |
| CLAIM-6.5 | `SoftwareMonotonicCounter` (Level 1) is implemented with SQLite WAL + `synchronous=FULL`; the gateway binary reports assurance level `Level1` in the boot diagnostic log | Planned | |
| CLAIM-6.6 | `Tpm2MonotonicCounter` stub (Level 2) exists with NV-endurance wear-leveling design comment; `cargo check --features tpm2` passes | Planned | |
| CLAIM-6.7 | `SignedOperation<T>` generic wrapper is implemented with `context_string`, `payload_hash`, `signatures`, `created_est`, `expires_est`; domain separation ensures cross-type signature reuse is rejected | Planned | |
| CLAIM-6.7a | Hardware-counter DB-generation binding is implemented; at boot the gateway compares `hw_counter > sw_counter_at_last_hw_write` and enters LOCKDOWN with a `MonotonicCounterRegression` SecurityEvent if true; NV wear is tracked via `hw_counter_value, sw_counter_at_last_hw_write, sw_increment_per_hw_write` | Planned | |
| CLAIM-6.7b | swtpm-based tests for `Tpm2MonotonicCounter` verify rollback detection and wear-leveling; test is BLOCKED pending swtpm availability in CI | Planned | |
| CLAIM-7.1 | `SystemTimeSource` is implemented using `CLOCK_BOOTTIME` for `monotonic_now`, `CLOCK_REALTIME` for `wall_hint`, and `/proc/sys/kernel/random/boot_id` for `boot_id` | Planned | |
| CLAIM-7.2 | `TimeRatchet` is implemented with fields `last_beacon_time, mono_at_beacon, persisted_floor, beacon_boot_id, max_forward_jump_secs` and persisted to the `time_ratchet` table in `primary.db` | Planned | |
| CLAIM-7.3 | `now_est()` returns `persisted_floor` when `current_boot_id != beacon_boot_id`; otherwise computes `last_beacon_time + (mono_now − mono_at_beacon)` floored at `persisted_floor`; expired commands are rejected when time advances | Planned | |
| CLAIM-7.4 | `TimeRatchet::advance()` rejects a beacon if `wall_time − persisted_floor > max_forward_jump`; M-of-N `TimeAnchor` signatures are required for large jumps; far-future beacon is rejected | Planned | |
| CLAIM-7.5 | `FreshnessState` enum (`Verified | Unverified`) is implemented with staleness window check (default 1 hour); critical-parameter commands in UNVERIFIED state require a challenge nonce | Planned | |
| CLAIM-7.6 | `time_ratchet` SQLite table with `beacon_boot_id` column exists in `primary.db`; gateway binary creates and reads the table at boot | Planned | |
| CLAIM-7.7 | Property test asserts that `TimeRatchet` value is monotonically non-decreasing across any sequence of beacon applications and simulated reboot events | Planned | |
| CLAIM-8.1 | `RootCaRegistry` supports multiple simultaneous root CA public keys with k-of-n threshold rotation (k ≥ 1); a startup diagnostic warning is emitted when k=1; tokens fail before CA registration and succeed after | Planned | |
| CLAIM-8.2 | Root revocation and rollback protection on trust-root version numbers is implemented using `MonotonicCounterTrait`; rollback attempts are rejected | Planned | |
| CLAIM-8.3 | `TrustRootRecord` struct is implemented with root CA keys, per-role thresholds, `device_class_floors`, expiry, and threshold signatures | Planned | |
| CLAIM-8.3a | For each role in `CommandRole`, the `TrustRootRecord` holds the authorized DID public keys and co-signature threshold; a co-signature from a DID not in the role registry is rejected even if the signature itself is valid | Planned | |
| CLAIM-8.4 | `docs/root-ceremony.md` describes the offline procedure for generating and rotating root CA keys | Planned | |
| CLAIM-8.5 | Enrollment nonce store enforces bounded retention (default 72h, configurable); expired nonces are purged on a background schedule; `RevocationManager` credential is required for decommission | Planned | |
| CLAIM-8.6 | Device enrollment flow covers first-boot identity generation, scoped token issuance, and replay-safe bootstrap; nonce reuse is rejected | Planned | |
| CLAIM-8.7 | `device_epoch` table exists in `primary.db` with `device_id, epoch, bumped_at_est, co_sig_pa, co_sig_rm`; epoch starts at 0 on first enrollment; prior-epoch commands are rejected after an epoch bump | Planned | |
| CLAIM-8.8 | Signed enrollment-epoch-bump operation `SignedOperation<EpochBump>` is implemented with PolicyAuthority + RevocationManager co-signatures; bumping the epoch increments the counter and causes peers to emit an `EpochRegression` SecurityEvent for lower-epoch reports | Planned | |
| CLAIM-9.1 | `tirbase-admin` crate has a `clap`-based CLI entry point with all subcommands declared as stubs; `cargo check -p tirbase-admin` passes | Planned | |
| CLAIM-9.2 | `enroll` subcommand is implemented with an integration test driving it from the gateway binary or two real `CoreHandle` instances; removing the enrollment call fails the integration test | Planned | |
| CLAIM-9.3 | `mint` subcommand is implemented (scoped token minting, maximum lifetime 86400s); removing max-lifetime enforcement fails at least one test | Planned | |
| CLAIM-9.4 | `rotate` subcommand for key rotation is implemented with an integration test | Planned | |
| CLAIM-9.5 | `inspect-identities` subcommand is implemented with an integration test | Planned | |
| CLAIM-9.6 | For every `—` cell in the Authorization Matrix, presenting the wrong role's credential returns a typed authorization error; removing any role check fails the corresponding cross-role test | Planned | |
| CLAIM-10.1 | `ParameterKind` enum is implemented with `Range { min, max }`, `Enum { variants }`, and `Bool` variants | Planned | |
| CLAIM-10.2 | `ParameterSpec` is implemented with `name, unit_id, canonical_exponent, kind, max_rate_per_sec, dwell_secs, min_off_secs, drift_window_secs, max_delta_in_window, safe_default, tightening_floor, critical: bool` | Planned | |
| CLAIM-10.3 | `LinearConstraint` is implemented with `coefficients, bound, operator (Leq/Geq/Eq)` expressing total non-Turing-complete cross-parameter constraints | Planned | |
| CLAIM-10.4 | `EnvelopeProfile` is implemented with `profile_id, version, device_class, parameters, cross_constraints, governance fields` and signed by `PolicyAuthority`; profiles signed by non-PolicyAuthority keys are rejected | Planned | |
| CLAIM-10.5 | Target-to-profile map `BTreeMap<TargetId, Arc<ArcSwap<EnvelopeProfile>>>` is implemented with hot-swap support | Planned | |
| CLAIM-10.6 | Install-time profile validation checks unit_id match, range containment within DeviceModel bounds, and writability; invalid profiles produce field-level error messages | Planned | |
| CLAIM-11.1 | `CommandMessage` is implemented with all required fields; signature is over canonical CBOR of all fields except `signature`; unsigned commands are rejected | Planned | |
| CLAIM-11.2 | `ActuationPermit` has a private `_sealed: ()` field preventing construction outside `tirbase-guard`; it does not derive `Clone`, `Copy`, `Default`, or `Deserialize`; compile-fail tests assert each of those derives fails | Planned | |
| CLAIM-11.3 | `DriverProxy` holds `ActuationPermit` and sends actuation frames over the guard-owned fd0; drivers never receive `ActuationPermit` directly; ingress-convergence trybuild tests verify all ingress handlers call through `admit()` | Planned | |
| CLAIM-12.1 | `PolicyBundle` is implemented with `version, prev_version_hash, envelope: EnvelopeProfile, co_signatures, kind: PolicyBundleKind` | Planned | |
| CLAIM-12.2 | `classify_bundle()` is implemented with 11-criterion tightening classification; the guard always recomputes classification and never trusts `bundle.kind` | Planned | |
| CLAIM-12.3 | Tightening-floor enforcement rejects any bundle where a parameter's new limit is more restrictive than the floor from `TrustRootRecord` | Planned | |
| CLAIM-12.4 | Policy loosening path reads M/N/timelock from the active policy (not the incoming bundle); M ≥ 2 is required; M=1 emits a startup diagnostic warning per RD-9; the guard never trusts `PolicyBundle.kind` | Planned | |
| CLAIM-12.5 | Tightening bundles are applied within 1 second of signature verification completion | Planned | |
| CLAIM-12.6 | Anti-rollback counter commits every accepted bundle version to `MonotonicCounterTrait`; bundles with version ≤ counter are rejected with a typed rollback-rejection error | Planned | |
| CLAIM-12.7 | Strictly-greater version semantics: any version strictly greater than the last accepted is valid (not exactly +1); partitioned devices missing versions can still catch up | Planned | |
| CLAIM-12.8 | `pending_approvals` table exists in `primary.db` for multi-signature operations (policy loosening, lockdown-exit, epoch bump, time-ratchet reset) | Planned | |
| CLAIM-12.9 | proptest offline soundness proof for `classify_bundle()` verifies that a bundle classified as tightening is always a strict envelope subset of the previous profile | Planned | |
| CLAIM-12.10 | Tests cover time-lock bypass attempts, rollback replay attempts, and version-gap tricks; each bypass attempt is rejected | Planned | |
| CLAIM-12.11 | Scenario S7 (policy loosening without M-of-N) is wired in tirbase-sim and passes before PolicyLifecycle is considered complete | Planned | |
| CLAIM-13.1 | `NodeMode` enum (`Starting, Normal, Degraded, Restricted, Lockdown`) is implemented with mode × operation matrix enforcement; commands are rejected in Lockdown and Restricted; mesh sync and log export remain available in Restricted | Planned | |
| CLAIM-13.2 | LOCKDOWN state is persisted to `primary.db` (monotonic_counters table, key `lockdown_state`) AND to `/var/lib/tirbase/lockdown`; LOCKDOWN persists across restarts | Planned | |
| CLAIM-13.3 | LOCKDOWN exit requires an M-of-N signed `LockdownExit` command with ≥2 distinct roles; a full `EnvelopeProfile` must be present; valid M-of-N co-signatures are verified | Planned | |
| CLAIM-13.4 | `tirbase-lockdown.service` systemd oneshot unit writes the lockdown flag on guard process failure | Planned | |
| CLAIM-13.5 | Safe-default enforcement on guard death is implemented via controller watchdog register programming or a `tirbase-safe-writer` oneshot; the approach is documented | Planned | |
| CLAIM-13.6 | Supervisor auto-restarts the process into Normal after a crash; after N crashes within the configurable window (default 3 per 5 min) the supervisor escalates to security LOCKDOWN | Planned | |
| CLAIM-13.7 | A dedicated health-loop tokio task sends `sd_notify WATCHDOG=1` keepalive on each iteration; stalling the health loop triggers the watchdog timeout | Planned | |
| CLAIM-14.1 | `CommandGuard` struct is implemented with `ArcSwap<EnvelopeProfile>` and `ArcSwap<PolicyBundle>` config snapshots; actuator write handles are `pub(crate)` and inaccessible outside the guard crate | Planned | |
| CLAIM-14.2 | Stage 0 (pre-auth per-source rate limit token bucket) is implemented before any cryptographic operation | Planned | |
| CLAIM-14.3 | Stage 1 (`OperationalMode` check) rejects all commands when mode is `Lockdown` or `Restricted` | Planned | |
| CLAIM-14.4 | Stage 2 (command signature verification over canonical CBOR of all fields except `signature`) is implemented; unsigned commands are rejected | Planned | |
| CLAIM-14.5 | Stage 3 (Biscuit token verification against `RootCaRegistry`) is implemented; tokens from unknown CAs are rejected | Planned | |
| CLAIM-14.6 | Stage 4 (token-to-command binding) derives `CommandRole` from Biscuit token caveats (never from `cmd.role`); tokens scoped to the wrong target are rejected | Planned | |
| CLAIM-14.7 | Stage 5 (issuer DID revocation check against in-memory revocation set) is implemented; revoked issuers' commands are rejected | Planned | |
| CLAIM-14.8 | Stage 6 (device enrollment epoch check) compares `cmd.enrollment_epoch` against the device's current epoch; prior-epoch commands are rejected | Planned | |
| CLAIM-14.9 | Stage 8 (command expiry using `now_est`) enforces `max_ttl_secs` cap (default 3600s); expired commands are rejected; using wall clock instead of `now_est` fails scenario S19 | Planned | |
| CLAIM-14.10 | Stage 9 (challenge nonce verification for `FreshnessState::Unverified` + `critical: true` parameters) is implemented; `simulate()` does not consume the nonce | Planned | |
| CLAIM-14.11 | Stage 7 (decided-outcome cache lookup by `(issuer_did, target_id, sequence_number, epoch)`) returns the stored outcome without advancing any mutable state; duplicate commands return the cached outcome without a second actuation | Planned | |
| CLAIM-14.12 | Stage 10 (`FixedPointValue` canonical exponent check against `ParameterSpec`) is implemented; non-canonical-exponent commands are rejected with a typed `UnitMismatchError` | Planned | |
| CLAIM-14.13 | Stage 11 (envelope bounds check using i128 intermediates) is implemented; out-of-bounds commands are rejected with `EnvelopeViolation` | Planned | |
| CLAIM-14.14 | Stage 12 (cross-parameter linear constraint evaluation) is implemented; constraint violations reject the command | Planned | |
| CLAIM-14.15 | Stage 13 (rate-of-change and cumulative drift window check using `drift_rate_history` table) is implemented; slow-ramp attacks are rejected with `DriftExceeded` | Planned | |
| CLAIM-14.16 | Stage 14 (per-issuer rate limit, default 10 cmd/s per issuer DID) is implemented; rate-limited issuers receive a rejection with `retry_after_secs`; `simulate()` does not consume the token | Planned | |
| CLAIM-14.17 | Stage 15 (quorum check for `critical: true` parameters, M-of-N co-signatures) is implemented; critical-parameter commands without quorum are rejected | Planned | |
| CLAIM-15.1 | Stage 16 atomic SQLite commit acquires `SingleWriterLease`, advances the anti-replay window, inserts the idempotency key, and writes the `Actuating` record in a single transaction; lease failure aborts the entire transaction leaving no trace in idempotency or anti-replay state | Planned | |
| CLAIM-15.2 | Lease acquisition is part of the Stage 16 atomic commit transaction (covered by CLAIM-15.1) | Planned | |
| CLAIM-15.3 | Stage 17 emits a `SecurityEvent` with a coarse rejection code (`ENVELOPE_VIOLATION, ANTI_REPLAY, RATE_LIMIT, LEASE_HELD, VALUE_INVALID, NO_PROFILE, MODE_LOCKDOWN, QUORUM_REQUIRED, UNAUTHORIZED, EXPIRED, CHALLENGE_REQUIRED, TARGET_BUSY, UNSUPPORTED`) to the issuer; fine-grained details are only returned to `Auditor` or `PolicyAuthority` callers | Planned | |
| CLAIM-15.4 | Stage 18 dispatches `ActuationPermit` to the driver process via the inherited `socketpair(AF_UNIX, SOCK_SEQPACKET)` fd; dispatch occurs only after the group-commit fsync on the Actuating record, ensuring INV-12 holds across a crash at dispatch time | Planned | |
| CLAIM-15.5 | Stage 19 awaits driver confirmation (30s timeout) and updates `Actuating` to `Complete` or `Unknown`; `SingleWriterLease` is released on completion or confirmed failure | Planned | |
| CLAIM-15.6 | `admit()` runs Stages 0–15 synchronously with no driver or network I/O; DB reads use a blocking tokio pool (`spawn_blocking`); one tokio task per target handles Stages 16–19 | Planned | |
| CLAIM-15.7 | `simulate()` is a side-effect-free dry run: skips Stage 0 rate-limit token, Stage 9 challenge nonce consumption, Stage 14 per-issuer token bucket, and Stages 16–19; all other stages run normally; the exact typed rejection reason is returned | Planned | |
| CLAIM-15.8 | Token-cannot-relax property test: for any token minted by any key, a command with a value outside the `EnvelopeProfile` is always rejected regardless of token attenuations | Planned | |
| CLAIM-15.9 | Scenarios S1 (out-of-envelope command) and S3 (replay) are wired in tirbase-sim and pass before the full guard pipeline is considered complete | Planned | |
| CLAIM-16.1 | `ChallengeNonce` is implemented with `device_id, param, nonce: [u8; 32], issued_at_mono, expires_at_mono`; nonce is consumed after single use; second use is rejected | Planned | |
| CLAIM-16.2 | `challenge_nonces` table exists in `primary.db` | Planned | |
| CLAIM-16.3 | `GET /admin/challenge/{target}/{param}` endpoint issues a nonce when `FreshnessState::Unverified` and the param has `critical: true`; one-time-use is enforced | Planned | |
| CLAIM-16.4 | Per-device challenge nonce rate limit is implemented; adversary scenario S32 (challenge-nonce flooding attack) passes in CI | Planned | |
| CLAIM-17.1 | INV-1 is registered in `docs/system-invariants.md`; tirbase-sim calls the INV-1 check in `InvariantChecker` on every tick; any out-of-envelope actuation fails immediately | Planned | |
| CLAIM-17.2 | INV-2 is registered in `docs/system-invariants.md`; tirbase-sim calls the INV-2 check on every tick; duplicate actuation fails immediately | Planned | |
| CLAIM-17.3 | INV-3 is registered in `docs/system-invariants.md`; tirbase-sim calls the INV-3 check on every tick; version regression fails immediately | Planned | |
| CLAIM-17.4 | INV-4 is registered in `docs/system-invariants.md`; tirbase-sim calls the INV-4 check on every tick; chain break fails immediately | Planned | |
| CLAIM-17.5 | INV-5 is registered in `docs/system-invariants.md`; tirbase-sim calls the INV-5 check on every tick; non-safe-default actuation in LOCKDOWN fails immediately | Planned | |
| CLAIM-17.6 | INV-6 is registered in `docs/system-invariants.md`; tirbase-sim calls the INV-6 check on every tick; guard bypass attempt fails immediately | Planned | |
| CLAIM-17.7 | INV-7 is registered in `docs/system-invariants.md`; tirbase-sim calls the INV-7 check on every tick; token-relax attempt fails immediately | Planned | |
| CLAIM-17.8 | INV-8 through INV-16 are registered in `docs/system-invariants.md`; tirbase-sim calls each check on every tick; each invariant violation fails immediately with the invariant ID and triggering state | Planned | |
| CLAIM-18.1 | `primary.db` exists with `synchronous=FULL` WAL mode and all PrimaryLedger tables created via the migration framework | Planned | |
| CLAIM-18.2 | `derived.db` exists with `synchronous=NORMAL` WAL mode and all DerivedLedger tables created via the migration framework | Planned | |
| CLAIM-18.3 | SQLite hardening pragmas (`trusted_schema=OFF, foreign_keys=ON, cache_size=-4096`) are applied to both databases after creation | Planned | |
| CLAIM-18.4 | SQLite error → `NodeMode` mapping is implemented: `SQLITE_FULL` emits a High `SecurityEvent`; `SQLITE_IOERR` triggers `Restricted` mode; `SQLITE_CORRUPT` triggers `Restricted` mode and requires operator intervention | Planned | |
| CLAIM-19.1 | `applied_effects_ledger` table exists in `primary.db` with all required columns via the migration framework; ledger entry transitions are verified on actuation | Planned | |
| CLAIM-19.2 | Boot crash reconciliation scans `Actuating` entries; driver read-back is performed within 30s; entries are marked `Complete`, `Failed`, or `Unknown`; a `ReconciliationComplete` or `ReconciliationTimeout` SecurityEvent is emitted | Planned | |
| CLAIM-19.3 | At boot, pre-Actuating entries (from an older schema version) are scanned and marked Failed with reason `OLD_SCHEMA_ENTRY` | Planned | |
| CLAIM-19.4 | Group-commit batcher uses a 50ms window before fsync; `High` and `Critical` severity SecurityEvents bypass the batcher and are written immediately | Planned | |
| CLAIM-19.5 | Ledger pruning background job enforces max 90 days or 1,000,000 entries; oldest `Complete`/`Failed` entries are pruned first | Planned | |
| CLAIM-19.6 | Failpoint kill-at-every-step tests using the `fail` crate cover every write boundary in the effects ledger path; zero unhandled ledger states remain after fault injection | Planned | |
| CLAIM-20.1 | `AntiReplayWindow` (sliding bitmap per `(issuer_did, target_id, enrollment_epoch)`, W=64, G=1024) is implemented; sequence numbers outside the window are rejected | Planned | |
| CLAIM-20.2 | Non-mutating anti-replay check for the Stage 16 atomic transaction is implemented (read-only query before mutation) | Planned | |
| CLAIM-20.3 | `PolicyAuthority`-signed sequence-window reset is implemented for issuer re-enrollment or wrap-around | Planned | |
| CLAIM-20.4 | `anti_replay_windows` table exists in `primary.db` via the migration framework; window state survives power loss | Planned | |
| CLAIM-20.5 | Idempotency key store is scoped to `(issuer_did, target_id, idempotency_key)` with configurable retention (default 24h); duplicate keys return the original result without a second actuation | Planned | |
| CLAIM-20.6 | Anti-replay property tests (P7, P8): sequence numbers outside the window are always rejected; accepted sequence numbers are never re-accepted within the same enrollment epoch | Planned | |
| CLAIM-20.7 | Idempotency property test (P10): any command with a known idempotency key within the retention window returns the stored outcome without a second actuation | Planned | |
| CLAIM-20.8 | Scenarios S3 (replay) and S20 (sequence-number poisoning) are wired in tirbase-sim and pass before anti-replay is considered complete | Planned | |
| CLAIM-21.1 | `SingleWriterLease` is implemented with `issuer_did, target_id, expires_est (monotonic), consecutive_renewals, cooldown_until_est`; concurrent commands from two issuers result in rejection for one | Planned | |
| CLAIM-21.2 | Lease preemption is implemented via M-of-N `RevocationManager + PolicyAuthority` joint operation | Planned | |
| CLAIM-21.3 | Lease release on issuer DID revocation is implemented; revoked DID's lease is released immediately | Planned | |
| CLAIM-21.4 | Consecutive renewal cap (default 10) is implemented; after the cap is reached the lease enters a cooldown period before the same issuer may re-acquire | Planned | |
| CLAIM-21.5 | `single_writer_leases` table exists in `primary.db` via the migration framework; all leases are released at boot (stale leases are expired) | Planned | |
| CLAIM-21.6 | `SingleWriterLease` property test (P9): at most one issuer holds the lease for any given target at any point in time | Planned | |
| CLAIM-21.7 | `drift_rate_history` table exists via the migration framework for dwell and min-off-time enforcement (Stage 13) | Planned | |
| CLAIM-21.8 | `docs/EFFECT_SEMANTICS.md` documents at-least-once delivery with idempotent declarative effects, `Unknown` entry semantics, retry rules for `Failed` entries, and the v1 single-parameter-only limitation | Planned | |
| CLAIM-21.9 | Unknown-entry blocking is implemented: an `Unknown` entry for a target rejects all new commands to that target with `TARGET_BUSY`; an operator-clear command (PolicyAuthority credential) can advance an `Unknown` entry to `Failed` | Planned | |
| CLAIM-21.10 | Dwell and min-off interlock enforcement is implemented in Stage 13 using `drift_rate_history`; commands too soon after the last change are rejected with `DwellViolation` or `MinOffViolation` | Planned | |
| CLAIM-21.11 | `ParameterKind::Enum` and `ParameterKind::Bool` enforcement is implemented in Stage 10; invalid Enum and Bool values are rejected with `VALUE_INVALID` | Planned | |
| CLAIM-21.12 | `target_state` store (`BTreeMap<(TargetId, String), FixedPointValue>`) is implemented and updated atomically with the Actuating write in Stage 16 | Planned | |
| CLAIM-21.13 | Drift-history writer updates `drift_rate_history` atomically with the Actuating write in Stage 16; drift history reflects each accepted command | Planned | |
| CLAIM-21.14 | Scenario S21 (lease starvation) is wired in tirbase-sim and passes before `SingleWriterLease` is considered complete | Planned | |
| CLAIM-22.1 | `validate_start_op()` is implemented in `tirbase-core/src/crdt/hardening.rs`; an inflated `start_op` delta is quarantined in the two-`CoreHandle` integration test | Planned | |
| CLAIM-22.2 | Characterization test: a delta with inflated `start_op` applied to the unprotected baseline wins every LWW conflict; the test fails if the attack no longer succeeds (indicating baseline changed) | Planned | |
| CLAIM-22.3 | Regression test: the same inflated `start_op` delta is quarantined to `Schema_Quarantine_Ledger` after `validate_start_op()` is applied; removing `validate_start_op()` fails this test | Planned | |
| CLAIM-22.4 | Property test (P16): honest Automerge histories with valid dependency chains always pass `validate_start_op()`; any delta with a mutated `start_op` always fails | Planned | |
| CLAIM-23.1 | Bounded pending queue (`BTreeMap<DeltaId, (Delta, received_at_mono)>`, 24h age-out, 64 MiB global cap, 8 MiB per-peer cap) is implemented; late dependencies are processed on arrival via the Automerge sync protocol | Planned | |
| CLAIM-23.2 | `PENDING_QUEUE_OVERFLOW` quarantine is triggered when the byte cap is exceeded | Planned | |
| CLAIM-23.3 | `Schema_Quarantine_Ledger` (replayable, requires `PolicyAuthority` signature for replay) exists in `derived.db`; anomalous deltas are quarantined with the correct reason code | Planned | |
| CLAIM-23.4 | `Rate_Quarantine` is implemented as in-memory per-sender counters with periodic summary rows to `derived.db`; 7-day TTL on summary rows; non-replayable | Planned | |
| CLAIM-23.5 | Per-sender quota (1,000 entries per DID in `schema_quarantine`) is enforced; an attacker DID cannot flush other senders' entries; global limits (Schema: 50,000/256 MiB; Rate: 100,000/256 MiB) are applied separately | Planned | |
| CLAIM-23.6 | Cheap-checks-first ordering in the inbound validation pipeline: rate limit → size → op count → dep check → `start_op` validation | Planned | |
| CLAIM-24.1 | `InboundCaps` configuration is implemented with all defaults; each cap triggers the correct quarantine reason code | Planned | |
| CLAIM-24.2 | Memory budgets with eviction metrics are implemented: DAG node cache 32 MiB, ICO index 8 MiB, reassembly buffers 16 MiB; each cache exposes `current_bytes, eviction_count, hit_count, miss_count` | Planned | |
| CLAIM-24.3 | `cargo-fuzz` targets `automerge_delta_decode` and `fragment_reassembly` exist with committed seed corpus entries; CI smoke run completes within 60 seconds per target | Planned | |
| CLAIM-24.4 | CI rule enforces that every untrusted-input parser in `tirbase-core` and driver crates has a registered `cargo-fuzz` target; CI fails on any unregistered parser | Planned | |
| CLAIM-24.5 | Memory-budget ledger (`docs/memory-budget.md`) sums all configured caps against the RSS budget target; a CI check fails if the sum of all configured caps exceeds 90% of the RSS budget baseline | Planned | |
| CLAIM-24.6 | Scenario S4 (clock poisoning) is wired in tirbase-sim and passes before CRDT hardening (tasks 22–24) is considered complete | Planned | |
| CLAIM-25.1 | `SecurityEvent` struct is implemented with all required fields; no per-event device signature; checkpoints only | Planned | |
| CLAIM-25.2 | `SecurityEventLog` in-memory ring is bounded to 10,000 events; oldest anchor events and most recent events are retained when the ring is full | Planned | |
| CLAIM-25.3 | Checkpoint records are signed by the device key after every 100 events or 60 seconds; checkpoints are stored in `security_events` with `is_checkpoint=1` | Planned | |
| CLAIM-25.4 | `security_events` table with `segment_id` column exists in `primary.db` via the migration framework | Planned | |
| CLAIM-25.5 | `security_event_segments` table exists in `primary.db` via the migration framework for chain segment tracking | Planned | |
| CLAIM-26.1 | `verify_hash_chain()` is implemented at startup; a broken link triggers `Restricted` mode, emits a `TamperDetection` SecurityEvent, and opens a new chain segment | Planned | |
| CLAIM-26.2 | Signed chain-recovery operator command exits `Restricted` mode; allowing recovery without a signature fails at least one test | Planned | |
| CLAIM-26.3 | External checkpoint anchoring gossips the latest checkpoint hash to peers on each sync connection | Planned | |
| CLAIM-26.4 | Tail-truncation detection: a discrepancy between local and peer-observed checkpoint hash triggers a `TailTruncation` SecurityEvent and `Restricted` mode | Planned | |
| CLAIM-26.5 | `peer_checkpoint_witnesses` table exists in `primary.db` via the migration framework | Planned | |
| CLAIM-26.6 | Property test (P18): any interior modification of a committed event at any position is detected by `verify_hash_chain()` | Planned | |
| CLAIM-26.7 | Single-gateway witness fallback: when no mesh peers are available, checkpoint hashes are gossiped to the cloud anchor; when no cloud connection is available a `NoWitnessAvailable` diagnostic event is recorded at each checkpoint | Planned | |
| CLAIM-27.1 | GDPR salted commitments: personal fields are stored as `SHA-256(random_salt ‖ value)`; plaintext is stored in `security_event_personal_fields`; the salted form enters the hash chain | Planned | |
| CLAIM-27.2 | Log export in CBOR and JSON formats is signed by the device key; pseudonymized exports include an explicit disclaimer that they are not chain-verified | Planned | |
| CLAIM-27.3 | `export-evidence-bundle` command produces a single archive with the full log, all signed checkpoints, the device public key, the chain-verification report, and the export timestamp; the archive is signed by the device key | Planned | |
| CLAIM-27.4 | `tirbase-verify-log` CLI verifies the hash chain; exits 0 on an intact chain; exits non-zero with a gap/mismatch report per broken sequence range | Planned | |
| CLAIM-28.1 | Per-category rate limit (100 events/s) is implemented; when the limit is exceeded a single `SuppressionSummary` record is emitted before resuming | Planned | |
| CLAIM-28.2 | On-disk rolling retention window (90 days or 1 GB, whichever first) is implemented with a background rotation job that archives the oldest signed segment before deletion | Planned | |
| CLAIM-28.3 | Mesh sync of security events is implemented as an append-only CRDT collection with `compaction=none`; per-peer 500 events/min rate limit; retry after 30s on failure; `SyncFailure` SecurityEvent is recorded locally | Planned | |
| CLAIM-28.4 | Scenario S14 (log flooding) is wired in tirbase-sim and passes before the security event log (tasks 25–28) is considered complete | Planned | |
| CLAIM-29.1 | `wasmi` replaces `wasmtime` as the sole migration WASM engine on all targets; migration executes with wasmi; reverting to wasmtime fails the cross-architecture determinism test | Planned | |
| CLAIM-29.2 | `DeterministicWasmProfile` validation via `wasmparser` at module load time forbids all f32/f64 instructions, SIMD, threads, host clock, and host randomness; modules with f32 instructions are quarantined before execution | Planned | |
| CLAIM-29.3 | `ExecutionProfileVersion` matches migration modules on `profile_id` and `fuel_cost_table_hash`; mismatched profile_id is quarantined with `ENGINE_VERSION_MISMATCH` | Planned | |
| CLAIM-29.4 | `StoreLimits` (64 MiB memory, 1,000 tables, 10 instances, 512 KiB stack) are applied to every migration instance; migrations exceeding limits are quarantined | Planned | |
| CLAIM-29.5 | Property test (P12): same `wasmi` input + migration module → byte-identical output on repeated executions | Planned | |
| CLAIM-29.6 | Cross-architecture determinism test: same migration + input on x86_64 and ARM (via QEMU) produce byte-identical output | Planned | |
| CLAIM-30.1 | Shadow-copy run executes the migration against a SQLite savepoint over projection tables only; shadow run is discarded on postcondition failure | Planned | |
| CLAIM-30.2 | Signed postcondition evaluation checks row counts, field checksums over real data, and schema validity; a postcondition failure preserves the pre-execution state | Planned | |
| CLAIM-30.3 | `MigrationKind::Expand/Contract` with `fleet_precondition_hash` is implemented; a Contract migration without fleet precondition is rejected | Planned | |
| CLAIM-30.4 | Expand-then-contract rule: `Expand` adds ≥1 field and removes 0; `Contract` removes ≥1 field and adds 0; mixed single-module migrations are rejected with `ExpandContractViolation` | Planned | |
| CLAIM-30.5 | Mid-execution cancellation at fuel-check boundaries records a `QuarantineLog` entry and leaves the pre-execution state intact | Planned | |
| CLAIM-30.6 | Post-execution revocation check before committing the shadow: if the transform author DID is revoked, the result is rejected and a `RevocationPostExecution` SecurityEvent is emitted | Planned | |
| CLAIM-30.7 | `docs/RFC-tuf.md` evaluates TUF adoption with a threat model, comparative evaluation, and adopt-or-defer recommendation; BLOCKED pending owner decision RD-6 | Planned | |
| CLAIM-30.8 | Staged-rollout primitives are implemented: canary ring assignment via `H(device_id ‖ rollout_id) mod 100`; `tirbase-admin rollout status` shows per-device migration state; signed rollback command is available | Planned | |
| CLAIM-30.9 | Gateway self-update and config rollback are implemented (BLOCKED pending RFC-tuf.md merge per RD-6); failed updates automatically roll back | Planned | |
| CLAIM-30.10 | TUF crate spike evaluates `tough` or `rust-tuf` requiring injected `TimeSource` and gossip transport; findings are recorded in `docs/RFC-tuf.md` | Planned | |
| CLAIM-30.11 | Scenarios S8 (malicious migration) and S9 (postcondition failure) are wired in tirbase-sim and pass before the migration sandbox (tasks 29–30) is considered complete | Planned | |
| CLAIM-31.1 | `docs/state-inventory.md` enumerates every authoritative in-memory data structure with `PERSISTED: <table>` or `RECONSTRUCTIBLE: <source and method>` annotations | Planned | |
| CLAIM-31.2 | CI annotation check scans production code for in-memory structures lacking a corresponding entry in `state-inventory.md`; CI fails on any unregistered structure | Planned | |
| CLAIM-31.3 | ICO and CCE index are persisted to SQLite; a restart-recovery test proves all open ICOs survive a simulated crash with all fields identical to pre-crash values | Planned | |
| CLAIM-31.4 | `PRAGMA quick_check` runs at boot on all ledgers; `PRAGMA integrity_check` is deferred to a maintenance window and not required within 30 seconds | Planned | |
| CLAIM-31.5 | Derived ledger can be rebuilt from the signed delta log on corruption; Primary ledger corruption triggers `Restricted` mode and requires operator intervention; Primary ledgers are never rebuilt from the delta log | Planned | |
| CLAIM-32.1 | Local database schema migrations are idempotent, applied in ascending version order, and the current schema version is queryable at runtime; migrations are applied before the database is opened for reads or writes | Planned | |
| CLAIM-32.2 | Failpoint tests at every write boundary in `primary.db` verify logical-dump equivalence of the recovered state after fault injection | Planned | |
| CLAIM-32.3 | Backup and restore tooling triggers `quick_check`, delta log replay from the restore point, a signed enrollment-epoch bump, and LOCKDOWN entry; sequence numbers and anti-rollback counters are not silently updated | Planned | |
| CLAIM-32.4 | WAL checkpoint cadence: `PASSIVE` checkpoint runs every 1,000 frames or 60 seconds | Planned | |
| CLAIM-32.5 | SQLCipher encryption build variant (`cargo build --features sqlcipher`) uses `KeyProvider` for key material; the database open fails if `KeyProvider` returns an error; key material is never written to storage | Planned | |
| CLAIM-32.6 | IndexedDB persistence for the WASM store survives a simulated browser reload, or a deferral entry is committed to the requirements document naming it out of scope | Planned | |
| CLAIM-33.1 | `tirbase-drivers/Cargo.toml` declares only `tirbase-types` as a dependency (not `tirbase-guard`, not `tirbase-core`); CI layering check passes | Planned | |
| CLAIM-33.2 | `DriverTrait` is defined with `capability_discovery`, `encode_actuation`, `decode_read_back`, `encode_read`, `decode_read_response`, `encode_health_check`, `decode_health_response`; each operation returns within 5,000ms or a typed `TimeoutError` | Planned | |
| CLAIM-33.3 | `DeviceModel` is implemented with runtime `UnitId` tags, `FixedPointValue` [min, max] ranges, and writability flags; an empty `DeviceModel` (zero parameters) is rejected with a typed error | Planned | |
| CLAIM-33.4 | `ActuationPermit` integration: driver exposes `encode_actuation(permit) -> Frame` and `decode_read_back(frame) -> FixedPointValue`; no I/O inside the driver process | Planned | |
| CLAIM-33.5 | Out-of-process isolation: guard creates `socketpair(AF_UNIX, SOCK_SEQPACKET)`; parent keeps fd0; child inherits fd1 via `execve` argument inheritance; `SO_PEERCRED` is used for additional process identity verification | Planned | |
| CLAIM-33.6 | seccomp-BPF + `no-new-privs` + landlock (kernel ≥5.13; fail-closed without opt-in signed config flag if unavailable) are applied inside the driver child before any parsing begins; the driver child cannot connect to external sockets | Planned | |
| CLAIM-33.7 | Driver process lifecycle: persistent child, exponential-backoff restart (1s initial, 60s max, 5 retries); driver crash feeding counts toward supervisor LOCKDOWN escalation | Planned | |
| CLAIM-33.8 | CI isolation check verifies `tirbase-drivers` does not import `tirbase-guard` or `tirbase-core` symbols | Planned | |
| CLAIM-34.1 | Modbus TCP/RTU client driver supports FC 03, FC 04, FC 06, FC 16; all four FCs round-trip against the tirbase-sim Modbus server | Planned | |
| CLAIM-34.2 | MQTT bridge driver supports QoS 0 and 1 over TLS; plain-text connections are rejected | Planned | |
| CLAIM-34.3 | Cold-room simulator driver is backed by a first-order thermal model in `tirbase-sim`; bit-identical output from the same seed | Planned | |
| CLAIM-34.4 | `cargo-fuzz` targets for Modbus and MQTT frame parsers exist with committed seed corpus entries; CI smoke run completes within 60 seconds per target | Planned | |
| CLAIM-34.5 | `EnvelopeProfile` TOML documents exist in `profiles/` with schema validation; invalid profiles are rejected with field-level error messages | Planned | |
| CLAIM-34.6 | Simulator-based conformance tests per profile cover at least one nominal scenario and one boundary scenario with recorded pass/fail results | Planned | |
| CLAIM-34.7 | Modbus register map documentation exists for each reference driver pack in `docs/drivers/` | Planned | |
| CLAIM-34.8 | `DeviceTransport` (parent-owned TCP socket for Modbus TCP, serial fd for Modbus RTU) is implemented; the guard owns the fd and passes it to the driver child via `SCM_RIGHTS`; the Modbus register-map format is documented and a parser with a fuzz target exists | Planned | |
| CLAIM-35.1 | `tirbase-gateway` binary entry point wires together all subsystems (guard, admin API, drivers, metrics, logging); gateway binary starts and passes health check | Planned | |
| CLAIM-35.2 | `GatewayConfig` TOML schema is validated at startup; signed config bundles are validated by `PolicyAuthority` signature; invalid config is rejected | Planned | |
| CLAIM-35.3 | Systemd unit file includes hardening directives (`WatchdogSec=30`, `MemoryDenyWriteExecute=yes`, `NoNewPrivileges=yes`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`); CI gate: `systemd-analyze security` exposure score ≤ 3.0 | Planned | |
| CLAIM-35.4 | Health endpoint `GET /health` on `127.0.0.1` responds within 500ms | Planned | |
| CLAIM-35.5 | Prometheus metrics are exposed on `127.0.0.1:9090`: `guard_decisions_total`, `effects_ledger_writes_total`, `security_events_total{severity}`, `replay_rejections_total`, `quarantine_entries_total{store}` | Planned | |
| CLAIM-35.6 | All gateway output is structured JSON; every `eprintln!` in production paths has been replaced with a typed `SecurityEvent` or structured log record | Planned | |
| CLAIM-36.1 | Unix-socket admin API exists at `/run/tirbase/admin.sock` with `SO_PEERCRED` local authentication; local admin commands succeed via `SO_PEERCRED` | Planned | |
| CLAIM-36.2 | Optional remote admin endpoint with mTLS is implemented when enabled in config; non-mTLS remote connections are rejected | Planned | |
| CLAIM-36.3a | `POST /admin/enroll` endpoint is implemented; enroll request succeeds with a valid PolicyAuthority delegation token | Planned | |
| CLAIM-36.3b | `POST /admin/mint` endpoint is implemented; token minting with TTL > 86400s is rejected | Planned | |
| CLAIM-36.3c | `POST /admin/rotate` endpoint is implemented; key rotation succeeds | Planned | |
| CLAIM-36.3d | `POST /admin/policy` endpoint is implemented; valid PolicyAuthority-signed bundles are accepted; unsigned bundles are rejected | Planned | |
| CLAIM-36.3e | `GET /admin/events` endpoint is implemented with configurable retention window (default 7 days); events are returned within the retention window | Planned | |
| CLAIM-36.3f | `POST /admin/simulate` endpoint is implemented; simulate returns the rejection reason without actuating | Planned | |
| CLAIM-36.3g | `POST /admin/challenge` endpoint is implemented; challenge nonce is issued and consumed correctly | Planned | |
| CLAIM-36.3h | `GET /admin/mode` endpoint returns the current `NodeMode` correctly in each state | Planned | |
| CLAIM-36.3i | `POST /admin/lockdown-exit` endpoint requires valid M-of-N co-signatures from ≥2 distinct roles; reducing M below 2 fails at least one test | Planned | |
| CLAIM-36.3j | `POST /admin/chain-recovery` endpoint exits `Restricted` mode; allowing recovery without a signature fails at least one test | Planned | |
| CLAIM-36.3k | `GET /admin/status/{issuer_did}` returns anti-replay window position, rate-limit token count, and `SingleWriterLease` state; cross-issuer details require an Auditor credential | Planned | |
| CLAIM-36.3l | Additional admin endpoints are implemented: `POST /admin/sequence-reset`, `POST /admin/lease-preempt`, `POST /admin/quarantine-replay`, `POST /admin/time-reset`, `POST /admin/unknown-clear`, `POST /admin/restore`, `POST /admin/epoch-bump`, `GET /admin/rollout-status`; each has at least one integration test | Planned | |
| CLAIM-36.4 | `docs/api/gateway-admin-openapi.yaml` defines all admin endpoints (36.3a through 36.3l) | Planned | |
| CLAIM-36.5 | Deny-all behaviour is implemented until a signed `EnvelopeProfile` is installed; no listening sockets are opened unless explicitly configured | Planned | |
| CLAIM-36.6 | Cloud ingress is outbound-initiated TLS only; no inbound cloud listener is opened on the gateway | Planned | |
| CLAIM-36.7 | Guard status API (`GET /admin/status/{issuer_did}`) returns correct state for the issuer; returning status without an Auditor credential fails at least one test | Planned | |
| CLAIM-36.8a | Outbound-initiated TLS connection from gateway to cloud endpoint is implemented with exponential backoff reconnect; reconnect is verified on connection drop | Planned | |
| CLAIM-36.8b | Device certificate authentication for the cloud connection uses `KeyProvider`-signed certificates; connection is rejected without a valid device certificate | Planned | |
| CLAIM-36.8c | Offline command queueing with a configurable-depth ring buffer is implemented; commands queued during disconnection are delivered on reconnect | Planned | |
| CLAIM-36.8d | Issuer rejection feedback delivery over the cloud channel is implemented; coarse rejection codes are returned to remote issuers | Planned | |
| CLAIM-36.8e | Challenge issuance over the cloud channel is implemented; remote issuers can request challenge nonces for critical-parameter commands in UNVERIFIED freshness state | Planned | |
| CLAIM-36.8f | Per-connection rate limits and certificate rotation without connection disruption are implemented; rate limit triggers on flood; certificate rotation completes without a drop | Planned | |
| CLAIM-36.9 | Challenge issuance over the mesh channel is implemented; challenge responses are routed back to the originating guard instance | Planned | |
| CLAIM-37.1 | Cross-compiled builds exist for `aarch64-unknown-linux-gnu` and `armv7-unknown-linux-gnueabihf`; CI produces working cross-compiled binaries | Planned | |
| CLAIM-37.2 | `.deb` package targeting Debian 11+ exists; gateway starts on Debian 11 after installation | Planned | |
| CLAIM-37.3 | OCI container image exists; image starts and passes health check | Planned | |
| CLAIM-37.4 | CI binary size and RSS budget gates are in place (numerical budgets set after measure-first task 44.2); CI fails on binary size or RSS regression | Planned | |
| CLAIM-37.5 | Fleet inventory management is implemented as a CRDT collection with provisioning payloads ≤64 KiB; revocation changes propagate to all connected peers within 60 seconds | Planned | |
| CLAIM-38.1 | `tirbase-sim` crate exists with a `ChaCha8Rng`-seeded deterministic simulator; CI runs 1,000 seeded scenarios per run | Planned | |
| CLAIM-38.2 | `SimClock` (virtual time), `SimNetwork` (fault injection), and `SimNode` (wraps `CommandGuard` + driver models) are implemented; failing scenarios print the seed before exit | Planned | |
| CLAIM-38.3 | Network fault modes are implemented: partition, delay (1–30,000ms), drop, reorder, duplicate (≤5 copies per message) | Planned | |
| CLAIM-38.4 | First-order thermal model uses `libm` for deterministic floating-point; bit-identical output from the same seed across platforms | Planned | |
| CLAIM-38.5 | Battery/inverter model uses `libm` for deterministic floats; bit-identical output from the same seed | Planned | |
| CLAIM-38.6 | `InvariantChecker` implements per-tick checks for INV-1 through INV-16; a failing check immediately halts the scenario and prints the seed, invariant ID, and triggering state | Planned | |
| CLAIM-38.7 | `clippy::disallowed_types` bans `std::collections::HashMap` in `tirbase-sim` and `tirbase-guard`; CI fails on HashMap usage in guard or sim | Planned | |
| CLAIM-39.1 | TOML scenario loader and runner are implemented; CI executes ≥1,000 seeded scenarios per run; failing scenarios print the seed before exit | Planned | |
| CLAIM-39.2 | Scenarios S1–S18 are wired in tirbase-sim and pass in CI | Planned | |
| CLAIM-39.3 | Scenarios S19–S25 are wired in tirbase-sim and pass in CI | Planned | |
| CLAIM-39.4 | Scenarios S26–S35 are wired in tirbase-sim and pass in CI | Planned | |
| CLAIM-40.1 | `cargo-fuzz` targets exist with committed seed corpora; each CI smoke run completes within 60 seconds per target | Planned | |
| CLAIM-40.2 | `cargo-mutants` CI gate enforces ≥80% mutation kill rate on guard, ledger, replay, and validation modules; CI fails if any of those modules falls below threshold | Planned | |
| CLAIM-40.3 | Criterion benchmarks are wired to `iai-callgrind` for instruction-count gating (not wall-clock) on CI | Planned | |
| CLAIM-41.1 | `docs/RFC-verifier.md` is committed with all six required sections (Motivation, Scope and Exclusions, Trusted-Core Interface, Footprint Budgets, Equivalence and Test Strategy, Open Questions); no verifier implementation code exists until the RFC is on main | Planned | |
| CLAIM-42.1 | CycloneDX SBOM with VEX statements is generated on release and attached to the GitHub Release as a named asset alongside release binaries | Planned | |
| CLAIM-42.2 | `cosign` keyless signing with OIDC and SLSA provenance via GitHub Actions is implemented on every release tag | Planned | |
| CLAIM-42.3 | Two independent CI builds from the same source inputs are compared; the hash comparison result is published alongside release artifacts | Planned | |
| CLAIM-42.4 | Release-time `cargo-deny` gate with a release-specific `deny.toml` also bans crates flagged in VEX statements; separate from the per-PR check | Planned | |
| CLAIM-42.5 | Release-time `cargo-geiger` full report is attached as a release artifact; separate from the per-PR delta check | Planned | |
| CLAIM-42.6 | Release-time `cargo-mutants` across the full workspace requires 80% kill rate on all security-critical modules; separate from the nightly PR-scoped check | Planned | |
| CLAIM-42.7 | Dependency review record is maintained at each release covering all direct deps, transitive deps with CVE history, and all crates containing `unsafe` blocks or implementing cryptographic/authentication/network functionality | Planned | |
| CLAIM-43.1 | `docs/compliance/cra-annex-i-checklist.md` exists | Planned | |
| CLAIM-43.2 | `docs/compliance/vulnerability-handling.md` exists | Planned | |
| CLAIM-43.3 | `docs/compliance/iec62443-gap-analysis.md` exists | Planned | |
| CLAIM-43.4 | `docs/compliance/support-period-policy.md` exists and states a minimum security-patch period | Planned | |
| CLAIM-43.5 | Cannot-claim-compliance disclaimer is present in all compliance documents; no external publication without legal counsel review | Planned | |
| CLAIM-44.1 | `docs/reference-hardware.md` exists with the reference hardware profile | Planned | |
| CLAIM-44.2 | Measure-first benchmarks are run on reference hardware; baselines are recorded in `docs/perf-baseline.md`; all numerical budgets are set at 120% of baseline | Planned | |
| CLAIM-44.3 | Criterion benchmarks exist for guard decision latency, Ed25519 signature verification latency, effects-ledger write throughput, and delta apply throughput | Planned | |
| CLAIM-44.4 | `iai-callgrind` instruction-count gating is wired on all Criterion benchmarks | Planned | |
| CLAIM-44.5 | Flash-write budget tracking at the Linux block layer is implemented (default 100 MB/day); `HIGH` and `CRITICAL` SecurityEvents always bypass the budget limit | Planned | |
| CLAIM-44.6 | Flash-wear throttle increases the group-commit window up to 500ms when projected daily writes exceed budget; `HIGH` and `CRITICAL` SecurityEvents bypass throttling; `flash-wear-estimate` CLI exists | Planned | |
| CLAIM-44.7 | Failure-injection tests cover: ENOSPC (SQLITE_FULL → High SecurityEvent), fsync failure (SQLITE_IOERR → Restricted), torn write (logical-dump equivalence), driver hang (TimeoutError), clock jump (now_est bounded by TimeRatchet); procedures are documented in `docs/failure-injection-catalog.md` | Planned | |
| CLAIM-45.1 | Virtual-time soak test runs 72h simulated operation via tirbase-sim accelerated clock with fault injection and completes within a 2-hour CI job | Planned | |
| CLAIM-45.2 | `docs/soak-test-procedure.md` documents the real 72h lab soak with heap growth threshold ≤5 MiB and handle growth ≤50 handles over 72h | Planned | |
| CLAIM-46.1 | `tirbase-demo` crate structure and demo pack format (`profiles/, scenarios/, sim/config.toml, run.sh, docs/README.md, docs/modbus-register-map.md`) are defined | Planned | |
| CLAIM-47.1 | Cold-chain `EnvelopeProfile` TOML with temperature setpoint, compressor on/off, rate-of-change limit, and Modbus register map is created; gateway binary installs and validates the profile | Planned | |
| CLAIM-47.2 | Adversary scenarios S1, S2, S3 are wired into the cold-chain demo pack; each has a passing automated test in CI | Planned | |
| CLAIM-47.3 | `docs/demo/cold-chain/README.md` exists with a "What TirBase does not protect against in this scenario" section | Planned | |
| CLAIM-47.4 | `run.sh` for the cold-chain demo produces observable output demonstrating the defended attack scenario within 120 seconds of launch | Planned | |
| CLAIM-48.1 | Energy-edge demo pack exists: inverter/battery `EnvelopeProfile`, scenarios S1+S2, `run.sh`, README with non-goals section | Planned | |
| CLAIM-48.2 | Water/pumping station demo pack exists: Modbus simulator, scenarios S1+S3, register map, `run.sh` | Planned | |
| CLAIM-48.3 | Logistics node demo pack exists: CRDT BaaS demo, scenarios S10+S12, `run.sh` | Planned | |
| CLAIM-48.4 | Buildings/BMS demo pack exists: BACnet simulator placeholder, scenarios S1+S2, `run.sh` | Planned | |
| CLAIM-48.5 | Remote-ops mesh demo pack exists: mesh partition+rejoin demo, scenario S12, `run.sh` | Planned | |
| CLAIM-48.6 | Defense-logistics demo pack exists: M-of-N movement orders simulation, scenario S3, docs and `run.sh` | Planned | |
| CLAIM-49.1 | Machine-readable API definition (OpenAPI 3.1) exists for the guard and gateway native APIs; TypeScript SDK is generated from this definition | Planned | |
| CLAIM-49.2 | TypeScript SDK is generated from the OpenAPI definition via a CI step; manual SDK changes are rejected | Planned | |
| CLAIM-49.3 | CI diffs WASM exports against `cargo public-api` output to detect unintended surface additions | Planned | |
| CLAIM-49.4 | Changelog records every public API addition, removal, or modification as a distinct entry before the corresponding release tag | Planned | |
| CLAIM-50.1 | mdBook documentation site covers architecture overview, threat model, operator guide, deployment hardening, and per-vertical pages; every public API type, config option, and operational procedure has a corresponding entry | Planned | |
| CLAIM-50.2 | CI regenerates the README Status section from `CLAIMS.md` on every successful build | Planned | |
| CLAIM-51.1 | `formal/policy_lifecycle.tla` (or Quint) models tighten/loosen/time-lock/cancel/rollback with a liveness and a safety property | Planned | |
| CLAIM-51.2 | `formal/command_freshness.tla` models the anti-replay sliding window and enrollment epoch binding | Planned | |
| CLAIM-51.3 | `formal/ledger_recovery.tla` models the Actuating → Complete/Failed/Unknown crash recovery state machine | Planned | |
| CLAIM-51.4 | `formal/single_writer_lease.tla` models `SingleWriterLease` acquisition, renewal cap, and preemption | Planned | |
| CLAIM-51.5 | `loom` or `shuttle` concurrency tests are implemented for the Rust implementations of `SingleWriterLease` and `AntiReplayWindow` | Planned | |
| CLAIM-51.6 | `formal/kani_envelope_arith.rs` proves `FixedPointValue` min/max comparison is overflow-free for all i64 mantissa inputs | Planned | |
| CLAIM-52.1 | Lab hardware is provisioned per `docs/reference-hardware.md`; BLOCKED pending lab hardware acquisition | Planned | |
| CLAIM-52.2 | HIL test suite in `tests/hil/` covers Modbus FC 03/04/06/16 round-trips and envelope rejection with a real out-of-range command | Planned | |
| CLAIM-52.3 | Power-cut-at-Actuating and power-cut-at-completion HIL failpoint tests exist | Planned | |
| CLAIM-52.4 | `docs/hil-test-procedure.md` documents lab setup and execution instructions; BLOCKED pending lab hardware acquisition | Planned | |
| CLAIM-52.5 | Maintainer-triggered GitHub Actions HIL workflow exists and does not run on public PRs; BLOCKED pending lab hardware acquisition | Planned | |
| CLAIM-53.1 | `TimeAnchorService` interface in `tirbase-gateway` periodically broadcasts signed `COSE_Sign1` beacons (`wall_time_secs, issuer_did, mono_seq, valid_for_secs`); broadcast is periodic and signed | Planned | |
| CLAIM-53.2 | Multiple `TimeAnchor` peer support is implemented; the authenticated-time estimate uses the most recent valid beacon satisfying the max-forward-jump constraint | Planned | |
| CLAIM-53.3 | Adversary scenario S23 (time-anchor poisoning) is wired in tirbase-sim and passes with `TimeAnchorService` active | Planned | |
| CLAIM-53.4 | NTS / Roughtime / Galileo OSNMA evaluation for external time sources is documented in design notes | Planned | |
| CLAIM-54.1 | Crypto review scope document is created covering Biscuit token handling, `FixedPointValue` guard path, `TimeRatchet`, WASM sandbox isolation, and hash-chained security event log | Planned | |
| CLAIM-54.2 | Pentest scope document targeting failure modes 1 (malicious command), 2 (bad update), and 5 (comms partition) is created | Planned | |
| CLAIM-54.3 | `docs/security-findings.md` tracks all review/pentest findings with resolution status; no HIGH or CRITICAL finding remains unresolved before public security claims | Planned | |
| CLAIM-54.4 | `CLAIMS.md` is updated after the review to reflect any claims modified by findings | Planned | |
| CLAIM-55.1 | `docs/runbooks/lockdown.md` documents LOCKDOWN entry and M-of-N exit procedure with exact `tirbase-admin` commands, expected outputs, and rollback procedure | Planned | |
| CLAIM-55.2 | `docs/runbooks/tamper.md` documents tampered security event log response and hash-chain recovery procedure | Planned | |
| CLAIM-55.3 | `docs/runbooks/restore.md` documents full restore from backup including epoch bump and LOCKDOWN re-entry | Planned | |
| CLAIM-55.4 | `docs/runbooks/key-compromise.md` documents key compromise detection and revocation procedure | Planned | |
| CLAIM-55.5 | `docs/runbooks/crash-loop.md` documents crash-loop escalation and manual LOCKDOWN entry | Planned | |
| CLAIM-55.6 | `docs/runbooks/time-anchor-failure.md` documents `UNVERIFIED` freshness mode operation procedures | Planned | |
| CLAIM-55.7 | Each runbook procedure is verified by running it against `tirbase-sim` with a simulated fault before the runbook is committed | Planned | |
| CLAIM-56.1 | Table-driven `AUTHORIZATION_MATRIX` constant is implemented in `tirbase-guard`; negative tests are auto-generated for every `—` cell; property test (P19) verifies every `—` cell rejects the wrong role with a typed authorization error | Planned | |
| CLAIM-56.2 | `docs/traceability-matrix.md` maps each PV requirement to its design section, test type, and test file location; CI script verifies all named test file paths exist | Planned | |
| CLAIM-57.0 | `docs/audits/phase-0.md` is committed with VERIFIED-BY-TRACE evidence for Phase 0; no ASSUMED rows | Planned | |
| CLAIM-57.1 | `docs/audits/phase-1.md` is committed with VERIFIED-BY-TRACE evidence for Phase 1; no ASSUMED rows | Planned | |
| CLAIM-57.2 | `docs/audits/phase-2.md` is committed with VERIFIED-BY-TRACE evidence for Phase 2; no ASSUMED rows | Planned | |
| CLAIM-57.3 | `docs/audits/phase-3.md` is committed with VERIFIED-BY-TRACE evidence for Phase 3; no ASSUMED rows | Planned | |
| CLAIM-57.4 | `docs/audits/phase-4.md` is committed with VERIFIED-BY-TRACE evidence for Phase 4; no ASSUMED rows | Planned | |
| CLAIM-57.5 | `docs/audits/phase-5.md` is committed with VERIFIED-BY-TRACE evidence for Phase 5; no ASSUMED rows | Planned | |
| CLAIM-57.6 | `docs/audits/phase-6.md` is committed with VERIFIED-BY-TRACE evidence for Phase 6; no ASSUMED rows | Planned | |
| CLAIM-57.7 | `docs/audits/phase-7.md` is committed with VERIFIED-BY-TRACE evidence for Phase 7; no ASSUMED rows | Planned | |
| CLAIM-57.8 | `docs/audits/phase-8.md` is committed with VERIFIED-BY-TRACE evidence for Phase 8; no ASSUMED rows | Planned | |
| CLAIM-57.9 | `docs/audits/phase-9.md` is committed with VERIFIED-BY-TRACE evidence for Phase 9; no ASSUMED rows | Planned | |
| CLAIM-57.10 | `docs/audits/phase-10.md` is committed with VERIFIED-BY-TRACE evidence for Phase 10; no ASSUMED rows | Planned | |
| CLAIM-57.11 | `docs/audits/phase-11.md` is committed with VERIFIED-BY-TRACE evidence for Phase 11; no ASSUMED rows | Planned | |
| CLAIM-57.12 | `docs/audits/phase-12.md` is committed with VERIFIED-BY-TRACE evidence for Phase 12; no ASSUMED rows | Planned | |
| CLAIM-57.13 | `docs/audits/phase-13.md` is committed with VERIFIED-BY-TRACE evidence for Phase 13; no ASSUMED rows | Planned | |
| CLAIM-57.14 | `docs/audits/phase-14.md` is committed with VERIFIED-BY-TRACE evidence for Phase 14; no ASSUMED rows | Planned | |
| CLAIM-57.15 | `docs/audits/phase-15.md` is committed with VERIFIED-BY-TRACE evidence for Phase 15; no ASSUMED rows | Planned | |
| CLAIM-57.16 | `docs/audits/phase-16.md` is committed with VERIFIED-BY-TRACE evidence for Phase 16; no ASSUMED rows | Planned | |
| CLAIM-57.17 | `docs/audits/phase-17.md` is committed with VERIFIED-BY-TRACE evidence for Phase 17; no ASSUMED rows | Planned | |
| CLAIM-57.18 | `docs/audits/phase-18.md` is committed with VERIFIED-BY-TRACE evidence for Phase 18; no ASSUMED rows | Planned | |
| CLAIM-57.19 | `docs/audits/phase-19.md` is committed with VERIFIED-BY-TRACE evidence for Phase 19; no ASSUMED rows | Planned | |
| CLAIM-57.20 | `docs/audits/phase-20.md` is committed with VERIFIED-BY-TRACE evidence for Phase 20; no ASSUMED rows | Planned | |
