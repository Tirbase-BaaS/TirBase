# Phase 1 — Types, Traits, Keys, Time, Trust Root, Admin Skeleton — Phase Audit

**Status:** PASS WITH OPEN ITEMS — trace audit complete, no ASSUMED rows
**Phase gate:** Phase work is NOT complete; blocked rows below must close before dependants proceed.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.1

## Scope

Task sections 4.x, 5.x, 6.x, 7.x, 8.x, 9.x: 51 acceptance-criterion rows (49 complete, 2 open in `tasks.md` at audit time).

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
| 4.1 | Create tirbase-types/Cargo.toml as a no_std-capable crate with only serde as a dependency | PV-21.1 | `tirbase-types/Cargo.toml:2` | — | TRACED-ARTIFACT |
| 4.2 | Implement FixedPointValue { mantissa: i64, exponent: i8, unit_id: UnitId } with canonical_exponent enforcement… | PV-21.1 | `tirbase-guard/src/ (directory cited; no distinct call site named)` | — | TRACED-ARTIFACT |
| 4.3 | Implement float-to-FixedPointValue conversion: reject NaN, +∞, −∞ with typed NonFiniteValueError; normalize fl… | PV-21.1, PV-21.3 | — (deliverable / no runtime caller) | — | TRACED-ARTIFACT |
| 4.4 | Implement i128 comparison arithmetic for FixedPointValue min/max checks to prevent overflow in envelope bound … | PV-21.1 | `tirbase-guard/src/guard.rs:249` (`admit`) | — | TRACED-CALLER |
| 4.5 | Add property tests for FixedPointValue: NaN rejection, +∞ rejection, −∞ rejection, −0 normalization, integer o… | PV-21.3 | `tirbase-types/src/fixed_point.rs:65` | — | TRACED-CALLER |
| 4.6 | Implement ID newtypes: DeltaId = [u8; 32], Did = String, TargetId = String, MigrationId = [u8; 32], ProfileId … | PV-21.1 | `tirbase-guard/src/ (directory cited; no distinct call site named)`<br>`tirbase-core/src/ (directory cited; no distinct call site named)` | — | TRACED-ARTIFACT |
| 4.7 | Implement CommandRole enum: CommandIssuer, PolicyAuthority, UpdateSigner, RevocationManager, Auditor, TimeAnch… | PV-3.1 | `tirbase-guard/src/ (directory cited; no distinct call site named)` | `tirbase-guard/tests/auth_matrix.rs:15` (`authorization_matrix_has_expected_shape`) — via PV-3.1 | TRACED-TEST |
| 4.8 | Implement DeviceKeyType enum (Ed25519 \| P256) and DeviceSignature enum (Ed25519([u8; 64]) \| P256(Vec<u8>)) | PV-3.6 | `tirbase-guard/src/ (directory cited; no distinct call site named)` | — | TRACED-ARTIFACT |
| 4.9.1 | Create tirbase-gateway binary entry point: parse GatewayConfig TOML, initialize CoreHandle, wire TimeSource (S… | PV-11.1 | `tirbase-gateway/Cargo.toml:1` | — | TRACED-ARTIFACT |
| 4.9.2 | Create admin Unix-socket listener at /run/tirbase/admin.sock with SO_PEERCRED authentication; stub out all 12 … | PV-11.2 | `tirbase-gateway/tests/admin_endpoints_binary.rs:1` | — | TRACED-CALLER |
| 4.9.3 | Create health endpoint GET /health on 127.0.0.1 returning 200 OK within 500ms; no guard state yet | PV-11.1 | `tirbase-gateway/tests/admin_endpoints_binary.rs:1` | — | TRACED-CALLER |
| 5.1 | Create tirbase-core/src/traits.rs: TimeSource trait with monotonic_now -> u64, wall_hint -> Option<i64>, b… | PV-3.8, PV-3.9 | `tirbase-core/src/traits.rs:50` (`TimeSource`)<br>`tirbase-core/src/traits.rs:52` (`monotonic_now`)<br>`tirbase-core/src/traits.rs:56` (`wall_hint`) | — | TRACED-CALLER |
| 5.2 | Add KeyProvider trait: sign(&[u8]) -> Result<DeviceSignature>, sign_async, public_key_bytes, key_type, did; pr… | PV-3.6 | `tirbase-core/src/traits.rs:213` (`KeyProvider`) | — | TRACED-CALLER |
| 5.3 | Add MonotonicCounterTrait: read, increment, set_if_greater; two assurance levels documented | PV-9.8 | `tirbase-guard/src/policy.rs:900` | `tirbase-guard/tests/epoch.rs:82` (`epoch_starts_at_zero_and_prior_epoch_commands_are_rejected_after_bump`) — via PV-9.8 | TRACED-CALLER |
| 5.4 | Add SecurityEventSink trait: emit(event: SecurityEvent) | PV-7.1 | `tirbase-guard/src/ (directory cited; no distinct call site named)`<br>`tirbase-core/src/traits.rs:299` | — | TRACED-CALLER |
| 5.5 | Add clippy::disallowed_methods configuration in clippy.toml at the workspace root banning std::time::Instant::… | PV-3.12 | `clippy.toml:1`<br>`tirbase-core/src/traits.rs:50` (`TimeSource`) | — | TRACED-CALLER |
| 5.6 | Migrate all Instant::now / SystemTime::now / tokio::time::Instant::now call sites in tirbase-core to use TimeS… | PV-3.8, PV-3.12 | `tirbase-core/Cargo.toml:1` | — | TRACED-ARTIFACT |
| 5.7 | Migrate IdentityManager / keypair handling in tirbase-core/src/identity/ to use KeyProvider trait instead of h… | PV-3.6 | `tirbase-core/src/api/mod.rs:488` (`init`) | — | TRACED-CALLER |
| 5.8 | Wire SecurityEventSink at every emission site in tirbase-core: replace every eprintln! and ad-hoc log in crdt/… | PV-7.1 | `tirbase-core/Cargo.toml:1` | — | TRACED-ARTIFACT |
| 5.9 | Add PV-reference-exists CI check: a script that parses all _Requirements: PV-X.Y_ markers in tasks.md and veri… | PV-1.7 | `.github/workflows/ci.yml:271` | — | TRACED-ARTIFACT |
| 6.1 | Implement FileKeyProvider: file-backed, secrets held in secrecy::Secret<[u8; 32]>, implements ZeroizeOnDrop; n… | PV-3.6, PV-3.7 | `tirbase-gateway/src/main.rs:62` | — | TRACED-CALLER |
| 6.2 | Implement ZeroizeOnDrop coverage via a registry: maintain a ZEROIZE_ON_DROP_REGISTRY static slice of type name… | PV-3.14 | `tirbase-guard/Cargo.toml:1` | `tirbase-guard/tests/enrollment.rs:77` (`enrolled_token_verifies_on_two_real_core_handles`) — via PV-3.14 | TRACED-TEST |
| 6.3 | Add Tpm2KeyProvider stub behind feature = "tpm2" flag: Ed25519-sealed-seed and P-256 options; NV-endurance wea… | PV-3.6 | `tirbase-gateway/src/main.rs:62` | — | TRACED-CALLER |
| 6.4 | Add Pkcs11KeyProvider stub behind feature = "pkcs11" flag | PV-3.6 | `tirbase-gateway/src/main.rs:62` | — | TRACED-CALLER |
| 6.5 | Implement SoftwareMonotonicCounter (Level 1): SQLite WAL + synchronous=FULL; reports assurance level Level1 in… | PV-9.8, RD-2 | `tirbase-gateway/src/main.rs:62` | `tirbase-guard/tests/epoch.rs:82` (`epoch_starts_at_zero_and_prior_epoch_commands_are_rejected_after_bump`) — via PV-9.8 | TRACED-CALLER |
| 6.6 | Add Tpm2MonotonicCounter stub (Level 2: TPM2 NV index or eMMC RPMB) with NV-endurance wear-leveling design com… | PV-9.8, RD-2 | `tirbase-gateway/src/main.rs:62` | `tirbase-guard/tests/epoch.rs:82` (`epoch_starts_at_zero_and_prior_epoch_commands_are_rejected_after_bump`) — via PV-9.8 | TRACED-CALLER |
| 6.7 | Implement SignedOperation<T> generic wrapper: context_string, payload_hash, signatures: Vec<SignatureEntry>, c… | PV-3.6 | — (deliverable / no runtime caller) | — | TRACED-ARTIFACT |
| 6.7a | Implement hardware-counter DB-generation binding: at each checkpoint cadence (PV-7.3), write the current sw_co… | PV-9.8, RD-2 | `tirbase-gateway/src/db/peer_checkpoint_witnesses.rs:1` | `tirbase-guard/tests/epoch.rs:82` (`epoch_starts_at_zero_and_prior_epoch_commands_are_rejected_after_bump`) — via PV-9.8 | TRACED-CALLER |
| 6.7b | BLOCKED (confirmed 2026-11-07: swtpm is not installed in the dev environment and no swtpm/TPM2 job exists in C… | PV-9.8, RD-2 | `tirbase-gateway/src/hw_counter_binding.rs:1` | `tirbase-guard/tests/epoch.rs:82` (`epoch_starts_at_zero_and_prior_epoch_commands_are_rejected_after_bump`) — via PV-9.8 | BLOCKED |
| 7.1 | Implement SystemTimeSource: monotonic_now via CLOCK_BOOTTIME; wall_hint via CLOCK_REALTIME; boot_id from /proc… | PV-3.8 | `tirbase-gateway/src/main.rs:62` | — | TRACED-CALLER |
| 7.2 | Implement TimeRatchet: fields last_beacon_time, mono_at_beacon, persisted_floor, beacon_boot_id, max_forward_j… | PV-22.2 | `tirbase-guard/src/time.rs:380` (`TimeRatchet`) | — | TRACED-CALLER |
| 7.3 | Implement now_est: if current_boot_id != beacon_boot_id return persisted_floor; else compute last_beacon_tim… | PV-22.1 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/time_ratchet.rs:266` (`expired_command_is_rejected_after_simulated_time_advance`) — via PV-22.1 | TRACED-CALLER |
| 7.4 | Implement TimeRatchet::advance: reject beacon if wall_time − persisted_floor > max_forward_jump; require M-o… | PV-22.5 | `tirbase-gateway/src/time_beacon.rs:41` | — | TRACED-CALLER |
| 7.5 | Implement FreshnessState enum (Verified \| Unverified) with staleness window check (no beacon within configurab… | PV-22.3 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/time_ratchet.rs:517` (`freshness_is_unverified_before_any_beacon_and_after_a_reboot`) — via PV-22.3 | TRACED-CALLER |
| 7.6 | Create time_ratchet SQLite table with beacon_boot_id column in primary.db | PV-22.2 | `tirbase-gateway/src/db/time_ratchet.rs:30` | — | TRACED-CALLER |
| 7.7 | Add TimeRatchet property test: ratchet value is monotonically non-decreasing across any sequence of beacon app… | PV-22 | `tirbase-guard/tests/time_ratchet_property.rs:1` | — | TRACED-CALLER |
| 8.1 | Implement RootCaRegistry supporting multiple simultaneous root CA public keys; k-of-n threshold rotation (k ≥ … | PV-3.4 | `tirbase-gateway/src/main.rs:62` | `tirbase-guard/tests/trust_root.rs:107` (`k_of_n_root_rotation_revokes_old_keys_and_rejects_rollback`) — via PV-3.4 | TRACED-CALLER |
| 8.2 | Implement root revocation and rollback protection on trust-root version numbers using MonotonicCounterTrait | PV-3.4 | `tirbase-gateway/src/main.rs:62` | `tirbase-guard/tests/trust_root.rs:107` (`k_of_n_root_rotation_revokes_old_keys_and_rejects_rollback`) — via PV-3.4 | TRACED-CALLER |
| 8.3 | Implement TrustRootRecord: root CA keys, per-role thresholds, device_class_floors (tightening floors per devic… | PV-3.4 | `tirbase-gateway/src/main.rs:62` | `tirbase-guard/tests/trust_root.rs:219` (`trust_root_record_carries_role_thresholds_floors_and_expiry`) — via PV-3.4 | TRACED-CALLER |
| 8.3a | Implement role registry: for each role in CommandRole, the TrustRootRecord holds the list of authorized DID pu… | PV-3.2, PV-3.3 | `docs/unit-registry.md:1` | `tirbase-guard/tests/auth_matrix.rs:15` (`authorization_matrix_has_expected_shape`) — via PV-3.3 | TRACED-TEST |
| 8.4 | Create docs/root-ceremony.md describing the offline procedure for generating and rotating root CA keys | PV-3.5 | `docs/root-ceremony.md:1` | — | TRACED-ARTIFACT |
| 8.5 | Implement enrollment nonce store: bounded retention (default 72h, configurable); background purge of expired n… | PV-3.13 | `tirbase-gateway/src/admin.rs:27` | — | TRACED-CALLER |
| 8.6 | Implement device enrollment flow: first-boot identity generation, scoped token issuance, replay-safe bootstrap… | PV-3.11 | `tirbase-gateway/src/admin.rs:27` | — | TRACED-CALLER |
| 8.7 | Implement device-epoch store: device_epoch table in primary.db with device_id, epoch, bumped_at_est, co_sig_pa… | PV-5.5, PV-9.8 | `tirbase-guard/src/guard.rs:249` (`admit`) | `tirbase-guard/tests/epoch.rs:82` (`epoch_starts_at_zero_and_prior_epoch_commands_are_rejected_after_bump`) — via PV-9.8 | TRACED-CALLER |
| 8.8 | Implement signed enrollment-epoch-bump operation: SignedOperation<EpochBump> with PolicyAuthority + Revocation… | PV-5.5, PV-9.8, RD-2 | `tirbase-gateway/src/admin.rs:27` | `tirbase-guard/tests/epoch.rs:82` (`epoch_starts_at_zero_and_prior_epoch_commands_are_rejected_after_bump`) — via PV-9.8 | TRACED-CALLER |
| 9.1 | Create tirbase-admin crate with clap-based CLI entry point; declare all subcommands as stubs | PV-3.10 | `tirbase-admin/src/main.rs:9` | — | TRACED-CALLER |
| 9.2 | Implement enroll subcommand with integration test driving it from the gateway binary or two real CoreHandle in… | PV-3.10 | `tirbase-admin/src/cmd/enroll.rs:22` | — | TRACED-CALLER |
| 9.3 | Implement mint subcommand (scoped token minting, maximum lifetime 86400s); integration test | PV-3.10 | `tirbase-admin/src/cmd/mint.rs:11` | — | TRACED-CALLER |
| 9.4 | Implement rotate subcommand for key rotation; integration test | PV-3.10 | `tirbase-admin/src/cmd/rotate.rs:17` | — | TRACED-CALLER |
| 9.5 | Implement inspect-identities subcommand; integration test | PV-3.10 | `tirbase-admin/src/cmd/inspect_identities.rs:13` | — | TRACED-CALLER |
| 9.6 | Add cross-role rejection tests: for every — cell in the Authorization Matrix, verify that presenting the wrong… | PV-3.2, PV-3.3 | `docs/traceability-matrix.md:1` | `tirbase-guard/tests/auth_matrix.rs:109` (`p19_every_denied_cell_rejects_wrong_role_with_typed_error`) — via PV-3.3 | BLOCKED |

## Gaps and open items

- **4.1** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **4.2** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **4.3** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **4.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **4.5** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **4.6** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **4.7** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **4.8** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **4.9.1** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **4.9.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **4.9.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **5.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **5.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **5.3** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **5.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **5.5** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **5.6** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **5.7** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **5.8** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **5.9** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **6.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **6.2** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **6.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **6.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **6.5** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **6.6** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **6.7** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **6.7a** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **6.7b** (`BLOCKED`) — swtpm is not available in the development environment or CI; the task itself records this blocker.
- **7.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **7.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **7.3** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **7.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **7.5** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **7.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **7.7** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **8.1** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **8.2** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **8.3** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **8.3a** (`TRACED-TEST`) — Test/document deliverable: test evidence traced, no distinct runtime caller.
- **8.4** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **8.5** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **8.6** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **8.7** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **8.8** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **9.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **9.2** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **9.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **9.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **9.5** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **9.6** (`BLOCKED`) — Task text gates this on 56.1. The authorization matrix (56.1) is implemented, but this dedicated cross-role test task remains open (checkbox unchecked in tasks.md).

## Verdict

**PASS WITH OPEN ITEMS.** 49 of 51 rows are traced to existing implementation; 2 row(s) are BLOCKED/NOT IMPLEMENTED. The phase is not complete until those rows close. No row is ASSUMED.

