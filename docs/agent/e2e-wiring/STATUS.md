# E2E Wiring — STATUS ledger

**Workstream:** 1–7 of 8 (inventory + foundations; TypeScript manager ops + gateway admin SDK; live Tier-1 quorum + spatial diversity; revocation gossip accumulation + M-of-N Saturate termination; CCE + Side-Car replay/recovery; fragmentation + multi-hop relay + BLE bridge + Noise 0-RTT/rotation; DRR floors + per-table compaction + outbound-queue guarantees)
**Branch:** `main`
**Baseline HEAD:** `5bea300` (WS4 started from `36ba045`)
**Last updated:** 2026-11-13

This ledger is the single source of truth for the wiring effort. It records the verified baseline,
every gap/PARTIAL annotation found in the repository, each item's classification under the charter
(`docs/agent/e2e-wiring/00-charter.md`), the proof that exists today, and the workstream that owns
closure. Rows are updated only with executable evidence.

---

## 1. Verified baseline (exact commands and results)

All commands run on this machine (macOS, cargo 1.97.1, Node 24.18.0, wasm-pack 0.15.0), from the
repository root, with `set -o pipefail` so a pipe cannot mask a non-zero exit.

| # | Command | Result on unmodified HEAD | Status after WS1 |
|---|---------|---------------------------|------------------|
| 1 | `cargo test -p tirbase-core --features native` | **715 passed / 1 failed** (`migration::profile::tests::conformance_corpus_hash_matches_committed_corpus`: left `[10,73,116,89,…]`, pin `[129,150,198,30,…]`) | **718 passed / 0 failed**, plus 8/1/2/5/1 integration tests all pass |
| 2 | `cargo test -p tirbase-gateway` | **did not compile** (`tests/openapi.rs` called a helper without `()`); after that fix, 66 lib tests passed and `admin_policy_mode_simulate_challenge_and_unimplemented_endpoints_over_binary` failed (`UNCONFIGURED` vs `BLOCKED_PENDING_RFC_TUF`) | **all suites pass** (66 lib + 8/6/6/3/5/4/2/2/7/5/2/2/2/1/5/4/8/2/6/1/0/4/6/3/1/1/4/8/1/3/2/4/5/1/4/5/4/0/2/2/7/7/3/6) |
| 3 | `cd tirbase-sdk && npm run build:wasm` | **failed** `E0063` missing field `update_signer_public_key` at `tirbase-core/src/lib.rs:275` | **succeeds** (~42 s) |
| 4 | `cd tirbase-sdk && npx jest` | **84 passed / 5 failed** — WASM `core_init(":memory:")` panicked at `api/mod.rs` `.expect("idb store must exist for non-:memory: path")` | **90 passed / 90 total**, 2/2 suites |
| 5 | `cargo check -p tirbase-core --no-default-features --features wasm --target wasm32-unknown-unknown` | (not run at baseline; build failed at step 3) | **Finished**, only the pre-existing `proc-macro-error2` future-incompat warning |
| 6 | `cargo test -p tirbase-core --features native --lib api::real_mesh_tests` | 11 pass (pre-existing tests) | **12 pass** (new JSON projection test) |
| 7 | `cargo test -p tirbase-core --features native --lib tests::api_parity` | 6 pass, but the old suite asserted hand-maintained lists, not sources | **6 pass over parsed sources**; drift injected on purpose → **2 failed / exit 101**, then file restored byte-identically |
| 8 | `npx jest src/__tests__/tirbase-wasm.test.ts` | (suite failing at step 4) | **9/9 pass**, includes the new `write-read-roundtrip` case |

### Pre-existing defects fixed in WS1 (they blocked every foundation)

These were repaired rather than documented, because B1/B5 and the CI gates cannot be green
otherwise. Each is a real repository defect on `5bea300`, not a test weakened to fit.

| Defect | File | Fix | Why it is not a workaround |
|--------|------|-----|----------------------------|
| WASM build missing struct field | `tirbase-core/src/lib.rs` | added `update_signer_public_key: None` to the WASM `DeploymentConfig` initialiser | brings the WASM initialiser in line with the native one |
| Gateway test does not compile | `tirbase-gateway/tests/openapi.rs` | added the missing `()` | the helper returns a future; this is a caller bug |
| Stale corpus pin | `tirbase-core/src/migration/profile.rs` | pin corrected to SHA-256 `0a497459…03e9be` (matches `shasum -a 256` of the committed corpus) | commit `dbb6c61` reformatted the corpus without updating the pin; the code is unchanged |
| Gateway status string contradicted its own test | `tirbase-gateway/src/admin.rs` | unconfigured `self_update` now reports `BLOCKED_PENDING_RFC_TUF` | honest status; matches the existing assertion |
| WASM `:memory:` panic | `tirbase-core/src/migration/{mod,quarantine,sidecar}.rs`, `src/api/mod.rs` | ledgers take `Option<Rc<IdbStore>>` with an in-memory `BTreeMap` fallback; `SchemaMigrationEngine::new` takes `Option<Rc<…>>` and the caller passes `store.idb_store_rc()` | `:memory:` is a supported production ledger mode; panicking on it was the bug, and Node has no IndexedDB |

No test was skipped, weakened, or `#[ignore]`d; no proptest case count changed.

---

## 2. Inventory

Source annotations scanned: all 35 `[Status: …]` markers in `README.md`, the `PARTIAL` statuses in
`tirbase-core/tests/README.md`, the documented gaps in `tirbase-core/src/tests/properties.rs`,
`CLAIMS.md` `Planned` rows, `docs/traceability-matrix.md`, and `docs/audits/*.md`.
`docs/traceability-matrix.md` contains no `PARTIAL`/gap rows (it uses `VERIFIED-BY-TRACE` /
`TRACED-*`), so it contributes no inventory items; its audit annotations are covered in
INV-45…INV-49.

Classifications per charter: `wired`, `under-proven`, `genuinely-unwired`, `stale-docs`,
`hardware-blocked`.

### 2.1 README claims

| ID | Claim (README line) | Production path / files | Current state | Proving test / evidence | WS | Commit |
|----|---------------------|-------------------------|---------------|--------------------------|----|--------|
| INV-01 | Status legend defines the three categories (L14) | `README.md` | `wired` (documentation) | n/a — definition only | 8 | — |
| INV-02 | Local DB syncs to peers and, when scoped, to cloud (L22–23) | `api::write` → `MeshTransport` broadcast; cloud path `api::cloud_sync_tests` | `under-proven` | each half is proven separately (`real_mesh_tests::…projected…`, `cloud_sync_tests::*`); no single test covers both | 4 | — |
| INV-03 | One Rust lib, two targets; same lib compiles native + WASM (L84) | `tirbase-core` default/native vs `wasm` feature | `stale-docs` (marker outdated) | `wasm-pack build` (step 3) + `cargo check --target wasm32-unknown-unknown` (step 5) | 1 | WS1 |
| INV-04 | API is identical across targets, differences are compile-time (L88) | `impl CoreHandle` ↔ `lib.rs` exports ↔ `WasmCore` | `wired` | `tests::api_parity` (source-parsed, 6 tests) + drift injection failed it | 1 | WS1 |
| INV-05 | Cross-device scalar LWW conflict resolution (L109) | `api::write` → `receive_inbound` merge → `read` | `wired` | `api::real_mesh_tests::two_devices_concurrent_scalar_write_lww_wins_over_real_mesh` (2 real Swarms) | 1 | WS1 |
| INV-06 | Cross-device RGA concurrent list edits (L113) | no public list-write API; RGA exists only in `crdt` internals | `genuinely-unwired` | property tests exercise RGA at engine level; nothing reaches it from `CoreHandle`/SDK | 2 | — |
| INV-07 | BLE bridge for LAN-less/offline topologies (L123) | `transport/ble.rs` `run_ble_bridge` ← `MeshTransport::send_delta`/`bind_ble_link` ← `DeploymentConfig::mesh_ble_enabled` | **`wired` (emulated link); radio `hardware-blocked`** | `transport::tests::ble_bridge_carries_a_fragmented_delta_over_an_emulated_link` (§3.9); real radio test `#[ignore]`d and not run | 6 | WS6 |
| INV-08 | Multi-hop relay topologies (L126) | `transport/discovery.rs` `find_relay_peer`, `MeshTransport::relay_decision` ← Swarm poll task re-publish | **`wired`** | `api::network_wiring_mesh_tests::three_node_chain_relays_a_delta_with_bounded_hops_and_no_duplicates` (§3.9): A–B–C chain, hop bounded, loop dropped, one forward | 6 | WS6 |
| INV-09 | MTU discovery + per-path fragmentation (L138) | `transport/{session,fragment}.rs`, production send | `wired` | `real_mesh_tests` low-MTU round-trip cases (Item 22 in `tests/README.md`) | 1 | — |
| INV-10 | 0-RTT session resumption (L154) | `transport/session.rs` `initiate_with_0rtt` / `respond` ← `MeshTransport::{initiate_session_with_payload, accept_noise_session}` | **`wired`** | `api::network_wiring_mesh_tests::{noise_session_resumes_with_0rtt_and_rotates_keys_in_place, resumption_negative_cases_fall_back_or_fail_closed}` (§3.9) | 6 | WS6 |
| INV-11 | Key rotation and session-cache invalidation (L164/167) | `transport/session.rs` `rotate_keys` ← `spawn_scheduler_tick_loop` → `tick_key_rotation` | **`wired`** | `noise_session_resumes_with_0rtt_and_rotates_keys_in_place` (§3.9): rekey in place, data continues, pre-rotation frame rejected | 6 | WS6 |
| INV-12 | SDK surfaces real-time trust levels (L176) | `tirbase-sdk` `onTrustLevelChanged` ← `core_poll_events` | **`wired`** | `tirbase-manager-ops.wasm.test.ts`: `presentToken` moves a real WASM instance to `VERIFIED` and emits `trust-level-changed`; an invalid token leaves `UNVERIFIED` plus the unverified warning; a peer revocation no longer mutates the local level (`TrustLevelChanged` now carries `did`) | 7 | WS2 |
| INV-13 | M-of-N revocation accumulates gossip across peers (L235) | `auth` revocation collector ← `receive_inbound` revocation deltas | **`wired`** | `api::revocation_saturate_mesh_tests::{partial_revocation_deltas_accumulate_across_offline_managers, below_threshold_never_revokes_and_threshold_signature_always_does, revocation_negative_cases_fail_closed}` (§3.7): three real Swarms produce partial deltas while partitioned and accumulate to M=2/3 over the wire | 4 | WS4 |
| INV-14 | A node one gossip round from the mesh isolates a revoked device (L255) | `auth`/`api` revocation application | **`wired`** | `api::revocation_saturate_mesh_tests::partial_revocation_deltas_accumulate_across_offline_managers` asserts isolation reaches every peer within one production gossip round of the first observer (1 s scheduler epoch + 50 ms drain) and the revoked author's Deltas being rejected at `apply_incoming_delta` | 4 | WS4 |
| INV-15 | Contamination forward trace identifies tainted devices (L260/262) | `contamination` → `verify_contamination` | **`wired`** | `api::contamination_mesh_tests::{revoked_author_over_real_mesh_taints_descendants_appends_tags_and_emits_events, composite_incident_over_real_mesh_merges_decomposes_and_decontaminates}` — real revocation over the mesh → append-only CONTAMINATED tags on every reachable descendant, ICO/Composite ICO, incident events (§3.8) | 6 | WS5 |
| INV-16 | Sidecar replay after corrected migration, tagged on success (L279) | `migration::SideCarLedger::replay_sidecar` | **`wired`** | `api::contamination_mesh_tests::sidecar_replay_on_corrected_migration_over_real_mesh_projects_replayed_rows` — bad migration + revocation + captured writes over the real mesh, corrected migration over the mesh, replay in recorded-timestamp order, rows readable through `read()` (§3.8) | 6 | WS5 |
| INV-17 | Replay conflicts flagged for manual resolution without abort (L286) | `migration/sidecar.rs` conflict counting | **`wired`** | `api::contamination_mesh_tests::sidecar_replay_conflict_is_observable_and_does_not_stop_other_entries` — a conflicting entry is flagged `CONFLICT`, the rest replay, and `CoreHandle::sidecar_conflicts()` exposes it (§3.8) | 6 | WS5 |
| INV-18 | Tier-1 durability from a live quorum of two devices (L298) | `durability` receipt exchange ← `receive_inbound` | `wired` | `api::real_mesh_tests::two_devices_reach_tier1_durability_via_genuine_receipt_exchange`; WS3 adds a 3-of-4 real-mesh quorum (`three_peers_reach_tier1_via_genuine_receipt_exchange`, §3.6) | 1/3 | WS3 |
| INV-19 | Tier-1 compaction with refetch from Tier-2 on miss (L316/318) | `crdt::maybe_compact`, `store/compaction.rs` | `under-proven` | compaction applies; no test drives a Tier-1 refetch after compaction | 4 | — |
| INV-20 | Outbound queue capacity 100,000 writes (L377) | `durability` outbound queue | `under-proven` | capacity constant asserted; no load test | 4 | — |
| INV-21 | Saturate renewal, expiry auto-demote, M-of-N termination (L406) | `saturate` ← `activate/renew/terminate_saturate_mode` | `wired` | `api::tests::saturate_runtime_lease_expiry_auto_demotes_without_renewal`, Subphase 3.2/3.4 suites | 1 | — |
| INV-22 | DRR scheduler enforces per-device floors (L448) | `transport/scheduler.rs` | `under-proven` | property 12 scheduler-level; no two-Swarm fairness measurement | 5 | — |
| INV-23 | Spare capacity flows to peers that need it (L455/457) | `transport/scheduler.rs` spare accounting | `under-proven` | unit/property only | 5 | — |
| INV-24 | LOW-priority peer guaranteed service within 10 epochs (L460/462) | `transport/scheduler.rs` | `under-proven` | property 13; not measured end-to-end | 5 | — |
| INV-25 | Each table is a separate Automerge document (L464) | `crdt/mod.rs` uses **one** `AutoCommit` with per-table keys | `stale-docs` (claim is false) | inspection: single `self.doc`, `_tirbase_table` root keys; compaction keyed by table name only | 2 | — |
| INV-26 | `CompactionPolicy::None` never compacts (L466) | `store/compaction.rs::should_compact` | `under-proven` | code returns `false`; no test asserts it | 2 | — |
| INV-27 | TypeScript SDK path is WASM → store → mesh (L468) | `tirbase-sdk/src/wasm-bridge.ts` | **`wired`** (WASM → store → peers) | production init now calls `core_init` with the deployment config; `receivePeerMessage` is async, merges a peer's signed Delta through the real WASM inbound path and polls events; `drainOutboundMessages` exposes real outbound frames. Cloud leg remains INV-02 (WS 4) | 7 | WS2 |
| INV-28 | SDK exposes manager operations (fleet, revocation, checkpoint, challenge) (L473) | `tirbase-sdk` delegation table | **`wired`** | `tirbase-manager-ops.wasm.test.ts` (11 tests) drives every manager op on real WASM; `sdk/typescript/test/gateway-admin.e2e.test.mjs` drives all 19 `ADMIN_PATHS`/`OPERATION_IDS` through the generated client against the real gateway binary | 7 | WS2 |
| INV-29 | 22-property suite (10 proptest + 12 deterministic) is wired (L475) | `src/tests/properties.rs`, `Cargo.toml` | `under-proven` | suite runs in CI; several properties are documented gaps (see INV-36…INV-43) | 2 | — |

### 2.2 README property bullets

| ID | Claim | Current state | Evidence | WS |
|----|-------|---------------|----------|----|
| INV-30 | Cross-build convergence (native and WASM produce identical bytes) | `under-proven` | `convergence_tests` are native-only; no WASM execution of the same vectors | 2 |
| INV-31 | Commutativity of concurrent writes (property 2) | `under-proven` | property asserts per-device acceptance, `tests/README.md` marks final-state equality PARTIAL | 2 |
| INV-32 | LWW/RGA conflict properties | `wired` for LWW (INV-05); `genuinely-unwired` for RGA (INV-06) | as above | 2 |
| INV-33 | Contamination completeness (property 8–10) | `wired` | property tests against real SQLite DAG; forward trace test in `contamination` | 1 |
| INV-34 | Composite incident propagation (property 11) | `wired` | property 11 + Subphase 7.5 composite-incident suite | 1 |
| INV-35 | Quotas, DRR floors, M-of-N thresholds (properties 7, 12, 13) | `under-proven` | thresholds proven; DRR/quotas scheduler-level only | 5 |
| INV-36 | Zero-trust migration gate (property 21) | `wired` | production `verify_contamination` gate + property 21 | 1 |
| INV-37 | Schema determinism / canonical hashing (property 15) | `wired` | property 15 + schema printer tests | 1 |
| INV-38 | Saturate state machine (property 20) | `wired` | property 20 + runtime expiry/termination integration tests | 1 |

### 2.3 `tirbase-core/tests/README.md` PARTIAL annotations

| ID | Annotation | Current state | Evidence | WS |
|----|------------|---------------|----------|----|
| INV-39 | Property 2 `PARTIAL` (cross-device acceptance, not final state) | `stale-docs` for LWW, `under-proven` for commutativity | LWW now proven over two Swarms (INV-05); final-state commutativity still unproven | 2 |
| INV-40 | Property 14 `PARTIAL` (Tier-1 only single device) | `stale-docs` | `two_devices_reach_tier1_durability_via_genuine_receipt_exchange`; `three_peers_reach_tier1_via_genuine_receipt_exchange` (K=3 over 4 real Swarms) and the negative quorum/diversity suite in §3.6 | 1/3 | WS3 |
| INV-41 | Item 7 `PARTIAL` (projection gap over real mesh) | `stale-docs` (closed by WS1) | `json_envelope_delta_over_real_mesh_projects_to_peer_store` + existing binary projection test | 1 |
| INV-42 | Cross-Device Mesh `PARTIAL` | `stale-docs` (partly) | Delta projection, Tier-1 and MTU now real; revocation/migration/cloud over the wire remain (WS3/WS4/WS6) | 1 |
| INV-43 | Single-process harness limitation note | `under-proven` | each test uses one process with two Swarms; no cross-process/multi-host run | 3 |

### 2.4 `properties.rs` documented gaps

| ID | Gap | Current state | WS |
|----|-----|---------------|----|
| INV-44 | Property 1: no shared cross-build harness | `stale-docs` — WS1 now provides a real-WASM Node harness and a real-mesh harness; the shared vector run is still missing | 2 |
| INV-45 | Properties 5/14: Tier-1 quorum only single-device | `stale-docs` — live K-of-N across networked peers now proven in §3.6 (single-process loopback; see its limits). The gap comment stays in `properties.rs` for WS8 | 3 |
| INV-46 | Property 20: runtime saturate expiry not exercised in engine | `stale-docs` (INV-21) | 1 |
| INV-47 | Properties 2/3/4: multi-device commutativity / RGA | `under-proven` (2) / `genuinely-unwired` (3–4) | 2 |

### 2.5 `CLAIMS.md` `Planned` rows

| ID | Claim | Current state | Evidence | WS |
|----|-------|---------------|----------|----|
| INV-48 | CLAIM-2.5 nightly `cargo-mutants` job | `genuinely-unwired` | no nightly workflow; no mutation job in `.github/workflows/` | 8 |
| INV-49 | CLAIM-3.4/3.8/3.9/3.10/3.12 (threat model, invariants, event catalog, unit registry, freshness) | `stale-docs` | the files and their CI checks exist (`docs/THREAT_MODEL.md`, `system-invariants.md`, `security-event-catalog.md`, `unit-registry.md`, `freshness-policy.md`); status not updated | 8 |
| INV-50 | CLAIM-4.2/4.5 `FixedPointValue` implementation + property tests | `stale-docs` | `tirbase-types/src/fixed_point.rs` + its property suite exist and run | 8 |
| INV-51 | CLAIM-32.4 WAL checkpoint cadence untested | `under-proven` | constants + `spawn_wal_checkpoint_loop` exist; no cadence test | 4 |
| INV-52 | CLAIM-52.1/52.2/52.3 HIL hardware claims | `hardware-blocked` | `hil_*.rs` tests are `#[ignore]` by design; RD-7 pending | — (external) |

### 2.6 Audit annotations

| ID | Annotation | Current state | WS |
|----|------------|---------------|----|
| INV-53 | `docs/audits/phase-1.md` 6.7b TPM2/swtpm binding | `hardware-blocked` — swtpm absent from dev env and CI | — |
| INV-54 | `docs/audits/phase-1.md` 9.6 dedicated cross-role rejection task | `under-proven` — `p19_every_denied_cell_rejects_wrong_role_with_typed_error` covers the matrix; the task remains open in `tasks.md` | 3 |
| INV-55 | `docs/audits/phase-17.md` 52.1/52.4/52.5 HIL workflow + procedure | `hardware-blocked` (workflow/artefact traced, execution blocked) | — |

---

## 3. Foundations delivered (B1–B5)

| Item | What landed | Files | Verification |
|------|-------------|-------|--------------|
| B1 | Real-WASM SDK round-trip: child-process runner loads the built `--target web` bundle and executes `core_init` → `core_write` → `core_read` → `core_query`; new `write-read-roundtrip` case | `tirbase-sdk/src/__tests__/tirbase-wasm.test.ts` | 9/9 in that suite; full `npx jest` 90/90 |
| B2 | Reusable real-mesh harness extracted from `real_mesh_tests` (`init_mesh_handle`, `connect_peers`, `wait_for_data`, …) | `tirbase-core/src/api/mesh_harness.rs`, `api/mod.rs` | `api::real_mesh_tests` 12/12, no behaviour change |
| B3 | Production-path projection over a real mesh with a **JSON-envelope** signed Delta; binary Automerge projection already covered | `api/mod.rs` (`json_envelope_delta_over_real_mesh_projects_to_peer_store`) | 12/12 real-mesh tests |
| B4 | Source-driven API parity instead of hard-coded lists: parses `impl CoreHandle`, `#[wasm_bindgen]` exports in `lib.rs`, and the TS `WasmCore` interface + `required('core_*')` calls, with an explicit documented exclusion policy | `tirbase-core/src/tests/api_parity.rs` | 6/6 pass; injected rename → 2 tests fail, exit 101, file restored |
| B5 | Mandatory CI gates in the `test` job (no `continue-on-error`, no `|| true`, no `--ignored`): real-mesh suite, projection (binary + JSON), API parity — alongside the pre-existing real-WASM build + SDK tests | `.github/workflows/ci.yml` | local equivalents green (steps 1–8) |

## 3.1 WS2 — TypeScript manager ops + gateway admin SDK (PROMPT 2 of 8)

Scope: `tirbase-sdk/` manager operations and `sdk/typescript/` only. Rows INV-12/INV-27/INV-28.

### What was actually unwired (found, not assumed)

| # | Defect | Fix |
|---|--------|-----|
| 1 | `loadWasmCore` never called `core_init`; the whole SDK ran on `MockWasmCore` | `initialiseCore(mod, config)` performs the real init; `loadWasmCore(config?, wasmUrl?)` forwards `InitConfig` |
| 2 | `core_init` hard-coded M=1/N=1 deployment thresholds, so M-of-N was impossible from WASM | optional 5th `deployment_json` arg (`deny_unknown_fields`), sourced from `InitConfig.deploymentConfig` |
| 3 | Revocation gossip was only enqueued under `#[cfg(test)]`/native, so a WASM device never produced peer revocation bytes | `enqueue_revocation_gossip` unconditional; `core_drain_outbound_messages` + `MeshTransport::drain_outbound_frames` expose the frames; WASM `write()` enqueues outbound |
| 4 | `TrustLevelChanged` had no `did`, so a peer's revocation marked the *local* device REVOKED | event carries `did`; SDK applies it only when `did === localDid()` |
| 5 | `read`/`query` always reported `contaminated: false`; `verify_data` never cleared resolved rows on WASM | both consult the CCE; WASM `verify_data` removes resolved rows (native parity) |
| 6 | Trust-level spelling mismatch (`Unverified` vs `UNVERIFIED`) leaked into the SDK type | `normalizeTrustLevel` at the bridge boundary |
| 7 | wasm-bindgen rejects with bare strings, breaking the SDK's `Error` contract | every export goes through `call`/`callAsync` → `asCoreError()` (`name: 'TirBaseCoreError'`) |
| 8 | The `caveat("disaster-alert")` token had no production minting path, so `activate_saturate_mode` was unreachable outside tests | `create_token_with_caveat` is now an ungated production builder, and the gateway `mint` endpoint issues the token (`caveat: "disaster-alert"`, core allowlist); the fixture no longer needs `test-hooks` (see §3.3) |
| 9 | `initiate_revocation` took a `manager_token` string and never looked at it — any non-blank value authorised a revocation | signature is now `(&self, target_did, manager_token: &[u8], now_secs)`; the token is verified offline against the deployment root CA, expiry is enforced at `now_secs`, and the role must be `RevocationManager` (see §3.2) |

### Tests added (fail-before / pass-after)

| Suite | File | Cases |
|-------|------|-------|
| Real-WASM manager operations | `tirbase-sdk/src/__tests__/tirbase-manager-ops.wasm.test.ts` | 12 |
| Real-gateway admin SDK | `sdk/typescript/test/gateway-admin.e2e.test.mjs` | 8 |

Both run against real artefacts: the SDK suite loads a `wasm-pack --target nodejs` build of the same crate/features as the browser bundle (one module copy per simulated device, so each has its own WASM thread-local `CORE`), and the gateway suite boots `target/debug/tirbase-gateway` with the mTLS remote listener and drives `GatewayAdminClient` over real TLS with a client certificate.

Coverage of the manager surface: `initiateRevocation` (partial delta + real outbound frame, plus rejection of untrusted/expired/wrong-role tokens), two-manager accumulation to the 2-of-3 threshold, contamination incident creation observed by both `pollEvents` and the emitter, `verifyData` root resolution, `adminClose` (archives without certifying), saturate activate/renew/threshold-termination/insufficient-signature rejection, `presentToken` trust transitions + unverified warnings, and `receivePeerMessage` raw-byte peer merge. Gateway coverage: all 19 paths/operation ids, typed success or typed denial for each, `MINT_TTL_EXCEEDED`, anonymous-client handshake rejection.

### Commands and results (this machine)

| Command | Result |
|---------|--------|
| `cd tirbase-sdk && npx jest` | **102 passed / 102**, 3 suites (was 90/90 before; +12 real-WASM manager tests) |
| `cargo test -p tirbase-core --features native` | **719 lib passed / 0 failed** + all integration suites |
| `cargo test -p tirbase-core --features native --lib tests::api_parity` | **6 passed** (parser now also reads `call('core_*')`/`callAsync('core_*')`) |
| `cargo check -p tirbase-core --no-default-features --features wasm --target wasm32-unknown-unknown` | clean (only the pre-existing `proc-macro-error2` future-incompat warning) |
| `cd sdk/typescript && npm test` | **10 passed / 10** (builds the TS SDK, runs the e2e plus the client transport unit tests) |
| `bash scripts/check-gateway-sdk-generated.sh` | **OK** (generator fixed; see below) |
| `cargo +nightly public-api -p tirbase-core` | unchanged surface: the caveat minter is `#[cfg(any(test, feature = "test-hooks"))]`, so no manifest churn |

### Generated gateway SDK drift (pre-existing, repaired)

`scripts/check-gateway-sdk-generated.sh` failed on the starting tree: the generator matched path keys with `^\s{2}`, which is satisfied by the newline before each path line except `paths:` itself, so `/admin/enroll` was silently dropped; the committed sources had also been hand-edited (SPDX headers). The generator now matches `^ {1,2}`, emits the SPDX header, and writes the manifest with stable formatting. Output currently equals the committed sources (19 operations, 19 paths); the manifest commit is a whitespace-only reformat.

### CI

- `test` job: `npm test` (both WASM targets via `pretest`, so the real-WASM suites run) plus an explicit `npm run test:wasm-e2e` step.
- New `gateway-admin-sdk-e2e` job: builds `tirbase-gateway`, installs `sdk/typescript`, runs `npm test` with `TIRBASE_GATEWAY_BIN`.

### Blockers / still-open items (do not mark wired)

1. ~~DISASTER_ALERT token issuance has no operator-facing surface~~ — **fixed** in §3.3: `POST /admin/mint` accepts `caveat: "disaster-alert"`, and the SDK fixture mints it through the production builder with no feature flag.
2. ~~`initiate_revocation` does not verify the manager token~~ — **fixed** in §3.2: the token is verified against the root CA, expiry-checked and role-checked (`RevocationManager`) before any signature is produced or gossiped.
3. **Signed admin operations are exercised to their auth gate, not through it.** `enroll`/`policy`/`lockdown-exit`/`chain-recovery`/`sequence-reset`/`lease-preempt`/`quarantine-replay`/`time-reset`/`unknown-clear`/`restore`/`epoch-bump` require PolicyAuthority or M-of-3 TimeAnchor `SignedOperation` bodies. Re-implementing the guard's canonical encoding in JavaScript would create a second security-critical implementation, so the TS test asserts the typed answer (never 404/501/silent skip) and the signed success paths stay covered by `tirbase-gateway/tests/admin_endpoints_binary.rs`.
4. ~~`sdk/typescript` mTLS requires a hand-written adapter~~ — **fixed** in §3.4: the package ships `createMtlsFetch` (subpath `./mtls`) and `fetchInit` for undici dispatchers; browsers use their own certificate store. Browser *certificate provisioning* is still out of band, because JavaScript cannot attach a client certificate.

### Files

- Core: `src/lib.rs`, `src/api/mod.rs`, `src/transport/mod.rs`, `src/contamination/mod.rs`, `src/auth/biscuit.rs`, `src/auth/revocation.rs`, `src/tests/api_parity.rs`, `examples/wasm_e2e_fixtures.rs`.
- SDK: `src/wasm-bridge.ts`, `src/tirbase.ts`, `src/types.ts`, `src/__helpers__/real-core.ts`, `src/__tests__/tirbase-manager-ops.wasm.test.ts`, `src/__tests__/tirbase.test.ts` (mock implements the two new `WasmCore` members), `src/__tests__/tirbase-wasm.test.ts` (5-arg `coreInit`), `scripts/prepare-wasm-test-package.mjs`, `package.json`.
- Gateway: `examples/admin_e2e_setup.rs`; `sdk/typescript/package.json`, `sdk/typescript/test/gateway-admin.e2e.test.mjs`; `scripts/generate-gateway-sdk.mjs`, `sdk/typescript/generation-manifest.json`; `.github/workflows/ci.yml`, `.gitignore`.

Commit for this workstream: the commit that adds this section (`git log -1 --format=%h -- docs/agent/e2e-wiring/STATUS.md`).

### 3.2 Follow-up — `initiate_revocation` now verifies its credential

`CoreHandle::initiate_revocation` used to require only a non-blank token string; the value was never parsed,
so any caller could contribute a Manager signature and gossip one. It now takes
`(target_did: &str, manager_token: &[u8], now_secs: i64)` and, before producing anything:

1. rejects an all-whitespace/empty token (`manager_token must not be blank`),
2. rejects a blank `target_did`,
3. fails closed when no root CA public key is registered,
4. verifies the Biscuit token offline against that key at `now_secs` (a foreign CA or an expired token →
   `manager token verification failed: …`),
5. requires `claims.role == "RevocationManager"` (`… is not authorised to initiate revocation`).

The WASM export `core_initiate_revocation(target_did, manager_token_hex, now_secs)` hex-decodes the token and
delegates, and the SDK passes `nowSecs` alongside `managerToken` (the same explicit-clock convention
`verifyData`/`adminClose` already use). A rejected call leaves no state: no partial delta is signed, nothing is
enqueued on the transport, and `revocationStatus` stays `PENDING` with zero signatures.

| Evidence | Result |
|----------|--------|
| `cargo test -p tirbase-core --features native --lib initiate_revocation` | **5 passed** (blank inputs, 1-of-1, self-revocation, partial+second signature, and the new `initiate_revocation_rejects_untrusted_expired_and_wrong_role_tokens`) |
| `npm run build:wasm:test && npx jest src/__tests__/tirbase-manager-ops.wasm.test.ts` | **12 passed**, including `initiateRevocation rejects untrusted, expired and non-manager tokens` through the real WASM export |
| `cargo test -p tirbase-core --features native` | **719 lib passed / 0 failed** + all integration suites |
| `cargo test … tests::api_parity` | 6 passed |
| `cargo +nightly public-api -p tirbase-core` | signature line updated in `public-api.txt` / `wasm-public-api.txt` |

The fixture generator additionally emits `auditorTokenHex` (trusted-CA token with the wrong role) so the SDK
suite can prove the role gate end to end.

### 3.3 DISASTER_ALERT issuance without a test hook

`activate_saturate_mode` requires a root-CA-signed `caveat("disaster-alert")` token, and there was no way to mint one
outside `test-hooks`: `biscuit::create_token` has no caveat parameter and the admin `mint` endpoint only emitted the
`did`/`role`/`issued_at` facts. Emergency activation therefore depended on a test-only build.

- `tirbase_core::auth::biscuit::create_token_with_caveat` is now an ordinary public builder (the `test-hooks` gate is
  gone), and `ALLOWED_CAVEATS` is a closed allowlist. The caveat is interpolated into a Datalog fact, so free text
  would have been a fact-injection primitive (`ttl_override("true")` is rejected, not just ignored).
- `POST /admin/mint` accepts an optional `caveat`; it is validated against the allowlist (`400
  MINT_CAVEAT_REJECTED` otherwise), minted with the production builder, and echoed in the response. The OpenAPI
  document and generated SDK carry the field.
- The Rust fixture example no longer needs `test-hooks`, so `tirbase-sdk`'s real-WASM suite generates fixtures from a
  plain build (the `--features test-hooks` flag and the example's `required-features` are removed).

| Evidence | Result |
|----------|--------|
| `cargo test -p tirbase-gateway --test admin_endpoints_binary admin_mint` | **2 passed**, including `admin_mint_issues_disaster_alert_caveat_token`: the minted token satisfies `verify_and_check_caveat("disaster-alert")`, fails for any other caveat, and an unlisted caveat returns `400 MINT_CAVEAT_REJECTED` |
| `cd sdk/typescript && npm test` | **10 passed**, including the caveat mint and the allowlist denial through the generated client |
| `cd tirbase-sdk && npx jest` | **102 passed** at the time of §3.3 (103 now, see §3.5), fixtures generated without `--features test-hooks` |

### 3.4 Gateway admin SDK transports (Node, undici, browser)

The generated client only needs a `fetch`-shaped function, so remote admin required every caller to reimplement the
client-certificate request. The package now ships the transport it needs:

- `createMtlsFetch({ cert, key, ca, ... })` in `src/mtls.ts` (hand-written, exported from the `./mtls` subpath so a
  browser bundle never imports `node:https`). It verifies the server against `ca` by default and sends an explicit
  `Content-Length`, which the gateway's remote admin reader requires.
- `ClientOptions.fetchInit` is merged into every request (after which `method`, `headers` and `body` always win), which
  covers an undici `dispatcher` bound to a TLS agent and a browser `credentials: 'include'`.

Browsers still cannot attach a client certificate from JavaScript: they select one from the OS/browser store during
the handshake, so provisioning is out of band. That limitation is documented in the package README, not worked around.

| Evidence | Result |
|----------|--------|
| `cd sdk/typescript && npm test` | **10 passed**: the e2e drives the real gateway through the shipped `createMtlsFetch`, and `test/client-options.test.mjs` pins the `fetchInit` merge and that transport fields cannot override the request the client owns |
| `bash scripts/check-gateway-sdk-generated.sh` | OK — the new `caveat` field and `fetchInit` are generator output, not hand edits |

### 3.5 Gateway-issued DISASTER_ALERT token activating Saturate_Mode on real WASM

§3.3 made the token mintable at the admin surface; this closes the loop across components: the real gateway binary
mints, a real WASM device activates.

`tirbase-sdk/src/__tests__/saturate-issuance.gateway.test.ts` (Jest, so it runs in the existing `test` CI job):

1. boots `target/debug/tirbase-gateway` with the Unix admin socket and the mTLS remote listener
   (`TIRBASE_GATEWAY_BIN`, default `target/debug/tirbase-gateway`),
2. configures the gateway to mint with the *same* root CA the device trusts — the setup example now accepts
   `TIRBASE_E2E_ROOT_CA_SEED_HEX` and prints `rootCaPublicHex`, and the test asserts the two keys are identical
   (otherwise the minted token could not verify, which is the seam this test exists to pin),
3. mints a caveat-less `PolicyAuthority` token and asserts the device rejects activation
   (`biscuit token is missing the disaster-alert caveat`),
4. mints `caveat: "disaster-alert"` over the production `POST /admin/mint` path and asserts the device is still not
   in Saturate_Mode (`renewSaturateMode` → `not in SATURATE mode`),
5. activates, then renews — renewal only succeeds inside an active lease, so its success is the observable effect of
   the real `SaturateModeStateMachine`, not an accepted-and-dropped call.

The device is a `wasm-pack --target nodejs` build of `tirbase-core` opened through the production SDK init, with the
M-of-N deployment config (2-of-3) applied. No mock, no `test-hooks`, no injected inbound path.

| Evidence | Result |
|----------|--------|
| `cd tirbase-sdk && npx jest src/__tests__/saturate-issuance.gateway.test.ts` | **1 passed** (~25 s: fixtures, setup example, gateway boot, mint, activate, renew) |
| `cd tirbase-sdk && npx jest` | **103 passed / 103**, 4 suites |
| `.github/workflows/ci.yml` | the `test` job builds `tirbase-gateway` explicitly before the SDK suite, so the binary requirement is a named step |

## 3.6 WS3 — Live K-of-N quorum + spatial diversity over real meshes (PROMPT 3 of 8)

Scope: `tirbase-core/src/durability/{quorum,spatial,receipt,mod,cloud_queue}.rs`, the
receipt/quorum path in `src/api/mod.rs`, and the real-mesh tests. Rows INV-18/INV-40/INV-45.

### What was actually unwired (found, not assumed)

| # | Defect | Fix |
|---|--------|-----|
| 1 | Every receipt a real device issued carried `spatial_tag: None` (the issue path hard-coded it), so `SpatialDiversityTracker` always saw zero distinct tags and `satisfies_diversity` always took the Req 14.5 flat-K-of-N fallback. Spatial diversity could not be enforced, let alone proven, over a real mesh. | Devices now declare their squad/tunnel_sector: `CoreHandle::set_local_spatial_tag` (deployment provisioning on both targets), and `issue_durability_receipt` stamps the configured tag onto every receipt. Blank tags normalise to `None` (untagged). |
| 2 | A validated revocation did not touch the durability subsystem: a REVOKED device's receipts already counted toward Quorum kept counting, and new ones were accepted — the quorum path had no revocation check at all. | `DurabilitySubsystem::mark_issuer_revoked` records the DID, withdraws every receipt it contributed (`Tier1QuorumTracker::remove_issuer`, which also rebuilds the diversity tallies) and drops it from cloud-queue re-fetch holder lists. `receive_receipt` rejects any later receipt from that issuer with `AuthorisationFailed`. Wired from the native **and** WASM inbound `RevocationDelta` `Applied` arms and from `initiate_revocation`'s applied branch. |
| 3 | The mesh harness had no way to configure quorum K/N, diversity, revocation thresholds, schema or a device's sector — every test ran K=1/N=1. | `mesh_harness::{mesh_deployment, mesh_config_with, init_mesh_handle_with_deployment, connect_peers_until}`. |

### Tests added (all real Swarms, loopback, production inbound drain)

| Test (`api::real_mesh_tests::…`) | Swarms | Proves |
|---|---|---|
| `three_peers_reach_tier1_via_genuine_receipt_exchange` | 4 | Writer + 3 peers, K=3, `spatial_diversity_min=2`, cap 0.6. Each peer merges the Delta over the wire, issues its own Ed25519 receipt with its configured sector tag; all three verify against the issuer's real key; writer reaches Tier-1 through `receive_inbound → register_peer_key → verify_receipt → Tier1QuorumTracker`; the `DurabilityTierChanged(Uncommitted → Tier1)` event fires on the production broadcast channel. |
| `k_minus_one_genuine_receipts_do_not_reach_tier1` | 3 | K=3 with only two genuine receipts stays `Uncommitted` for the whole 2 s bounded window. |
| `insufficient_spatial_diversity_blocks_tier1_until_diluted` | 5 | K=3, min=2, cap 0.5: three receipts with a 2-of-3 sector majority (66.7%) are blocked; a fourth peer in a third sector is handed the Delta over the production fragmented outbound path, its genuine receipt dilutes sector-a to 50%, and Tier-1 then forms — which also proves the blocked receipts were received and counted. |
| `same_sector_receipts_never_form_tier1` | 4 | Three peers all declaring `sector-x` (100% of receipts, cap 50%) never form Tier-1 despite K genuine receipts. |
| `tampered_wrong_hash_unknown_and_duplicate_receipts_do_not_count` | 3 | Adversarial receipts published through the production `MeshTransport::send_receipt` framing: (a) corrupted signature, (b) valid signature over a different state hash, (c) receipt naming an unresolvable `did:web:` issuer, (d) duplicate of the same genuine receipt. The Delta is written before the peers connect, so only these crafted receipts exist. Two genuine receipts then form K=2; if any negative had counted, the duplicate would have completed K early and the final Tier-1 assertion would be unreachable. |
| `revocation_mid_quorum_withdraws_the_revoked_receipt` | 5 | K=3. B and C are the only connected peers at write time, so two receipts are counted. A 1-of-1 `initiate_revocation` of C applies (root-CA-verified `RevocationManager` token, `device_revocation_status` reports REVOKED) and withdraws C's receipt. D then joins and genuinely attests the Delta: B+D = 2 < K=3 stays `Uncommitted` (if the withdrawal had not happened it would be 3 and Tier-1). E's genuine receipt then completes the quorum from three honest holders. |
| `tier1_then_compaction_refetch_and_cloud_sync_reach_tier2` | 3 | K=2 with an `Aggressive { threshold: 1 }` schema so the second write compacts; both Deltas reach Tier-1 via genuine receipts, one production `run_cloud_sync_cycle` re-fetches the compacted entry and reaches Tier-2 (`acknowledged=2, deferred=0, rejected=0`, queue drained, ledger committed), and the receipt holder still holds the Delta and its row. |
| `three_processes_reach_tier1_across_os_processes` | 4 OS processes | Multi-process variant. The lib test binary re-executes itself as one writer and three peer processes (`--exact api::real_mesh_tests::multiprocess_quorum_child_process`, config in `TIRBASE_MP_QUORUM_CHILD`); each boots its own file-backed `CoreHandle`/Swarm through the production public API (`init`, `set_local_spatial_tag`, `dial_peer`, `write`, `subscribe_durability_events`, `mesh_status`, `local_did`, `read`). The writer reaches Tier-1 only after three other *processes* merged the Delta and their signed receipts crossed loopback TCP between processes (no shared memory/in-process channels). The parent asserts 4 distinct DIDs, `MP_MERGED` from every peer process, the writer's `MP_TIER1`/production `DurabilityTierChanged` transition, and the writer process exiting successfully. |
| `durability::tests::revoked_issuer_receipt_is_rejected_and_withdrawn` | unit | Revocation withdraws a counted receipt and subsequent receipts from that issuer return `AuthorisationFailed`. |
| `durability::quorum::tests::{remove_issuer_withdraws_its_receipt_and_diversity_contribution, removing_a_pre_quorum_receipt_prevents_tier1}` | unit | Removal decrements the receipt count, drops the withdrawn issuer's tag from the diversity tallies, and a removed receipt no longer contributes to K. |

### Commands and results (this machine)

| Command | Result |
|---------|--------|
| `cargo test -p tirbase-core --features native` | **731 lib passed / 0 failed** + every integration suite passes (8/1/2/5/1/2 …) |
| `cargo test -p tirbase-core --features native --lib api::real_mesh_tests` | **21 passed / 0 failed** (12 pre-existing + 9 new, including the multi-process variant) |
| `cargo test -p tirbase-core --features native --lib durability::` | **90 passed / 0 failed** |
| `cargo test -p tirbase-core --features native --lib -- --test-threads=1 api::real_mesh_tests::three_processes_reach_tier1_across_os_processes` | **1 passed / 0 failed** (writer + 3 peer OS processes, Tier-1 on attempt 1) |
| `cargo check -p tirbase-core --no-default-features --features wasm --target wasm32-unknown-unknown` | clean (only the pre-existing `proc-macro-error2` future-incompat warning) |
| `cargo clippy -p tirbase-core --features native --lib` | no new warnings (pre-existing doc-list/dead-code warnings only) |
| `cargo +nightly public-api -p tirbase-core` | two approved additions (`local_spatial_tag`, `set_local_spatial_tag`), manifests updated |

### Honest limits (do not overclaim)

1. **Self-declared sectors, not attested location.** The receipts used here are labelled by
   `set_local_spatial_tag`, a self-declared squad/tunnel_sector string. `Anchor_Attested_Location`'s
   beacon mode is **not** exercised by these tests, and nothing here proves beacon-attested
   location; an adversary can still lie about its sector. The existing anchor unit tests
   (`durability::tests::anchor_mode_*`) remain the only coverage of the beacon path.
2. **No receipt expiry.** `DurabilityReceipt` has no TTL or expiry field, so an "expired" receipt
   is not representable and no expiry enforcement is claimed. The prompt's expired/**revoked**
   issuer case is proven for the revoked half only.
3. **Multi-process, but same host.** `three_processes_reach_tier1_across_os_processes` runs
   writer and peers as separate OS processes (re-executions of the lib test binary) with real
   loopback TCP between them and no shared in-process state, so receipts are no longer handed over
   in-process handles. It does not prove cross-host behaviour, NAT traversal, or failure of the
   host's loopback stack (INV-43 remains partly open).
4. **Re-fetch source is the local DAG.** The production `run_cloud_sync_cycle` re-fetch callback
   resolves compacted bytes from the writer's own DAG; there is no peer-to-peer Delta fetch
   protocol. The test proves the compacted Delta still reaches Tier-2 and that the receipt holder
   independently retains the Delta — not that the writer fetches it from that holder over the wire.
5. **Tier-1 is sticky.** Withdrawing a revoked holder's receipt does not demote a Delta that had
   already reached Tier-1; the negative case proven is revocation *mid-quorum*.
6. **`properties.rs` gap text untouched.** The Property 5 / Property 14 gap comments still say
   live K-of-N is deferred; WS8 owns that reconciliation.

### Files

- Core: `src/durability/quorum.rs`, `src/durability/spatial.rs` (no code change; documentation
  of the fallback clarified by the new tests), `src/durability/receipt.rs` (no code change),
  `src/durability/mod.rs`, `src/durability/cloud_queue.rs`, `src/api/mesh_harness.rs`,
  `src/api/mod.rs`, `src/tests/api_parity.rs`, `public-api.txt`, `wasm-public-api.txt`.

Commit for this workstream: the commit that adds this section
(`git log -1 --format=%h -- docs/agent/e2e-wiring/STATUS.md`).

## 3.7 WS4 — Revocation gossip accumulation + M-of-N Saturate termination (PROMPT 4 of 8)

Scope: `tirbase-core/src/auth/revocation.rs`, `tirbase-core/src/transport/saturate.rs`,
`tirbase-core/src/transport/message.rs`, the manager-operation/mesh paths in
`tirbase-core/src/api/mod.rs`, `tirbase-core/src/tests/api_parity.rs` and the
`tirbase-core` public API manifests. Rows INV-13/INV-14.

### What was actually unwired (found, not assumed)

| # | Defect | Fix |
|---|--------|-----|
| 1 | **Gossiped RevocationDeltas never crossed the native mesh.** `enqueue_revocation_gossip` publishes a synthetic `Delta` with `author_did == "tirbase/revocation"` whose `automerge_bytes` holds a `GossipMessage::InboundRevocationDelta`, but `receive_inbound`'s `InboundDelta` arm only unwrapped the **fleet** envelope. On the receiving peer the wrapper fell into `apply_incoming_delta`, which rejected it (unsigned synthetic Delta from an unresolvable author), so only the initiating device's local bookkeeping ever saw a signature. | The `tirbase/revocation` envelope is unwrapped before the merge gate and dispatched to `handle_inbound_revocation_delta` — the direct-variant arm was extracted into that one method, so both wire framings run the same implementation. |
| 2 | **Below-threshold deltas were gossiped exactly once, at initiation.** A Manager that produced its partial delta while partitioned never got its signature to peers after reconnection (the production scheduler drained it once, with no subscribers, and dropped it). | `PendingRevocationStore::pending_partial_deltas` / `RevocationSubsystem::build_pending_partial_deltas` expose accumulations still below M; `spawn_scheduler_tick_loop` re-enqueues them at HIGH priority once per epoch (at most one per pending target per epoch, and it stops the moment M is met — once applied the target is excluded). |
| 3 | **M-of-N Saturate termination had no mesh path at all.** `terminate_saturate_mode` only accepted co-signatures collected out of band; there was no message, no canonical lease binding and no collection state. | Canonical lease-bound termination message (`TERMINATION_MESSAGE_PREFIX`; epoch = lease activation timestamp, plus expiry window and activating manager DID), `SaturateModeStateMachine::{canonical_termination_message, build_termination_message, parse_termination_message, validate_termination_message, is_current_termination_message, record_termination_signature, collected_termination_signatures, collected_termination_signature_count, has_termination_signature, terminate_with_collected}`, `CoreHandle::{saturate_termination_message, saturate_termination_signature_count, request_saturate_termination}`, and the HIGH-priority `GossipMessage::SaturateTerminationCoSignature` envelope (synthetic `tirbase/saturate` framing on native, its own variant on WASM). Receivers verify signature + canonical shape + a live lease window, co-sign once themselves, re-broadcast, and terminate when M distinct valid signatures are collected. Activation, renewal, expiry and termination all clear the collected set, so a signature set can never outlive its lease epoch. |

### Tests added (`api::revocation_saturate_mesh_tests`, all real Swarms)

| Test | Peers | Proves |
|------|-------|--------|
| `partial_revocation_deltas_accumulate_across_offline_managers` | 4 | Three Managers each call `initiate_revocation` with a real root-CA `RevocationManager` token **while disconnected** (asserted `peer_count == 0`, each holds `Pending{1,2}`); the HIGH-priority classification is observed at the publish point (an `InboundDelta` wrapper with `PriorityClass::High` carrying `InboundRevocationDelta` for the target); after reconnecting the full mesh every peer isolates the target **within one production gossip round of the first observer** (bounded by 1 s scheduler epoch + 50 ms drain, measured on the monotonic clock; the bound is the fan-out delay, not mesh-formation time on a loaded host), records it through `device_revocation_status` with a receipt timestamp, and holds an immutable 2-signature delta recoverable via `build_recent_revocation_deltas`. The revoked author's later signed Delta is rejected by `apply_incoming_delta` (`MergeOutcome::Rejected`) on every peer, never reaches the DAG and is never projected, while an honest author's Delta merges over the same path. |
| `below_threshold_never_revokes_and_threshold_signature_always_does` | 4 | M=3: two Managers' contributions stay `Pending{2,3}` and never revoke across two full gossip rounds on any peer; the third Manager's initiation revokes on every peer within one round. |
| `revocation_negative_cases_fail_closed` | 2 | A duplicated Manager signature counts once (never twice); a signature bound to another target DID is rejected outright (cross-target replay: no accumulation, no revocation); an expired manager token, a non-`RevocationManager` role and a foreign-CA token are all rejected with `AuthorisationFailed` and contribute nothing; a replayed complete delta and a late third signature leave the applied delta unchanged (2 signatures, identical `created_at`). |
| `saturate_activation_routes_high_only_and_holds_medium_low` | 1 | Real `CoreHandle` activation with a DISASTER_ALERT token puts the state machine and DRR mirror in SATURATE; one Delta per priority class enqueued through the production scheduler: HIGH is served, MEDIUM and LOW stay queued (held, not dropped); M-of-N termination with a real distinct co-manager signature clears lease + mirror, after which the held MEDIUM/LOW Deltas are served. |
| `saturate_renewal_is_bounded_and_requires_valid_tokens` | 2 | Activation opens the configured 60 s window; a heartbeat extends by exactly one configured window from `now` and records `last_renewed_at`; repeated renewal never accumulates windows; foreign-CA and caveat-less tokens are rejected without moving the lease; renewal outside SATURATE fails. |
| `saturate_termination_below_threshold_preserves_mode_over_mesh` | 2 | With M=3, a mesh request collects only 2 distinct signatures (requester + peer, the peer co-signing over the wire) and both devices stay SATURATE with the mirror intact across two gossip rounds. |
| `saturate_termination_m_of_n_collected_over_real_mesh` | 3 | Invalid, wrong-message and expired-lease co-signatures published over the real mesh are all rejected (count stays 0, mode untouched); a duplicated signature counts once; the remaining peers co-sign the canonical lease-bound message over the wire and M=3 terminates **every** peer with the scheduler mirror cleared inside two gossip rounds; afterwards no canonical message exists and renewal is rejected. |
| `canonical_termination_message_is_lease_bound` | unit | The canonical message embeds the lease epoch/expiry/manager, a stale window is rejected, and a renewal changes the message so previously collected signatures no longer authorise termination. |
| `auth::revocation::tests::test_pending_partial_deltas_track_accumulation_until_threshold` | unit | The partial-delta re-gossip list carries accumulated signatures below M and excludes an applied target. |

**Fails-before evidence.** With the `tirbase/revocation` envelope unwrap disabled
(`if false && delta.author_did == REVOCATION_GOSSIP_AUTHOR`), `partial_revocation_deltas_accumulate_across_offline_managers`
fails (`0 passed; 1 failed`, the peers never isolate the device); restoring it passes. The Saturate tests fail
before the change because `request_saturate_termination`/`SaturateTerminationCoSignature` do not exist
(no mesh collection path to compile against).

### Commands and results (this machine)

| Command | Result |
|---------|--------|
| `cargo test -p tirbase-core --features native` | **740 lib passed / 0 failed**, 0 ignored (was 731), every integration suite green (`contamination_resolution` 8, `crash_recovery` 1, `fleet_inventory` 2, `security_event_sync` 2, `shadow_postconditions` 5, `time_source_injection` 1) |
| `cargo test --features native --lib -- --test-threads=1 revocation_saturate_mesh_tests::` | 7/7 new mesh tests + the lease-bound unit test pass individually and in the parallel suite |
| `cargo check --no-default-features --features wasm --target wasm32-unknown-unknown` | clean (only the pre-existing `proc-macro-error2` future-incompat warning) |
| `cargo check --workspace` | clean |
| `cargo +nightly public-api -p tirbase-core` | approved additions appended to `public-api.txt` / `wasm-public-api.txt` (3 `CoreHandle` methods, the pending-partial-delta accessors, the canonical termination-message API and the `SaturateTerminationCoSignature` variant) |

### Honest limits (do not overclaim)

1. **Same host, loopback TCP.** Every test runs several Swarms in one process over loopback. This is a real
   transport (genuine gossipsub publish/subscribe, fragmentation, drain loops), but it does not prove
   cross-host/NAT behaviour (INV-43 stays open).
2. **Managers are self-certifying.** `RevocationDelta`/termination signatures are verified against the
   signer's `did:key`; there is no registry of the N authorised Manager DIDs, so "unauthorised manager" is
   proven at the credential boundary (token role expiry/CA/role checks in `initiate_revocation`) and for
   revoked signing keys, not against a per-fleet manager roster.
3. **`RevocationDelta` has no epoch/sequence field**, so "stale epoch/sequence" is represented by (a) manager
   token expiry and (b) replay of an already-applied delta, both proven above. Stale-lease binding *is*
   proven for the Saturate termination message, which carries the lease epoch explicitly.
4. **Peer-issued termination requests are accepted on a live-lease check.** A co-manager co-signs any
   well-formed termination message whose embedded lease window is live; it cannot verify that the requester
   actually holds that lease (the requester's lease is local state). M-of-N still bounds the damage: M
   distinct Managers must co-sign, duplicates/invalid/expired sets are rejected, and the requester's own
   signatures are bound to its own canonical message.
5. **Re-gossip cadence is per scheduler epoch.** A pending partial delta is retransmitted once per DRR epoch
   (1 s in production) until M is met; this is bounded but does produce periodic control traffic for a
   revocation that stays below threshold for a long time (24 h window, then it stops).

### Files

- Core: `src/auth/revocation.rs`, `src/transport/saturate.rs`, `src/transport/message.rs`,
  `src/transport/mod.rs` (WASM outbound-frame passthrough for the `tirbase/saturate` author),
  `src/api/mod.rs`, `src/api/revocation_saturate_mesh_tests.rs` (new), `src/tests/api_parity.rs`,
  `public-api.txt`, `wasm-public-api.txt`.

Commit for this workstream: the commit that adds this section
(`git log -1 --format=%h -- docs/agent/e2e-wiring/STATUS.md`).

## 3.8 WS5 — CCE + Side-Car replay/recovery over real meshes (PROMPT 5 of 8)

Scope: `tirbase-core/src/contamination/*`, `migration/sidecar.rs`, `migration/quarantine.rs`,
`migration/shadow.rs`, the inbound/CCE/migration paths in `api/mod.rs`, and the observable
native/WASM event surfaces. Rows INV-15/INV-16/INV-17 (and the Item 7 projection-gap annotation).

### What was actually unwired (found, not assumed)

| # | Defect | Fix |
|---|--------|-----|
| 1 | **No native incident event surface.** `IncidentCreated`/`Updated`/`Closed` were pushed only as `WasmEvent` under `#[cfg(feature = "wasm")]`; a native host could not observe any incident transition. | `CausalContaminationEngine::set_incident_event_listener` is registered by `CoreHandle::init` and forwards `IncidentEvent { kind, incident_id, ico }` onto a broadcast channel exposed by `CoreHandle::subscribe_incident_events` (the native analogue of `core_poll_events`). |
| 2 | **A migration could not reach a peer over the mesh at all.** `InboundMigrationDelta`/`InboundMigrationRevocationDelta` had no production publish path, so “corrected migration arrives over the real mesh” was untestable without `inject_inbound`. | New `MeshTransport::send_message` publishes a pre-framed `GossipMessage` directly (the same framing `send_receipt` uses); `CoreHandle::publish_migration_delta` / `publish_migration_revocation_delta` are the manager-side production callers. The receiver's existing `receive_inbound` arms handle both. |
| 3 | **Side-Car replay never wrote projection rows.** `replay_sidecar` merged only into the Automerge document; `read()`/`query()` stayed stale, and post-replay `project_table_to_store` could only project the *last* merged row because every Delta overwrites the ROOT `_tirbase_table`/`_tirbase_key` metadata. | `CrdtEngine::project_delta_bytes_to_store` reads the row from the replayed Delta's own changeset; `SideCarLedger` holds the projection store and projects each successfully replayed entry individually. |
| 4 | **Replay was not resumable and the corruption window was not persisted.** A restart lost `corrupted_schema_windows`, stranding the captured writes forever; a resumed pass re-applied already-replayed entries. | Windows persist in `migration_corruption_windows` (loaded by `SchemaMigrationEngine::new`, written on open, cleared on replay). `replay_sidecar` skips entries already `REPLAYED`/`COMPLETE`, so a partially-completed pass resumes; `CoreHandle::init` resumes windows whose schema the device has left. |
| 5 | **A chain overlapping an existing composite opened a disjoint ICO.** Overlap detection only looked at regular OPEN incidents, so a third contamination chain could never join the composite it was causally part of. | `tag_contamination_root` extends the matching OPEN composite (union of roots/deltas/affected rows), marks the new ICO `SupersededBy`, and emits `IncidentUpdated`. |
| 6 | **Signed tags were absent from the append-only tag log.** `ChangesetDag::insert` always stores `tags_json = "[]"`, so a human-reaction write's `ContaminatedByHumanReaction` tag existed only inside the signed payload and was unobservable in `dag_nodes.tags_json`. | `CrdtEngine::insert_dag_node` appends the Delta's signed tags to the log after inserting the node (append-only; no entry modified). |
| 7 | **A conflicting Side-Car entry was not observable from a public boundary.** | `CoreHandle::sidecar_conflicts()` returns every entry whose replay status is `Conflict { .. }`. |

### Tests added (`api::contamination_mesh_tests`, real Swarms + production inbound path)

| Test | Proves |
|------|--------|
| `revoked_author_over_real_mesh_taints_descendants_appends_tags_and_emits_events` | Author A and observer B are real Swarms; B projects A's Delta and authors a descendant. A root-CA `RevocationManager` revocation applied on B (production `initiate_revocation` → CCE trigger → `tag_contamination_root`) tags the root **and every reachable DAG descendant** CONTAMINATED, opens an ICO with the correct affected rows, and emits `IncidentCreated`. Resolving appends `Resolved`/`Decontaminated`: the pre-resolution tag list is an exact **prefix** of the post-resolution list (nothing modified or removed), rows clean, `IncidentClosed` observed. |
| `composite_incident_over_real_mesh_merges_decomposes_and_decontaminates` | Two interleaved authors (`a1:x1 → a2:y1 → a1:x2`) are revoked over the mesh; exactly **one** `CompositeIncidentInstance` is formed with the union delta set and every root. Resolving one root decomposes it (`Decomposed`, surviving open ICO, rows still CONTAMINATED); resolving all roots appends `Decontaminated`, clears the rows and emits `IncidentClosed`. |
| `human_reaction_write_on_contaminated_row_over_real_mesh_joins_open_ico` | A real `CoreHandle::write` against a row the revocation ICO marked CONTAMINATED carries `ContaminatedByHumanReaction` in its signed Delta (observable in the tag log) and is registered in the active OPEN ICO. |
| `sidecar_replay_on_corrected_migration_over_real_mesh_projects_replayed_rows` | Bad migration `s→t` published over the mesh is applied by B; manager revocation published over the mesh opens the CCE `BadMigration` ICO **and** the Side-Car window; three writes are captured byte-for-byte; the corrected `t→u` migration published over the mesh replays them in recorded-timestamp order, marks every entry `COMPLETE`, appends `ReplayComplete`, closes the (persisted) window, and **every replayed row is readable through `read()`**. |
| `sidecar_replay_conflict_is_observable_and_does_not_stop_other_entries` | A Side-Car entry stamped with an unregistered schema hash is quarantined during replay and flagged `CONFLICT` with the reason, while the legitimate entry still replays and its row is projected; `CoreHandle::sidecar_conflicts()` exposes the conflict. |
| `sidecar_replay_resume_is_idempotent_without_duplicate_or_lost_writes` | The durable state a kill mid-replay leaves (first entry committed `REPLAYED`, remainder pending) is resumed: the production corrected-migration trigger replayes only the remainder, every entry ends `COMPLETE`, each Delta appears exactly once in the DAG, every row is present with the captured value, and a second ledger pass re-applies **0** entries and stays `complete`. |

### Commands and results (this machine)

| Command | Result |
|---------|--------|
| `cargo test -p tirbase-core --features native --lib` | **746 passed / 0 failed**, 0 ignored (was 740; +6) |
| `cargo test -p tirbase-core --features native --lib -- --test-threads=1 api::contamination_mesh_tests` | **6/6 pass** (~1.5 s) |
| `cargo test -p tirbase-core --features native` | every integration suite passes (`contamination_resolution`, `crash_recovery`, `fleet_inventory`, `security_event_sync`, `shadow_postconditions`, `time_source_injection`, …) |
| `cargo check -p tirbase-core --no-default-features --features wasm --target wasm32-unknown-unknown` | clean |
| `cargo test -p tirbase-core --features native --lib tests::api_parity` | passes (three new `CoreHandle` methods documented as intentionally unexported) |

CI: a named mandatory gate was added to the `test` job —
`CCE + Side-Car e2e (revocation taint, composite ICO, replay/recovery)` runs
`cargo test -p tirbase-core --features native --lib api::contamination_mesh_tests -- --test-threads=1`
(no `#[ignore]`, no `continue-on-error`), and the job's full `cargo test --features native` step covers it too.
**Caveat:** `.github/workflows/ci.yml` does not parse as YAML even at HEAD — its block scalars (`run: |`)
are written at the same indentation as the `run:` key, so `ruby -ryaml`/`js-yaml` reject the file at line 25
(a pre-existing condition from earlier CI edits, not introduced here). The new step follows the file's
existing style; whether GitHub executes the workflow could not be verified locally.

### Fails-before evidence

All six tests are compiled against APIs added by this workstream (`subscribe_incident_events`,
`publish_migration_delta`, `publish_migration_revocation_delta`, `sidecar_conflicts`,
`open_composite_incidents`), so they cannot build on the starting HEAD. Individually disabling the wiring
reproduces the specific defect: with `project_delta_bytes_to_store` removed, the three replay tests fail on
the `read()` assertions (`key not found`); with the composite-extension block removed,
`composite_incident_…` fails with “expected exactly one composite, got 0” for the third chain; with the
signed-tag append removed, the human-reaction test times out on the tag assertion.

### Honest limits (do not overclaim)

1. **Same host, loopback TCP.** Real gossipsub publish/subscribe and the production drain loops, but no
   cross-host/NAT behaviour (INV-43 stays open).
2. **Crash recovery is proven from the durable ledger state, not a real SIGKILL.** The test commits the
   state a killed pass leaves (per-entry status writes are their own transactions) and resumes through the
   production corrected-migration trigger. The restart path in `CoreHandle::init` is wired
   (persisted windows + skip-already-replayed) but its end-to-end resume is not exercised by a real process
   kill, because the device's own schema hash is not persisted (a pre-existing durability gap that belongs
   to WS4): after a restart the migration engine starts at the deployment's first version, not at the
   committed corrected schema.
3. **Quarantine-on-corrupted-schema is proven indirectly.** This workstream proves Side-Car capture and
   replay ordering; the byte-for-byte quarantine ledger path is covered by
   `api::tests::quarantine_ledger_wiring_two_core_handle_instances` and the conflict test's
   `UnknownSchemaHash` quarantine, not by a second write-path quarantine test.
4. **Events are proven on the native surface.** The WASM `WasmEvent::Incident*` queue already existed and was
   not re-run here; the native broadcast channel is the new surface.
5. **`IncidentUpdated` is emitted for partial resolution and composite extension**, but the tests assert the
   `Created`/`Closed` transitions and the composed state directly; they do not enumerate every `Updated`.
6. **`public-api.txt` was updated by hand for the new items, not regenerated.** `cargo +nightly public-api`
   (0.52.0, current nightly) now emits `Result<(), …>` where the committed manifest holds `Result<, …>` and
   enumerates extra blanket impls, i.e. the manifest already drifts from the toolchain on every pre-existing
   entry (~498 differing lines, none of them from this workstream) — regenerating would have produced a
   repo-wide unrelated diff. The substantive new lines (3 `CoreHandle` methods, `MeshTransport::send_message`,
   `CrdtEngine::project_delta_bytes_to_store`, the Side-Car ledger accessors, the CCE listener/`open_composite_incidents`,
   `IncidentEvent`/`IncidentEventKind`) are in the manifest; the `Result<()`-vs-`Result<` drift is pre-existing and
   unfixed here.

### Files

- Core: `src/contamination/{mod,incident}.rs`, `src/migration/{mod,sidecar}.rs`, `src/crdt/mod.rs`,
  `src/transport/mod.rs`, `src/api/mod.rs`, `src/api/contamination_mesh_tests.rs` (new),
  `src/tests/api_parity.rs`, `src/store/sqlite.rs`.
- Docs: `tirbase-core/tests/README.md` (Item 7 projection gap reconciled to the code).

Commit for this workstream: the commit that adds this section
(`git log -1 --format=%h -- docs/agent/e2e-wiring/STATUS.md`).


## 3.9 WS6 — Fragmentation, multi-hop relay, BLE bridge, Noise 0-RTT + rotation (PROMPT 6 of 8)

Scope: `tirbase-core/src/transport/{ble,fragment,session,message,mod}.rs`, the relay path in the
Swarm polling task (`src/api/mod.rs`), `DeploymentConfig::mesh_ble_enabled`, and the new real-mesh
suites. Rows INV-07/INV-08/INV-09/INV-10/INV-11.

### What was actually unwired (found, not assumed)

| # | Defect | Fix |
|---|--------|-----|
| 1 | **`mesh_mtu = 256` did not fragment.** `prepare_outbound` only fragmented when `0 < mtu < 256`, so the exact MTU the prompt/`DeploymentConfig` documents produced whole-Delta frames. | Any non-zero `mtu` fragments at that size; `0` still disables fragmentation. The `DeploymentConfig::mesh_mtu` doc now says "non-zero" and names 256 as the BLE/LoRa-class value. |
| 2 | **Multi-hop relay had no forwarding half.** `send_delta` wrapped a non-neighbour Delta in `GossipMessage::RelayDelta`, but the receiving poll task only unwrapped it when the target was itself; a relay node silently dropped every envelope for someone else. The envelope carried no hop count or visited set, so even a forwarder could not bound or de-loop. | `RelayDelta` now carries `hop_count` and `visited`; `MeshTransport::relay_decision` returns `Deliver` / `Forward` / `Drop` (loop, or hop budget reached), and the production Swarm polling task re-publishes `Forward` envelopes (`gossipsub.publish`) with `hop_count + 1` and itself appended to `visited`. The WASM inbound arm bounds/drops relay envelopes it cannot forward. |
| 3 | **Fragments had no timeout, and a duplicate after completion re-opened slot.** A partial Delta could be pinned until capacity eviction, and a duplicate fragment arriving after reassembly opened a fresh, never-completing assembly. | `ReassemblyBuffer::add_fragment_at(now_us)` expires assemblies older than `FRAGMENT_STALE_TIMEOUT_US` (30 s) on insertion, and the last `MAX_COMPLETED_ASSEMBLIES` (1024) completed Delta ids absorb retransmissions. `BleChunkAssembler` has the same completed-id guard. |
| 4 | **The Noise wire framing was unusable and `initiate` never resumed.** `AsyncNoiseStream::read_noise_message` read exactly `buf.len()` and the caller used `msg2.len()` (65535) as the message length, so a real stream could never complete a handshake; `SessionManager::initiate` always ran a full IK handshake and only *stored* a resumption credential. There was no responder implementation at all. | Length-prefixed framing (4-byte BE) shared by `DuplexNoiseStream` and a new `TcpNoiseStream`; `read_noise_message` returns the byte count. `SessionManager::initiate_with_0rtt` attempts a cached-ticket resumption that carries the first application frame inside handshake message 1, with counters (`ResumptionStats`) and a transparent full-handshake fallback; `SessionManager::respond` (+ `MeshTransport::accept_noise_session`) implement the responder half. Every flight is bounded by `HANDSHAKE_FLIGHT_TIMEOUT` (5 s). |
| 5 | **The BLE I/O loop was untestable dead-end code and BLE inbound never reached the CRDT.** Framing/assembly lived inline in a `tokio::spawn` inside `start()`, reachable only with a real radio; `poll_ble_inbound` recorded the message under `cfg(test)` and dropped it otherwise. There was also no deployment switch: `TransportConfig::mesh_ble_enabled` was always `false` from `CoreHandle::init`. | The loop is now `transport::ble::run_ble_bridge` behind a `BleLink` trait. `MeshTransport::{init_ble_channels, bind_ble_link, spawn_platform_ble_bridge}` start it (radio or emulated link), `poll_ble_inbound` dispatches reassembled messages into the mesh inbound channel (`set_ble_dispatch`), and `DeploymentConfig::mesh_ble_enabled` enables the whole path from `CoreHandle::init` (channels + drain loop + platform radio). |

### Tests added (all run in the mandatory `test` job)

| Test | What it proves |
|------|----------------|
| `api::network_wiring_mesh_tests::fragmented_large_row_crosses_a_256_byte_mesh_mtu` | Two real Swarms, `mesh_mtu = 256`: a 1.2 KiB row leaves A as several `InboundDeltaFragment` frames (each payload ≤ 256, same delta id, consistent totals, no whole-Delta frame), is reassembled on B and readable through the ordinary `read()` path, and is merged into B's DAG. |
| `api::network_wiring_mesh_tests::incomplete_fragment_set_is_never_partially_applied` | Every fragment but one is fed through `process_wire_message`: nothing is delivered, no row is projected, the DAG has no node; the partial expires (`expire_stale`) after `FRAGMENT_STALE_TIMEOUT_US`; a complete retransmission then applies through `receive_inbound`. |
| `transport::tests::{out_of_order_and_duplicate_fragments_reassemble_exactly_once, missing_fragment_leaves_no_partial_delta_and_times_out}` | Out-of-order + duplicated fragments reassemble exactly once (and are not retained); a missing fragment yields no Delta and the partial times out. |
| `api::network_wiring_mesh_tests::three_node_chain_relays_a_delta_with_bounded_hops_and_no_duplicates` | A–B–C chain with no A–C link: A publishes exactly one `RelayDelta` (hop 0, visited `[A]`), B forwards exactly once (hop 1, visited contains B), C receives and projects the row, C never re-forwards, and the Delta is in C's DAG. |
| `api::network_wiring_mesh_tests::{relay_hop_bound_is_enforced_by_the_transport, transport::tests::relay_drops_loops_and_exhausted_hop_budget}` | `relay_decision` delivers for the target, forwards with `hop_count + 1`, drops a repeated node (loop) and drops at `max_hop_count`. |
| `transport::tests::ble_bridge_carries_a_fragmented_delta_over_an_emulated_link` | Two transports joined by an emulated `BleLink`: `send_delta` selects the BLE path (the Gossipsub channel stays empty), `ble::run_ble_bridge` chunks/assembles through the production framing, and `poll_ble_inbound` dispatches the reassembled `InboundDelta` for the production inbound path. |
| `transport::tests::ble_chunk_assembler_accepts_out_of_order_and_duplicate_chunks` | `BleChunkAssembler` completes a multi-chunk group delivered in reverse with a duplicate, and holds no slot afterwards. |
| `api::network_wiring_mesh_tests::noise_session_resumes_with_0rtt_and_rotates_keys_in_place` | Two real Swarms + a real loopback TCP Noise exchange: first connection is a full handshake (`full_handshakes = 1`), the reconnect is a 0-RTT resumption (`resumptions = 1`, `full_handshakes` unchanged, payload delivered in flight 1, `resumed = true` on both sides), `tick_key_rotation` rekeys in place past the configured interval, data still decrypts after rotation, and a frame captured under the pre-rotation keys is rejected. |
| `api::network_wiring_mesh_tests::resumption_negative_cases_fall_back_or_fail_closed` | A ticket cached for another peer never satisfies this peer's lookup (full handshake); an expired ticket (> 24 h injected clock) falls back to a full handshake; a tampered ticket fails closed, is evicted, and the next connection is a full handshake; filling the cache beyond 1024 entries evicts the peer's ticket and forces a full handshake. |
| `api::network_wiring_mesh_tests::revoked_peer_is_refused_at_the_handshake_layer` | `initiate_session(..., TrustLevel::Revoked, ...)` returns `PeerRevoked` before any byte is written (the peer stream stays silent) and registers no session. |
| `transport::fragment::tests::{incomplete_assembly_is_discarded_after_the_stale_timeout, duplicate_fragment_index_is_idempotent_and_completes}` | Deterministic-clock timeout and duplicate idempotence at the buffer level. |
| `transport::tests::ble_hardware_scan_connect_and_write_round_trip` | **Hardware-gated** (`#[ignore]`, documented): real adapter scan/connect/subscribe/chunk write. Not run in CI. |

### Commands and results (this machine)

| Command | Result |
|---------|--------|
| `cargo test -p tirbase-core --features native --lib api::network_wiring_mesh_tests -- --test-threads=1` | **7 passed / 0 failed** |
| `cargo test -p tirbase-core --features native --lib transport::` | **116 passed / 0 failed / 1 ignored** (only the BLE hardware test) |
| `cargo test -p tirbase-core --features native` | **762 lib passed / 0 failed / 1 ignored**; every integration suite passes (8/1/2/2/5/1 …) |
| `cargo check -p tirbase-core --no-default-features --features wasm --target wasm32-unknown-unknown` | clean |
| `cargo check --workspace --all-targets` | clean |
| `cargo +nightly public-api -p tirbase-core` | WS6 additions recorded in `public-api.txt` / `wasm-public-api.txt` |

### Honest limits (do not overclaim)

1. **BLE is wired and tested over an emulated link; real-radio verification is hardware-gated.**
   `ble_hardware_scan_connect_and_write_round_trip` is `#[ignore]`d and was **not** run here (no
   BLE adapter/peripheral was available). The GATT write/subscribe/scan code is unverified on
   hardware; what is proven is the bridge/framing/selection/dispatch path that the radio plugs into.
2. **Multi-hop is proven on one host, loopback, single process.** The chain test uses three
   Swarms in one process; the relay entry in A's peer table is registered through
   `on_peer_discovered` (what relay discovery would do) rather than via mDNS. It does not prove
   cross-host relays, NAT traversal, or bandwidth accounting per hop.
3. **"No duplication" at the Delta layer is idempotent-merge + single-forward evidence.** C
   receives the envelope once per forwarder (its own Swarms' gossipsub propagation may also carry
   the same envelope), so duplication is prevented by the single forward per relay plus
   `apply_incoming_delta` idempotence, not by a wire-level exactly-once guarantee.
4. **0-RTT here means "cached ticket + first application frame in handshake message 1".** It is not
   a separate Noise `psk` pattern; a resumption still costs one round trip for message 2, but the
   data is in flight from the first flight. The ticket is the cached remote static key plus its
   issue time, bound to the peer DID and cached for 24 h.
5. **Rotation cipher states are exercised in memory.** The session was established over real
   loopback TCP, and rotation is the production `tick_key_rotation` → `snow`
   `rekey_outgoing/rekey_incoming`, but the post-rotation frames are encrypted/decrypted through the
   stored transport states rather than re-sent over the socket. Old-frame rejection replays a frame
   captured under the pre-rotation keys; it proves "not accepted", not the exact rejection reason.
6. **`scripts/check-public-api.sh` fails on this machine independently of WS6** (pre-existing
   toolchain rendering drift: `tirbase-guard`, untouched here, reports additions; `tirbase-core`
   already reported removed/re-rendered lines). Only the WS6 items were appended to the manifests.
7. **Relay envelopes are not authenticated separately.** A relay forwards the wrapped, signed
   Delta; the target verifies the Delta signature exactly as for a direct delivery. Hop/visited
   fields are routing metadata, not a trust assertion.

### Files

- `tirbase-core/src/transport/fragment.rs` (timeout + completed-id ring, tests)
- `tirbase-core/src/transport/ble.rs` (`BleLink`, `run_ble_bridge`, `BleChunkAssembler`, `chunk_id_for`, adapter impl)
- `tirbase-core/src/transport/session.rs` (length-prefixed framing, `TcpNoiseStream`, 0-RTT resumption, `respond`, `ResumptionStats`)
- `tirbase-core/src/transport/message.rs` (`RelayDelta` hop/visited)
- `tirbase-core/src/transport/mod.rs` (fragment threshold, `relay_decision`, `SessionEstablishment`, BLE channels/bridge/dispatch, tests)
- `tirbase-core/src/api/mod.rs` (relay forwarding + recording, BLE deployment wiring, `DeploymentConfig::mesh_ble_enabled`, WASM relay bound)
- `tirbase-core/src/api/network_wiring_mesh_tests.rs` (new suite)
- `tirbase-core/src/api/mesh_harness.rs`, `tirbase-core/src/lib.rs` (deployment field literals)
- `.github/workflows/ci.yml` (two mandatory WS6 steps)
- `tirbase-core/public-api.txt`, `tirbase-core/wasm-public-api.txt`

Commit for this workstream: the commit that adds this section
(`git log -1 --format=%h -- docs/agent/e2e-wiring/STATUS.md`).


## 3.10 WS7 — DRR floors, per-table compaction, outbound-queue guarantees (PROMPT 7 of 8)

Scope: `src/transport/scheduler.rs`, `src/crdt/mod.rs` (compaction paths and the
per-table document store), `src/store/compaction.rs`, `src/durability/cloud_queue.rs`,
the `CoreHandle` observability surface and a new real-mesh suite. Rows INV-19/INV-20/
INV-22/INV-23/INV-24/INV-25/INV-26.

### What was actually unwired (found, not assumed)

| # | Defect | Fix |
|---|--------|-----|
| 1 | **"Each table is a separate Automerge document" was false.** One `AutoCommit` served every table (`_tirbase_table` was just a ROOT key that each write overwrote), so compaction could not be scoped to a table and `CompactionPolicy::None` had no isolation to guarantee. | `CrdtEngine` now holds `docs: BTreeMap<String, AutoCommit>` plus `last_table`/`actor`. `write_scalar` routes to the table's own document; `apply` recovers the table from the incoming payload's `_tirbase_table` and merges only into that document; `project_table_to_store` reads that table's document. Legacy accessors (`doc`, `read_scalar`, `doc_map_range_root`, `convergent_state`) resolve through `last_table`, preserving their previous "state after the last write/merge" semantics. |
| 2 | **Compaction marked every table's DAG nodes.** `compact_table` ran `UPDATE dag_nodes SET compacted = 1 WHERE compacted = 0`, so compacting one table rewrote the other tables' history markers. | `mark_table_nodes_compacted` scans uncompacted nodes, decompresses the zstd payload (payloads are compressed at insert time), reads `_tirbase_table` and marks only this table's ids. Unattributable payloads stay unmarked (guessing would cross the isolation boundary). |
| 3 | **The scheduler had no observable counters**, so the 70/20/10 floors, spare flow and the LOW epoch bound could only be asserted at unit level. | `SchedulerStats` (epochs, bytes and Delta counts per class), plus `DrrScheduler::{stats, reset_stats, floor_quanta, deficits, queued_bytes}`, `MeshTransport::{scheduler_stats, reset_scheduler_stats, set_scheduler_link_capacity, scheduler_queued_bytes, low_queue_depth, medium_queue_depth}` and `CoreHandle::{scheduler_stats, reset_scheduler_stats, set_scheduler_link_capacity}`. |
| 4 | **`update_link_capacity` kept stale deficit credit.** A capacity change left bytes of *old-link* floor credit in the deficit counters, so the next epoch could burst (or starve) against the new link — this was visible immediately when the scheduler was re-based for a 10 000 B/s link. | `update_link_capacity` clears the three deficit counters; credit is denominated in the current link's floor bytes. |
| 5 | **The 100k queue bound was a constant with no reduced-bound path**, so overflow/no-drop behaviour could not be proven at a size CI can afford. | `CloudOutboundQueue::with_capacity(n)` / `capacity()`; `new()` keeps `MAX_QUEUE_DEPTH = 100_000`, and `enqueue` enforces `self.capacity`. `with_capacity` is a production constructor (same enqueue/acknowledge code). |

### Tests added — all through production paths

| Test | Proves |
|------|--------|
| `api::drr_compaction_queue_tests::drr_byte_floors_hold_over_ten_real_mesh_epochs` | Two real Swarms; 220 HIGH + 90 MEDIUM + 45 LOW real signed Deltas enqueued via `MeshTransport::enqueue_outbound`, ten epochs driven by the production `MeshTransport::tick_scheduler` (the exact function `CoreHandle::spawn_scheduler_tick_loop` calls) at a 10 000 B/s link. Measured: **10 epochs**, total **98 042 B** scheduled — HIGH **69 431 B (70.82 %)**, MEDIUM **19 084 B (19.47 %)**, LOW **9 527 B (9.72 %)**. Cumulative allocation (`served + residual deficit`) is **≥ 70 000 / 20 000 / 10 000 B**, i.e. the 70/20/10 floors exactly; observed transmission is within one whole Delta (1 365 B) of each floor because DRR sends whole Deltas. The peer reads a HIGH, a MEDIUM and a LOW row through the ordinary projection path. |
| `…::spare_capacity_goes_to_high_first_and_low_clears_within_ten_epochs` | HIGH backlogged, MEDIUM empty, LOW backlog **9 514 B ≤ clearing capacity 10 000 B** (`DrrScheduler::low_clearing_capacity(10_000)`). Epoch 1: HIGH **8 208 B > 7 000 B floor** (it took the spare), MEDIUM **0 B**, LOW **0 B ≤ 1 000 B floor** — spare flows to the highest-priority backlog first. The LOW queue depth reaches **0 at epoch 10** (all 7 LOW Deltas in 9 514 B), and the peer reads the last LOW row. Over the window HIGH took 85 665 B. |
| `…::compaction_is_per_table_and_none_policy_is_never_compacted` | One deployment, two tables: `agg` = `Aggressive { threshold: 3 }`, `keep` = `None`. Writes 0–2 of `agg` are uncompacted; the 4th write crosses the threshold and compacts exactly the three existing `agg` nodes; the next write compacts the Delta the crossing write produced. Six `keep` writes stay **uncompacted** while `agg` is compacted. `table_names()` shows separate `agg`/`keep` documents with different saved sizes; all five `agg` and six `keep` rows read back correctly and `refetch_delta_bytes` still returns the compacted Delta. |
| `…::cloud_queue_bound_holds_and_never_drops_queued_entries` | `MAX_QUEUE_DEPTH == 100 000` and `CloudOutboundQueue::new().capacity() == 100 000`; at a reduced bound of 256 the 257th enqueue fails with `CloudQueueFull { depth: 256 }`, depth stays 256 (no eviction/drop), and the slot freed by `acknowledge` accepts the next entry. |
| `…::offline_writes_accumulate_without_drop_and_drain_on_reconnect` | 64 writes through `CoreHandle::write` while no cloud sync runs: queue depth 64 and every row readable (nothing dropped). One production `run_cloud_sync_cycle`: `acknowledged = 64`, `deferred = 0`, `rejected = 0`, depth 0, every Delta committed in the Cloud Ledger and at `Tier2`. |
| `…::full_scale_100k_offline_writes_fill_the_queue_without_loss` | **Gated full-scale** (`#[ignore]`, documented): 100 000 real writes fill the production queue to `MAX_QUEUE_DEPTH`, the next write is refused with `CloudQueueFull` and the depth is unchanged. Not run in CI (too slow); the constant, enforcement and no-drop behaviour are covered by the two tests above and by `durability::tests::cloud_queue_overflow_returns_queue_full`. |
| `api::real_mesh_tests::tier1_then_compaction_refetch_and_cloud_sync_reach_tier2` (extended) | Tier-1 + compaction + re-fetch through the durability path: the writer's earlier Delta is marked `compacted` while the receipt holder's copy is **not**, and re-fetching the compacted Delta from the holder returns **byte-identical** payload to the writer's re-fetch (`refetch_delta_bytes`), on top of the existing Tier-2 ack assertions. |

### Commands and results (this machine)

| Command | Result |
|---------|--------|
| `cargo test -p tirbase-core --features native --lib api::drr_compaction_queue_tests -- --test-threads=1` | **5 passed / 0 failed / 1 ignored** (the gated full-scale test) |
| `cargo test -p tirbase-core --features native` | **767 lib passed / 0 failed / 2 ignored** (BLE radio + full-scale), every integration suite green (`contamination_resolution` 8, `crash_recovery` 1, `fleet_inventory` 2, `security_event_sync` 2, `shadow_postconditions` 5, `time_source_injection` 1) |
| `cargo test -p tirbase-core --features native --lib api::real_mesh_tests` | **21 passed / 0 failed** |
| `cargo test -p tirbase-core --features native --lib crdt::` | **113 passed / 0 failed** |
| `cargo test -p tirbase-core --features native --lib store::` / `durability::` | **22 passed** / **90 passed** |
| `cargo check -p tirbase-core --no-default-features --features wasm --target wasm32-unknown-unknown` | clean (only the pre-existing `proc-macro-error2` future-incompat warning) |
| `cargo test -p tirbase-core --features native --lib tests::api_parity` | **6 passed** (the three new observability methods are documented exclusions) |

CI: a mandatory step — `WS7 e2e (DRR floors, spare capacity, LOW bound, compaction, queue)` running
`cargo test -p tirbase-core --features native --lib api::drr_compaction_queue_tests -- --test-threads=1`
— was added to the `test` job (no `continue-on-error`, no `|| true`, no `--ignored`). The job's full
`cargo test --features native` step covers it as well. The pre-existing caveat that
`.github/workflows/ci.yml` does not parse as YAML (block scalars at the same indentation as `run:`)
still applies; the new step follows the file's existing style.

### Fails-before evidence

- Before this change the scheduler exposed no counters at all, so the three DRR tests cannot compile
  on the starting tree (no `scheduler_stats`, no `deficits`, no `queued_bytes`).
- Before the per-table split, `compact_table` marked **all** uncompacted nodes and the engine had one
  document: `compaction_is_per_table_and_none_policy_is_never_compacted` fails on the per-table
  assertions (the `keep` nodes come back `compacted`, and `table_names()` has a single entry).
- Before `update_link_capacity` cleared the deficits, the floors measurement transmitted the whole
  485 KB backlog in epoch 1 (`high=300 958 B`, i.e. 62 % of the window) instead of 70 %, and the
  ten-epoch bound was unobservable.
- Before `with_capacity`, the reduced-bound test cannot express a 256-entry bound without faking the
  constant.

### Honest limits (do not overclaim)

1. **Same host, loopback.** Every DRR scenario uses two Swarms in one process over loopback TCP with
   genuine gossipsub publish/subscribe and the production drain loops; it does not prove cross-host
   behaviour (INV-43 stays open).
2. **Whole-Delta quantization.** DRR transmits complete Deltas, so an observed fraction is at most one
   Delta below its floor. The floors are proven exactly as **allocated** bytes (`served + deficit`)
   and as observed bytes within `ONE_DELTA_SLACK = 2 048 B`; the measured run is 70.82 / 19.47 / 9.72 %.
3. **Epochs are driven directly.** The tests call `MeshTransport::tick_scheduler` (the production
   function, production per-epoch budget) ten times rather than sleeping through ten 1-second ticks;
   `CoreHandle::spawn_scheduler_tick_loop` is separately covered by the pre-existing scheduler-loop
   tests. No test-only scheduler branch exists.
4. **Queue bound at reduced size.** The 100 000 constant and overflow behaviour are asserted directly
   (`MAX_QUEUE_DEPTH`, `new().capacity()`, and the existing 100k-fill unit test), but the end-to-end
   no-drop/reconnect path is exercised at 64 real writes; the full 100k end-to-end run is the gated
   `#[ignore]` test and was **not** run here.
5. **Compaction is proven on a single device** (schema + policies + DAG marking + reads + re-fetch).
   The durability half reuses the WS3 Tier-1 test rather than re-testing quorum formation, as scoped.
6. **`public-api.txt` was appended by hand** for the new items (the manifest already drifts from
   `cargo +nightly public-api` on ~498 pre-existing lines; regenerating would produce an unrelated
   repo-wide diff). `scripts/check-public-api.sh` continues to fail for that pre-existing reason.
7. **`compaction_policy_for` falls back to `None`** when no schema definition is registered for the
   current hash — unchanged behaviour, documented at the call site.

### Files

- `tirbase-core/src/transport/scheduler.rs` (SchedulerStats, deficits/queued_bytes, capacity-change reset)
- `tirbase-core/src/transport/mod.rs` (scheduler observability + link-capacity control)
- `tirbase-core/src/crdt/mod.rs` (per-table Automerge documents; table-routed apply/projection/compaction)
- `tirbase-core/src/crdt/merge.rs` (hardening gate reads the Delta's own table document)
- `tirbase-core/src/store/compaction.rs` (table-scoped DAG compaction marking)
- `tirbase-core/src/durability/cloud_queue.rs` (configurable capacity bound)
- `tirbase-core/src/api/mod.rs` (CoreHandle observability; extended Tier-1 compaction/re-fetch test; suite module)
- `tirbase-core/src/api/drr_compaction_queue_tests.rs` (new suite)
- `tirbase-core/src/tests/api_parity.rs` (documented exclusions for the observability methods)
- `tirbase-core/public-api.txt`, `.github/workflows/ci.yml`

Commit for this workstream: the commit that adds this section
(`git log -1 --format=%h -- docs/agent/e2e-wiring/STATUS.md`).

## 4. Blockers / limits of this workstream

- **No commit of the inventory yet** — this file and the charter are committed with the WS1
  foundation commit; the SHA is recorded below.
- **RGA (INV-06)** has no public write surface at all; it needs a new API (WS2), not wiring.
- **BLE (INV-07), HIL (INV-52/55), TPM2 (INV-53)** are hardware-blocked and cannot be closed by
  code in this environment; they must not be marked wired.
- The real-mesh harness runs two Swarms in one process. A multi-process variant
  (`three_processes_reach_tier1_across_os_processes`) now proves genuine receipt exchange across
  separate OS processes over loopback, but it does not prove cross-host behaviour (INV-43).
- `real_mesh_tests` use loopback ports reserved by binding; on a machine with heavy port pressure
  they can still collide (documented in `mesh_harness`).

## 5. Handoff

- Charter: `docs/agent/e2e-wiring/00-charter.md`.
- WS1 foundation commit: `08a2156` (`test(core,sdk,ci): wire e2e foundations and inventory wiring gaps`), 14 files, 1181 insertions / 438 deletions.
- Post-commit verification: `cargo test -p tirbase-core --features native` → 718 lib passed, 0 failed; `cargo test -p tirbase-gateway` → all suites pass; `npx jest` → 90/90; `cargo check --target wasm32-unknown-unknown --features wasm` → clean.
- WS2 (prompt 2 of 8) closed INV-12/INV-27/INV-28; see §3.1 for its evidence and CI jobs. §3.2 records the follow-up
  that authenticated `initiate_revocation`, §3.3 the DISASTER_ALERT issuance path, §3.4 the gateway SDK transports
  and §3.5 the gateway→WASM saturate e2e. The one remaining item is signed admin operations proven only to their auth gate, which stays with
  `tirbase-gateway/tests/admin_endpoints_binary.rs`.
- WS4 (prompt 4 of 8) closed INV-13/INV-14 and added the mesh path for M-of-N Saturate termination; see §3.7.
- WS5 (prompt 5 of 8) closed INV-15/INV-16/INV-17, added the native incident event surface, real-mesh
  migration/revocation distribution, Side-Car replay projection + resume, composite extension, and reconciled
  the `tests/README.md` Item 7 projection-gap text; see §3.8.
- WS6 (prompt 6 of 8) closed INV-08/INV-10/INV-11 and took INV-07 to `wired (emulated link)` with the
  radio hardware-gated; it also extended INV-09 to the documented `mesh_mtu = 256` path; see §3.9.
- WS7 (prompt 7 of 8) closed INV-19/INV-20/INV-22/INV-23/INV-24/INV-25/INV-26: per-table Automerge
  documents, table-scoped compaction, production DRR counters with measured 70/20/10 floors, spare
  flow, the LOW 10-epoch bound, the queue bound/no-drop path and a byte-identical Tier-1 re-fetch; see §3.10.
- The next unclaimed rows are INV-06/INV-30/INV-31/INV-47 (INV-25/INV-26 are closed by §3.10).
- WS8 must not mark INV-03, INV-04, INV-40, INV-41, INV-44…INV-46, INV-49, INV-50 as gaps — they
  are stale markers over now-executable proof.
