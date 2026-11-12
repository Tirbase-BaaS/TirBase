# E2E Wiring — STATUS ledger

**Workstream:** 1–2 of 8 (inventory + foundations; TypeScript manager ops + gateway admin SDK)
**Branch:** `main`
**Baseline HEAD:** `5bea300`
**Last updated:** 2026-11-12

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
| INV-07 | BLE bridge for LAN-less/offline topologies (L123) | `transport/ble.rs` (unit-level) | `hardware-blocked` | no BLE adapter/CI job; unit tests only; documented Phase 1 blocker | 3 | — |
| INV-08 | Multi-hop relay topologies (L126) | `transport/discovery.rs` `find_relay_peer`, `message.rs` relay envelope | `under-proven` | discovery/relay unit tests exist; no e2e relay through two Swarms | 3 | — |
| INV-09 | MTU discovery + per-path fragmentation (L138) | `transport/{session,fragment}.rs`, production send | `wired` | `real_mesh_tests` low-MTU round-trip cases (Item 22 in `tests/README.md`) | 1 | — |
| INV-10 | 0-RTT session resumption (L154) | `transport/session.rs` resume cache | `under-proven` | session unit tests; no live re-dial over the wire | 3 | — |
| INV-11 | Key rotation and session-cache invalidation (L164/167) | `transport/session.rs`, `auth` | `under-proven` | unit tests only; no rotation mid-mesh e2e | 3 | — |
| INV-12 | SDK surfaces real-time trust levels (L176) | `tirbase-sdk` `onTrustLevelChanged` ← `core_poll_events` | **`wired`** | `tirbase-manager-ops.wasm.test.ts`: `presentToken` moves a real WASM instance to `VERIFIED` and emits `trust-level-changed`; an invalid token leaves `UNVERIFIED` plus the unverified warning; a peer revocation no longer mutates the local level (`TrustLevelChanged` now carries `did`) | 7 | WS2 |
| INV-13 | M-of-N revocation accumulates gossip across peers (L235) | `auth` revocation collector ← `receive_inbound` revocation deltas | `under-proven` | `revocation_delta_enqueued_at_high_priority_after_threshold_met` + property 7; not accumulated from two live peers | 3 | — |
| INV-14 | A node one gossip round from the mesh isolates a revoked device (L255) | `auth`/`api` revocation application | `under-proven` | threshold logic tested; no timed e2e isolation assertion | 3 | — |
| INV-15 | Contamination forward trace identifies tainted devices (L260/262) | `contamination` → `verify_contamination` | `under-proven` | composite-incident + revocation mesh tests exist; no revoked-author → CCE tag e2e | 6 | — |
| INV-16 | Sidecar replay after corrected migration, tagged on success (L279) | `migration::SideCarLedger::replay_sidecar` | `under-proven` | `sidecar.rs` unit tests + property 22; not exercised through a production migration run | 6 | — |
| INV-17 | Replay conflicts flagged for manual resolution without abort (L286) | `migration/sidecar.rs` conflict counting | `under-proven` | `replay_with_conflicts_does_not_append_replay_complete_tag`; flag not surfaced through API | 6 | — |
| INV-18 | Tier-1 durability from a live quorum of two devices (L298) | `durability` receipt exchange ← `receive_inbound` | `wired` | `api::real_mesh_tests::two_devices_reach_tier1_durability_via_genuine_receipt_exchange` | 1 | — |
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
| INV-40 | Property 14 `PARTIAL` (Tier-1 only single device) | `stale-docs` | `two_devices_reach_tier1_durability_via_genuine_receipt_exchange` | 1 |
| INV-41 | Item 7 `PARTIAL` (projection gap over real mesh) | `stale-docs` (closed by WS1) | `json_envelope_delta_over_real_mesh_projects_to_peer_store` + existing binary projection test | 1 |
| INV-42 | Cross-Device Mesh `PARTIAL` | `stale-docs` (partly) | Delta projection, Tier-1 and MTU now real; revocation/migration/cloud over the wire remain (WS3/WS4/WS6) | 1 |
| INV-43 | Single-process harness limitation note | `under-proven` | each test uses one process with two Swarms; no cross-process/multi-host run | 3 |

### 2.4 `properties.rs` documented gaps

| ID | Gap | Current state | WS |
|----|-----|---------------|----|
| INV-44 | Property 1: no shared cross-build harness | `stale-docs` — WS1 now provides a real-WASM Node harness and a real-mesh harness; the shared vector run is still missing | 2 |
| INV-45 | Properties 5/14: Tier-1 quorum only single-device | `stale-docs` (INV-18 / INV-40) | 1 |
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
| 8 | The `caveat("disaster-alert")` token had no production minting path, so `activate_saturate_mode` was unreachable outside tests | `create_token_with_caveat` keeps production signing, gated on `test`/`test-hooks`; documented as a blocker below |
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
| `cd sdk/typescript && npm test` | **8 passed / 8** (builds the TS SDK, runs the e2e) |
| `bash scripts/check-gateway-sdk-generated.sh` | **OK** (generator fixed; see below) |
| `cargo +nightly public-api -p tirbase-core` | unchanged surface: the caveat minter is `#[cfg(any(test, feature = "test-hooks"))]`, so no manifest churn |

### Generated gateway SDK drift (pre-existing, repaired)

`scripts/check-gateway-sdk-generated.sh` failed on the starting tree: the generator matched path keys with `^\s{2}`, which is satisfied by the newline before each path line except `paths:` itself, so `/admin/enroll` was silently dropped; the committed sources had also been hand-edited (SPDX headers). The generator now matches `^ {1,2}`, emits the SPDX header, and writes the manifest with stable formatting. Output currently equals the committed sources (19 operations, 19 paths); the manifest commit is a whitespace-only reformat.

### CI

- `test` job: `npm test` (both WASM targets via `pretest`, so the real-WASM suites run) plus an explicit `npm run test:wasm-e2e` step.
- New `gateway-admin-sdk-e2e` job: builds `tirbase-gateway`, installs `sdk/typescript`, runs `npm test` with `TIRBASE_GATEWAY_BIN`.

### Blockers / still-open items (do not mark wired)

1. **DISASTER_ALERT token issuance has no operator-facing surface.** `activate_saturate_mode` requires a root-CA-signed `caveat("disaster-alert")` token, but neither `biscuit::create_token` nor the gateway `mint` endpoint can produce one (mint hard-codes the role → fact mapping and has no caveat field). The e2e mints it with the same production signing code under `test-hooks`. Closing this needs an admin/manager issuance path — a product/API decision, not wiring.
2. ~~`initiate_revocation` does not verify the manager token~~ — **fixed** in §3.2: the token is verified against the root CA, expiry-checked and role-checked (`RevocationManager`) before any signature is produced or gossiped.
3. **Signed admin operations are exercised to their auth gate, not through it.** `enroll`/`policy`/`lockdown-exit`/`chain-recovery`/`sequence-reset`/`lease-preempt`/`quarantine-replay`/`time-reset`/`unknown-clear`/`restore`/`epoch-bump` require PolicyAuthority or M-of-3 TimeAnchor `SignedOperation` bodies. Re-implementing the guard's canonical encoding in JavaScript would create a second security-critical implementation, so the TS test asserts the typed answer (never 404/501/silent skip) and the signed success paths stay covered by `tirbase-gateway/tests/admin_endpoints_binary.rs`.
4. **`sdk/typescript` mTLS uses a custom `fetchImpl`.** The generated client only needs `ok`/`status`/`json()`; the test provides an `https` adapter with a client certificate. Node's global `fetch` cannot present client certificates, so remote admin from a browser/undici client remains unsupported.

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

## 4. Blockers / limits of this workstream

- **No commit of the inventory yet** — this file and the charter are committed with the WS1
  foundation commit; the SHA is recorded below.
- **RGA (INV-06)** has no public write surface at all; it needs a new API (WS2), not wiring.
- **BLE (INV-07), HIL (INV-52/55), TPM2 (INV-53)** are hardware-blocked and cannot be closed by
  code in this environment; they must not be marked wired.
- The real-mesh harness runs two Swarms in one process. It does not prove cross-host behaviour
  (INV-43); WS3 owns a multi-process variant.
- `real_mesh_tests` use loopback ports reserved by binding; on a machine with heavy port pressure
  they can still collide (documented in `mesh_harness`).

## 5. Handoff

- Charter: `docs/agent/e2e-wiring/00-charter.md`.
- WS1 foundation commit: `08a2156` (`test(core,sdk,ci): wire e2e foundations and inventory wiring gaps`), 14 files, 1181 insertions / 438 deletions.
- Post-commit verification: `cargo test -p tirbase-core --features native` → 718 lib passed, 0 failed; `cargo test -p tirbase-gateway` → all suites pass; `npx jest` → 90/90; `cargo check --target wasm32-unknown-unknown --features wasm` → clean.
- WS2 (prompt 2 of 8) closed INV-12/INV-27/INV-28; see §3.1 for its evidence, CI jobs and the items it leaves open
  (DISASTER_ALERT issuance surface, signed admin operations proven to the auth gate, and no mTLS-capable browser
  `fetch`). §3.2 records the follow-up that authenticated `initiate_revocation`.
- The next unclaimed rows are INV-06/INV-25/INV-26/INV-30/INV-31/INV-47.
- WS8 must not mark INV-03, INV-04, INV-40, INV-41, INV-44…INV-46, INV-49, INV-50 as gaps — they
  are stale markers over now-executable proof.
