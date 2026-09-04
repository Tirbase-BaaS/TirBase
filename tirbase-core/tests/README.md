# TirBase Core — End-to-End Test Coverage Notes

This document records the test status of all 22 correctness properties from
`design.md`, plus the end-to-end integration test items from Task 34 of the
implementation plan.  Each entry lists one of three statuses:

- **VERIFIED** — the property has a passing test that exercises the full
  production code path (no mocks substituting real subsystems).
- **PARTIAL** — the property is tested at a subsystem level; cross-device or
  cross-build components are covered by unit tests but not live mesh traffic.
- **DEFERRED** — the property cannot be fully tested in the current in-process
  harness.  The reason is stated explicitly so contributors know the gap is
  intentional, not overlooked.

---

## Property-Based Test Suite (Task 15)

### Property 1 — Cross-Build State Convergence (Req 1.4)

**Status:** PARTIAL

The test (`prop_01_cross_build_state_convergence` in `src/tests/properties.rs`)
applies identical Delta sequences to two independent `CrdtEngine` instances
compiled to the **same** native target and verifies their Lamport clocks
converge.

**Deferred aspect:** True byte-for-byte parity between the WASM build
(`wasmi`-sandboxed migrations) and the native build (`wasmtime`-sandboxed
migrations) requires running both binaries against the same input corpus and
comparing serialised Local Store state.  This cannot be done within a single
`cargo test` invocation because `wasm32-unknown-unknown` and
`x86_64-apple-darwin` are separate build targets.

**Mitigation:** The WASM build compiles without errors
(`cargo check --no-default-features --features wasm --target wasm32-unknown-unknown`).
`src/tests/wasm_tests.rs` confirms the WASM in-memory store round-trips
correctly.  The Automerge library provides cross-platform convergence
guarantees.  The `arb_ordered_delta_sequence` generator includes
`Migration_Delta` entries to cover the `wasmi`/`wasmtime` divergence risk
path when the full WASM test harness is wired.

---

### Property 2 — CRDT Causal Commutativity (Req 4.7)

**Status:** PARTIAL

Tests that applying the same Delta set in different orders (forward vs. reverse)
results in the same merge count on both engines.

**Deferred aspect:** True multi-device commutativity over a live P2P mesh is
not tested.  The property exercises CRDT semantics in isolation without a
transport layer.

---

### Property 3 — LWW Scalar Conflict Resolution (Req 4.5)

**Status:** VERIFIED

`prop_03_lww_scalar_conflict_resolution` passes 200 cases.  The
`CrdtEngine` is initialised with the DID public-key bytes as the Automerge
actor ID (`AutoCommit::with_actor`), ensuring the LWW tiebreak uses the same
key material as the spec mandates.

---

### Property 4 — RGA Sequence Merge Completeness (Req 4.5a)

**Status:** VERIFIED

`prop_04_rga_sequence_merge_completeness` passes 200 cases.  Concurrent list
insertions are sorted by `(lamport DESC, actor_id DESC)` and verified to be
consistent with `rga_incoming_has_priority`.

---

### Property 5 — Write-Before-Acknowledge Durability (Req 3.2)

**Status:** VERIFIED

`prop_05_write_before_acknowledge_durability` passes 200 cases against a
live in-memory SQLite store, confirming data is readable from the projection
table before the function returns.

---

### Property 6 — Delta Signature Round-Trip and Tamper Rejection (Req 7.2, 7.3)

**Status:** VERIFIED

`prop_06_delta_signature_round_trip_and_tamper_rejection` passes 200 cases,
covering both valid round-trips and tampered-payload rejection.

---

### Property 7 — M-of-N Revocation Threshold Enforcement (Req 9.1, 9.3)

**Status:** VERIFIED

`prop_07_mofn_revocation_threshold_enforcement` passes 200 cases across all
values of M from 1 to 4, using real Ed25519 signatures.

---

### Property 8 — Contamination Propagates to All Reachable Descendants (Req 10.2)

**Status:** VERIFIED

`prop_08_contamination_propagates_to_all_descendants` passes 200 cases with
linear DAG chains of 3–8 nodes, confirmed via direct SQLite tag reads.

---

### Property 9 — CONTAMINATED Tag Persists Until All Roots Resolved (Req 10.3)

**Status:** VERIFIED

`prop_09_contaminated_tag_persists_until_all_roots_resolved` passes 200 cases
with a two-root / shared-descendant DAG structure, verified via tag reads.

---

### Property 10 — Tag Log Monotonic Append-Only Invariant (Req 10.4)

**Status:** VERIFIED

`prop_10_tag_log_monotonic_append_only` passes 200 cases, confirming the tag
log length is non-decreasing and no entry is modified or removed.

---

### Property 11 — Composite Incident Formation on DAG Overlap (Req 10.5)

**Status:** VERIFIED

`prop_11_composite_incident_formation_on_dag_overlap` passes 200 cases,
confirming that two contamination chains sharing a node produce exactly one
`CompositeIncidentInstance`.

---

### Property 12 — DRR Guaranteed Bandwidth Floors (Req 12.2–12.4)

**Status:** VERIFIED

`prop_12_drr_guaranteed_bandwidth_floors` passes 200 cases over ≥10 scheduler
epochs, verifying HIGH ≥70%, MEDIUM ≥20%, LOW ≥10% byte fractions.

---

### Property 13 — LOW Queue Bounded Wait at Clearing Capacity (Req 12.8)

**Status:** VERIFIED

`prop_13_low_queue_bounded_wait_at_clearing_capacity` passes 200 cases with
LOW queue depth ≤ clearing capacity, confirming every delta is transmitted
within 10 epochs.

---

### Property 14 — Tier-1 Quorum Detection (Req 14.2, 14.3)

**Status:** PARTIAL

`prop_14_tier1_quorum_detection` passes 200 cases with real Ed25519-signed
receipts and a mock `DurabilitySubsystem`.

**Deferred aspect:** Live K-of-N quorum formation with distinct networked
peers is not exercised.  The in-process test uses injected receipts rather
than receipts from distinct tokio tasks over loopback libp2p.  Full live
quorum testing is deferred to `durability/integration_tests.rs` (post-v1).

---

### Property 15 — Schema Hash Determinism (Req 17.1, 20.5)

**Status:** VERIFIED

`prop_15_schema_hash_determinism` passes 200 cases, confirming
`SchemaIdentifierHash` is independent of declaration order.

---

### Property 16 — Schema Delta Routing Additive vs Breaking (Req 17.3, 17.4)

**Status:** VERIFIED

`prop_16_schema_delta_routing_additive_vs_breaking` passes 200 cases,
confirming additive deltas are merged and breaking deltas are quarantined.

---

### Property 17 — Migration Zero-Trust Gate (Req 18.2, 18.3)

**Status:** VERIFIED

`prop_17_migration_zero_trust_gate` passes 200 cases, confirming that
tampering either the CA signature or the transform SHA-256 results in
rejection regardless of check order.

---

### Property 18 — Schema Parse-Print-Parse Round-Trip (Req 20.4)

**Status:** VERIFIED

`prop_18_schema_parse_print_parse_round_trip` passes 200 cases, confirming
`parse(print(parse(input)))` produces structurally equal schemas.

---

### Property 19 — Schema Parse Error Coverage (Req 20.2)

**Status:** VERIFIED

`prop_19_schema_parse_error_coverage` passes 200 cases with syntactically
invalid mutations, confirming every invalid input produces at least one error
with line, column, and description.

---

### Property 20 — Saturate Mode Lease State Machine (Req 13.1–13.7)

**Status:** VERIFIED

`prop_20_saturate_mode_state_machine_invariants` covers invariants (a)–(d)
with a mock (non-Biscuit) state machine at 200 cases.

`prop_20_biscuit` (sub-properties 20a–20d) exercises the full Biscuit token
verification path at **30 cases per sub-property** — reduced from 200 because
each case creates and verifies a fresh Biscuit token.  The Biscuit Datalog
authorizer now uses `authorize_with_limits` with a generous budget
(10 000 iterations) to avoid per-authorizer budget exhaustion across the full
test suite.

**Production wiring (Subphase 3.1–3.2):** activation, heartbeat renewal, and
M-of-N termination are exercised over the real production path — the
`SaturateModeStateMachine` instantiated inside `MeshTransport` — by
integration tests at the transport level (`transport::tests::renew_saturate_*`,
`transport::tests::terminate_saturate_mode_*`) and at the `CoreHandle` level
(`api::tests::saturate_mode_lifecycle_routes_through_state_machine_and_scheduler`),
including the regression assert that a successful M-of-N termination clears the
DRR scheduler's Saturate_Mode flag (the bare `set_saturate_mode(true)` boolean
bypass could never demote it).  Renewal/termination on WASM are reachable via
the `core_renew_saturate_mode` / `core_terminate_saturate_mode` exports.

**Production wiring (Subphase 3.3):** lease expiry auto-demotion is now
driven by the production tick loop — `CoreHandle::spawn_scheduler_tick_loop`
(the Phase 1.4 loop `CoreHandle::init` spawns) calls
`MeshTransport::tick_saturate` every epoch with the wall clock, which ticks
the real `SaturateModeStateMachine` and reconciles the DRR scheduler mirror
(transport/mod.rs → saturate.rs).  The integration test
`api::tests::scheduler_tick_loop_auto_demotes_expired_saturate_lease` drives
that identical loop with a short interval, activates Saturate_Mode through the
real production facade, backdates the lease (the loop runs on real time; a
60-minute lease cannot be waited out in a test), and asserts the background
task — not a manual `tick()` call — demotes the state machine and clears the
scheduler.  `transport::tests::tick_saturate_demotes_expired_lease_and_clears_scheduler`
covers the transport-level demotion + scheduler reconcile.

**Production wiring (Subphase 3.4):** the runtime expiry path is now covered
end-to-end with no test-only state manipulation.  The lease duration is a
production configuration knob (`DeploymentConfig::saturate_lease_duration_secs`
→ `TransportConfig::saturate_lease_duration_secs` →
`SaturateModeStateMachine`, wired in `CoreHandle::init`; defaults to the
spec-mandated 60-minute window, Req 13.3).  `api::tests::saturate_runtime_lease_expiry_auto_demotes_without_renewal`
configures a 2-second window through that exact production construction,
activates Saturate_Mode through the production facade, performs **no renewal
and no backdating**, and asserts the production tick loop
(`CoreHandle::spawn_scheduler_tick_loop`, wall-clock driven) auto-demotes the
state machine and clears the DRR scheduler mirror only after the lease
genuinely expires through the actual runtime — the test additionally asserts
the wall clock actually crossed the natural expiry before demotion.
`SaturateModeStateMachine` itself now takes the lease duration as a
constructor parameter; `SATURATE_LEASE_DURATION_SECS` remains the canonical
default.

**Deferred aspect (generator-level only):** the proptest generator does not
include time-ordered activation + renewal sequences because generating valid
ordered Biscuit token pairs inside a proptest strategy is impractical without
a custom strategy that maintains the token timestamp invariant.  The runtime
lease-expiry behaviour this deferral previously covered is now exercised by
the Subphase 3.4 integration test above.

---

### Property 21 — Migration Revocation Halts In-Progress Transforms (Req 18.5–18.7)

**Status:** VERIFIED

`prop_21_migration_revocation_halts_in_progress_transforms` passes 200 cases,
confirming that a pre-sent `MigrationRevocationDelta` blocks subsequent
execution of the same migration hash.

---

### Property 22 — Side-Car Ledger Replay Continues Past Conflicts (Req 19.3, 19.4, 19.6)

**Status:** VERIFIED

`prop_22_sidecar_ledger_replay_continues_past_conflicts` passes 200 cases.
The test asserts:
- `total_entries == n_valid + n_invalid`
- `complete == (conflicts == 0)`
- Every replayed delta carries `DeltaTag::ReplayComplete` after a zero-conflict run
- No `ReplayComplete` tag appears when `conflicts > 0`

---

## Integration Tests (Task 34, Checklist)

### Item 1 — Native Test Suite

**Status:** VERIFIED (525 tests, 0 failures)

`cargo test --features native` passes all 525 tests including all 22 property
tests and all CoreHandle integration tests (Subphase 4.1 added the two
`api::cloud_sync_tests` production cloud-sync drain tests; Subphase 4.2 added
the two `api::tier2_ack_tests` Tier-2 acknowledgement tests and the
`durability::tests::tier_changed_listener_fires_on_cloud_ack_transition`
listener unit test; Subphase 4.3 added the nine Anchor-Attested Location tests
listed in Item 11).

---

### Item 2 — WASM Check

**Status:** VERIFIED (zero errors, zero warnings)

`cargo check --no-default-features --features wasm --target wasm32-unknown-unknown`

Note: the `--features wasm` flag **must** be paired with `--no-default-features`
because the workspace `default = ["native"]` would otherwise activate the
mutually-exclusive `native` feature.

Note: `wasm-pack build` (version 0.15.0) has a bug where it attempts to add
the JS output target (e.g., `"web"`) as a Rust `rustup` target.  Use the
manual build pipeline instead:

```sh
cargo build --no-default-features --features wasm --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/tirbase_core.wasm \
    --out-dir tirbase-sdk/wasm --target web
```

---

### Item 3 — TypeScript SDK Tests

**Status:** VERIFIED (65 tests, 0 failures)

`npm test` in `tirbase-sdk/` passes all 65 Jest tests (including the WASM
event bridge tests added in Task 31 and the Subphase 3.2
`renewSaturateMode` / `terminateSaturateMode` delegation tests).

---

### Item 4 — WASM Artefact and `core_poll_events`

**Status:** VERIFIED

The wasm-bindgen export surface — regenerated into
`tirbase-sdk/wasm/tirbase_core.d.ts` by the manual pipeline above on release —
consists of 15 required exports:
`core_init`, `core_read`, `core_write`, `core_query`, `core_trust_level`,
`core_mesh_status`, `core_initiate_revocation`, `core_revocation_status`,
`core_verify_data`, `core_admin_close`, `core_activate_saturate_mode`,
`core_renew_saturate_mode`, `core_terminate_saturate_mode`,
`core_receive_peer_message`, `core_poll_events`.

---

### Item 5 — Properties 3 and 4 with DID Actor ID

**Status:** VERIFIED

Both properties pass 200 cases with `CrdtEngine` now using the 32-byte
Ed25519 public key as the Automerge actor ID (via `AutoCommit::with_actor`).
LWW and RGA tiebreaks are deterministic on the DID-derived bytes per spec.

---

### Item 6 — Property 22 `DeltaTag::ReplayComplete`

**Status:** VERIFIED

Property 22 asserts that every zero-conflict sidecar replay appends
`DeltaTag::ReplayComplete { migration_id }` to each replayed delta, and
confirms no such tag appears when there are conflicts.

---

### Item 7 — Inbound Delta Pipeline End-to-End

**Status:** PARTIAL

`api::inbound_tests::end_to_end_inbound_pipeline_write_a_read_b` exercises:

1. Write to `handle_a` → produces a non-zero `delta_id`.
2. Construct an equivalent `GossipMessage::InboundDelta` with a valid
   Ed25519 signature from a separate peer identity.
3. Inject into `handle_b` via `inject_inbound`.
4. Call `process_inbound_messages()` → returns 1 (exactly one message processed).
5. The CRDT merge logs `[inbound] delta … merged from …`, confirming
   `MergeOutcome::Merged`.

**Deferred aspect — projection gap:** After `process_inbound_messages()`,
`handle_b.read("sensors", "reading-1")` returns `Err` (key not found).
This is because `receive_inbound` merges the delta at the Automerge/CRDT
level but does **not** write-through to the SQLite projection table
(`proj_{table}`).  The data lives in the Automerge document but is invisible
to `LocalStore::read()`, which reads from the SQL projection.

Adding a projection step inside `receive_inbound` (calling `project_table`
or `store.write()` after a successful merge) would close this gap and make
inbound deltas immediately readable.  This is tracked as a post-v1
follow-on task.  It does not affect correctness of the CRDT state —
the Automerge document is correct; only the SQL projection cache is stale.

---

### Item 8 — Untestable Properties Documentation

This document (you are reading it).

---

### Item 9 — Production Cloud Sync Drain (Subphase 4.1)

**Status:** VERIFIED

A real `CloudConnection` is now attached to the production system and a
production loop drains the Durability Subsystem's cloud outbound queue in
causal order (Req 16.3).  The wiring is native-only (the `CloudLedger` embeds
a rusqlite-backed `CrdtEngine`):

- `CoreHandle::init` hosts a real `CloudLedger` (constructed from the
  process's own identity + default schema hash) and stores it as the
  `cloud_ledger` field, then spawns `CoreHandle::spawn_cloud_sync_loop`
  (`CLOUD_SYNC_INTERVAL_MS` — 1 s in production builds, inert 1 h in test
  builds so queue-state unit tests stay deterministic).
- Each tick runs `CoreHandle::run_cloud_sync_cycle`, which calls
  `cloud_sync_loop` — topological (causal) order over `causal_parents`, send
  via the real `CloudLedgerConnection` adapter, ack-removal (Req 16.3),
  rejection retention (Req 16.5) — against that ledger.

`api::cloud_sync_tests` covers it end-to-end over the real production
construction (`CoreHandle::init` → `write()` → durability cloud queue →
drain → ledger): `cloud_sync_cycle_drains_writes_to_ledger` (one explicit
cycle, asserting 3/3 acked, queue depth 0, every Delta committed) and
`production_cloud_sync_loop_drains_writes_to_ledger` (the spawned background
loop does the draining — no manual cycle call).  The same `cloud_sync_loop`
function's causal-order enforcement is additionally covered with a recording
connection in `durability/integration_tests.rs`.

---

### Item 10 — Tier-2 Acknowledgement Path (Subphase 4.2)

**Status:** VERIFIED

A real Cloud Ledger ack now marks Deltas durable and notifies
CoreHandle/SDK, so the per-Delta durability state backing
`WriteResult.durability_tier` no longer stays `Uncommitted` forever in real
deployments (Req 14.4, 14.7):

- `cloud_sync_loop` now reports the Delta IDs it freshly acknowledged
  (`CloudSyncResult::acknowledged_ids`; entries already flagged
  `tier2_durable` by an earlier cycle are excluded so marking is not
  repeated).
- `CoreHandle::run_cloud_sync_cycle` — the function the production
  `CoreHandle::init`-spawned `spawn_cloud_sync_loop` calls every tick —
  invokes `DurabilitySubsystem::on_cloud_ack` once per freshly-acked Delta:
  the Delta's tier advances to `Tier2` (the state `WriteResult`
  `durability_tier` reports), the queue removal is confirmed (idempotent),
  and the application layer is notified.
- `DurabilitySubsystem` gained an instance-level tier-change listener
  (`set_tier_changed_listener`) fired on Tier-1 quorum and Tier-2 ack
  transitions alongside the existing crate-global notifier (stderr native /
  `DurabilityTierChanged` WASM event queue).  `CoreHandle::init` registers a
  listener forwarding each transition onto a new native broadcast channel,
  consumed by `CoreHandle::subscribe_durability_events` — the native
  analogue of the SDK's `durability-tier-changed` event.  WASM behaviour is
  unchanged: the SDK still receives `DurabilityTierChanged` events through
  `core_poll_events()`.

`api::tier2_ack_tests` covers it over the real production construction
(`CoreHandle::init` → `write()` → durability cloud queue → production drain →
real Cloud Ledger → `on_cloud_ack`):
`cloud_ack_marks_delta_tier2_and_notifies_corehandle` (one explicit cycle —
asserts the tier transitioned `Uncommitted` → `Tier2` via
`CoreHandle::durability_tier`, queue depth 0, ledger committed, and a
`DurabilityTierChanged { previous: Uncommitted, new: Tier2 }` event delivered
to a subscriber) and
`production_cloud_sync_loop_transitions_writes_to_tier2` (the spawned
background loop — no manual cycle call — transitions every write to Tier-2
with one notification per Delta).  The listener contract itself is unit-tested
in `durability::tests::tier_changed_listener_fires_on_cloud_ack_transition`.

---

### Item 11 — Anchor-Attested Location in Quorum Formation (Subphase 4.3)

**Status:** VERIFIED

Anchor-Attested Location now influences real `DurabilityReceipt`s when the
feature is enabled — `beacon_token` is no longer ignored (`None`-only) in the
production receipt path (Req 15.1–15.4):

- `DeploymentConfig` gained `beacon_public_keys` (the trusted fixed-beacon
  Ed25519 keys; empty is the explicit unconfigured state, mirroring
  `root_ca_keys`).
- `CoreHandle::init` constructs an `AnchorAttestedLocation` verifier from
  `anchor_attested_location` + `beacon_public_keys` (DIDs derived `did:key:`)
  and installs it on the `DurabilitySubsystem` via
  `DurabilitySubsystem::with_anchor`.
- `DurabilitySubsystem::receive_receipt` — the function the production
  native/WASM inbound pipelines call for every inbound
  `GossipMessage::InboundDurabilityReceipt` (api/mod.rs
  `receive_inbound`/`receive_inbound_wasm`) — now performs the Req 15.2/15.3
  gate: in BeaconAttested mode a receipt must carry a beacon token that
  verifies against the deployment registry (registered beacon DID, current
  epoch, valid signature); such receipts are counted toward Spatial_Diversity
  under the **beacon-verified location claim** (never the spoofable
  self-declared squad tag), and receipts without a valid token are excluded
  from Quorum formation and logged with the issuer DID + reason.  Squad-tag
  fallback (Req 15.4) and feature-disabled builds behave exactly as before.

`durability::tests` covers the gate end-to-end at the subsystem level (real
Ed25519-signed receipts + real beacon-signed tokens):
`anchor_mode_counts_verified_beacon_claims_toward_diversity_and_reaches_tier1`,
`anchor_mode_rejects_receipts_with_missing_or_invalid_beacon_tokens` (missing
/ unknown-beacon / stale-epoch / tampered-signature),
`anchor_mode_counts_attested_claim_not_declared_squad_tag` (the spoofed
squad-tag attack cannot fabricate diversity),
`squad_tag_fallback_after_signal_loss_skips_beacon_gate`, and
`anchor_is_absent_when_anchor_attested_location_not_enabled`.
`durability::anchor::tests::from_beacon_public_keys_*` covers the
registry-from-config construction, and `api::tier2_ack_tests::anchor_*`
asserts the production `CoreHandle::init` plumbing (verifier present and in
BeaconAttested mode when enabled, absent when disabled).

Receipt *issuance* between two live devices remains deferred to Subphase 4.5
(real mesh receipt exchange); this subphase wires the verification/consumption
side into the production receipt-handling path that issuance will feed.

---

### Item 12 — Req 14.3 default diversity rule + configurable max fraction (Subphase 4.4)

**Status:** VERIFIED

Req 14.3's *real* default diversity rule is implemented and the single-sector
fraction cap is now deployment-configurable:

- `DeploymentConfig::spatial_diversity_min == 0` (the default) is no longer
  passed straight through as a raw "require 0 distinct tags" minimum.  It is
  the explicit *unconfigured* marker that `Tier1QuorumTracker` resolves at
  runtime to the Req 14.3 default rule `min(K, distinct tags available)`
  (`quorum.rs effective_min_distinct`) — "available" being the distinct tags
  among the receipts collected so far, the tracker's only knowledge of tag
  availability (the reconciled model documented in design.md:914; the candidate
  pool carries no tag registry).  An explicit `spatial_diversity_min > 0` is
  enforced as configured, with the existing Req 14.5 degradation fallback
  (flat K-of-N + warning) when fewer distinct tags are available.
- `DeploymentConfig` gained `max_single_sector_fraction` (default `0.7` — the
  pre-4.4 hardcode), replacing the hardcoded `0.7` in `CoreHandle::init`.
  Values outside `(0, 1]` fall back to the `0.7` default at init rather than
  being enforced literally (a 0 cap would forbid every receipt and disable
  Quorum).

Coverage:
- `durability::quorum::tests` unit-tests the resolution
  (`unconfigured_min_resolves_to_min_of_k_and_available_distinct`,
  `configured_min_is_used_verbatim_not_recomputed`,
  `unconfigured_min_with_cap_off_accepts_single_sector_deployment`,
  `unconfigured_min_keeps_fraction_cap_enforcement`).
- `api::diversity_config_tests` drives the knobs through the production
  construction (`CoreHandle::init` → `DeploymentConfig` → `QuorumConfig` →
  `DurabilitySubsystem` → `Tier1QuorumTracker`): a raised 1.0 cap lets a
  single-sector K=3 deployment reach Tier-1 (impossible under the old 0.7
  hardcode), a strict 0.5 cap blocks it, the unconfigured-min marker flows
  through untouched and keeps the fraction cap binding, and invalid fractions
  fall back to 0.7.

---

## Cross-Device Mesh Sync

**Status:** DEFERRED — requires two live networked peers

Properties and requirements that depend on real P2P message delivery
(Req 4.3–4.7, 5.1–5.8, 6.1–6.7, 9.2–9.4, 14.2–14.4, 16.3) cannot be fully
verified within a single-process unit test.  They require:

- Two distinct `CoreHandle` instances with separate Ed25519 identities.
- A loopback libp2p Swarm (or in-memory transport channel) so that Deltas
  written on instance A are received by instance B via the Gossipsub event loop.
- The `process_inbound_messages` loop on instance B must be driven by a real
  tokio task polling `transport.poll_next_message()`.

This is deferred to the post-v1 integration test suite in
`durability/integration_tests.rs`.
