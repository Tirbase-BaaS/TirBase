# E2E Wiring Workstream — Charter

**Status:** active (workstream 1 of 8)
**Owner of this file:** workstream 1 (inventory + foundations)
**Last updated:** 2026-11-12

This charter is the shared contract for the eight-workstream effort that closes the
"[Status: Implemented but not wired]" gap. Every workstream reads it before starting and
updates `STATUS.md` as it lands evidence.

---

## 1. Definition of wired

A feature is **wired** only when **all five** conditions hold:

1. **Real production caller path.** A public boundary (SDK export, `CoreHandle` method, CLI,
   gateway endpoint, background loop spawned by production init) reaches the feature and produces
   an observable effect.
2. **No stand-ins on the asserted path.** No `MockWasmCore`, no `inject_inbound`, no
   `#[cfg(test)]`-only branch, no stub/inject-only helper sits between the boundary and the
   assertion. Test doubles may exist elsewhere; they may not carry the proof.
3. **A failing-before test.** An executable test fails on current HEAD (or fails when the wiring is
   disabled) and passes after the change. "It compiles" and "the code exists" are not evidence.
4. **Runs in CI.** The test runs in a mandatory CI job with no `continue-on-error`, no `|| true`,
   and no `#[ignore]`.
5. **Docs follow proof.** `README.md`, `CLAIMS.md`, `docs/traceability-matrix.md`,
   `tirbase-core/tests/README.md` and `properties.rs` annotations are updated only after the test
   proves the behaviour. A stale marker is a defect of its own.

A feature that runs in production but lacks condition 3 is **under-proven**, not wired
(workstreams must add the proof, not the code). A feature with no production caller is
**genuinely unwired**. A marker that no longer matches the code is **stale documentation**.

## 2. Non-negotiables

- Real production path only; no test-only branch on the asserted e2e path.
- No `#[ignore]`, no lowered proptest case counts, no deleted or weakened existing tests.
- Never weaken `revocation_m`, `spatial_diversity_min`, signature checks, token expiry, or lease
  checks.
- No unbounded sleeps: poll with a monotonic deadline (see `mesh_harness::wait_for_data`).
- Preserve error types and fail-closed behaviour.
- Leave the workspace building at every commit.
- One commit per workstream (foundation docs may land in a follow-up STATUS update commit).
- Do not claim a speedup or a guarantee without a measurement/proof.

## 3. Evidence format

Every row in `STATUS.md` and every commit message must cite evidence in this shape:

```
<item> — <classification>
  path:    <public boundary> → <production caller> → <observable effect>
  test:    <module::test_name>  (command that runs it)
  result:  <exact pass/fail counts on this machine>
  limits:  <what the test does NOT prove>
```

Classifications: `wired`, `under-proven`, `genuinely-unwired`, `stale-docs`,
`hardware-blocked`.

A test is only admissible if it is reachable from the listed command without filters that could
skip it, and if its failure mode is a normal assertion failure (not a skip).

## 4. Workstream map

| WS | Scope | Owns |
|----|-------|------|
| **1** | Inventory, charter, STATUS ledger, real-WASM harness, real-mesh harness, projection write-through, API parity, CI gates | `docs/agent/e2e-wiring/*`, `tirbase-core/src/api/mesh_harness.rs`, `tirbase-core/src/tests/api_parity.rs`, real-WASM SDK tests, `.github/workflows/ci.yml` e2e steps |
| **2** | CRDT merge proofs: cross-build byte parity, commutativity, RGA/list path, per-table document semantics, compaction policy | `tirbase-core/src/crdt/*`, `src/tests/convergence_tests.rs`, `src/tests/properties.rs` (props 1–4) |
| **3** | Identity/trust/transport: SDK trust-level event path, M-of-N revocation accumulation over the mesh, one-round isolation, BLE bridge, multi-hop routing | `tirbase-core/src/auth/*`, `src/transport/{ble,discovery}.rs`, `tirbase-sdk/*` |
| **4** | Durability: Tier-1 compaction/refetch, outbound queue capacity, cloud re-fetch, live quorum hardening | `tirbase-core/src/durability/*`, `src/api/mod.rs` cloud sync |
| **5** | Scheduler / Saturate: DRR floors end-to-end, spare-capacity flow, 10-epoch LOW bound, saturate expiry under load | `tirbase-core/src/transport/{scheduler,saturate}.rs` |
| **6** | Migration/contamination: sidecar replay after corrected migration, conflict flagging, forward taint tracing over the mesh | `tirbase-core/src/migration/*`, `src/contamination/*` |
| **7** | SDK: manager operations against real WASM, TypeScript → WASM → store → mesh path, trust events | `tirbase-sdk/*` |
| **8** | Claims closeout: README markers, CLAIMS rows, traceability matrix, audit annotations, tests/README and properties.rs gap text | `README.md`, `CLAIMS.md`, `docs/*`, `tirbase-core/tests/README.md` |

Workstream 1 does **not** implement WS2–WS8 feature work. It only records each item's
disposition, its owner, and any blocker.

## 5. Foundation artefacts delivered by WS1

- `tirbase-core/src/api/mesh_harness.rs` — reusable, `cfg(test)`-gated two-device real-Swarm
  harness (`init_mesh_handle`, `connect_peers`, `wait_for_data`, …) built on production
  `CoreHandle::init` / `dial_peer` / `spawn_inbound_drain_loop` / `read`.
- `api::real_mesh_tests::json_envelope_delta_over_real_mesh_projects_to_peer_store` — JSON-envelope
  projection over the production transport (binary projection is already covered by the Phase
  0.3(a)/(b) tests).
- `tirbase-core/src/tests/api_parity.rs` — source-parsed parity gate over `CoreHandle`, `lib.rs`
  `#[wasm_bindgen]` exports and `tirbase-sdk/src/wasm-bridge.ts` `WasmCore`.
- `tirbase-sdk/src/__tests__/tirbase-wasm.test.ts` — real-WASM write→read→query round-trip through
  the child-process harness (no `MockWasmCore`).
- Mandatory CI steps for real-mesh, projection and parity (plus the existing real-WASM build +
  `npm test`).
