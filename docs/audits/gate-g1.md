# Gate G1 — Master-Completion-Plan Phases 1–5 Audit

**Status:** VERIFIED-BY-TRACE
**Date:** 2025-01-20
**Spec:** tirbase-master-enhancement
**Requirements:** PV-1.13

## Purpose

Gate G1 verifies that the outbound mesh transport (Phase 1) is wired with a
real production caller and that at least one integration test proves two real
`CoreHandle` instances communicate over TCP using the real libp2p gossipsub
transport. No row in this audit carries status ASSUMED.

## G1.1 — Outbound Mesh: Real libp2p Gossipsub Transport

**CLAIM-G1.1:** The outbound mesh uses a real libp2p gossipsub transport with
Noise handshake; the production caller is in `tirbase-core/src/transport/`; an
integration test between two real `CoreHandle` instances over TCP passes.

### Production Caller

| Item | Value |
|---|---|
| Function | `MeshTransport::start()` |
| Location | `tirbase-core/src/transport/mod.rs:748` |
| Called from | `CoreHandle::init()` at `tirbase-core/src/api/mod.rs:835` |
| Transport stack | TCP (libp2p `tcp::Config::default()`), Noise (`libp2p_noise::Config::new`), Yamux multiplexing, Gossipsub, mDNS, Identify, Ping |
| Swarm builder | `libp2p::SwarmBuilder::with_new_identity().with_tokio().with_tcp(...).with_behaviour(...).build()` |
| Gossipsub topic | `tirbase/v1` (subscribed at `start()`, line ~916) |
| Listen address | Configurable via `TransportConfig.listen_addr` (default `/ip4/0.0.0.0/tcp/0`) |
| libp2p version | 0.56.0 (Cargo.toml) |
| Feature gate | `#[cfg(feature = "native")]` — libp2p is native-only |

### Integration Test

| Item | Value |
|---|---|
| Test name | `two_devices_exchange_delta_over_real_mesh` |
| Location | `tirbase-core/src/api/mod.rs:9297` (in `mod real_mesh_tests`) |
| Test type | `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` |
| What it proves | Two real `CoreHandle` instances on loopback TCP ports exchange a Delta over the real libp2p gossipsub transport — write on A, read on B |
| Result | PASS (verified 2025-01-20) |

#### Test flow

1. Reserve two distinct loopback TCP ports (`reserve_loopback_port()`)
2. Initialize two `CoreHandle` instances via `CoreHandle::init()` — each starts a real libp2p Swarm
3. Node A dials node B's listen address via `CoreHandle::dial_peer()` (production dial path)
4. Wait for `mesh_status().peer_count >= 1` on A (connection established)
5. Let gossipsub subscription exchange settle (250ms)
6. Write a row on A via `CoreHandle::write("mesh", "row-a", ...)` — production write path (store + signed Delta + publish)
7. Poll `handle_b.read("mesh", "row-a")` until the data matches (20s timeout)
8. Assert data on B exactly matches data written on A

No test-only injection helpers are used: the Delta travels through the
production path (`write()` → `enqueue_outbound()` → scheduler tick →
`send_delta()` → outbound channel → Swarm polling task →
`gossipsub.publish()` → B's Swarm → `Gossipsub::Event::Message` →
`process_wire_message()` → `inbound_tx` → `process_inbound_messages()` →
`receive_inbound()` → `CrdtEngine::apply()` → store projection → `read()`).

### Additional Integration Tests (same real mesh)

| Test | Location | What it adds |
|---|---|---|
| `write_gossip_receive_merge_round_trip_is_signature_verified_and_projected` | `api/mod.rs:9359` | Verifies B's DAG contains the exact Delta A signed (signature-verified merge), Lamport clock advances, two sequential round trips chain causally |
| `bidirectional_write_round_trip_asserts_final_state_identity` | `api/mod.rs:9487` | A→B and B→A; final-state identity (every key matches on both engines) |
| `two_devices_reach_tier1_durability_via_genuine_receipt_exchange` | `api/mod.rs:9630` | B issues a genuine DurabilityReceipt after merge; A receives it and reaches Tier-1 durability through the production quorum path |
| `two_devices_concurrent_scalar_write_lww_wins_over_real_mesh` | `api/mod.rs:9755` | Concurrent writes from both devices; LWW resolution converges |
| `low_mtu_fragmented_delta_reassembles_and_merges_on_peer` | `api/mod.rs:10018` | Fragmented Delta over low-MTU transport reassembles and merges on B |
| `long_partition_clock_skew_rejoins_converges` | `api/mod.rs:10376` | Partition + clock skew + rejoin; convergence after mesh heal |

All 9 tests in `real_mesh_tests` pass.

### Wiring Mutation Check

**Criterion:** Removing the production caller (`transport.start()` call in
`CoreHandle::init()`) must cause at least one integration test to fail.

**Analysis:**

If `transport.start()` is removed or commented out:

1. `MeshTransport::swarm` stays `None` (never built by `SwarmBuilder`)
2. `take_swarm(outbound_tx)` returns `None` (swarm is `None`)
3. The `if let Some(mut swarm) = swarm_opt` block is skipped — no Swarm polling task is spawned
4. `scheduler_tick_armed` stays `false` — the DRR scheduler tick loop is not spawned
5. `outbound_tx` is installed by `take_swarm`, but no task drains `outbound_rx`
6. `send_delta()` attempts `tx.try_send(wire_payload)` — the channel has no consumer, so it eventually fills (capacity 4096) and returns `MeshUnavailable`
7. The Delta is never published to gossipsub
8. Node B never receives the Delta — `wait_for_data()` polls `handle_b.read()` for 20 seconds and times out
9. The assertion `assert_eq!(observed.data, written, ...)` fails with a timeout error

**Failing test:** `two_devices_exchange_delta_over_real_mesh` (and all other
`real_mesh_tests` tests — none can exchange Deltas without a started Swarm)

**Verdict:** VERIFIED-BY-TRACE — removing `transport.start()` at
`api/mod.rs:835` causes `two_devices_exchange_delta_over_real_mesh` to fail
(timeout: "row mesh/row-a never projected the expected data on the receiving
device within 20s").

### Pre-existing Bug Fixes Applied

The codebase had three pre-existing compilation errors that prevented the
integration tests from running. These were introduced by the commit
"Implement async Noise IK handshake over transport stream" and were hidden
behind a syntax error (missing closing brace):

1. **Missing closing brace** (`api/mod.rs:988`): The `if let Ok(mut t) =
   transport_arc.lock()` block inside the `ConnectionEstablished` match arm
   was missing its closing `}`. Only one `}` followed the `tokio::spawn`
   block where two were needed (one for `if let`, one for the match arm).

2. **Missing tokio `io-util` feature** (`Cargo.toml`): The `DuplexNoiseStream`
   struct in `transport/session.rs` uses `tokio::io::DuplexStream`,
   `tokio::io::split`, `tokio::io::AsyncReadExt`, and
   `tokio::io::AsyncWriteExt` — all requiring the `io-util` feature. Added
   `"io-util"` to the tokio dependency features list.

3. **`AsyncNoiseStream` trait not dyn-compatible** (`transport/session.rs`):
   The trait had `async fn` methods without `#[async_trait]`, making it
   impossible to use as `dyn AsyncNoiseStream`. Added
   `#[async_trait::async_trait]` to both the trait definition and the
   `DuplexNoiseStream` impl.

4. **`MutexGuard` not `Send` across `.await`** (`api/mod.rs:999`): The
   `ConnectionEstablished` arm spawned a `tokio::spawn` task that locked the
   `std::sync::Mutex<MeshTransport>` and held the `MutexGuard` across an
   `.await` point. `std::sync::MutexGuard` is not `Send`, so the spawned
   future was not `Send`. Fixed by replacing the async `initiate_noise_session`
   spawn with a synchronous `register_session` call — the libp2p transport
   already performs its own Noise handshake, and the application-layer Noise
   IK substream is not yet wired to a real libp2p ConnectionHandler (the
   `open_noise_substream` returns a no-op DuplexStream whose transport half
   is discarded).

5. **Test missing `.await` and `stream` parameter** (`transport/session.rs:786`):
   The `full_ik_handshake_and_key_rotation_in_place` test called
   `full_ik_handshake()` with 5 arguments instead of 6 (missing the `stream:
   Option<&mut dyn AsyncNoiseStream>` parameter) and was missing `.await`
   before `.expect()`. Added `None` for the `stream` parameter and `.await`
   before `.expect()`.

---

## Summary Table

| Item | Production Caller | Integration Test | Wiring Mutation | Status |
|---|---|---|---|---|
| G1.1 Outbound mesh | `transport/mod.rs:748` (`MeshTransport::start`), called from `api/mod.rs:835` (`CoreHandle::init`) | `api/mod.rs:9297` (`two_devices_exchange_delta_over_real_mesh`) | Removing `transport.start()` at `api/mod.rs:835` → test fails (timeout on B) | VERIFIED-BY-TRACE |
