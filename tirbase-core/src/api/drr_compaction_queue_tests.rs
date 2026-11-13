//! WS7 — DRR floors, compaction isolation and outbound-queue guarantees.
//!
//! Every assertion here runs through production code:
//!
//! - the DRR tests enqueue real, signed Deltas on a real `MeshTransport` and
//!   drive the same `MeshTransport::tick_scheduler` the production scheduler
//!   loop (`CoreHandle::spawn_scheduler_tick_loop`) calls, then observe the
//!   peer merging the bytes over the real Swarm;
//! - the compaction tests write through `CoreHandle::write` →
//!   `CrdtEngine::maybe_compact` → `store::compaction::compact_table`;
//! - the queue tests enqueue through `CoreHandle::write` → durability
//!   subsystem → `CloudOutboundQueue`, and through the queue's own public
//!   `enqueue`/`acknowledge` API for the reduced-bound case.
//!
//! No `#[cfg(test)]`-only branch, mock transport or injected inbound path sits
//! on the asserted routes.

#![cfg(all(test, feature = "native"))]

use super::mesh_harness::*;
use super::*;
use crate::crdt::delta::PriorityClass;
use crate::durability::cloud_queue::{CloudOutboundQueue, QueueEntry};
use crate::schema::{FieldDef, FieldType, Schema, TableDef};
use crate::store::compaction::CompactionPolicy;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Link capacity used by the DRR scenarios: 10 000 bytes/sec gives the
/// documented floors 7 000 / 2 000 / 1 000 bytes per one-second epoch.
const LINK_CAPACITY: u64 = 10_000;

/// One in-flight Delta of slack when comparing observed bytes against a floor:
/// the DRR only transmits whole Deltas, so a floor can be short by at most the
/// head Delta still sitting at the front of the queue.
const ONE_DELTA_SLACK: u64 = 2048;

fn class_tag(class: PriorityClass) -> &'static str {
    match class {
        PriorityClass::High => "h",
        PriorityClass::Medium => "m",
        PriorityClass::Low => "l",
    }
}

/// Enqueue one real, signed Delta at `class` on the handle's production
/// transport. Each Delta targets its own table so the payload stays small and
/// the peer's projection is trivially attributable.
fn enqueue_priority_row(handle: &Arc<CoreHandle>, class: PriorityClass, idx: usize) {
    let table = format!("drr_{}_{}", class_tag(class), idx);
    let delta = {
        let mut crdt = handle.crdt.lock().expect("crdt mutex");
        let bytes = crdt
            .write_scalar(&table, "row", &json!({ "seq": idx }))
            .expect("write_scalar must succeed");
        crdt.produce_delta(bytes, class, vec![])
            .expect("produce_delta must succeed")
    };
    let mut transport = handle.transport.lock().expect("transport mutex");
    transport.enqueue_outbound(delta);
}

/// Run exactly one production scheduling epoch.
fn run_epoch(handle: &Arc<CoreHandle>) -> usize {
    handle
        .transport
        .lock()
        .expect("transport mutex")
        .tick_scheduler(LINK_CAPACITY)
        .expect("one DRR epoch must forward its Deltas")
}

/// Two real Swarms, connected over loopback, with the DRR configured for the
/// 10 000 bytes/sec link the scenarios measure.
async fn drr_mesh(prefix: &str) -> (Arc<CoreHandle>, Arc<CoreHandle>) {
    let port_a = reserve_loopback_port();
    let deployment = mesh_deployment();

    let handle_a = init_mesh_handle_with_deployment(&format!("{prefix}_A"), port_a, deployment.clone()).await;
    let handle_b = init_mesh_handle_with_deployment(
        &format!("{prefix}_B"),
        reserve_loopback_port(),
        deployment,
    )
    .await;

    let addr_b = handle_b
        .transport
        .lock()
        .expect("transport mutex")
        .config
        .listen_addr
        .clone();
    connect_peers(&handle_a, &addr_b).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    handle_a.set_scheduler_link_capacity(LINK_CAPACITY);
    handle_a.reset_scheduler_stats();
    (handle_a, handle_b)
}

// ─── 1. Byte-fraction floors over ten real-mesh epochs ───────────────────────

/// HIGH ≥ 70 %, MEDIUM ≥ 20 %, LOW ≥ 10 % of the scheduled bytes over ten
/// epochs with backlog in every class, observed through the production
/// scheduler counters while the peer merges the same Deltas over the Swarm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drr_byte_floors_hold_over_ten_real_mesh_epochs() {
    let (handle_a, handle_b) = drr_mesh("ws7_floors").await;

    // Backlog deeper than ten epochs' worth of each class' floor:
    // HIGH floor 70 KB, MEDIUM 20 KB, LOW 10 KB over the window.
    for i in 0..220 {
        enqueue_priority_row(&handle_a, PriorityClass::High, i);
    }
    for i in 0..90 {
        enqueue_priority_row(&handle_a, PriorityClass::Medium, i);
    }
    for i in 0..45 {
        enqueue_priority_row(&handle_a, PriorityClass::Low, i);
    }

    let mut epoch_high = Vec::new();
    let mut epoch_medium = Vec::new();
    let mut epoch_low = Vec::new();
    for epoch in 1..=10 {
        run_epoch(&handle_a);
        let (high, medium, low, _deficits) = {
            let transport = handle_a.transport.lock().expect("transport mutex");
            (
                transport.scheduler_stats().high_bytes,
                transport.scheduler_stats().medium_bytes,
                transport.scheduler_stats().low_bytes,
                transport.scheduler.deficits(),
            )
        };
        epoch_high.push(high);
        epoch_medium.push(medium);
        epoch_low.push(low);
        eprintln!("[ws7-floors] epoch {epoch}: high={high} medium={medium} low={low}");
    }

    let (stats, deficits) = {
        let transport = handle_a.transport.lock().expect("transport mutex");
        (transport.scheduler_stats(), transport.scheduler.deficits())
    };

    assert_eq!(stats.epochs, 10, "ten scheduling epochs must be recorded");
    let total = stats.total_bytes();
    assert!(total > 0, "the scheduler must have transmitted traffic");
    assert_eq!(
        stats.total_deltas(),
        stats.high_deltas + stats.medium_deltas + stats.low_deltas
    );

    // Cumulative floors honoured: served + unspent deficit ≥ floor allocation.
    assert!(
        stats.high_bytes as i64 + deficits.0 >= 70_000,
        "HIGH floor allocation violated: served {} + deficit {} < 70000",
        stats.high_bytes,
        deficits.0
    );
    assert!(
        stats.medium_bytes as i64 + deficits.1 >= 20_000,
        "MEDIUM floor allocation violated: served {} + deficit {} < 20000",
        stats.medium_bytes,
        deficits.1
    );
    assert!(
        stats.low_bytes as i64 + deficits.2 >= 10_000,
        "LOW floor allocation violated: served {} + deficit {} < 10000",
        stats.low_bytes,
        deficits.2
    );

    // Observed byte fractions (whole-Delta granularity, hence ±1 Delta).
    let high_floor = total * 70 / 100;
    let medium_floor = total * 20 / 100;
    let low_floor = total * 10 / 100;
    assert!(
        stats.high_bytes + ONE_DELTA_SLACK >= high_floor,
        "HIGH fraction {} / {total} bytes is below the 70 % floor",
        stats.high_bytes
    );
    assert!(
        stats.medium_bytes + ONE_DELTA_SLACK >= medium_floor,
        "MEDIUM fraction {} / {total} bytes is below the 20 % floor",
        stats.medium_bytes
    );
    assert!(
        stats.low_bytes + ONE_DELTA_SLACK >= low_floor,
        "LOW fraction {} / {total} bytes is below the 10 % floor",
        stats.low_bytes
    );

    eprintln!(
        "[ws7-floors] totals: high={} ({:.2}%) medium={} ({:.2}%) low={} ({:.2}%) total={}",
        stats.high_bytes,
        stats.fraction_for(PriorityClass::High) * 100.0,
        stats.medium_bytes,
        stats.fraction_for(PriorityClass::Medium) * 100.0,
        stats.low_bytes,
        stats.fraction_for(PriorityClass::Low) * 100.0,
        total
    );

    // The traffic really crossed the wire: one row per class is readable on
    // the peer through the ordinary projection path.
    for (class, idx) in [
        (PriorityClass::High, 0usize),
        (PriorityClass::Medium, 0usize),
        (PriorityClass::Low, 0usize),
    ] {
        let table = format!("drr_{}_{}", class_tag(class), idx);
        wait_for_data(
            &handle_b,
            &table,
            "row",
            &json!({ "seq": idx }),
            Duration::from_secs(20),
        )
        .await;
    }

    cleanup(&tmp_path("ws7_floors_A"));
    cleanup(&tmp_path("ws7_floors_B"));
}

// ─── 2. Spare capacity + LOW 10-epoch clearing bound ─────────────────────────

/// With HIGH and LOW backlogged and MEDIUM empty, spare capacity flows to
/// HIGH (the highest-priority backlog) and never to LOW, while a LOW backlog at
/// or below the clearing capacity (10 % × link × 10 epochs) is fully
/// transmitted within ten epochs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spare_capacity_goes_to_high_first_and_low_clears_within_ten_epochs() {
    let (handle_a, handle_b) = drr_mesh("ws7_spare").await;

    let clearing_capacity = crate::transport::scheduler::DrrScheduler::low_clearing_capacity(
        LINK_CAPACITY,
    );
    assert_eq!(clearing_capacity, 10_000);

    for i in 0..220 {
        enqueue_priority_row(&handle_a, PriorityClass::High, i);
    }
    // LOW backlog at or below the clearing capacity.
    let mut low_queued = 0usize;
    loop {
        enqueue_priority_row(&handle_a, PriorityClass::Low, low_queued);
        low_queued += 1;
        let (depth, queued_bytes) = {
            let transport = handle_a.transport.lock().expect("transport mutex");
            (
                transport.low_queue_depth(),
                transport.scheduler_queued_bytes(PriorityClass::Low),
            )
        };
        assert_eq!(depth, low_queued);
        // Stop while still at or below the clearing capacity: one more Delta
        // could overshoot it, so target 90 % of the bound.
        if queued_bytes >= clearing_capacity * 9 / 10 {
            break;
        }
    }
    let low_backlog_bytes = {
        let transport = handle_a.transport.lock().expect("transport mutex");
        transport.scheduler_queued_bytes(PriorityClass::Low)
    };
    assert!(
        low_backlog_bytes <= clearing_capacity,
        "the LOW backlog must be at or below the clearing capacity, got {low_backlog_bytes}"
    );
    assert!(
        low_backlog_bytes >= clearing_capacity * 3 / 4,
        "the LOW backlog must be a meaningful fraction of the clearing capacity"
    );

    // Epoch 1: HIGH takes its floor plus the spare; LOW is confined to its floor.
    run_epoch(&handle_a);
    let first = {
        let transport = handle_a.transport.lock().expect("transport mutex");
        (transport.scheduler_stats(), transport.low_queue_depth())
    };
    assert!(
        first.0.high_bytes >= 7_000,
        "HIGH must receive at least its 7000-byte floor first, got {}",
        first.0.high_bytes
    );
    assert_eq!(
        first.0.medium_bytes, 0,
        "MEDIUM has no backlog and must receive nothing"
    );
    assert!(
        first.0.low_bytes <= 1_000 + ONE_DELTA_SLACK,
        "LOW must not absorb spare capacity while HIGH is backlogged, got {} bytes",
        first.0.low_bytes
    );
    assert!(
        first.0.high_bytes > 7_000,
        "spare capacity must flow to the highest-priority backlog (HIGH), got {} bytes",
        first.0.high_bytes
    );

    // Remaining epochs until the LOW queue clears.
    let mut cleared_at_epoch = if first.1 == 0 { Some(1u32) } else { None };
    for epoch in 2..=10u32 {
        run_epoch(&handle_a);
        let depth = {
            let transport = handle_a.transport.lock().expect("transport mutex");
            transport.low_queue_depth()
        };
        if depth == 0 && cleared_at_epoch.is_none() {
            cleared_at_epoch = Some(epoch);
        }
    }

    let cleared = cleared_at_epoch.expect("LOW backlog at clearing capacity must clear within 10 epochs");
    assert!(
        cleared <= 10,
        "LOW cleared at epoch {cleared}, outside the 10-epoch bound"
    );

    let stats = handle_a.scheduler_stats();
    eprintln!(
        "[ws7-spare] low_queued={low_queued} cleared_at_epoch={cleared} \
         low_bytes={} high_bytes={} total_epochs={}",
        stats.low_bytes, stats.high_bytes, stats.epochs
    );

    // The peer received the LOW traffic too (the last LOW row is readable).
    let last_low = low_queued.saturating_sub(1);
    let table = format!("drr_{}_{}", class_tag(PriorityClass::Low), last_low);
    wait_for_data(
        &handle_b,
        &table,
        "row",
        &json!({ "seq": last_low }),
        Duration::from_secs(20),
    )
    .await;

    cleanup(&tmp_path("ws7_spare_A"));
    cleanup(&tmp_path("ws7_spare_B"));
}

// ─── 3. Per-table compaction isolation through the production write path ────

fn two_table_schema() -> Schema {
    let field = || FieldDef {
        name: "value".to_string(),
        field_type: FieldType::Integer,
        nullable: false,
        default: None,
    };
    Schema {
        tables: vec![
            TableDef {
                name: "agg".to_string(),
                fields: vec![field()],
                compaction_policy: CompactionPolicy::Aggressive { threshold: 3 },
                constraints: vec![],
            },
            TableDef {
                name: "keep".to_string(),
                fields: vec![field()],
                compaction_policy: CompactionPolicy::None,
                constraints: vec![],
            },
        ],
        version: "1.0.0".to_string(),
    }
}

/// Compaction is per Automerge document: `Aggressive { threshold }` compacts at
/// the threshold, a `CompactionPolicy::None` table is never compacted even
/// while its neighbour is, and post-compaction reads and re-fetch still work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compaction_is_per_table_and_none_policy_is_never_compacted() {
    let schema = two_table_schema();
    let schema_hash = schema.identifier_hash();
    let mut deployment = mesh_deployment();
    deployment.schema_definitions = vec![schema];
    deployment.schema_version_path = vec![schema_hash];

    let handle = init_mesh_handle_with_deployment(
        "ws7_compaction",
        reserve_loopback_port(),
        deployment,
    )
    .await;

    // Aggressive { threshold: 3 }: the fourth write crosses the threshold and
    // compacts the history already in the DAG. The Delta produced *by* that
    // write is inserted after compaction runs, so it is marked by the next one.
    let mut agg_ids = Vec::new();
    for i in 0..4u32 {
        let written = handle
            .write("agg", &format!("row-{i}"), json!({ "value": i }))
            .await
            .expect("agg write");
        agg_ids.push(written.delta_id);
        if i < 3 {
            let compacted = handle
                .crdt
                .lock()
                .expect("crdt mutex")
                .dag_node(&written.delta_id)
                .expect("DAG lookup")
                .map(|n| n.compacted)
                .unwrap_or(false);
            assert!(
                !compacted,
                "agg write {i} is at or below the threshold and must not be compacted"
            );
        }
    }

    // The 4th write exceeded the threshold: the three earlier agg nodes were
    // folded into the compactmed snapshot and marked.
    for (i, id) in agg_ids.iter().take(3).enumerate() {
        let node = handle
            .crdt
            .lock()
            .expect("crdt mutex")
            .dag_node(id)
            .expect("DAG lookup")
            .expect("agg node must exist");
        assert!(
            node.compacted,
            "agg write {i} must be marked compacted once the threshold is crossed"
        );
    }

    // The next write compacts the Delta the threshold-crossing write produced.
    let fifth = handle
        .write("agg", "row-4", json!({ "value": 4 }))
        .await
        .expect("agg write");
    agg_ids.push(fifth.delta_id);
    let node = handle
        .crdt
        .lock()
        .expect("crdt mutex")
        .dag_node(&agg_ids[3])
        .expect("DAG lookup")
        .expect("agg node must exist");
    assert!(
        node.compacted,
        "the Delta produced by the threshold-crossing write must be compacted by the next write"
    );

    // `keep` is CompactionPolicy::None — many writes, never compacted.
    let mut keep_ids = Vec::new();
    for i in 0..6u32 {
        let written = handle
            .write("keep", &format!("row-{i}"), json!({ "value": i }))
            .await
            .expect("keep write");
        keep_ids.push(written.delta_id);
    }
    for id in &keep_ids {
        let node = handle
            .crdt
            .lock()
            .expect("crdt mutex")
            .dag_node(id)
            .expect("DAG lookup")
            .expect("keep node must exist");
        assert!(
            !node.compacted,
            "a CompactionPolicy::None table must never be marked compacted"
        );
    }

    // Each table has its own Automerge document.
    let (tables, agg_doc_len, keep_doc_len) = {
        let mut crdt = handle.crdt.lock().expect("crdt mutex");
        let names = crdt.table_names();
        let agg_len = crdt
            .doc_for_table_mut("agg")
            .map(|d| d.save().len())
            .unwrap_or(0);
        let keep_len = crdt
            .doc_for_table_mut("keep")
            .map(|d| d.save().len())
            .unwrap_or(0);
        (names, agg_len, keep_len)
    };
    assert!(tables.contains(&"agg".to_string()), "agg needs its own doc");
    assert!(tables.contains(&"keep".to_string()), "keep needs its own doc");
    assert!(agg_doc_len > 0 && keep_doc_len > 0);
    assert_ne!(
        agg_doc_len, keep_doc_len,
        "the two tables must not share one Automerge document"
    );

    // Post-compaction reads still return every row…
    for i in 0..5u32 {
        let row = handle.read("agg", &format!("row-{i}")).await.expect("read agg");
        assert_eq!(row.data, json!({ "value": i }));
    }
    for i in 0..6u32 {
        let row = handle.read("keep", &format!("row-{i}")).await.expect("read keep");
        assert_eq!(row.data, json!({ "value": i }));
    }

    // …and re-fetch still resolves the compacted Delta's bytes from the DAG.
    let agg_bytes = handle
        .crdt
        .lock()
        .expect("crdt mutex")
        .refetch_delta_bytes(&agg_ids[3])
        .expect("re-fetch must not fail")
        .expect("the compacted Delta must still be re-fetchable");
    assert!(!agg_bytes.is_empty());

    cleanup(&tmp_path("ws7_compaction"));
}

// ─── 4. Cloud outbound queue: capacity bound and no-drop behaviour ──────────

fn queue_entry(i: usize) -> QueueEntry {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&(i as u64).to_le_bytes());
    QueueEntry::new(id, vec![0u8; 8], vec![])
}

/// The production capacity constant is 100 000. At a reduced (but identically
/// enforced) bound the queue accepts exactly `capacity` entries, rejects the
/// next with `CloudQueueFull` **without dropping anything already queued**, and
/// accepts again once an entry is acknowledged.
#[test]
fn cloud_queue_bound_holds_and_never_drops_queued_entries() {
    use crate::durability::cloud_queue::MAX_QUEUE_DEPTH;

    assert_eq!(MAX_QUEUE_DEPTH, 100_000);
    assert_eq!(
        CloudOutboundQueue::new().capacity(),
        MAX_QUEUE_DEPTH,
        "the production queue must use the 100k Delta bound"
    );

    let mut queue = CloudOutboundQueue::with_capacity(256);
    assert_eq!(queue.capacity(), 256);

    for i in 0..256 {
        queue.enqueue(queue_entry(i)).expect("within the bound");
    }
    assert_eq!(queue.depth(), 256);

    let overflow = queue.enqueue(queue_entry(256));
    assert!(
        matches!(overflow, Err(TirBaseError::CloudQueueFull { depth: 256 })),
        "the 257th enqueue must fail with CloudQueueFull at depth 256, got {overflow:?}"
    );
    assert_eq!(
        queue.depth(),
        256,
        "a rejected enqueue must not drop or evict any queued entry"
    );

    let first = queue_entry(0);
    queue.acknowledge(&first.delta_id);
    assert_eq!(queue.depth(), 255);
    queue
        .enqueue(queue_entry(257))
        .expect("capacity freed by an acknowledge is reusable");
    assert_eq!(queue.depth(), 256);
}

/// Extended offline period at the production queue: writes accumulate without
/// loss, are all still readable, and one production cloud-sync cycle drains
/// every one of them to Tier-2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_writes_accumulate_without_drop_and_drain_on_reconnect() {
    let path = tmp_path("ws7_offline");
    cleanup(&path);
    let handle = CoreHandle::init(mesh_config(&path, reserve_loopback_port()))
        .await
        .expect("init");

    const OFFLINE_WRITES: usize = 64;
    let mut ids = Vec::new();
    for i in 0..OFFLINE_WRITES {
        let written = handle
            .write("offline", &format!("row-{i}"), json!({ "seq": i }))
            .await
            .expect("write while offline");
        ids.push(written.delta_id);
    }
    assert_eq!(
        handle.cloud_queue_depth(),
        OFFLINE_WRITES,
        "every offline write must be queued — none may be dropped"
    );

    // All rows are durable locally while the cloud is unreachable.
    for i in 0..OFFLINE_WRITES {
        let row = handle
            .read("offline", &format!("row-{i}"))
            .await
            .expect("offline read");
        assert_eq!(row.data, json!({ "seq": i }));
    }

    // Reconnect: one production cycle drains the whole backlog.
    let sync = handle.run_cloud_sync_cycle().expect("cloud sync cycle");
    assert_eq!(sync.acknowledged, OFFLINE_WRITES);
    assert_eq!(sync.rejected, 0);
    assert_eq!(handle.cloud_queue_depth(), 0);
    for id in &ids {
        assert!(
            handle.cloud_ledger_is_committed(id),
            "every queued Delta must reach the Cloud Ledger"
        );
        assert_eq!(handle.durability_tier(id), DurabilityTier::Tier2);
    }

    cleanup(&path);
}

/// Gated full-scale proof: 100 000 real writes through the production write
/// path must fill the queue to its bound without losing a single entry.
///
/// Ignored because it performs 100 000 full writes (SQLite + Automerge +
/// Ed25519 + projection). Run with
/// `cargo test -p tirbase-core --features native --lib -- --ignored full_scale_100k`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "full-scale: 100_000 real writes; run explicitly with --ignored"]
async fn full_scale_100k_offline_writes_fill_the_queue_without_loss() {
    use crate::durability::cloud_queue::MAX_QUEUE_DEPTH;

    let path = tmp_path("ws7_full_100k");
    cleanup(&path);
    let handle = CoreHandle::init(mesh_config(&path, reserve_loopback_port()))
        .await
        .expect("init");

    for i in 0..MAX_QUEUE_DEPTH {
        handle
            .write("full", &format!("row-{i}"), json!({ "seq": i }))
            .await
            .expect("write below the bound");
    }
    assert_eq!(handle.cloud_queue_depth(), MAX_QUEUE_DEPTH);

    // The bound is enforced, not faked: one more write is refused by the queue
    // and every already-queued entry survives the rejection.
    let overflow = handle
        .write("full", "row-overflow", json!({ "seq": MAX_QUEUE_DEPTH }))
        .await;
    assert!(
        matches!(overflow, Err(TirBaseError::CloudQueueFull { .. })),
        "the write past the 100k bound must fail with CloudQueueFull"
    );
    assert_eq!(
        handle.cloud_queue_depth(),
        MAX_QUEUE_DEPTH,
        "the overflow rejection must not drop any queued Delta"
    );

    cleanup(&path);
}
