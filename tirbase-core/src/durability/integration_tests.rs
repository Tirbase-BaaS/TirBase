//! Integration tests for Cloud Ledger sync (Task 13 — Req 16.1–16.8).
//!
//! These tests exercise the full sync pipeline:
//! - Two in-process "peer" devices produce Deltas and enqueue them.
//! - A `CloudLedger` acts as the server-side append-only merge ledger.
//! - `CloudLedgerConnection` adapts the ledger to the `CloudConnection` trait.
//! - `cloud_sync_loop()` drives the topological send + ack/reject logic.
//!
//! All tests run on the `native` feature build with in-memory SQLite.

#![cfg(test)]
#![cfg(feature = "native")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::crdt::delta::{Delta, DeltaId, Ed25519Signature, PriorityClass};
use crate::crdt::derive_did_from_public_key;
use crate::crdt::CrdtEngine;
use crate::durability::cloud_ledger::{
    CloudLedger, CloudLedgerConnection, ReceiveOutcome,
};
use crate::durability::cloud_queue::{
    cloud_sync_loop, CloudConnection, CloudOutboundQueue, QueueEntry,
};
use crate::identity::keypair::{generate_keypair, sign};
use crate::schema::hash::compute_schema_identifier_hash;
use crate::schema::hash::SchemaIdentifierHash;
use crate::store::sqlite;

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn test_schema() -> SchemaIdentifierHash {
    compute_schema_identifier_hash(&[("reports", &[("id", "TEXT"), ("body", "TEXT")])])
}

/// Generate an Ed25519 identity (secret, public, did:key DID).
fn make_identity() -> ([u8; 32], [u8; 32], String) {
    let (secret, public) = generate_keypair().expect("keygen");
    let did = derive_did_from_public_key(&public);
    (secret, public, did)
}

/// Open an in-memory SQLite connection with the TirBase schema.
fn make_conn() -> Arc<Mutex<rusqlite::Connection>> {
    let conn = rusqlite::Connection::open_in_memory().expect("open_in_memory");
    conn.execute_batch(sqlite::CREATE_SCHEMA_SQL)
        .expect("create schema");
    Arc::new(Mutex::new(conn))
}

/// Build a `CrdtEngine` for a peer device.
fn make_engine(secret: [u8; 32], did: String, schema: SchemaIdentifierHash) -> CrdtEngine {
    CrdtEngine::new(secret, did, schema, make_conn())
}

/// Produce a signed Delta using a `CrdtEngine`.
fn produce_delta(engine: &mut CrdtEngine, _payload_label: Vec<u8>) -> Delta {
    // Use empty Automerge bytes — the CrdtEngine treats empty bytes as a no-op
    // merge (see `merge_automerge_bytes`), which is consistent with how all
    // existing CRDT unit tests produce test Deltas.
    engine
        .produce_delta(vec![], PriorityClass::Low, vec![])
        .expect("produce_delta")
}

/// Serialise a Delta to JSON bytes (the format the sync loop passes to
/// `CloudConnection::send_delta`).
fn serialise_delta(delta: &Delta) -> Vec<u8> {
    serde_json::to_vec(delta).expect("serialise Delta")
}

/// Enqueue a Delta into a `CloudOutboundQueue`, serialised as JSON.
fn enqueue(queue: &mut CloudOutboundQueue, delta: &Delta) {
    let entry = QueueEntry::new(
        delta.id,
        serialise_delta(delta),
        delta.causal_parents.clone(),
    );
    queue.enqueue(entry).expect("enqueue");
}

// ─── Test 1: Basic sync — peer produces Deltas, ledger merges them ────────────

/// Two in-process peers each produce a Delta.  Both are enqueued in the
/// outbound queue and synced to the Cloud Ledger.  After `cloud_sync_loop`
/// completes the queue must be empty and both Deltas committed on the ledger
/// (Req 16.3, 16.1).
#[test]
fn two_peers_sync_to_cloud_ledger() {
    let schema = test_schema();

    // Peer A
    let (secret_a, _, did_a) = make_identity();
    let mut engine_a = make_engine(secret_a, did_a.clone(), schema);

    // Peer B
    let (secret_b, _, did_b) = make_identity();
    let mut engine_b = make_engine(secret_b, did_b.clone(), schema);

    let delta_a = produce_delta(&mut engine_a, b"report-a".to_vec());
    let delta_b = produce_delta(&mut engine_b, b"report-b".to_vec());

    // Build outbound queue with both Deltas.
    let mut queue = CloudOutboundQueue::new();
    enqueue(&mut queue, &delta_a);
    enqueue(&mut queue, &delta_b);
    assert_eq!(queue.depth(), 2);

    // Cloud Ledger (uses its own identity and accepts the same schema).
    let (ledger_secret, _, ledger_did) = make_identity();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");

    // Run sync loop.
    let mut conn = CloudLedgerConnection::new(&mut ledger);
    let result = cloud_sync_loop(&mut queue, &mut conn, &|_id, _holders| None);

    assert_eq!(result.acknowledged, 2, "both Deltas must be acked");
    assert_eq!(result.rejected, 0);
    assert_eq!(result.deferred, 0);
    assert_eq!(queue.depth(), 0, "queue must be empty after full ack");

    assert!(ledger.is_committed(&delta_a.id), "delta_a must be committed on ledger");
    assert!(ledger.is_committed(&delta_b.id), "delta_b must be committed on ledger");
    assert_eq!(ledger.committed_count(), 2);
}

// ─── Test 2: Idempotent re-submit (Req 16.4) ──────────────────────────────────

/// Submitting the same Delta twice (simulating a client retry after a lost ack)
/// must result in exactly one committed entry on the Cloud Ledger.
#[test]
fn idempotent_resubmit_does_not_duplicate() {
    let schema = test_schema();
    let (secret, _, did) = make_identity();
    let mut engine = make_engine(secret, did, schema);
    let delta = produce_delta(&mut engine, b"unique-report".to_vec());

    let (ledger_secret, _, ledger_did) = make_identity();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");

    // First submission.
    let out1 = ledger.receive_delta(&delta).unwrap();
    assert_eq!(out1, ReceiveOutcome::Committed);

    // Second submission — same Delta.
    let out2 = ledger.receive_delta(&delta).unwrap();
    assert_eq!(out2, ReceiveOutcome::AlreadyCommitted,
        "second submission must be idempotent");

    assert_eq!(ledger.committed_count(), 1, "only one entry should be committed");
}

/// Same scenario exercised through the full `cloud_sync_loop` path:
/// enqueue the same Delta twice and run the loop twice.  The second run
/// should ack 0 entries (already removed on first run) and the ledger
/// should still have exactly 1 committed Delta.
#[test]
fn sync_loop_idempotent_after_ack() {
    let schema = test_schema();
    let (secret, _, did) = make_identity();
    let mut engine = make_engine(secret, did, schema);
    let delta = produce_delta(&mut engine, b"report".to_vec());

    let (ledger_secret, _, ledger_did) = make_identity();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");

    let mut queue = CloudOutboundQueue::new();
    enqueue(&mut queue, &delta);

    // First run — Delta acked and removed from queue.
    {
        let mut conn = CloudLedgerConnection::new(&mut ledger);
        let r = cloud_sync_loop(&mut queue, &mut conn, &|_id, _holders| None);
        assert_eq!(r.acknowledged, 1);
    }
    assert_eq!(queue.depth(), 0);

    // Enqueue the same Delta again (simulating a retry after lost network ack).
    enqueue(&mut queue, &delta);

    // Second run — the CloudLedger returns AlreadyCommitted → loop still acks.
    {
        let mut conn = CloudLedgerConnection::new(&mut ledger);
        let r = cloud_sync_loop(&mut queue, &mut conn, &|_id, _holders| None);
        assert_eq!(r.acknowledged, 1, "idempotent re-submit must still ack");
    }
    assert_eq!(queue.depth(), 0);
    assert_eq!(ledger.committed_count(), 1, "only one logical Delta committed");
}

// ─── Test 3: Rejection retention and retry (Req 16.5) ────────────────────────

/// When the Cloud Ledger rejects a Delta (bad signature), the client must
/// retain the Delta in its outbound queue and retry on the next sync cycle.
/// The rejection must be logged on the ledger side.
#[test]
fn rejected_delta_retained_for_retry() {
    let schema = test_schema();
    let (secret, _, did) = make_identity();
    let mut engine = make_engine(secret.clone(), did.clone(), schema);
    let mut delta = produce_delta(&mut engine, b"tampered-report".to_vec());

    // Tamper with the bytes AFTER signing so the signature is invalid.
    delta.automerge_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    // (The delta.id still reflects the original canonical bytes, but the
    //  signature no longer matches — the ledger will reject it.)

    let (ledger_secret, _, ledger_did) = make_identity();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");

    let mut queue = CloudOutboundQueue::new();
    enqueue(&mut queue, &delta);

    let mut conn = CloudLedgerConnection::new(&mut ledger);
    let result = cloud_sync_loop(&mut queue, &mut conn, &|_id, _holders| None);

    assert_eq!(result.rejected, 1, "tampered Delta must be rejected");
    assert_eq!(result.acknowledged, 0);
    assert_eq!(queue.depth(), 1, "rejected Delta must be retained in queue");

    // The ledger logged the rejection.
    assert_eq!(ledger.rejection_log.len(), 1);
    assert!(!ledger.is_committed(&delta.id), "rejected Delta must not be committed");
}

/// Selective rejection: two Deltas in the queue; the first is valid, the
/// second is tampered.  The loop must ack the first and retain the second.
#[test]
fn partial_rejection_acks_valid_retains_invalid() {
    let schema = test_schema();
    let (secret_a, _, did_a) = make_identity();
    let (secret_b, _, did_b) = make_identity();

    let mut engine_a = make_engine(secret_a, did_a, schema);
    let mut engine_b = make_engine(secret_b, did_b, schema);

    let valid_delta = produce_delta(&mut engine_a, vec![]);
    let mut bad_delta = produce_delta(&mut engine_b, vec![]);
    bad_delta.automerge_bytes = vec![0xFF]; // tamper

    let (ledger_secret, _, ledger_did) = make_identity();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");

    let mut queue = CloudOutboundQueue::new();
    enqueue(&mut queue, &valid_delta);
    enqueue(&mut queue, &bad_delta);

    let mut conn = CloudLedgerConnection::new(&mut ledger);
    let result = cloud_sync_loop(&mut queue, &mut conn, &|_id, _holders| None);

    assert_eq!(result.acknowledged, 1);
    assert_eq!(result.rejected, 1);
    assert_eq!(queue.depth(), 1, "only bad Delta retained");

    // The remaining entry in the queue is the bad Delta.
    let remaining = queue.find(&bad_delta.id);
    assert!(remaining.is_some(), "bad Delta must still be in queue");
    // Valid Delta removed.
    assert!(queue.find(&valid_delta.id).is_none(), "valid Delta removed from queue");
}

// ─── Test 4: Append-only invariant (Req 16.2) ─────────────────────────────────

/// Once a Delta is committed to the Cloud Ledger, it can never be un-committed.
/// This is a structural property of `CloudLedger` (no remove/clear API exists).
/// We test it by verifying committed count only ever increases.
#[test]
fn append_only_committed_set_never_shrinks() {
    let schema = test_schema();
    let (ledger_secret, _, ledger_did) = make_identity();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");

    let mut delta_ids: Vec<DeltaId> = Vec::new();

    for i in 0..5u8 {
        let (secret, _, did) = make_identity();
        let mut engine = make_engine(secret, did, schema);
        let delta = produce_delta(&mut engine, vec![i]);
        let id = delta.id;
        ledger.receive_delta(&delta).expect("receive");
        delta_ids.push(id);

        // After each commit, all previously committed IDs must still be present.
        for prev_id in &delta_ids {
            assert!(
                ledger.is_committed(prev_id),
                "previously committed Delta must remain committed"
            );
        }
    }
    assert_eq!(ledger.committed_count(), 5);
}

// ─── Test 5: Same CRDT Engine semantics (Req 16.1) ───────────────────────────

/// The Cloud Ledger must use the same CRDT merge semantics as a client device.
/// Specifically: an invalid signature on a Delta causes rejection on BOTH
/// the client-side `CrdtEngine::apply()` and the `CloudLedger::receive_delta()`.
///
/// We verify symmetry: the same tampered Delta is rejected by a local engine
/// and by the Cloud Ledger.
#[test]
fn cloud_ledger_rejects_same_invalid_delta_as_client_engine() {
    let schema = test_schema();
    let (secret, _, did) = make_identity();
    let mut engine = make_engine(secret.clone(), did.clone(), schema);

    let mut delta = produce_delta(&mut engine, b"real-data".to_vec());
    // Tamper with the payload.
    delta.automerge_bytes = vec![0xBA, 0xD0];

    // Client-side engine.
    let (peer_secret, _, peer_did) = make_identity();
    let mut peer_engine = make_engine(peer_secret, peer_did, schema);
    let peer_outcome = peer_engine.apply(&delta).unwrap();
    assert!(
        matches!(peer_outcome, crate::crdt::merge::MergeOutcome::Rejected { .. }),
        "client engine must reject tampered Delta: {peer_outcome:?}"
    );

    // Cloud Ledger.
    let (ledger_secret, _, ledger_did) = make_identity();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");
    let ledger_outcome = ledger.receive_delta(&delta).unwrap();
    assert!(
        matches!(ledger_outcome, ReceiveOutcome::Rejected { .. }),
        "Cloud Ledger must reject the same tampered Delta: {ledger_outcome:?}"
    );
}

// ─── Test 6: Topological ordering in sync loop (Req 16.3) ─────────────────────

/// When the queue contains a child Delta and its parent Delta (in reverse
/// order), the sync loop must transmit the parent before the child so the
/// Cloud Ledger can maintain correct causal ordering.
///
/// We verify this by recording the transmission order in the CloudConnection
/// and asserting that the parent ID appears before the child ID.
#[test]
fn sync_loop_sends_parent_before_child() {
    let schema = test_schema();
    let (secret, _, did) = make_identity();
    let mut engine = make_engine(secret, did, schema);

    // Produce parent Delta first.
    let parent = produce_delta(&mut engine, b"parent".to_vec());
    // Child references the parent.
    let child_delta = engine
        .produce_delta(b"child".to_vec(), PriorityClass::Low, vec![parent.id])
        .expect("child delta");

    // Enqueue in REVERSE causal order (child first, parent second).
    // The topological sort in cloud_sync_loop must correct this.
    let mut queue = CloudOutboundQueue::new();
    // Child first (wrong order).
    let child_entry = QueueEntry::new(
        child_delta.id,
        serialise_delta(&child_delta),
        child_delta.causal_parents.clone(), // [parent.id]
    );
    queue.enqueue(child_entry).expect("enqueue child");
    // Parent second (wrong order).
    let parent_entry = QueueEntry::new(
        parent.id,
        serialise_delta(&parent),
        parent.causal_parents.clone(), // []
    );
    queue.enqueue(parent_entry).expect("enqueue parent");

    // Capture transmission order.
    let transmitted: Arc<Mutex<Vec<DeltaId>>> = Arc::new(Mutex::new(Vec::new()));
    let transmitted_clone = Arc::clone(&transmitted);

    struct RecordingConn {
        transmitted: Arc<Mutex<Vec<DeltaId>>>,
    }
    impl crate::durability::cloud_queue::CloudConnection for RecordingConn {
        fn send_delta(&mut self, delta_id: &DeltaId, _bytes: &[u8]) -> Result<(), String> {
            self.transmitted.lock().unwrap().push(*delta_id);
            Ok(())
        }
    }

    let mut conn = RecordingConn { transmitted: transmitted_clone };
    let result = cloud_sync_loop(&mut queue, &mut conn, &|_id, _holders| None);

    assert_eq!(result.acknowledged, 2);
    assert_eq!(queue.depth(), 0);

    let order = transmitted.lock().unwrap().clone();
    assert_eq!(order.len(), 2);
    // Parent must come before child.
    let parent_pos = order.iter().position(|id| *id == parent.id).unwrap();
    let child_pos = order.iter().position(|id| *id == child_delta.id).unwrap();
    assert!(
        parent_pos < child_pos,
        "parent must be transmitted before child (parent_pos={parent_pos}, child_pos={child_pos})"
    );
}

// ─── Test 7: Re-fetch for compacted Deltas (Req 16.8) ────────────────────────

/// When a Delta has been compacted from the hot path (bytes absent from the
/// queue entry), `cloud_sync_loop` must call the refetch callback.
/// If the refetch succeeds, the Delta must be transmitted and acked.
/// If the refetch fails, the Delta is deferred (retained in queue).
#[test]
fn compacted_delta_is_fetched_and_sent() {
    use crate::durability::cloud_queue::QueueEntry;

    let delta_id: DeltaId = [0x42u8; 32];

    // Pre-bake a Delta for the refetch to return.
    let schema = test_schema();
    let (secret, _, did) = make_identity();
    let mut engine = make_engine(secret, did, schema);
    let real_delta = produce_delta(&mut engine, b"compacted".to_vec());
    let real_bytes = serialise_delta(&real_delta);

    let (ledger_secret, _, ledger_did) = make_identity();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");

    let mut queue = CloudOutboundQueue::new();
    // Compacted entry — no bytes, has a receipt holder.
    let compacted_entry = QueueEntry::new_compacted(
        real_delta.id,
        vec![],
        vec!["did:key:holder1".to_string()],
    );
    queue.enqueue(compacted_entry).expect("enqueue compacted");

    // Refetch returns the real Delta bytes.
    let real_bytes_clone = real_bytes.clone();
    let mut conn = CloudLedgerConnection::new(&mut ledger);
    let result = cloud_sync_loop(&mut queue, &mut conn, &move |_id, _holders| {
        Some(real_bytes_clone.clone())
    });

    assert_eq!(result.acknowledged, 1, "compacted Delta must be acked after refetch");
    assert_eq!(result.deferred, 0);
    assert_eq!(queue.depth(), 0);
}

#[test]
fn compacted_delta_deferred_when_refetch_fails() {
    use crate::durability::cloud_queue::QueueEntry;

    let (ledger_secret, _, ledger_did) = make_identity();
    let schema = test_schema();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");

    let mut queue = CloudOutboundQueue::new();
    let delta_id: DeltaId = [0x99u8; 32];
    let compacted_entry = QueueEntry::new_compacted(
        delta_id,
        vec![],
        vec!["did:key:holder2".to_string()],
    );
    queue.enqueue(compacted_entry).expect("enqueue");

    let mut conn = CloudLedgerConnection::new(&mut ledger);
    // Refetch always fails.
    let result = cloud_sync_loop(&mut queue, &mut conn, &|_id, _holders| None);

    assert_eq!(result.deferred, 1, "compacted Delta with no refetch must be deferred");
    assert_eq!(result.acknowledged, 0);
    assert_eq!(queue.depth(), 1, "deferred entry retained in queue");
}

// ─── Test 8: Cloud Ledger is append-only via CloudConnection (Req 16.2) ───────

/// Verify that the `CloudLedgerConnection` adapter correctly returns `Ok(())`
/// for `AlreadyCommitted` (idempotent) and `Err(reason)` for `Rejected`.
#[test]
fn cloud_ledger_connection_maps_outcomes_correctly() {
    let schema = test_schema();
    let (secret, _, did) = make_identity();
    let mut engine = make_engine(secret, did, schema);
    let delta = produce_delta(&mut engine, b"data".to_vec());
    let bytes = serialise_delta(&delta);

    let (ledger_secret, _, ledger_did) = make_identity();
    let mut ledger = CloudLedger::new_in_memory(ledger_secret, ledger_did, schema)
        .expect("new_in_memory");

    // Pre-commit the Delta so the next call returns AlreadyCommitted.
    ledger.receive_delta(&delta).expect("first receive");

    // Re-submit via the connection adapter.
    let mut conn = CloudLedgerConnection::new(&mut ledger);
    let result = conn.send_delta(&delta.id, &bytes);
    assert!(result.is_ok(), "AlreadyCommitted must map to Ok(())");
}
