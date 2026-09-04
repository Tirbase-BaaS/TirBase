//! Cloud outbound queue — 100k Delta cap, topological sync loop, re-fetch protocol
//! (Req 16.3–16.8).
//!
//! # Responsibilities
//!
//! - `CloudOutboundQueue` holds Deltas waiting for Cloud Ledger acknowledgement in
//!   causal order (topologically sorted at enqueue time).
//! - `enqueue()` enforces the 100,000 Delta cap and returns `CloudQueueFull` on overflow.
//! - `acknowledge()` removes a Delta from the queue only after a per-Delta ack (Req 16.3).
//! - `cloud_sync_loop()` sends each Delta to the Cloud Ledger in causal order and
//!   removes acknowledged Deltas; retained on rejection for retry (Req 16.5).
//! - `refetch_for_cloud_sync()` re-fetches compacted Deltas from receipt-holding peers
//!   before cloud sync; logs `RefetchUnavailable` when no peers are reachable (Req 16.8).

#![allow(dead_code, unused_variables)]

use crate::crdt::delta::{Delta, DeltaId, Did};
use crate::errors::TirBaseError;
use std::collections::{HashMap, VecDeque};

/// Maximum Deltas allowed in the cloud outbound queue (Req 16.6).
pub const MAX_QUEUE_DEPTH: usize = 100_000;

// ─── Queue Entry ──────────────────────────────────────────────────────────────

/// An entry in the cloud outbound queue.
#[derive(Debug, Clone)]
pub struct QueueEntry {
    /// The Delta identifier.
    pub delta_id: DeltaId,
    /// Serialised Delta bytes (may need re-fetching if `compacted = true`).
    pub delta_bytes: Option<Vec<u8>>,
    /// Causal parent IDs — used for topological ordering.
    pub causal_parents: Vec<DeltaId>,
    /// True if this Delta has been compacted from the hot read path and its
    /// `delta_bytes` may be absent; requires re-fetch before cloud sync (Req 14.8).
    pub compacted: bool,
    /// Peer DIDs that issued `DurabilityReceipt`s for this Delta (for re-fetch — Req 16.8).
    pub receipt_holders: Vec<Did>,
    /// True when the Cloud Ledger has acknowledged this Delta (Tier-2 durable).
    pub tier2_durable: bool,
}

impl QueueEntry {
    /// Create a new non-compacted queue entry with its serialised bytes.
    pub fn new(delta_id: DeltaId, delta_bytes: Vec<u8>, causal_parents: Vec<DeltaId>) -> Self {
        Self {
            delta_id,
            delta_bytes: Some(delta_bytes),
            causal_parents,
            compacted: false,
            receipt_holders: Vec::new(),
            tier2_durable: false,
        }
    }

    /// Create a compacted queue entry (bytes absent, must be re-fetched).
    pub fn new_compacted(
        delta_id: DeltaId,
        causal_parents: Vec<DeltaId>,
        receipt_holders: Vec<Did>,
    ) -> Self {
        Self {
            delta_id,
            delta_bytes: None,
            causal_parents,
            compacted: true,
            receipt_holders,
            tier2_durable: false,
        }
    }
}

// ─── Cloud Outbound Queue ─────────────────────────────────────────────────────

/// Cloud outbound queue with 100k Delta cap (Req 16.6).
///
/// Maintains insertion order (causal order — callers topologically sort before
/// enqueueing). Entries are removed only after a per-Delta Cloud Ledger ack (Req 16.3).
#[derive(Debug)]
pub struct CloudOutboundQueue {
    /// Ordered queue of pending entries.
    queue: VecDeque<QueueEntry>,
    /// Index from `delta_id` → position in `queue` for O(1) acknowledge.
    /// Rebuilt on demand since `VecDeque` doesn't support stable indices — we use
    /// a `retain`-based acknowledge which is O(n) but safe for the 100k cap.
    _index_placeholder: (),
}

impl CloudOutboundQueue {
    /// Create an empty queue.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            _index_placeholder: (),
        }
    }

    /// Enqueue a Delta for cloud sync (Req 16.3).
    ///
    /// The caller is responsible for topological ordering before enqueueing.
    ///
    /// Returns `CloudQueueFull` if the queue is at or beyond `MAX_QUEUE_DEPTH` (Req 16.7).
    pub fn enqueue(&mut self, entry: QueueEntry) -> Result<(), TirBaseError> {
        if self.queue.len() >= MAX_QUEUE_DEPTH {
            let depth = self.queue.len();
            log_queue_overflow(depth);
            return Err(TirBaseError::CloudQueueFull { depth });
        }
        self.queue.push_back(entry);
        Ok(())
    }

    /// Mark a Delta as Tier-2 durable and remove it from the queue after a
    /// per-Delta Cloud Ledger acknowledgement (Req 16.3).
    pub fn acknowledge(&mut self, delta_id: &DeltaId) {
        self.queue.retain(|e| &e.delta_id != delta_id);
    }

    /// Mark a Delta as Tier-2 durable **without** removing it — used to update
    /// the `tier2_durable` flag while retaining the entry for re-fetch tracking.
    pub fn mark_tier2(&mut self, delta_id: &DeltaId) {
        for entry in self.queue.iter_mut() {
            if &entry.delta_id == delta_id {
                entry.tier2_durable = true;
                break;
            }
        }
    }

    /// Add a receipt holder DID to an existing queue entry.
    pub fn add_receipt_holder(&mut self, delta_id: &DeltaId, holder_did: Did) {
        for entry in self.queue.iter_mut() {
            if &entry.delta_id == delta_id {
                if !entry.receipt_holders.contains(&holder_did) {
                    entry.receipt_holders.push(holder_did);
                }
                break;
            }
        }
    }

    /// Current queue depth.
    pub fn depth(&self) -> usize {
        self.queue.len()
    }

    /// Iterate pending entries in queue order (causal order, as enqueued).
    pub fn pending_entries(&self) -> impl Iterator<Item = &QueueEntry> {
        self.queue.iter().filter(|e| !e.tier2_durable)
    }

    /// Look up a queue entry by Delta ID.
    pub fn find(&self, delta_id: &DeltaId) -> Option<&QueueEntry> {
        self.queue.iter().find(|e| &e.delta_id == delta_id)
    }
}

impl Default for CloudOutboundQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Re-fetch Protocol ────────────────────────────────────────────────────────

/// Outcome of a re-fetch attempt.
#[derive(Debug)]
pub enum RefetchOutcome {
    /// The Delta bytes were successfully retrieved from a receipt-holding peer.
    Success(Vec<u8>),
    /// No receipt-holding peer was reachable.
    Unavailable,
}

/// Attempt to re-fetch a compacted Delta from receipt-holding peers (Req 16.8).
///
/// The session manager is not embedded in this function; instead, callers inject
/// a `try_fetch_from_peer` callback that handles the actual peer communication.
/// This keeps the function pure and testable without a live transport.
///
/// # Parameters
///
/// * `delta_id` — the Delta to re-fetch.
/// * `receipt_holders` — DIDs of peers that issued receipts for this Delta.
/// * `try_fetch_from_peer` — async callback that attempts to retrieve the Delta
///   bytes from a specific peer.  Returns `None` if the peer is unreachable.
///
/// # Behaviour
///
/// Iterates through `receipt_holders` in order. Returns the bytes from the first
/// reachable peer. If all peers are unreachable, logs `RefetchUnavailable` and
/// returns `Err(TirBaseError::RefetchUnavailable)` (Req 16.8).
pub async fn refetch_for_cloud_sync<F, Fut>(
    delta_id: DeltaId,
    receipt_holders: Vec<Did>,
    try_fetch_from_peer: F,
) -> Result<Vec<u8>, TirBaseError>
where
    F: Fn(Did, DeltaId) -> Fut,
    Fut: std::future::Future<Output = Option<Vec<u8>>>,
{
    for peer_did in &receipt_holders {
        if let Some(bytes) = try_fetch_from_peer(peer_did.clone(), delta_id).await {
            return Ok(bytes);
        }
    }

    // All peers unreachable — log and defer (Req 16.8).
    log_refetch_unavailable(&delta_id, &receipt_holders);
    Err(TirBaseError::RefetchUnavailable {
        delta_id: hex::encode(delta_id),
    })
}

// ─── Topological sort helper ─────────────────────────────────────────────────

/// Topologically sort the Delta IDs in the queue so that causal parents are
/// transmitted before their children (Req 16.3).
///
/// Uses Kahn's algorithm on the `causal_parents` relationship embedded in each
/// `QueueEntry`. Deltas whose parents are not in the queue (already sent or
/// from a previous session) are treated as roots.
///
/// Returns a vector of Delta IDs in causal order (parents before children).
/// Deltas not reachable via the dependency graph (cycles or orphans) are
/// appended at the end in their original queue order so nothing is silently
/// dropped.
fn topological_sort_queue(queue: &CloudOutboundQueue) -> Vec<DeltaId> {
    use std::collections::{HashMap, VecDeque};

    // Build a map from delta_id → index for O(1) look-ups.
    let id_set: std::collections::HashSet<DeltaId> =
        queue.queue.iter().map(|e| e.delta_id).collect();

    // in_degree[id] = number of parents still in the queue.
    let mut in_degree: HashMap<DeltaId, usize> = HashMap::new();
    // children_map[parent] = list of children in the queue.
    let mut children_map: HashMap<DeltaId, Vec<DeltaId>> = HashMap::new();

    for entry in queue.queue.iter() {
        in_degree.entry(entry.delta_id).or_insert(0);
        children_map.entry(entry.delta_id).or_default();

        for parent_id in &entry.causal_parents {
            if id_set.contains(parent_id) {
                // Parent is also in the queue → this entry depends on it.
                *in_degree.entry(entry.delta_id).or_insert(0) += 1;
                children_map
                    .entry(*parent_id)
                    .or_default()
                    .push(entry.delta_id);
            }
        }
    }

    // Kahn's BFS: start with all zero-in-degree nodes.
    let mut ready: VecDeque<DeltaId> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(id, _)| *id)
        .collect();

    // Maintain stable ordering within same in-degree level by using queue
    // insertion order as a secondary key.
    let order_index: HashMap<DeltaId, usize> = queue
        .queue
        .iter()
        .enumerate()
        .map(|(i, e)| (e.delta_id, i))
        .collect();

    // Sort initial ready set by original queue position for determinism.
    let mut ready_vec: Vec<DeltaId> = ready.drain(..).collect();
    ready_vec.sort_by_key(|id| order_index.get(id).copied().unwrap_or(usize::MAX));
    ready.extend(ready_vec);

    let mut sorted: Vec<DeltaId> = Vec::with_capacity(queue.queue.len());

    while let Some(node) = ready.pop_front() {
        sorted.push(node);
        if let Some(children) = children_map.get(&node) {
            let mut next_ready: Vec<DeltaId> = children
                .iter()
                .filter_map(|child| {
                    let deg = in_degree.get_mut(child)?;
                    *deg -= 1;
                    if *deg == 0 {
                        Some(*child)
                    } else {
                        None
                    }
                })
                .collect();
            // Stable ordering within the newly-ready batch.
            next_ready
                .sort_by_key(|id| order_index.get(id).copied().unwrap_or(usize::MAX));
            for id in next_ready {
                ready.push_back(id);
            }
        }
    }

    // Append any remaining (cycle / unreachable) entries in original order.
    let sorted_set: std::collections::HashSet<DeltaId> = sorted.iter().cloned().collect();
    for entry in queue.queue.iter() {
        if !sorted_set.contains(&entry.delta_id) {
            sorted.push(entry.delta_id);
        }
    }

    sorted
}

// ─── Cloud Sync Loop ──────────────────────────────────────────────────────────

/// Trait for the Cloud Ledger connection — allows testing without a live connection.
pub trait CloudConnection: Send {
    /// Send one Delta to the Cloud Ledger.
    ///
    /// Returns:
    /// - `Ok(())` — Cloud Ledger acknowledged this Delta.
    /// - `Err(reason)` — Cloud Ledger rejected the Delta; caller should retain it.
    fn send_delta(&mut self, delta_id: &DeltaId, bytes: &[u8]) -> Result<(), String>;
}

/// Cloud sync loop — sends each Delta in **topological (causal) order** to the
/// Cloud Ledger, removing entries only after per-Delta acknowledgement (Req 16.3).
///
/// The loop first computes a topological ordering of all pending queue entries
/// using their `causal_parents` relationships so that parents are always
/// transmitted before their children.  This is safe even if some parents have
/// already been sent and removed from the queue — those entries simply have
/// zero in-queue parents and are treated as roots.
///
/// On rejection the Delta is retained and its rejection is logged (Req 16.5).
/// On `RefetchUnavailable` for a compacted Delta, sync is deferred for that entry.
///
/// # Re-fetch behaviour
///
/// For entries where `compacted = true` and `delta_bytes = None`, this function
/// calls `refetch` to obtain the bytes before sending.  If re-fetch fails, the
/// entry is skipped for this sync cycle.
///
/// # Parameters
///
/// * `queue` — the cloud outbound queue (mutated in place).
/// * `conn` — the Cloud Ledger connection.
/// * `refetch` — synchronous re-fetch callback for compacted entries.
pub fn cloud_sync_loop(
    queue: &mut CloudOutboundQueue,
    conn: &mut dyn CloudConnection,
    refetch: &dyn Fn(&DeltaId, &[Did]) -> Option<Vec<u8>>,
) -> CloudSyncResult {
    let mut acknowledged = 0usize;
    let mut rejected = 0usize;
    let mut deferred = 0usize;
    // Delta IDs the Cloud Ledger freshly acknowledged this cycle.  The caller
    // uses these to mark each Delta Tier-2 durable in its durability-state
    // table (Subphase 4.2 — `DurabilitySubsystem::on_cloud_ack`), so a real
    // cloud ack transitions `WriteResult`-backing state out of `Uncommitted`.
    let mut acknowledged_ids: Vec<DeltaId> = Vec::new();

    // Compute causal order before processing (Req 16.3).
    let ids = topological_sort_queue(queue);

    for delta_id in ids {
        let entry = match queue.queue.iter().find(|e| e.delta_id == delta_id) {
            Some(e) => e.clone(),
            None => continue, // already removed by a prior ack
        };

        if entry.tier2_durable {
            // Already acknowledged in a previous cycle — remove and continue.
            // Not reported in `acknowledged_ids`: the Tier-2 state marking and
            // notification for this Delta already happened when it was first
            // acknowledged, and re-marking would emit a duplicate event.
            queue.acknowledge(&delta_id);
            acknowledged += 1;
            continue;
        }

        // Resolve bytes: either inline or via re-fetch.
        let bytes = if let Some(b) = &entry.delta_bytes {
            b.clone()
        } else if entry.compacted {
            match refetch(&delta_id, &entry.receipt_holders) {
                Some(b) => b,
                None => {
                    log_refetch_unavailable(&delta_id, &entry.receipt_holders);
                    deferred += 1;
                    continue; // defer this Delta; process the rest
                }
            }
        } else {
            // No bytes and not compacted — should not happen; skip.
            deferred += 1;
            continue;
        };

        // Send to Cloud Ledger.
        match conn.send_delta(&delta_id, &bytes) {
            Ok(()) => {
                queue.acknowledge(&delta_id);
                acknowledged += 1;
                acknowledged_ids.push(delta_id);
            }
            Err(reason) => {
                // Retain in queue; log rejection (Req 16.5).
                log_cloud_rejection(&delta_id, &reason);
                rejected += 1;
            }
        }
    }

    CloudSyncResult {
        acknowledged,
        rejected,
        deferred,
        acknowledged_ids,
    }
}

/// Summary of one cloud sync cycle.
#[derive(Debug, Default)]
pub struct CloudSyncResult {
    pub acknowledged: usize,
    pub rejected: usize,
    pub deferred: usize,
    /// Delta IDs the Cloud Ledger acknowledged **during this cycle** (fresh
    /// acks only — entries already flagged `tier2_durable` in a previous
    /// cycle are counted in `acknowledged` but excluded here so their Tier-2
    /// marking is not repeated).  The production drain caller marks each of
    /// these Tier-2 durable in the Durability Subsystem (Subphase 4.2).
    pub acknowledged_ids: Vec<DeltaId>,
}

// ─── Internal logging ────────────────────────────────────────────────────────

fn log_queue_overflow(depth: usize) {
    eprintln!(
        "[cloud_queue] CloudQueueFull: depth={depth}. \
         New Delta rejected from outbound queue."
    );
}

fn log_refetch_unavailable(delta_id: &DeltaId, holders: &[Did]) {
    eprintln!(
        "[cloud_queue] RefetchUnavailable for delta {}. \
         Attempted peers: [{}]. Deferring cloud sync.",
        hex::encode(delta_id),
        holders.join(", ")
    );
}

fn log_cloud_rejection(delta_id: &DeltaId, reason: &str) {
    eprintln!(
        "[cloud_queue] Cloud Ledger rejected delta {}: {reason}. \
         Retaining in queue for next sync cycle.",
        hex::encode(delta_id)
    );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_delta_id(byte: u8) -> DeltaId {
        [byte; 32]
    }

    fn make_entry(byte: u8) -> QueueEntry {
        QueueEntry::new(make_delta_id(byte), vec![byte; 16], vec![])
    }

    fn make_compacted_entry(byte: u8, receipt_holders: Vec<Did>) -> QueueEntry {
        QueueEntry::new_compacted(make_delta_id(byte), vec![], receipt_holders)
    }

    // ── enqueue ────────────────────────────────────────────────────────────

    #[test]
    fn enqueue_increments_depth() {
        let mut q = CloudOutboundQueue::new();
        assert_eq!(q.depth(), 0);
        q.enqueue(make_entry(1)).unwrap();
        assert_eq!(q.depth(), 1);
        q.enqueue(make_entry(2)).unwrap();
        assert_eq!(q.depth(), 2);
    }

    #[test]
    fn enqueue_at_capacity_returns_queue_full() {
        let mut q = CloudOutboundQueue::new();
        // Fill up to MAX_QUEUE_DEPTH.
        for i in 0..MAX_QUEUE_DEPTH {
            let id: [u8; 32] = {
                let mut arr = [0u8; 32];
                let bytes = i.to_le_bytes();
                arr[..bytes.len()].copy_from_slice(&bytes);
                arr
            };
            let entry = QueueEntry::new(id, vec![0u8; 4], vec![]);
            q.enqueue(entry).unwrap();
        }
        assert_eq!(q.depth(), MAX_QUEUE_DEPTH);

        // One more must fail.
        let overflow = QueueEntry::new([0xFF; 32], vec![1, 2, 3], vec![]);
        let result = q.enqueue(overflow);
        assert!(
            matches!(result, Err(TirBaseError::CloudQueueFull { depth }) if depth == MAX_QUEUE_DEPTH),
            "100_001st entry must return CloudQueueFull"
        );
    }

    // ── acknowledge ────────────────────────────────────────────────────────

    #[test]
    fn acknowledge_removes_entry_from_queue() {
        let mut q = CloudOutboundQueue::new();
        q.enqueue(make_entry(0xAA)).unwrap();
        q.enqueue(make_entry(0xBB)).unwrap();
        assert_eq!(q.depth(), 2);

        q.acknowledge(&make_delta_id(0xAA));
        assert_eq!(q.depth(), 1);
        assert!(q.find(&make_delta_id(0xAA)).is_none());
        assert!(q.find(&make_delta_id(0xBB)).is_some());
    }

    #[test]
    fn acknowledge_nonexistent_id_is_noop() {
        let mut q = CloudOutboundQueue::new();
        q.enqueue(make_entry(0x01)).unwrap();
        q.acknowledge(&make_delta_id(0xFF)); // doesn't exist
        assert_eq!(q.depth(), 1);
    }

    // ── cloud_sync_loop ───────────────────────────────────────────────────

    /// A mock CloudConnection that acks everything.
    struct AlwaysOkConn;
    impl CloudConnection for AlwaysOkConn {
        fn send_delta(&mut self, _id: &DeltaId, _bytes: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    /// A mock CloudConnection that rejects everything.
    struct AlwaysErrConn;
    impl CloudConnection for AlwaysErrConn {
        fn send_delta(&mut self, _id: &DeltaId, _bytes: &[u8]) -> Result<(), String> {
            Err("ledger unavailable".to_string())
        }
    }

    #[test]
    fn sync_loop_acknowledges_all_entries_on_success() {
        let mut q = CloudOutboundQueue::new();
        q.enqueue(make_entry(0x01)).unwrap();
        q.enqueue(make_entry(0x02)).unwrap();
        q.enqueue(make_entry(0x03)).unwrap();

        let mut conn = AlwaysOkConn;
        let result = cloud_sync_loop(&mut q, &mut conn, &|_id, _holders| None);

        assert_eq!(result.acknowledged, 3);
        assert_eq!(result.rejected, 0);
        assert_eq!(q.depth(), 0, "queue should be empty after full ack");
    }

    #[test]
    fn sync_loop_retains_entries_on_rejection() {
        let mut q = CloudOutboundQueue::new();
        q.enqueue(make_entry(0xAA)).unwrap();
        q.enqueue(make_entry(0xBB)).unwrap();

        let mut conn = AlwaysErrConn;
        let result = cloud_sync_loop(&mut q, &mut conn, &|_id, _holders| None);

        assert_eq!(result.rejected, 2);
        assert_eq!(result.acknowledged, 0);
        assert_eq!(q.depth(), 2, "rejected entries must remain in queue");
    }

    #[test]
    fn sync_loop_defers_compacted_entry_when_refetch_fails() {
        let mut q = CloudOutboundQueue::new();
        q.enqueue(make_compacted_entry(
            0xCC,
            vec!["did:key:holder1".to_string()],
        ))
        .unwrap();

        let mut conn = AlwaysOkConn;
        // Re-fetch always returns None → deferred.
        let result = cloud_sync_loop(&mut q, &mut conn, &|_id, _holders| None);

        assert_eq!(result.deferred, 1);
        assert_eq!(result.acknowledged, 0);
        assert_eq!(q.depth(), 1, "deferred entry must remain in queue");
    }

    #[test]
    fn sync_loop_sends_compacted_entry_when_refetch_succeeds() {
        let mut q = CloudOutboundQueue::new();
        q.enqueue(make_compacted_entry(
            0xDD,
            vec!["did:key:holder2".to_string()],
        ))
        .unwrap();

        let mut conn = AlwaysOkConn;
        // Re-fetch succeeds.
        let result =
            cloud_sync_loop(&mut q, &mut conn, &|_id, _holders| Some(vec![0xDE, 0xAD]));

        assert_eq!(result.acknowledged, 1);
        assert_eq!(result.deferred, 0);
        assert_eq!(q.depth(), 0);
    }

    // ── refetch_for_cloud_sync (async) ────────────────────────────────────

    #[tokio::test]
    async fn refetch_succeeds_from_first_reachable_peer() {
        let delta_id = make_delta_id(0x42);
        let result = refetch_for_cloud_sync(
            delta_id,
            vec!["did:key:peer1".to_string(), "did:key:peer2".to_string()],
            |did, _id| async move {
                if did == "did:key:peer1" {
                    Some(vec![1, 2, 3])
                } else {
                    None
                }
            },
        )
        .await;
        assert_eq!(result.unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn refetch_returns_unavailable_when_all_peers_unreachable() {
        let delta_id = make_delta_id(0x43);
        let result = refetch_for_cloud_sync(
            delta_id,
            vec!["did:key:p1".to_string(), "did:key:p2".to_string()],
            |_did, _id| async move { None },
        )
        .await;
        assert!(
            matches!(result, Err(TirBaseError::RefetchUnavailable { .. })),
            "all peers unreachable must return RefetchUnavailable"
        );
    }

    #[tokio::test]
    async fn refetch_empty_holders_returns_unavailable() {
        let delta_id = make_delta_id(0x44);
        let result =
            refetch_for_cloud_sync(delta_id, vec![], |_did, _id| async move { None }).await;
        assert!(matches!(result, Err(TirBaseError::RefetchUnavailable { .. })));
    }

    // ── add_receipt_holder ────────────────────────────────────────────────

    #[test]
    fn add_receipt_holder_no_duplicate() {
        let mut q = CloudOutboundQueue::new();
        let id = make_delta_id(0x10);
        q.enqueue(QueueEntry::new(id, vec![], vec![])).unwrap();
        q.add_receipt_holder(&id, "did:key:h1".to_string());
        q.add_receipt_holder(&id, "did:key:h1".to_string()); // duplicate
        let entry = q.find(&id).unwrap();
        assert_eq!(entry.receipt_holders.len(), 1);
    }
}
