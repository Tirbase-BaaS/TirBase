//! Cloud outbound queue — 100k Delta cap, topological sync, re-fetch logic (Req 16.3–16.8).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::{Delta, DeltaId, Did};
use crate::errors::TirBaseError;
use std::collections::VecDeque;

/// Maximum Deltas allowed in the cloud outbound queue (Req 16.6).
pub const MAX_QUEUE_DEPTH: usize = 100_000;

/// An entry in the cloud outbound queue.
#[derive(Debug, Clone)]
pub struct QueueEntry {
    pub delta_id: DeltaId,
    /// True if this Delta has been compacted from the hot path and requires re-fetch (Req 14.8).
    pub compacted: bool,
    /// Peer DIDs that issued Durability_Receipts for this Delta (for re-fetch — Req 16.8).
    pub receipt_holders: Vec<Did>,
    /// True when the Cloud Ledger has acknowledged this Delta.
    pub tier2_durable: bool,
}

/// Cloud outbound queue with 100k Delta cap.
pub struct CloudOutboundQueue {
    queue: VecDeque<QueueEntry>,
}

impl CloudOutboundQueue {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    /// Enqueue a Delta for cloud sync (Req 16.3).
    ///
    /// Returns `CloudQueueFull` if the queue is at capacity (Req 16.7).
    pub fn enqueue(&mut self, entry: QueueEntry) -> Result<(), TirBaseError> {
        if self.queue.len() >= MAX_QUEUE_DEPTH {
            return Err(TirBaseError::CloudQueueFull {
                depth: self.queue.len(),
            });
        }
        self.queue.push_back(entry);
        Ok(())
    }

    /// Remove a Delta from the queue after Tier-2 acknowledgement (Req 16.3).
    pub fn acknowledge(&mut self, delta_id: &DeltaId) {
        self.queue.retain(|e| &e.delta_id != delta_id);
    }

    /// Current queue depth.
    pub fn depth(&self) -> usize {
        self.queue.len()
    }
}

impl Default for CloudOutboundQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Attempt to re-fetch a compacted Delta from a receipt-holding peer (Req 16.8).
///
/// Returns `RefetchUnavailable` and logs a warning if no peer is reachable.
pub async fn refetch_for_cloud_sync(
    delta_id: DeltaId,
    receipt_holders: Vec<Did>,
) -> Result<Vec<u8>, TirBaseError> {
    todo!("Task 12: implement re-fetch protocol via SessionManager")
}

/// Cloud sync loop — topological sort, send each Delta in causal order,
/// remove from queue only after per-Delta acknowledgement (Req 16.3).
pub async fn cloud_sync_loop(queue: &mut CloudOutboundQueue) -> Result<(), TirBaseError> {
    todo!("Task 13: implement cloud sync loop with idempotent receive")
}
