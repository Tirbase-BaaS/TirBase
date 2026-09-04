//! DrrScheduler — Deficit Round Robin scheduler with three priority queues (Req 12).
//!
//! Bandwidth allocation per 1-second scheduling epoch:
//!   - HIGH:   70% guaranteed floor
//!   - MEDIUM: 20% guaranteed floor
//!   - LOW:    10% guaranteed floor
//!
//! Spare capacity flows to queues with backlog in priority order (HIGH → MEDIUM → LOW).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::{Delta, PriorityClass};
use crate::errors::TirBaseError;
use std::collections::VecDeque;

/// A Delta queued for transmission, with its serialised byte length.
#[derive(Debug, Clone)]
pub struct QueuedDelta {
    pub delta: Delta,
    /// Pre-computed serialised byte length for scheduling.
    pub serialized_len: u64,
    /// Timestamp when this Delta was enqueued (UTC microseconds).
    pub enqueued_at: i64,
}

/// The Deficit Round Robin scheduler (design §DRR Scheduler Implementation).
pub struct DrrScheduler {
    high_queue:   VecDeque<QueuedDelta>,
    medium_queue: VecDeque<QueuedDelta>,
    low_queue:    VecDeque<QueuedDelta>,

    // Deficit counters (bytes)
    high_deficit:   i64,
    medium_deficit: i64,
    low_deficit:    i64,

    // Quantum allotments per scheduling epoch (1 second)
    // Computed from link_capacity_bps at init and on link change.
    high_quantum:   u64,    // 70% of epoch capacity
    medium_quantum: u64,    // 20% of epoch capacity
    low_quantum:    u64,    // 10% of epoch capacity

    /// True when Saturate_Mode is active (Req 13.2).
    saturate_mode: bool,
}

impl DrrScheduler {
    /// Create a new scheduler for the given link capacity in bytes per second.
    pub fn new(link_capacity_bytes_per_sec: u64) -> Self {
        let high_quantum   = (link_capacity_bytes_per_sec * 70) / 100;
        let medium_quantum = (link_capacity_bytes_per_sec * 20) / 100;
        let low_quantum    = (link_capacity_bytes_per_sec * 10) / 100;
        Self {
            high_queue:   VecDeque::new(),
            medium_queue: VecDeque::new(),
            low_queue:    VecDeque::new(),
            high_deficit:   0,
            medium_deficit: 0,
            low_deficit:    0,
            high_quantum,
            medium_quantum,
            low_quantum,
            saturate_mode: false,
        }
    }

    /// Update the link capacity and recompute quantum allotments.
    ///
    /// Call this when the active transport reports a link speed change.
    pub fn update_link_capacity(&mut self, link_capacity_bytes_per_sec: u64) {
        self.high_quantum   = (link_capacity_bytes_per_sec * 70) / 100;
        self.medium_quantum = (link_capacity_bytes_per_sec * 20) / 100;
        self.low_quantum    = (link_capacity_bytes_per_sec * 10) / 100;
    }

    /// Enqueue a Delta for transmission in the appropriate priority queue (Req 12.1).
    pub fn enqueue(&mut self, delta: QueuedDelta) {
        match delta.delta.priority {
            PriorityClass::High   => self.high_queue.push_back(delta),
            PriorityClass::Medium => self.medium_queue.push_back(delta),
            PriorityClass::Low    => self.low_queue.push_back(delta),
        }
    }

    /// Run one scheduling epoch (1 second) and return the Deltas to transmit
    /// in order (design §DRR Scheduler Implementation, `tick()`).
    ///
    /// In Saturate_Mode all bandwidth goes to HIGH; MEDIUM and LOW are queued
    /// without dropping (Req 13.2).
    ///
    /// Returns the drained `QueuedDelta`s in transmission order.
    pub fn tick(&mut self, link_capacity_bytes: u64) -> Vec<QueuedDelta> {
        if self.saturate_mode {
            // All bandwidth to HIGH; MEDIUM and LOW are queued but not served.
            return drain_queue(&mut self.high_queue, link_capacity_bytes as i64, &mut self.high_deficit);
        }

        // --- Phase 1: Add guaranteed floor quanta to deficit counters ---
        self.high_deficit   += self.high_quantum   as i64;  // 70%
        self.medium_deficit += self.medium_quantum as i64;  // 20%
        self.low_deficit    += self.low_quantum    as i64;  // 10%

        // --- Phase 2: Serve each queue up to its guaranteed floor ---
        let mut sent_high   = drain_queue(&mut self.high_queue,   self.high_deficit,   &mut self.high_deficit);
        let mut sent_medium = drain_queue(&mut self.medium_queue, self.medium_deficit, &mut self.medium_deficit);
        let mut sent_low    = drain_queue(&mut self.low_queue,    self.low_deficit,    &mut self.low_deficit);

        let bytes_sent_high:   u64 = sent_high.iter().map(|d| d.serialized_len).sum();
        let bytes_sent_medium: u64 = sent_medium.iter().map(|d| d.serialized_len).sum();
        let bytes_sent_low:    u64 = sent_low.iter().map(|d| d.serialized_len).sum();

        // --- Phase 3: Redistribute spare capacity HIGH → MEDIUM → LOW ---
        let total_sent = bytes_sent_high + bytes_sent_medium + bytes_sent_low;
        let mut spare = (link_capacity_bytes as i64) - (total_sent as i64);

        if spare > 0 && !self.high_queue.is_empty() {
            let extra = drain_queue(&mut self.high_queue, spare, &mut self.high_deficit);
            spare -= extra.iter().map(|d| d.serialized_len as i64).sum::<i64>();
            sent_high.extend(extra);
        }
        if spare > 0 && !self.medium_queue.is_empty() {
            let extra = drain_queue(&mut self.medium_queue, spare, &mut self.medium_deficit);
            spare -= extra.iter().map(|d| d.serialized_len as i64).sum::<i64>();
            sent_medium.extend(extra);
        }
        if spare > 0 && !self.low_queue.is_empty() {
            let extra = drain_queue(&mut self.low_queue, spare, &mut self.low_deficit);
            sent_low.extend(extra);
        }

        // Combine in priority order
        let mut result = sent_high;
        result.extend(sent_medium);
        result.extend(sent_low);
        result
    }

    /// Activate / deactivate the scheduler's Saturate_Mode flag (Req 13.2).
    ///
    /// The scheduler is a **mirror**, not a source of truth: it must only be
    /// written by `MeshTransport::reconcile_scheduler_saturate_mode`
    /// (Subphase 3.2), which derives the flag from the transport's
    /// `SaturateModeStateMachine` after every lease-lifecycle event.  Callers
    /// outside `transport` must not flip this boolean directly — doing so
    /// bypasses lease activation / renewal / M-of-N-termination entirely.
    ///
    /// When leaving saturate mode the deficit counters may have accumulated;
    /// reset them to avoid a sudden burst on the first normal-mode epoch.
    pub(crate) fn set_saturate_mode(&mut self, active: bool) {
        self.saturate_mode = active;
        // When leaving saturate mode the deficit counters may have accumulated;
        // reset them to avoid a sudden burst on the first normal-mode epoch.
        if !active {
            self.high_deficit   = 0;
            self.medium_deficit = 0;
            self.low_deficit    = 0;
        }
    }

    /// Returns true if saturate mode is currently active.
    pub(crate) fn is_saturate_mode(&self) -> bool {
        self.saturate_mode
    }

    /// Returns true if any queue has pending Deltas.
    pub fn has_backlog(&self) -> bool {
        !self.high_queue.is_empty()
            || !self.medium_queue.is_empty()
            || !self.low_queue.is_empty()
    }

    /// Returns the current depth of the LOW priority queue.
    pub fn low_queue_depth(&self) -> usize {
        self.low_queue.len()
    }

    /// Returns the current depth of the HIGH priority queue.
    pub fn high_queue_depth(&self) -> usize {
        self.high_queue.len()
    }

    /// Returns the current depth of the MEDIUM priority queue.
    pub fn medium_queue_depth(&self) -> usize {
        self.medium_queue.len()
    }

    /// Compute the clearing capacity for the LOW queue (Req 12.8):
    /// 10% of `link_capacity_bytes_per_sec` × 10 seconds.
    pub fn low_clearing_capacity(link_capacity_bytes_per_sec: u64) -> u64 {
        (link_capacity_bytes_per_sec * 10 / 100) * 10
    }
}

// ─── drain_queue helper ───────────────────────────────────────────────────────

/// Drain as many Deltas from `queue` as fit within `budget` bytes.
///
/// The deficit counter is decremented by the total bytes sent.
/// Returns the drained `QueuedDelta`s.
fn drain_queue(
    queue: &mut VecDeque<QueuedDelta>,
    budget: i64,
    deficit: &mut i64,
) -> Vec<QueuedDelta> {
    let mut sent: Vec<QueuedDelta> = Vec::new();
    let mut bytes_sent: i64 = 0;

    while let Some(front) = queue.front() {
        let len = front.serialized_len as i64;
        if bytes_sent + len <= budget {
            let delta = queue.pop_front().unwrap();
            bytes_sent += len;
            sent.push(delta);
        } else {
            break;
        }
    }

    *deficit -= bytes_sent;
    sent
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};

    fn make_delta(priority: PriorityClass) -> Delta {
        Delta {
            id: [0u8; 32],
            author_did: "did:key:test".to_string(),
            signature: Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![],
            priority,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        }
    }

    fn make_queued(priority: PriorityClass, size_bytes: u64) -> QueuedDelta {
        QueuedDelta {
            delta: make_delta(priority),
            serialized_len: size_bytes,
            enqueued_at: 0,
        }
    }

    // ── Floor guarantee: all queues populated ─────────────────────────────

    #[test]
    fn drr_floor_fractions_over_10_epochs() {
        // Link: 1000 bytes/sec  →  floors: HIGH 700, MEDIUM 200, LOW 100
        // We need all three queues to have backlog throughout all 10 epochs so
        // the floor guarantee is observable.  Each epoch drains at most 1000
        // bytes; 10 epochs = 10 000 bytes max.  Load each queue with 2 000
        // items × 10 bytes = 20 000 bytes — well above what can be sent.
        let link_cap = 1000u64;
        let mut sched = DrrScheduler::new(link_cap);

        for _ in 0..2_000 {
            sched.enqueue(make_queued(PriorityClass::High,   10));
            sched.enqueue(make_queued(PriorityClass::Medium, 10));
            sched.enqueue(make_queued(PriorityClass::Low,    10));
        }

        let mut total_high:   u64 = 0;
        let mut total_medium: u64 = 0;
        let mut total_low:    u64 = 0;

        for _ in 0..10 {
            let drained = sched.tick(link_cap);
            for d in &drained {
                match d.delta.priority {
                    PriorityClass::High   => total_high   += d.serialized_len,
                    PriorityClass::Medium => total_medium += d.serialized_len,
                    PriorityClass::Low    => total_low    += d.serialized_len,
                }
            }
        }

        let total = total_high + total_medium + total_low;
        // Floor guarantee: each class must receive AT LEAST its guaranteed
        // fraction of total bytes transmitted over ≥10 epochs (Req 12.2–12.4,
        // Property 12).  Small integer rounding tolerance: 1 byte per epoch.
        assert!(
            total_high * 100 >= total * 70 - 10,
            "HIGH floor violated: {total_high}/{total}"
        );
        assert!(
            total_medium * 100 >= total * 20 - 10,
            "MEDIUM floor violated: {total_medium}/{total}"
        );
        assert!(
            total_low * 100 >= total * 10 - 10,
            "LOW floor violated: {total_low}/{total}"
        );
    }

    // ── Spare redistribution to HIGH-only backlog ─────────────────────────

    #[test]
    fn spare_redistribution_to_high_only_backlog() {
        // Link: 1000 bytes/epoch. Only HIGH queue is populated.
        // After serving HIGH's 700-byte floor, 300 spare bytes should go to HIGH as well.
        let link_cap = 1000u64;
        let mut sched = DrrScheduler::new(link_cap);

        // Enqueue 1000 bytes worth of HIGH deltas (10 × 100 bytes each)
        for _ in 0..10 {
            sched.enqueue(make_queued(PriorityClass::High, 100));
        }

        let drained = sched.tick(link_cap);
        let bytes_sent: u64 = drained.iter().map(|d| d.serialized_len).sum();

        // With a 1000-byte budget and only 100-byte packets, all 1000 bytes consumed
        assert_eq!(bytes_sent, 1000, "all link capacity should go to HIGH when only HIGH has backlog");
    }

    // ── LOW bounded wait at clearing capacity ─────────────────────────────

    #[test]
    fn low_bounded_wait_at_clearing_capacity() {
        // LOW clearing capacity = 10% * link_cap * 10 epochs
        // With link_cap = 1000: clearing capacity = 100 * 10 = 1000 bytes
        let link_cap = 1000u64;
        let clearing_cap = DrrScheduler::low_clearing_capacity(link_cap); // 1000
        let mut sched = DrrScheduler::new(link_cap);

        // Fill LOW queue up to exactly the clearing capacity (10 × 100 bytes)
        let n_deltas = 10usize;
        for _ in 0..n_deltas {
            sched.enqueue(make_queued(PriorityClass::Low, 100));
        }

        // No HIGH or MEDIUM backlog — all spare goes to LOW as well
        let mut transmitted_low = 0usize;
        for _ in 0..10 {
            let drained = sched.tick(link_cap);
            for d in &drained {
                if d.delta.priority == PriorityClass::Low {
                    transmitted_low += 1;
                }
            }
        }

        assert_eq!(
            transmitted_low, n_deltas,
            "all LOW deltas should be transmitted within 10 epochs when at clearing capacity"
        );
    }

    // ── Saturate mode: all bandwidth to HIGH ─────────────────────────────

    #[test]
    fn saturate_mode_all_bandwidth_to_high() {
        let link_cap = 1000u64;
        let mut sched = DrrScheduler::new(link_cap);
        sched.set_saturate_mode(true);

        for _ in 0..5 {
            sched.enqueue(make_queued(PriorityClass::High, 100));
            sched.enqueue(make_queued(PriorityClass::Medium, 100));
            sched.enqueue(make_queued(PriorityClass::Low, 100));
        }

        let drained = sched.tick(link_cap);

        // Only HIGH should be served in saturate mode
        for d in &drained {
            assert_eq!(
                d.delta.priority,
                PriorityClass::High,
                "only HIGH should be served in saturate mode"
            );
        }

        // MEDIUM and LOW should remain queued
        assert_eq!(sched.medium_queue_depth(), 5, "MEDIUM should still be queued");
        assert_eq!(sched.low_queue_depth(), 5, "LOW should still be queued");
    }

    // ── Saturate mode: MEDIUM and LOW not dropped ─────────────────────────

    #[test]
    fn saturate_mode_medium_low_not_dropped() {
        let link_cap = 1000u64;
        let mut sched = DrrScheduler::new(link_cap);
        sched.set_saturate_mode(true);

        for _ in 0..3 {
            sched.enqueue(make_queued(PriorityClass::Medium, 50));
            sched.enqueue(make_queued(PriorityClass::Low, 50));
        }

        // Run several epochs in saturate mode
        for _ in 0..5 {
            sched.tick(link_cap);
        }

        // MEDIUM and LOW must not be dropped
        assert_eq!(sched.medium_queue_depth(), 3, "MEDIUM must not be dropped");
        assert_eq!(sched.low_queue_depth(), 3, "LOW must not be dropped");
    }

    // ── Deficit counter resets when leaving saturate mode ─────────────────

    #[test]
    fn deficit_reset_on_leaving_saturate_mode() {
        let mut sched = DrrScheduler::new(1000);
        sched.set_saturate_mode(true);

        // In saturate mode, run ticks to accumulate deficit
        for _ in 0..5 {
            sched.tick(1000);
        }

        // Leave saturate mode
        sched.set_saturate_mode(false);

        // Immediately add data and tick — should not burst beyond one epoch's allotment
        for _ in 0..20 {
            sched.enqueue(make_queued(PriorityClass::High, 50));
            sched.enqueue(make_queued(PriorityClass::Medium, 50));
            sched.enqueue(make_queued(PriorityClass::Low, 50));
        }

        let drained = sched.tick(1000);
        let bytes_sent: u64 = drained.iter().map(|d| d.serialized_len).sum();

        // Should not exceed the link capacity (no deficit burst after saturation)
        assert!(
            bytes_sent <= 1000,
            "should not burst beyond link capacity on first normal epoch after saturation: {bytes_sent}"
        );
    }

    // ── has_backlog / queue depth helpers ─────────────────────────────────

    #[test]
    fn has_backlog_returns_true_when_any_queue_nonempty() {
        let mut sched = DrrScheduler::new(1000);
        assert!(!sched.has_backlog());
        sched.enqueue(make_queued(PriorityClass::Low, 10));
        assert!(sched.has_backlog());
    }

    #[test]
    fn low_clearing_capacity_calculation() {
        // 10% * 1000 * 10 = 1000
        assert_eq!(DrrScheduler::low_clearing_capacity(1000), 1000);
        // 10% * 10000 * 10 = 10000
        assert_eq!(DrrScheduler::low_clearing_capacity(10000), 10000);
    }

    // ── No data: tick returns empty ────────────────────────────────────────

    #[test]
    fn tick_with_empty_queues_returns_empty() {
        let mut sched = DrrScheduler::new(1000);
        let drained = sched.tick(1000);
        assert!(drained.is_empty(), "tick on empty scheduler should return nothing");
    }
}
