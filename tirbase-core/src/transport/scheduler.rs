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
    pub fn tick(&mut self, link_capacity_bytes: u64) -> Vec<&QueuedDelta> {
        todo!("Task 10: implement DRR tick with floor guarantees and spare redistribution")
    }

    /// Activate Saturate_Mode (Req 13.1–13.2).
    pub fn set_saturate_mode(&mut self, active: bool) {
        self.saturate_mode = active;
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
}
