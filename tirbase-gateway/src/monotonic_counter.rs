//! Software-backed monotonic counter for the gateway binary.
//!
//! The `MonotonicCounterTrait` will be defined in `tirbase-core/src/traits.rs`
//! (task 5.3 — CLAIM-5.3).  This module provides the concrete
//! `SoftwareMonotonicCounter` struct (assurance Level 1) that will implement
//! that trait once it lands.  A full SQLite-WAL-backed persistence layer is
//! planned in CLAIM-6.5.

use std::sync::atomic::{AtomicU64, Ordering};

/// Software-backed monotonic counter (no TPM / secure element required).
///
/// This is assurance **Level 1**: backed by an in-memory atomic integer.
/// A durable SQLite WAL backing store will be added in task 6.5 (CLAIM-6.5).
pub struct SoftwareMonotonicCounter {
    inner: AtomicU64,
}

impl SoftwareMonotonicCounter {
    /// Construct a new counter initialised to `initial`.
    pub fn new(initial: u64) -> Self {
        SoftwareMonotonicCounter {
            inner: AtomicU64::new(initial),
        }
    }

    /// Read the current counter value without advancing it.
    pub fn read(&self) -> u64 {
        self.inner.load(Ordering::SeqCst)
    }

    /// Atomically increment the counter by one and return the **new** value.
    pub fn increment(&self) -> u64 {
        self.inner.fetch_add(1, Ordering::SeqCst) + 1
    }
}
