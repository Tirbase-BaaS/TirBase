//! System time source backed by CLOCK_BOOTTIME (Linux only).
//!
//! The `TimeSource` trait will be defined in `tirbase-core/src/traits.rs`
//! (task 5.1 — CLAIM-5.1).  This module provides the concrete
//! `SystemTimeSource` struct that will implement that trait once the trait
//! lands.

/// System time source backed by `CLOCK_BOOTTIME` for monotonic reads and
/// `CLOCK_REALTIME` for the wall-clock hint (Linux-native).
pub struct SystemTimeSource;

impl SystemTimeSource {
    /// Construct a new `SystemTimeSource`.
    pub fn new() -> Self {
        SystemTimeSource
    }
}

impl Default for SystemTimeSource {
    fn default() -> Self {
        Self::new()
    }
}
