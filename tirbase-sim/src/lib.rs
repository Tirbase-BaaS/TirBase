//! TirBase seeded deterministic simulator.
//! Provides SimClock, ChaCha8Rng, network fault injection,
//! thermal/battery models, adversary scenario runner, and INV checks.
//! Full runtime implementation continues in tasks 38.1-38.7.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

/// Per-tick invariant checks (INV-1..INV-16, CLAIM-17.1..17.8, CLAIM-38.6).
pub mod invariants;

#[cfg(test)]
pub mod scenarios;

pub use invariants::{
    assert_invariants_hold, InvariantChecker, InvariantId, InvariantViolation, SimState,
};
pub use tirbase_types;

pub use scenarios::s14_log_flooding;
