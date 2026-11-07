//! TirBase seeded deterministic simulator.
//! Provides SimClock, ChaCha8Rng, network fault injection,
//! thermal/battery models, adversary scenario runner, and INV checks.
//! Full implementation in tasks 24+.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

pub use tirbase_types;
