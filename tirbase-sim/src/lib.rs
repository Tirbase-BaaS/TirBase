//! TirBase seeded deterministic simulator.
//! Provides SimClock, ChaCha8Rng, network fault injection,
//! thermal/battery models, adversary scenario runner, and INV checks.
//! Full implementation in tasks 24+.

#![forbid(unsafe_code)]

pub use tirbase_types;
