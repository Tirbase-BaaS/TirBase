//! TirBase vertical demo packs.
//! Bundles: cold-chain, energy-edge, water, logistics,
//!          buildings, remote-ops, defense-logistics.
//! Full implementation in tasks 27+.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

pub use tirbase_types;
