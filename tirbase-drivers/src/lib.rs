//! TirBase device driver framework.
//! Provides DriverTrait, DeviceModel, and driver implementations.
//! Depends ONLY on tirbase-types (not tirbase-guard, not tirbase-core).
//! Full implementation in tasks 18+.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

pub use tirbase_types;
