//! TirBase Command Guard crate.
//! Provides the CommandGuard, EnvelopeProfile, PolicyLifecycle,
//! AppliedEffectsLedger, AntiReplayWindow, SingleWriterLease,
//! TimeRatchet, ActuationPermit, and SecurityEventLog.
//! Full implementation in tasks 7–16.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

pub use tirbase_types;
