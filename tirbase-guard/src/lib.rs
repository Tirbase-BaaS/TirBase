//! TirBase Command Guard crate.
//! Provides the CommandGuard, EnvelopeProfile, PolicyLifecycle,
//! AppliedEffectsLedger, AntiReplayWindow, SingleWriterLease,
//! TimeRatchet, ActuationPermit, and SecurityEventLog.
//! Full implementation in tasks 7–16.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

pub mod signed_operation;

/// `TimeRatchet`, authenticated-time estimate, and freshness state
/// (tasks 7.2–7.5 — CLAIM-7.2…7.5, PV-22).
pub mod time;

pub use signed_operation::{
    SignatureEntry, SignedOperation, SignedOperationError, SignedOperationPayload,
    CONTEXT_EPOCH_BUMP, CONTEXT_LOCKDOWN_EXIT, CONTEXT_POLICY_BUNDLE,
};

pub use time::{
    FreshnessState, RatchetAdvance, TimeBeacon, TimeRatchet, TimeRatchetConfig, TimeRatchetError,
    TimeRatchetRecord, TimeRatchetStore, CONTEXT_TIME_BEACON, DEFAULT_MAX_FORWARD_JUMP_SECS,
    DEFAULT_REQUIRED_ANCHOR_SIGNATURES, DEFAULT_STALENESS_WINDOW_SECS,
};

pub use tirbase_types;
