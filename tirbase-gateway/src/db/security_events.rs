//! Security event log DB helpers (PV-7.2–PV-7.4, /25.5).
//!
//! Production callers:
//! - `tirbase-gateway/src/security_log.rs` persists chained events and checkpoints.
//! - Migration framework creates `security_events` and `security_event_segments`
//! in `primary.db` (CLAIM-25.4, CLAIM-25.5).

pub use crate::security_log::{
    ensure_security_log_schema, read_security_event_segments, read_security_events,
};
