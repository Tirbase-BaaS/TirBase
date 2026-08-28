//! PriorityClassifier — maps Delta content to HIGH/MEDIUM/LOW (Req 12.5–12.7).

#![allow(dead_code)]

use crate::crdt::delta::{Delta, PriorityClass};

/// Classify the given Delta into a priority class.
///
/// Rules (Req 12.5–12.7):
///   - HIGH:   RevocationDelta, safety-alert or emergency-alert payload flag
///   - MEDIUM: peer reachability, link-state, or session-validity record
///   - LOW:    all other application Deltas
pub fn classify(delta: &Delta) -> PriorityClass {
    // TODO(task-10): inspect Delta metadata flags to route correctly.
    // For the scaffold, return the priority that was set at write time.
    delta.priority
}

/// Payload flags embedded in a Delta's metadata to override default priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFlag {
    /// Marks a Revocation_Delta (always HIGH — Req 12.5).
    Revocation,
    /// Emergency or safety alert (always HIGH — Req 12.5).
    SafetyAlert,
    /// Emergency alert (always HIGH — Req 12.5).
    EmergencyAlert,
    /// Peer reachability or link-state record (MEDIUM — Req 12.6).
    PeerReachability,
    /// Session-validity record (MEDIUM — Req 12.6).
    SessionValidity,
}
