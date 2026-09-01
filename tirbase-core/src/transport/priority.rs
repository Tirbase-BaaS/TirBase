//! PriorityClassifier — maps Delta content to HIGH/MEDIUM/LOW (Req 12.5–12.7).
//!
//! Classification rules:
//!   - HIGH:   RevocationDelta, safety-alert or emergency-alert payload flag
//!   - MEDIUM: peer reachability, link-state, or session-validity record
//!   - LOW:    all other application Deltas
//!
//! The authoritative classification is stored in `delta.priority` at write time
//! by the producing device.  `classify()` returns that value directly.
//! `classify_with_flags()` is provided for production code that needs to assign
//! priority before enqueuing a freshly-created Delta.

#![allow(dead_code)]

use crate::crdt::delta::{Delta, PriorityClass};

/// Payload flags that override the default priority classification (Req 12.5–12.6).
///
/// These are attached to a Delta at write time by the local application layer.
/// The scheduler reads `delta.priority`, which is set using `classify_with_flags()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFlag {
    /// Marks a Revocation_Delta (always HIGH — Req 12.5).
    Revocation,
    /// Safety-alert payload flag (always HIGH — Req 12.5).
    SafetyAlert,
    /// Emergency-alert payload flag (always HIGH — Req 12.5).
    EmergencyAlert,
    /// Peer reachability or link-state record (MEDIUM — Req 12.6).
    PeerReachability,
    /// Link-state record (MEDIUM — Req 12.6).
    LinkState,
    /// Session-validity record (MEDIUM — Req 12.6).
    SessionValidity,
}

/// Classify a Delta into a priority class using its stored `priority` field (Req 12.1).
///
/// The `priority` field is set at Delta-production time via [`classify_with_flags`].
/// This function returns it verbatim so the scheduler always respects the
/// producing device's authoritative classification.
#[inline]
pub fn classify(delta: &Delta) -> PriorityClass {
    delta.priority
}

/// Derive the correct [`PriorityClass`] for a Delta being produced locally,
/// given zero or more payload flags (Req 12.5–12.7).
///
/// | Flag(s) present                                      | Result   |
/// |------------------------------------------------------|----------|
/// | `Revocation`, `SafetyAlert`, or `EmergencyAlert`     | HIGH     |
/// | `PeerReachability`, `LinkState`, or `SessionValidity`| MEDIUM   |
/// | (none of the above)                                  | LOW      |
///
/// When a single Delta carries flags from multiple tiers (e.g. a revocation
/// that is also flagged as a safety-alert), the highest tier wins.
pub fn classify_with_flags(flags: &[PayloadFlag]) -> PriorityClass {
    let mut result = PriorityClass::Low;

    for flag in flags {
        match flag {
            PayloadFlag::Revocation
            | PayloadFlag::SafetyAlert
            | PayloadFlag::EmergencyAlert => {
                // HIGH beats everything — short-circuit
                return PriorityClass::High;
            }
            PayloadFlag::PeerReachability
            | PayloadFlag::LinkState
            | PayloadFlag::SessionValidity => {
                // MEDIUM upgrades from LOW, but HIGH still wins
                result = PriorityClass::Medium;
            }
        }
    }

    result
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};

    fn make_delta(priority: PriorityClass) -> Delta {
        Delta {
            id: [0u8; 32],
            author_did: "did:key:test".to_string(),
            signature: Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![],
            priority,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        }
    }

    // ── classify() returns stored priority ───────────────────────────────

    #[test]
    fn classify_returns_high_for_high_delta() {
        let d = make_delta(PriorityClass::High);
        assert_eq!(classify(&d), PriorityClass::High);
    }

    #[test]
    fn classify_returns_medium_for_medium_delta() {
        let d = make_delta(PriorityClass::Medium);
        assert_eq!(classify(&d), PriorityClass::Medium);
    }

    #[test]
    fn classify_returns_low_for_low_delta() {
        let d = make_delta(PriorityClass::Low);
        assert_eq!(classify(&d), PriorityClass::Low);
    }

    // ── classify_with_flags: HIGH flags ──────────────────────────────────

    #[test]
    fn revocation_flag_yields_high() {
        assert_eq!(
            classify_with_flags(&[PayloadFlag::Revocation]),
            PriorityClass::High
        );
    }

    #[test]
    fn safety_alert_flag_yields_high() {
        assert_eq!(
            classify_with_flags(&[PayloadFlag::SafetyAlert]),
            PriorityClass::High
        );
    }

    #[test]
    fn emergency_alert_flag_yields_high() {
        assert_eq!(
            classify_with_flags(&[PayloadFlag::EmergencyAlert]),
            PriorityClass::High
        );
    }

    // ── classify_with_flags: MEDIUM flags ────────────────────────────────

    #[test]
    fn peer_reachability_flag_yields_medium() {
        assert_eq!(
            classify_with_flags(&[PayloadFlag::PeerReachability]),
            PriorityClass::Medium
        );
    }

    #[test]
    fn link_state_flag_yields_medium() {
        assert_eq!(
            classify_with_flags(&[PayloadFlag::LinkState]),
            PriorityClass::Medium
        );
    }

    #[test]
    fn session_validity_flag_yields_medium() {
        assert_eq!(
            classify_with_flags(&[PayloadFlag::SessionValidity]),
            PriorityClass::Medium
        );
    }

    // ── classify_with_flags: LOW (no flags) ──────────────────────────────

    #[test]
    fn no_flags_yields_low() {
        assert_eq!(classify_with_flags(&[]), PriorityClass::Low);
    }

    // ── classify_with_flags: mixed tiers — highest wins ──────────────────

    #[test]
    fn revocation_beats_medium_flags() {
        assert_eq!(
            classify_with_flags(&[PayloadFlag::PeerReachability, PayloadFlag::Revocation]),
            PriorityClass::High
        );
    }

    #[test]
    fn safety_alert_beats_medium_flags() {
        assert_eq!(
            classify_with_flags(&[PayloadFlag::SessionValidity, PayloadFlag::SafetyAlert]),
            PriorityClass::High
        );
    }

    #[test]
    fn medium_beats_low_default() {
        assert_eq!(
            classify_with_flags(&[PayloadFlag::LinkState]),
            PriorityClass::Medium
        );
    }
}
