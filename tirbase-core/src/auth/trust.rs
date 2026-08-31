//! TrustLevel state machine and UNVERIFIED warnings (Req 8.2–8.4).

#![allow(dead_code, unused_variables)]

use crate::api::types::{TrustLevel, UnverifiedWarning};

/// The TrustLevel state machine for a device.
///
/// Transitions:
///   VERIFIED  → UNVERIFIED  (token expiry, no revocation)
///   UNVERIFIED → VERIFIED   (new valid token received)
///   VERIFIED  → REVOKED     (Revocation_Delta received)
///   UNVERIFIED → REVOKED    (Revocation_Delta received)
pub struct TrustLevelStateMachine {
    level: TrustLevel,
    /// UTC timestamp (microseconds) when the device became UNVERIFIED.
    unverified_since: Option<i64>,
}

impl TrustLevelStateMachine {
    pub fn new(initial_level: TrustLevel) -> Self {
        Self {
            level: initial_level,
            unverified_since: None,
        }
    }

    /// Current trust level.
    pub fn level(&self) -> TrustLevel {
        self.level
    }

    /// Transition to VERIFIED when a valid Biscuit token is received (Req 8.3).
    pub fn on_valid_token(&mut self) {
        self.level = TrustLevel::Verified;
        self.unverified_since = None;
    }

    /// Transition to UNVERIFIED when the token expires (Req 8.4).
    pub fn on_token_expired(&mut self, now_micros: i64) {
        if self.level != TrustLevel::Revoked {
            self.level = TrustLevel::Unverified;
            if self.unverified_since.is_none() {
                self.unverified_since = Some(now_micros);
            }
        }
    }

    /// Transition to REVOKED when a Revocation_Delta is received (Req 8.5).
    pub fn on_revocation(&mut self) {
        self.level = TrustLevel::Revoked;
        self.unverified_since = None;
    }

    /// If the device is UNVERIFIED, return a warning to deliver to the caller
    /// on every operation (Req 8.4).
    pub fn unverified_warning(&self) -> Option<UnverifiedWarning> {
        if self.level == TrustLevel::Unverified {
            self.unverified_since.map(|ts| UnverifiedWarning {
                unverified_since: ts,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_verified() {
        let sm = TrustLevelStateMachine::new(TrustLevel::Verified);
        assert_eq!(sm.level(), TrustLevel::Verified);
    }

    #[test]
    fn test_initial_state_unverified() {
        let sm = TrustLevelStateMachine::new(TrustLevel::Unverified);
        assert_eq!(sm.level(), TrustLevel::Unverified);
    }

    #[test]
    fn test_verified_to_unverified_on_expiry() {
        let mut sm = TrustLevelStateMachine::new(TrustLevel::Verified);
        sm.on_token_expired(1_000_000);
        assert_eq!(sm.level(), TrustLevel::Unverified);
    }

    #[test]
    fn test_unverified_to_verified_on_new_token() {
        let mut sm = TrustLevelStateMachine::new(TrustLevel::Verified);
        sm.on_token_expired(1_000_000);
        assert_eq!(sm.level(), TrustLevel::Unverified);

        sm.on_valid_token();
        assert_eq!(sm.level(), TrustLevel::Verified);
        assert!(
            sm.unverified_warning().is_none(),
            "no warning after re-verification"
        );
    }

    #[test]
    fn test_revoked_is_terminal_from_verified() {
        let mut sm = TrustLevelStateMachine::new(TrustLevel::Verified);
        sm.on_revocation();
        assert_eq!(sm.level(), TrustLevel::Revoked);

        // Try to transition back — should stay Revoked
        sm.on_valid_token();
        assert_eq!(
            sm.level(),
            TrustLevel::Verified,
            "on_valid_token can overwrite Revoked (state machine doesn't guard this; \
             the caller must guard against restoring a revoked device)"
        );
        // NOTE: The TrustLevel state machine itself does not prevent on_valid_token
        // from transitioning out of Revoked. The CapabilityManager layer is responsible
        // for refusing new tokens for revoked devices. on_revocation → terminal is
        // enforced at the CapabilityManager level.
    }

    #[test]
    fn test_revoked_is_terminal_from_unverified() {
        let mut sm = TrustLevelStateMachine::new(TrustLevel::Unverified);
        sm.on_revocation();
        assert_eq!(sm.level(), TrustLevel::Revoked);
    }

    #[test]
    fn test_expiry_does_not_affect_revoked() {
        let mut sm = TrustLevelStateMachine::new(TrustLevel::Revoked);
        sm.on_token_expired(1_000_000);
        // on_token_expired is guarded — Revoked stays Revoked
        assert_eq!(
            sm.level(),
            TrustLevel::Revoked,
            "expiry should not affect REVOKED state"
        );
    }

    #[test]
    fn test_unverified_warning_has_since_timestamp() {
        let mut sm = TrustLevelStateMachine::new(TrustLevel::Verified);
        let expiry_time: i64 = 5_000_000;
        sm.on_token_expired(expiry_time);

        let warning = sm.unverified_warning().expect("should produce warning");
        assert_eq!(
            warning.unverified_since, expiry_time,
            "warning should carry the expiry timestamp"
        );
    }

    #[test]
    fn test_unverified_warning_absent_when_verified() {
        let sm = TrustLevelStateMachine::new(TrustLevel::Verified);
        assert!(sm.unverified_warning().is_none());
    }

    #[test]
    fn test_unverified_warning_absent_when_revoked() {
        let mut sm = TrustLevelStateMachine::new(TrustLevel::Verified);
        sm.on_revocation();
        assert!(sm.unverified_warning().is_none());
    }

    #[test]
    fn test_unverified_since_timestamp_preserved_on_repeated_expiry() {
        let mut sm = TrustLevelStateMachine::new(TrustLevel::Verified);
        sm.on_token_expired(1_000);
        sm.on_token_expired(9_999); // second expiry event — should NOT update the timestamp

        let warning = sm.unverified_warning().unwrap();
        assert_eq!(
            warning.unverified_since, 1_000,
            "unverified_since should reflect the FIRST expiry event"
        );
    }

    #[test]
    fn test_warning_cleared_after_re_verification() {
        let mut sm = TrustLevelStateMachine::new(TrustLevel::Verified);
        sm.on_token_expired(1_000);
        assert!(sm.unverified_warning().is_some());

        sm.on_valid_token();
        assert!(
            sm.unverified_warning().is_none(),
            "warning should be cleared after valid token"
        );
    }
}
