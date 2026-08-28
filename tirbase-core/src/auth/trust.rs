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
