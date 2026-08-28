//! SaturateMode state machine and Lease tracking (Req 13).

#![allow(dead_code, unused_variables)]

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;

/// Duration of a Saturate_Mode Lease: 60 minutes in seconds (Req 13.3).
pub const SATURATE_LEASE_DURATION_SECS: i64 = 60 * 60;

/// Renewal window: 15 minutes before expiry (Req 13.4).
pub const RENEWAL_WINDOW_SECS: i64 = 15 * 60;

/// SaturateMode operating state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaturateState {
    Normal,
    Saturate,
}

/// A Saturate_Mode Lease (Req 13.3).
#[derive(Debug, Clone)]
pub struct SaturateLease {
    /// UTC microseconds when Saturate_Mode was activated.
    pub activated_at: i64,
    /// UTC microseconds when the Lease expires (activated_at + 3600s).
    pub expires_at: i64,
    /// UTC microseconds of the last valid heartbeat renewal.
    pub last_renewed_at: Option<i64>,
    /// The Manager DID that activated this Lease.
    pub activating_manager_did: Did,
}

/// The Saturate_Mode state machine.
pub struct SaturateModeStateMachine {
    state: SaturateState,
    lease: Option<SaturateLease>,
    /// Configured M-of-N termination threshold.
    termination_threshold_m: usize,
}

impl SaturateModeStateMachine {
    pub fn new(termination_threshold_m: usize) -> Self {
        Self {
            state: SaturateState::Normal,
            lease: None,
            termination_threshold_m,
        }
    }

    /// Current operating state.
    pub fn state(&self) -> SaturateState {
        self.state
    }

    /// Activate Saturate_Mode via a DISASTER_ALERT (Req 13.1).
    ///
    /// Validates the Manager Biscuit token carries the `disaster-alert` caveat.
    /// Returns `SignatureVerificationFailed` if the token is absent, expired, or invalid.
    pub fn activate(
        &mut self,
        manager_did: Did,
        manager_sig: &[u8],
        biscuit_token: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        todo!("Task 10: validate token caveat and activate")
    }

    /// Process a heartbeat renewal (Req 13.4).
    pub fn renew(
        &mut self,
        manager_did: Did,
        manager_sig: &[u8],
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        todo!("Task 10: validate sig and extend lease by 60 min")
    }

    /// Process a Lease Termination Delta (Req 13.6).
    ///
    /// Requires M valid distinct Manager DID signatures.
    pub fn terminate(
        &mut self,
        signatures: Vec<(Did, Vec<u8>)>,
        now_secs: i64,
    ) -> Result<(), TirBaseError> {
        todo!("Task 10: verify M-of-N sigs and terminate")
    }

    /// Advance the clock — transitions to NORMAL if the Lease has expired
    /// without renewal (Req 13.5).
    pub fn tick(&mut self, now_secs: i64) {
        if self.state == SaturateState::Saturate {
            if let Some(ref lease) = self.lease {
                if now_secs >= lease.expires_at {
                    self.state = SaturateState::Normal;
                    self.lease = None;
                }
            }
        }
    }
}
