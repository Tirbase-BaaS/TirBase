//! CapabilityManager — Biscuit token verification, TrustLevel state machine (Req 8).

#![allow(dead_code, unused_variables, unused_imports)]

pub mod biscuit;
pub mod revocation;
pub mod root_ca;
pub mod trust;

use crate::api::types::TrustLevel;
use crate::errors::TirBaseError;

/// The Capability Manager handles Biscuit token creation and offline verification,
/// TrustLevel state transitions, and the M-of-N revocation accumulation.
pub struct CapabilityManager {
    // TODO(task-4): embed TrustLevelStateMachine, RootCaRegistry, PendingRevocationStore
}

impl CapabilityManager {
    /// Initialise the Capability Manager with the given deployment CA keys and config.
    pub fn new(root_ca_keys: Vec<[u8; 32]>) -> Self {
        todo!("Task 4: initialise CapabilityManager")
    }

    /// Verify a Biscuit token and update TrustLevel (Req 8.3).
    pub fn verify_token(&mut self, token_bytes: &[u8], now_secs: i64) -> Result<TrustLevel, TirBaseError> {
        todo!("Task 4: implement token verification")
    }

    /// Return the current TrustLevel of the local device (Req 2.4, 8.2).
    pub fn trust_level(&self) -> TrustLevel {
        todo!("Task 4: return from TrustLevelStateMachine")
    }

    /// Apply the REVOKED trust level from a validated Revocation_Delta (Req 8.5, 9.4).
    pub fn apply_revocation(&mut self) -> Result<(), TirBaseError> {
        todo!("Task 4 / Task 11: apply REVOKED state")
    }
}
