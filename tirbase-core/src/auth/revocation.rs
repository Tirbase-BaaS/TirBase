//! RevocationDelta, M-of-N threshold accumulation, and PendingRevocationStore (Req 9).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::{Did, Ed25519Signature};
use crate::errors::TirBaseError;
use std::collections::HashMap;

/// A Manager DID signature contribution toward a RevocationDelta.
#[derive(Debug, Clone)]
pub struct ManagerSignature {
    pub manager_did: Did,
    pub signature: Ed25519Signature,
}

/// A complete Revocation_Delta — produced when M signatures are accumulated (Req 9.1).
#[derive(Debug, Clone)]
pub struct RevocationDelta {
    /// DID of the device being revoked.
    pub target_did: Did,
    /// All M authorising Manager DID signatures.
    pub signatures: Vec<ManagerSignature>,
    /// UTC timestamp (microseconds).
    pub created_at: i64,
}

/// Per-target accumulation state in the PendingRevocationStore.
#[derive(Debug, Clone)]
pub struct PendingRevocation {
    pub target_did: Did,
    pub signatures: Vec<ManagerSignature>,
    pub threshold_m: usize,
    pub threshold_n: usize,
    pub initiated_at: i64,
}

/// Current accumulation status returned by `add_signature`.
#[derive(Debug, Clone)]
pub enum RevocationStatus {
    /// Not yet reached the M threshold.
    Pending {
        collected: usize,
        required: usize,
    },
    /// M signatures collected; Revocation_Delta applied.
    Applied,
}

/// Accumulates partial RevocationDelta signatures from mesh gossip until M reached (Req 9.1, 9.3).
#[derive(Debug, Default)]
pub struct PendingRevocationStore {
    pending: HashMap<Did, PendingRevocation>,
}

impl PendingRevocationStore {
    /// Add a Manager signature for the given target DID.
    ///
    /// Returns `Applied` when M signatures are accumulated; `Pending` otherwise.
    /// Returns `ThresholdNotMet` if the signature is invalid or the signing key is REVOKED.
    pub fn add_signature(
        &mut self,
        target_did: Did,
        sig: ManagerSignature,
        threshold_m: usize,
        threshold_n: usize,
    ) -> Result<RevocationStatus, TirBaseError> {
        todo!("Task 4 / Task 11: implement signature accumulation")
    }

    /// Check the current accumulation state for a target DID without adding a signature.
    pub fn status(&self, target_did: &Did) -> Option<RevocationStatus> {
        self.pending.get(target_did).map(|p| {
            if p.signatures.len() >= p.threshold_m {
                RevocationStatus::Applied
            } else {
                RevocationStatus::Pending {
                    collected: p.signatures.len(),
                    required: p.threshold_m,
                }
            }
        })
    }

    /// Queryable status flag: last known TrustLevel + timestamp of last RevocationDelta
    /// receipt, for the isolated-device scenario (Req 9.5).
    pub fn last_revocation_receipt_timestamp(&self, target_did: &Did) -> Option<i64> {
        todo!("Task 4 / Task 11: implement last receipt tracking")
    }
}
