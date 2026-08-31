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
    /// UTC timestamp (microseconds) of the last RevocationDelta receipt for this target.
    pub last_receipt_timestamp: Option<i64>,
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
    ///
    /// Rejects:
    /// - Duplicate signatures from the same `manager_did` (Req 9.3)
    /// - When M is reached, marks the entry as applied (Req 9.1)
    pub fn add_signature(
        &mut self,
        target_did: Did,
        sig: ManagerSignature,
        threshold_m: usize,
        threshold_n: usize,
    ) -> Result<RevocationStatus, TirBaseError> {
        let entry = self
            .pending
            .entry(target_did.clone())
            .or_insert_with(|| PendingRevocation {
                target_did: target_did.clone(),
                signatures: Vec::new(),
                threshold_m,
                threshold_n,
                initiated_at: current_timestamp_micros(),
                last_receipt_timestamp: None,
            });

        // Update thresholds in case they were updated (use latest provided values)
        entry.threshold_m = threshold_m;
        entry.threshold_n = threshold_n;

        // Reject duplicate Manager DID (Req 9.3)
        if entry
            .signatures
            .iter()
            .any(|s| s.manager_did == sig.manager_did)
        {
            return Err(TirBaseError::AuthorisationFailed {
                reason: format!(
                    "duplicate signature from manager DID '{}'",
                    sig.manager_did
                ),
            });
        }

        // Reject if already applied
        if entry.signatures.len() >= threshold_m {
            return Ok(RevocationStatus::Applied);
        }

        entry.signatures.push(sig);

        // Check if we've reached the threshold
        if entry.signatures.len() >= threshold_m {
            // Record the receipt timestamp
            entry.last_receipt_timestamp = Some(current_timestamp_micros());
            Ok(RevocationStatus::Applied)
        } else {
            Ok(RevocationStatus::Pending {
                collected: entry.signatures.len(),
                required: threshold_m,
            })
        }
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

    /// Queryable status flag: last known timestamp of last RevocationDelta
    /// receipt, for the isolated-device scenario (Req 9.5).
    pub fn last_revocation_receipt_timestamp(&self, target_did: &Did) -> Option<i64> {
        self.pending
            .get(target_did)
            .and_then(|p| p.last_receipt_timestamp)
    }

    /// Build a `RevocationDelta` from the accumulated signatures for a target DID.
    ///
    /// Returns `None` if the threshold has not been met.
    pub fn build_revocation_delta(&self, target_did: &Did) -> Option<RevocationDelta> {
        let entry = self.pending.get(target_did)?;
        if entry.signatures.len() < entry.threshold_m {
            return None;
        }
        Some(RevocationDelta {
            target_did: target_did.clone(),
            signatures: entry.signatures.clone(),
            created_at: entry.last_receipt_timestamp.unwrap_or(entry.initiated_at),
        })
    }

    /// Emit a warning string if M=1, N=1 (single manager has unilateral exile power).
    ///
    /// Returns `Some(warning)` when M=1 and N=1 (Req 9.7).
    pub fn check_1_of_1_warning(threshold_m: usize, threshold_n: usize) -> Option<String> {
        if threshold_m == 1 && threshold_n == 1 {
            Some(
                "WARNING: M=1, N=1 configuration grants a single Manager unilateral revocation power (Req 9.7)".to_string(),
            )
        } else {
            None
        }
    }
}

/// Returns a wall-clock timestamp in microseconds.
fn current_timestamp_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sig(manager_did: &str) -> ManagerSignature {
        ManagerSignature {
            manager_did: manager_did.to_string(),
            signature: Ed25519Signature::default(),
        }
    }

    #[test]
    fn test_below_threshold_returns_pending() {
        let mut store = PendingRevocationStore::default();
        let target = "did:key:z6MkTarget".to_string();

        let status = store
            .add_signature(target.clone(), make_sig("did:key:z6MkMgr1"), 3, 5)
            .expect("add_signature should succeed");

        match status {
            RevocationStatus::Pending { collected, required } => {
                assert_eq!(collected, 1);
                assert_eq!(required, 3);
            }
            RevocationStatus::Applied => panic!("should not be Applied with 1/3 signatures"),
        }
    }

    #[test]
    fn test_at_threshold_returns_applied() {
        let mut store = PendingRevocationStore::default();
        let target = "did:key:z6MkTarget".to_string();

        store
            .add_signature(target.clone(), make_sig("did:key:z6MkMgr1"), 2, 3)
            .unwrap();

        let status = store
            .add_signature(target.clone(), make_sig("did:key:z6MkMgr2"), 2, 3)
            .expect("second signature should succeed");

        match status {
            RevocationStatus::Applied => {} // expected
            RevocationStatus::Pending { collected, required } => {
                panic!("should be Applied at threshold, got Pending({collected}/{required})")
            }
        }
    }

    #[test]
    fn test_duplicate_manager_did_rejected() {
        let mut store = PendingRevocationStore::default();
        let target = "did:key:z6MkTarget".to_string();

        store
            .add_signature(target.clone(), make_sig("did:key:z6MkMgr1"), 3, 5)
            .unwrap();

        // Same manager DID again
        let result = store.add_signature(
            target.clone(),
            make_sig("did:key:z6MkMgr1"), // duplicate
            3,
            5,
        );

        assert!(result.is_err(), "duplicate Manager DID should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("duplicate"),
            "error should mention duplicate: {err}"
        );
    }

    #[test]
    fn test_status_query_without_adding() {
        let store = PendingRevocationStore::default();
        let target = "did:key:z6MkNonexistent".to_string();
        assert!(store.status(&target).is_none(), "no status for unknown target");
    }

    #[test]
    fn test_last_revocation_receipt_set_when_applied() {
        let mut store = PendingRevocationStore::default();
        let target = "did:key:z6MkTarget".to_string();

        // Add enough signatures to reach threshold
        store
            .add_signature(target.clone(), make_sig("did:key:z6MkMgr1"), 1, 1)
            .unwrap();

        let ts = store.last_revocation_receipt_timestamp(&target);
        assert!(
            ts.is_some(),
            "last receipt timestamp should be set after Applied"
        );
        assert!(ts.unwrap() > 0, "timestamp should be positive");
    }

    #[test]
    fn test_build_revocation_delta_before_threshold_returns_none() {
        let mut store = PendingRevocationStore::default();
        let target = "did:key:z6MkTarget".to_string();

        store
            .add_signature(target.clone(), make_sig("did:key:z6MkMgr1"), 3, 5)
            .unwrap();

        assert!(
            store.build_revocation_delta(&target).is_none(),
            "delta should not be available before threshold"
        );
    }

    #[test]
    fn test_build_revocation_delta_at_threshold() {
        let mut store = PendingRevocationStore::default();
        let target = "did:key:z6MkTarget".to_string();

        for i in 1..=2 {
            store
                .add_signature(
                    target.clone(),
                    make_sig(&format!("did:key:z6MkMgr{i}")),
                    2,
                    3,
                )
                .unwrap();
        }

        let delta = store
            .build_revocation_delta(&target)
            .expect("delta should be available at threshold");
        assert_eq!(delta.target_did, target);
        assert_eq!(delta.signatures.len(), 2);
    }

    #[test]
    fn test_1_of_1_warning_emitted() {
        let warning = PendingRevocationStore::check_1_of_1_warning(1, 1);
        assert!(warning.is_some(), "1-of-1 should emit a warning");
        let msg = warning.unwrap();
        assert!(
            msg.contains("unilateral") || msg.contains("WARNING"),
            "warning should mention unilateral power: {msg}"
        );
    }

    #[test]
    fn test_no_warning_for_2_of_3() {
        let warning = PendingRevocationStore::check_1_of_1_warning(2, 3);
        assert!(warning.is_none(), "2-of-3 should not emit a warning");
    }
}
