//! RevocationDelta, M-of-N threshold accumulation, and RevocationSubsystem (Req 9).
//!
//! ## Architecture
//!
//! The revocation flow has two layers:
//!
//! 1. **`PendingRevocationStore`** — accumulates partial `ManagerSignature` contributions
//!    from mesh gossip until M signatures are collected. Verifies each signature against
//!    the signing Manager's DID-derived public key and rejects signing keys that are
//!    themselves REVOKED. This is a pure accumulation layer with no side-effects.
//!
//! 2. **`RevocationSubsystem`** — orchestrates the full workflow: receives incoming
//!    (possibly partial) RevocationDeltas, drives `PendingRevocationStore`, and when M
//!    is reached applies `TrustLevel::Revoked` to the target device and invokes the
//!    `CausalContaminationEngine::tag_contamination_root()` for all Deltas authored
//!    by the revoked DID (Req 10.1).
//!
//! ## Queryable Status (Req 9.5)
//!
//! `RevocationSubsystem::device_status(did)` returns the last-known `TrustLevel` and
//! the UTC timestamp of the last `RevocationDelta` receipt for any target DID. This
//! handles the isolated-device scenario where the Biscuit TTL has not yet expired.
//!
//! ## 30-Second Application Window (Req 9.4)
//!
//! The spec requires that the REVOKED `TrustLevel` is applied within 30 seconds of
//! receipt. In this implementation the application is **synchronous** — it happens
//! in the same `process_incoming_delta()` call that pushes the threshold-completing
//! signature. This satisfies the ≤30s requirement by construction (bounded only by
//! processing latency, not by any timer). A comment in the code explains this.

#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::HashMap;

use crate::api::types::TrustLevel;
use crate::crdt::delta::{Did, DeltaId, Ed25519Signature};
use crate::errors::TirBaseError;
use crate::identity::{did as did_mod, keypair};

// ─── Core data types ──────────────────────────────────────────────────────────

/// A Manager DID signature contribution toward a RevocationDelta.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManagerSignature {
    /// The DID of the Manager who produced this signature.
    pub manager_did: Did,
    /// Ed25519 signature over the canonical revocation payload.
    ///
    /// The signing payload is defined as: `SHA-256("revoke:" || target_did.as_bytes())`
    /// This ensures the signature is unambiguous and cannot be replayed for other targets.
    pub signature: Ed25519Signature,
}

/// A complete Revocation_Delta — produced when M signatures are accumulated (Req 9.1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevocationDelta {
    /// DID of the device being revoked.
    pub target_did: Did,
    /// All M authorising Manager DID signatures.
    pub signatures: Vec<ManagerSignature>,
    /// UTC timestamp (microseconds) when the threshold was reached.
    pub created_at: i64,
}

impl RevocationDelta {
    /// Compute the canonical signing payload for a revocation targeting `target_did`.
    ///
    /// The payload is `SHA-256("revoke:" || target_did.as_bytes())` so that each
    /// Manager signature is unambiguous and replay-resistant.
    pub fn signing_payload(target_did: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"revoke:");
        hasher.update(target_did.as_bytes());
        hasher.finalize().to_vec()
    }
}

// ─── Per-target accumulation state ───────────────────────────────────────────

/// Per-target accumulation state in the `PendingRevocationStore`.
#[derive(Debug, Clone)]
pub struct PendingRevocation {
    pub target_did: Did,
    pub signatures: Vec<ManagerSignature>,
    pub threshold_m: usize,
    pub threshold_n: usize,
    pub initiated_at: i64,
    /// UTC timestamp (microseconds) of the last RevocationDelta receipt.
    pub last_receipt_timestamp: Option<i64>,
}

// ─── RevocationStatus ────────────────────────────────────────────────────────

/// Current accumulation status returned by `add_signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Not yet reached the M threshold.
    Pending {
        collected: usize,
        required: usize,
    },
    /// M signatures collected; Revocation_Delta is ready to apply.
    Applied,
}

// ─── Queryable device status (Req 9.5) ───────────────────────────────────────

/// The queryable revocation status of a device (Req 9.5).
///
/// Exposed to callers so an isolated device can surface its last-known state
/// even when the Biscuit TTL has not yet expired.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceRevocationStatus {
    /// DID of the device.
    pub device_did: Did,
    /// Last known trust level (may be stale if the device is isolated).
    pub last_known_trust_level: TrustLevel,
    /// UTC timestamp (microseconds) of the last RevocationDelta receipt for this device.
    /// `None` if no RevocationDelta has ever been received.
    pub last_revocation_delta_received_at: Option<i64>,
}

// ─── PendingRevocationStore ───────────────────────────────────────────────────

/// Accumulates partial `RevocationDelta` signatures from mesh gossip until M
/// valid, distinct signatures are collected (Req 9.1, 9.3).
///
/// # Signature Verification
///
/// Every `ManagerSignature` is verified against the Manager's DID-derived Ed25519
/// public key before being accepted. Signatures from managers whose keys cannot be
/// resolved are rejected. Signatures from managers whose `TrustLevel` is `Revoked`
/// are rejected (Req 9.4).
#[derive(Debug, Default)]
pub struct PendingRevocationStore {
    pending: HashMap<Did, PendingRevocation>,
}

impl PendingRevocationStore {
    /// Add a Manager signature for the given target DID.
    ///
    /// # Verification
    ///
    /// 1. Resolves the Manager's DID to its Ed25519 public key.
    /// 2. Verifies the signature over `RevocationDelta::signing_payload(target_did)`.
    /// 3. Checks that no prior signature from the same `manager_did` is present.
    ///
    /// Returns `Applied` when M valid, distinct signatures are accumulated; `Pending` otherwise.
    ///
    /// # Parameters
    /// - `revoked_dids`: The set of DIDs currently known to be REVOKED. Any Manager DID
    ///   present in this set is rejected as a signing key (Req 9.4).
    pub fn add_signature(
        &mut self,
        target_did: Did,
        sig: ManagerSignature,
        threshold_m: usize,
        threshold_n: usize,
        revoked_dids: &[Did],
    ) -> Result<RevocationStatus, TirBaseError> {
        // Req 9.4 — reject if the signing Manager's key is itself REVOKED.
        if revoked_dids.contains(&sig.manager_did) {
            return Err(TirBaseError::AuthorisationFailed {
                reason: format!(
                    "manager DID '{}' is REVOKED and cannot contribute revocation signatures",
                    sig.manager_did
                ),
            });
        }

        // Verify the signature against the Manager's DID-resolved public key.
        let payload = RevocationDelta::signing_payload(&target_did);
        let public_key = did_mod::resolve_did(&sig.manager_did)?;
        keypair::verify(&public_key, &payload, &sig.signature)?;

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

        // Update thresholds in case they were updated (use latest provided values).
        entry.threshold_m = threshold_m;
        entry.threshold_n = threshold_n;

        // Reject duplicate Manager DID (Req 9.3).
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

        // Already applied — idempotent.
        if entry.signatures.len() >= threshold_m {
            return Ok(RevocationStatus::Applied);
        }

        entry.signatures.push(sig);

        if entry.signatures.len() >= threshold_m {
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

    /// Queryable status flag: last known timestamp of last RevocationDelta receipt
    /// for the isolated-device scenario (Req 9.5).
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
                "WARNING (Req 9.7): M=1, N=1 revocation configuration grants a single \
                 Manager DID unilateral exile power over any device without requiring \
                 a second approval. Document this as an accepted risk before sealing \
                 the configuration."
                    .to_string(),
            )
        } else {
            None
        }
    }
}

// ─── RevocationSubsystem ─────────────────────────────────────────────────────

/// High-level orchestrator for the full revocation workflow (Req 9, 10.1).
///
/// Wraps `PendingRevocationStore` and applies side-effects when the threshold
/// is reached:
/// 1. Records the device as REVOKED in the device-status map (Req 9.4).
/// 2. Records the timestamp of the application (Req 9.5).
/// 3. Invokes the gossip callback to immediately gossip the complete
///    `RevocationDelta` at HIGH priority (Req 9.2).
/// 4. Invokes the CCE callback to tag all Deltas authored by the revoked DID
///    with `TaintSource::DeviceRevocation` (Req 10.1).
///
/// # 30-Second Application Window (Req 9.4)
///
/// The `process_incoming_delta()` method applies the REVOKED `TrustLevel`
/// synchronously in the same call that collects the threshold-completing
/// signature. This satisfies Req 9.4 by construction — the application latency
/// is bounded by the time to process a single function call, which is orders of
/// magnitude below 30 seconds.
#[cfg(feature = "native")]
pub struct RevocationSubsystem {
    /// Accumulates partial signature contributions.
    store: PendingRevocationStore,
    /// Per-DID device status — last known TrustLevel + last receipt timestamp.
    device_status: HashMap<Did, DeviceRevocationStatus>,
    /// M threshold.
    threshold_m: usize,
    /// N threshold.
    threshold_n: usize,
    /// DIDs that have been applied as REVOKED (for signing-key rejection).
    revoked_dids: Vec<Did>,
    /// SQLite connection — used to query DAG for deltas authored by a revoked DID.
    conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
}

#[cfg(feature = "native")]
impl RevocationSubsystem {
    /// Create a new `RevocationSubsystem`.
    pub fn new(
        threshold_m: usize,
        threshold_n: usize,
        conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
    ) -> Self {
        Self {
            store: PendingRevocationStore::default(),
            device_status: HashMap::new(),
            threshold_m,
            threshold_n,
            revoked_dids: Vec::new(),
            conn,
        }
    }

    /// Process an incoming partial or complete `RevocationDelta` (Req 9.3–9.4).
    ///
    /// For each signature in `delta.signatures`:
    /// 1. Verifies the signature against the Manager's DID-resolved public key.
    /// 2. Checks the signing Manager is not itself REVOKED.
    /// 3. Rejects duplicates (same Manager DID already contributed).
    ///
    /// When M valid distinct signatures are accumulated:
    /// 4. Records the target DID as REVOKED synchronously (≤30s by construction).
    /// 5. Calls `on_revocation_applied(target_did, revocation_delta)` — the caller
    ///    provides this callback to trigger HIGH-priority gossip (Req 9.2).
    /// 6. Calls `on_cce_trigger(target_did)` — the caller provides this callback
    ///    to invoke `CausalContaminationEngine::tag_contamination_root()` for all
    ///    Deltas authored by the revoked DID (Req 10.1).
    ///
    /// Returns `Ok(RevocationStatus)`:
    /// - `Pending` if threshold not yet met.
    /// - `Applied` if threshold met (whether just now or previously).
    ///
    /// Returns `Err` if any signature check fails (Req 9.3, 9.4).
    pub fn process_incoming_delta(
        &mut self,
        delta: &RevocationDelta,
        on_revocation_applied: &mut dyn FnMut(&Did, &RevocationDelta),
        on_cce_trigger: &mut dyn FnMut(&Did, Vec<DeltaId>),
    ) -> Result<RevocationStatus, TirBaseError> {
        // Validate: target_did must be non-empty (Req 9.4).
        if delta.target_did.is_empty() {
            return Err(TirBaseError::DeltaMalformed {
                reason: "RevocationDelta.target_did is empty".to_string(),
            });
        }

        // Validate: must have at least one signature.
        if delta.signatures.is_empty() {
            return Err(TirBaseError::ThresholdNotMet {
                got: 0,
                need: self.threshold_m,
            });
        }

        let mut last_status = None;

        for sig in &delta.signatures {
            match self.store.add_signature(
                delta.target_did.clone(),
                sig.clone(),
                self.threshold_m,
                self.threshold_n,
                &self.revoked_dids,
            ) {
                Ok(status) => {
                    last_status = Some(status);
                }
                Err(TirBaseError::AuthorisationFailed { reason }) => {
                    // Log and continue — other signatures in the delta may be valid.
                    // A single bad signature does not invalidate the whole delta.
                    log_revocation_failure(&delta.target_did, &reason);
                }
                Err(e) => {
                    // DID resolution or crypto failure — log and continue.
                    log_revocation_failure(&delta.target_did, &e.to_string());
                }
            }
        }

        // If we have never seen any signature yet, threshold not met.
        let current_status = last_status
            .or_else(|| self.store.status(&delta.target_did))
            .ok_or_else(|| TirBaseError::ThresholdNotMet {
                got: 0,
                need: self.threshold_m,
            })?;

        if current_status == RevocationStatus::Applied {
            // Only trigger side effects once (idempotent).
            if !self.revoked_dids.contains(&delta.target_did) {
                let now = current_timestamp_micros();

                // 1. Record REVOKED status (Req 9.4) — applied synchronously, ≤30s by construction.
                self.revoked_dids.push(delta.target_did.clone());
                let complete_delta = self
                    .store
                    .build_revocation_delta(&delta.target_did)
                    .unwrap_or_else(|| delta.clone());

                self.device_status.insert(
                    delta.target_did.clone(),
                    DeviceRevocationStatus {
                        device_did: delta.target_did.clone(),
                        last_known_trust_level: TrustLevel::Revoked,
                        last_revocation_delta_received_at: Some(now),
                    },
                );

                // 2. Query DAG for all Delta IDs authored by the revoked DID.
                let authored_delta_ids =
                    self.query_deltas_by_author(&delta.target_did).unwrap_or_default();

                // 3. Gossip callback — HIGH priority (Req 9.2).
                on_revocation_applied(&delta.target_did, &complete_delta);

                // 4. CCE trigger — tag all authored Deltas (Req 10.1).
                if !authored_delta_ids.is_empty() {
                    on_cce_trigger(&delta.target_did, authored_delta_ids);
                }
            }
        }

        Ok(current_status)
    }

    /// Validate a received `RevocationDelta` for incoming verification without
    /// applying side effects (Req 9.3–9.4 verification logic only).
    ///
    /// Returns `Ok(())` if:
    /// - target_did is present
    /// - at least M valid, distinct, non-REVOKED Manager signatures are present
    ///
    /// Returns `Err(ThresholdNotMet)` if fewer than M valid sigs present.
    pub fn validate_revocation_delta(
        &self,
        delta: &RevocationDelta,
    ) -> Result<(), TirBaseError> {
        if delta.target_did.is_empty() {
            return Err(TirBaseError::DeltaMalformed {
                reason: "RevocationDelta.target_did is empty".to_string(),
            });
        }

        let payload = RevocationDelta::signing_payload(&delta.target_did);
        let mut valid_count = 0usize;
        let mut seen_dids: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for sig in &delta.signatures {
            // Reject REVOKED signing keys.
            if self.revoked_dids.contains(&sig.manager_did) {
                continue;
            }

            // Skip duplicates.
            if !seen_dids.insert(sig.manager_did.as_str()) {
                continue;
            }

            // Verify signature.
            let Ok(public_key) = did_mod::resolve_did(&sig.manager_did) else {
                continue;
            };
            if keypair::verify(&public_key, &payload, &sig.signature).is_ok() {
                valid_count += 1;
            }
        }

        if valid_count >= self.threshold_m {
            Ok(())
        } else {
            Err(TirBaseError::ThresholdNotMet {
                got: valid_count,
                need: self.threshold_m,
            })
        }
    }

    /// Produce a new partial `RevocationDelta` signed by the given Manager (Req 9.1).
    ///
    /// The caller provides the Manager's signing key bytes. The returned delta
    /// carries a single `ManagerSignature` and should be gossiped at HIGH priority
    /// so that peer devices can accumulate further signatures.
    pub fn produce_partial_delta(
        &self,
        target_did: Did,
        manager_did: Did,
        manager_signing_key: &[u8; 32],
    ) -> Result<RevocationDelta, TirBaseError> {
        let payload = RevocationDelta::signing_payload(&target_did);
        let sig = keypair::sign(manager_signing_key, &payload)?;
        Ok(RevocationDelta {
            target_did,
            signatures: vec![ManagerSignature {
                manager_did,
                signature: sig,
            }],
            created_at: current_timestamp_micros(),
        })
    }

    /// Queryable device status: last known TrustLevel + last RevocationDelta receipt
    /// timestamp for the isolated-device scenario (Req 9.5).
    ///
    /// Returns `None` if no RevocationDelta has ever been received for this DID.
    pub fn device_status(&self, device_did: &str) -> Option<&DeviceRevocationStatus> {
        self.device_status.get(device_did)
    }

    /// Return all DIDs currently known to be REVOKED.
    pub fn revoked_dids(&self) -> &[Did] {
        &self.revoked_dids
    }

    /// Return the M threshold.
    pub fn threshold_m(&self) -> usize {
        self.threshold_m
    }

    /// Check the accumulation state for a target DID (delegates to the inner store).
    pub fn store_status(&self, target_did: &Did) -> Option<RevocationStatus> {
        self.store.status(target_did)
    }

    /// Emit a 1-of-1 revocation warning if applicable (Req 9.7).
    pub fn check_1_of_1_warning(&self) -> Option<String> {
        PendingRevocationStore::check_1_of_1_warning(self.threshold_m, self.threshold_n)
    }

    /// Return all complete RevocationDeltas that were received/applied within
    /// `within_micros` microseconds ago. Used to re-announce to newly discovered peers (Req 9.2).
    pub fn build_recent_revocation_deltas(&self, within_micros: i64) -> Vec<RevocationDelta> {
        let cutoff = current_timestamp_micros() - within_micros;
        self.revoked_dids
            .iter()
            .filter(|did| {
                self.device_status
                    .get(*did)
                    .and_then(|s| s.last_revocation_delta_received_at)
                    .map(|ts| ts >= cutoff)
                    .unwrap_or(false)
            })
            .filter_map(|did| self.store.build_revocation_delta(did))
            .collect()
    }

    /// Query the DAG for all Delta IDs authored by a given DID.
    ///
    /// This is used to collect the initial set of root Deltas to pass to the CCE
    /// when a device is revoked (Req 10.1).
    fn query_deltas_by_author(&self, author_did: &Did) -> Result<Vec<DeltaId>, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("RevocationSubsystem mutex poisoned: {e}"),
        })?;

        let mut stmt = conn
            .prepare("SELECT id FROM dag_nodes WHERE author_did = ?1;")
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Prepare query_deltas_by_author failed: {e}"),
            })?;

        let ids: Vec<DeltaId> = stmt
            .query_map(rusqlite::params![author_did], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Query dag_nodes by author failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .filter_map(|bytes: Vec<u8>| bytes.try_into().ok())
            .collect();

        Ok(ids)
    }
}

// ─── WASM stub ────────────────────────────────────────────────────────────────

/// WASM-target RevocationSubsystem — full M-of-N threshold logic using the shared
/// PendingRevocationStore; no SQLite connection required.
#[cfg(not(feature = "native"))]
pub struct RevocationSubsystem {
    store: PendingRevocationStore,
    device_status: HashMap<Did, DeviceRevocationStatus>,
    threshold_m: usize,
    threshold_n: usize,
    revoked_dids: Vec<Did>,
    /// Delta IDs authored per DID — the WASM analogue of the native DAG query
    /// (`query_deltas_by_author` over `dag_nodes`).
    ///
    /// Populated by [`Self::record_authored_delta`] from the two WASM paths
    /// that prove authorship: `CoreHandle::write` (the local device produced a
    /// signed Delta) and `CoreHandle::receive_inbound_wasm` (a peer Delta
    /// passed signature verification and merged).  The CCE trigger for a
    /// revoked DID (Req 10.1) is fed from this index instead of an empty list.
    authored_deltas: HashMap<Did, std::collections::HashSet<DeltaId>>,
}

#[cfg(not(feature = "native"))]
impl RevocationSubsystem {
    pub fn new(threshold_m: usize, threshold_n: usize) -> Self {
        Self {
            store: PendingRevocationStore::default(),
            device_status: HashMap::new(),
            threshold_m,
            threshold_n,
            revoked_dids: Vec::new(),
            authored_deltas: HashMap::new(),
        }
    }

    /// Record that `delta_id` was authored by `author_did` (WASM only).
    ///
    /// Idempotent.  Called by the production WASM paths that establish
    /// authorship — [`crate::api::CoreHandle::write`] for locally produced
    /// Deltas and [`crate::api::CoreHandle::receive_inbound_wasm`] for
    /// signature-verified inbound Deltas that merged.  The CCE trigger for a
    /// revoked DID reads this index ([`Self::authored_delta_ids`]), mirroring
    /// the native `query_deltas_by_author` DAG query.
    pub(crate) fn record_authored_delta(&mut self, author_did: Did, delta_id: DeltaId) {
        self.authored_deltas
            .entry(author_did)
            .or_default()
            .insert(delta_id);
    }

    /// Delta IDs authored by `did` that this WASM device has seen (locally
    /// produced or signature-verified inbound), in arbitrary order.
    pub(crate) fn authored_delta_ids(&self, did: &Did) -> Vec<DeltaId> {
        self.authored_deltas
            .get(did)
            .map(|ids| ids.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn process_incoming_delta(
        &mut self,
        delta: &RevocationDelta,
        on_revocation_applied: &mut dyn FnMut(&Did, &RevocationDelta),
        on_cce_trigger: &mut dyn FnMut(&Did, Vec<DeltaId>),
    ) -> Result<RevocationStatus, TirBaseError> {
        if delta.target_did.is_empty() {
            return Err(TirBaseError::DeltaMalformed {
                reason: "RevocationDelta.target_did is empty".to_string(),
            });
        }
        if delta.signatures.is_empty() {
            return Err(TirBaseError::ThresholdNotMet {
                got: 0,
                need: self.threshold_m,
            });
        }

        let mut last_status = None;
        for sig in &delta.signatures {
            match self.store.add_signature(
                delta.target_did.clone(),
                sig.clone(),
                self.threshold_m,
                self.threshold_n,
                &self.revoked_dids,
            ) {
                Ok(status) => { last_status = Some(status); }
                Err(TirBaseError::AuthorisationFailed { reason }) => {
                    log_revocation_failure(&delta.target_did, &reason);
                }
                Err(e) => {
                    log_revocation_failure(&delta.target_did, &e.to_string());
                }
            }
        }

        let current_status = last_status
            .or_else(|| self.store.status(&delta.target_did))
            .ok_or_else(|| TirBaseError::ThresholdNotMet {
                got: 0,
                need: self.threshold_m,
            })?;

        if current_status == RevocationStatus::Applied
            && !self.revoked_dids.contains(&delta.target_did)
        {
            let now = current_timestamp_micros();
            self.revoked_dids.push(delta.target_did.clone());
            let complete_delta = self
                .store
                .build_revocation_delta(&delta.target_did)
                .unwrap_or_else(|| delta.clone());

            self.device_status.insert(
                delta.target_did.clone(),
                DeviceRevocationStatus {
                    device_did: delta.target_did.clone(),
                    last_known_trust_level: crate::api::types::TrustLevel::Revoked,
                    last_revocation_delta_received_at: Some(now),
                },
            );

            // Push TrustLevelChanged event (WASM target only).
            #[cfg(feature = "wasm")]
            crate::push_wasm_event(crate::WasmEvent::TrustLevelChanged {
                previous: "Verified".to_string(),
                new: "Revoked".to_string(),
            });

            on_revocation_applied(&delta.target_did, &complete_delta);

            // Req 10.1 — CCE-tag every Delta authored by the revoked DID, fed
            // from the per-author index maintained by
            // `record_authored_delta` (the WASM analogue of the native
            // `query_deltas_by_author` DAG query).  Subphase 6.3: the trigger
            // receives the ACTUAL authored Delta IDs instead of an empty list,
            // so the revoked device's own writes are tagged on WASM too.
            let authored_delta_ids = self.authored_delta_ids(&delta.target_did);
            if !authored_delta_ids.is_empty() {
                on_cce_trigger(&delta.target_did, authored_delta_ids);
            }
        }

        Ok(current_status)
    }

    pub fn validate_revocation_delta(
        &self,
        delta: &RevocationDelta,
    ) -> Result<(), TirBaseError> {
        if delta.target_did.is_empty() {
            return Err(TirBaseError::DeltaMalformed {
                reason: "RevocationDelta.target_did is empty".to_string(),
            });
        }

        let payload = RevocationDelta::signing_payload(&delta.target_did);
        let mut valid_count = 0usize;
        let mut seen_dids: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for sig in &delta.signatures {
            if self.revoked_dids.contains(&sig.manager_did) {
                continue;
            }
            if !seen_dids.insert(sig.manager_did.as_str()) {
                continue;
            }
            let Ok(public_key) = did_mod::resolve_did(&sig.manager_did) else {
                continue;
            };
            if keypair::verify(&public_key, &payload, &sig.signature).is_ok() {
                valid_count += 1;
            }
        }

        if valid_count >= self.threshold_m {
            Ok(())
        } else {
            Err(TirBaseError::ThresholdNotMet {
                got: valid_count,
                need: self.threshold_m,
            })
        }
    }

    pub fn produce_partial_delta(
        &self,
        target_did: Did,
        manager_did: Did,
        manager_signing_key: &[u8; 32],
    ) -> Result<RevocationDelta, TirBaseError> {
        let payload = RevocationDelta::signing_payload(&target_did);
        let sig = keypair::sign(manager_signing_key, &payload)?;
        Ok(RevocationDelta {
            target_did,
            signatures: vec![ManagerSignature {
                manager_did,
                signature: sig,
            }],
            created_at: current_timestamp_micros(),
        })
    }

    pub fn device_status(&self, device_did: &str) -> Option<&DeviceRevocationStatus> {
        self.device_status.get(device_did)
    }

    pub fn revoked_dids(&self) -> &[Did] {
        &self.revoked_dids
    }

    /// Return the M threshold.
    pub fn threshold_m(&self) -> usize {
        self.threshold_m
    }

    /// Check the accumulation state for a target DID (delegates to the inner store).
    pub fn store_status(&self, target_did: &Did) -> Option<RevocationStatus> {
        self.store.status(target_did)
    }

    pub fn check_1_of_1_warning(&self) -> Option<String> {
        PendingRevocationStore::check_1_of_1_warning(self.threshold_m, self.threshold_n)
    }

    /// Return all complete RevocationDeltas that were received/applied within
    /// `within_micros` microseconds ago. Used to re-announce to newly discovered peers (Req 9.2).
    pub fn build_recent_revocation_deltas(&self, within_micros: i64) -> Vec<RevocationDelta> {
        let cutoff = current_timestamp_micros() - within_micros;
        self.revoked_dids
            .iter()
            .filter(|did| {
                self.device_status
                    .get(*did)
                    .and_then(|s| s.last_revocation_delta_received_at)
                    .map(|ts| ts >= cutoff)
                    .unwrap_or(false)
            })
            .filter_map(|did| self.store.build_revocation_delta(did))
            .collect()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Returns a wall-clock timestamp in microseconds.
pub fn current_timestamp_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

/// Log a revocation verification failure (structured record, Req 9.4).
fn log_revocation_failure(target_did: &str, reason: &str) {
    // In a production build this would write to the structured diagnostic log.
    // For v1 we use eprintln so the record is always visible without a log subscriber.
    eprintln!(
        "[RevocationSubsystem] verification failure for target='{}': {}",
        target_did, reason
    );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::identity::IdentityManager;
    use crate::store::sqlite;

    // ─── Test helpers ────────────────────────────────────────────────────────

    fn open_conn() -> std::sync::Arc<std::sync::Mutex<rusqlite::Connection>> {
        let conn = sqlite::open(":memory:").expect("open in-memory SQLite");
        std::sync::Arc::new(std::sync::Mutex::new(conn))
    }

    fn make_subsystem(m: usize, n: usize) -> RevocationSubsystem {
        RevocationSubsystem::new(m, n, open_conn())
    }

    /// Make a Manager identity and return (RevocationSubsystem helper) + manager DID + signing key.
    fn make_manager() -> (String, [u8; 32]) {
        let mgr = IdentityManager::init_in_memory().unwrap();
        let sk = mgr.signing_key_bytes();
        (mgr.did().to_string(), sk)
    }

    /// Build a partial delta signed by a single manager.
    fn partial_delta(
        sys: &RevocationSubsystem,
        target_did: &str,
        manager_did: &str,
        manager_sk: &[u8; 32],
    ) -> RevocationDelta {
        sys.produce_partial_delta(
            target_did.to_string(),
            manager_did.to_string(),
            manager_sk,
        )
        .expect("produce_partial_delta should succeed")
    }

    /// No-op callbacks for testing (we verify effects via device_status).
    fn noop_gossip(_target: &Did, _delta: &RevocationDelta) {}
    fn noop_cce(_target: &Did, _delta_ids: Vec<DeltaId>) {}

    // ─── Test 1: Below threshold → Pending ───────────────────────────────────

    #[test]
    fn test_below_threshold_returns_pending() {
        let mut sys = make_subsystem(3, 5);
        let target = "did:key:z6MkTarget111111111111111111111111111".to_string();

        let (mgr1_did, mgr1_sk) = make_manager();
        let delta = partial_delta(&sys, &target, &mgr1_did, &mgr1_sk);

        let status = sys
            .process_incoming_delta(&delta, &mut noop_gossip, &mut noop_cce)
            .expect("process_incoming_delta should not fail with 1/3 sigs");

        assert!(
            matches!(status, RevocationStatus::Pending { collected: 1, required: 3 }),
            "expected Pending(1/3), got: {status:?}"
        );
    }

    // ─── Test 2: Exactly at threshold → Applied ───────────────────────────────

    #[test]
    fn test_at_threshold_returns_applied() {
        let mut sys = make_subsystem(2, 3);
        let target = "did:key:z6MkTarget222222222222222222222222222".to_string();

        let (mgr1_did, mgr1_sk) = make_manager();
        let (mgr2_did, mgr2_sk) = make_manager();

        let d1 = partial_delta(&sys, &target, &mgr1_did, &mgr1_sk);
        let d2 = partial_delta(&sys, &target, &mgr2_did, &mgr2_sk);

        // Merge both sigs into a combined delta (as mesh would do).
        let combined = RevocationDelta {
            target_did: target.clone(),
            signatures: [d1.signatures, d2.signatures].concat(),
            created_at: current_timestamp_micros(),
        };

        let status = sys
            .process_incoming_delta(&combined, &mut noop_gossip, &mut noop_cce)
            .expect("process_incoming_delta should succeed at threshold");

        assert_eq!(status, RevocationStatus::Applied, "expected Applied at M=2");

        // Device must now be in the REVOKED map.
        let device_st = sys.device_status(&target).expect("device status must exist");
        assert_eq!(device_st.last_known_trust_level, TrustLevel::Revoked);
        assert!(device_st.last_revocation_delta_received_at.is_some());
    }

    // ─── Test 3: M-1 sigs rejected (threshold not met) ────────────────────────

    #[test]
    fn test_m_minus_1_sigs_returns_pending() {
        let m = 3usize;
        let mut sys = make_subsystem(m, 5);
        let target = "did:key:z6MkTarget333333333333333333333333333".to_string();

        let managers: Vec<(String, [u8; 32])> = (0..m - 1).map(|_| make_manager()).collect();

        let mut sigs = Vec::new();
        for (did, sk) in &managers {
            let d = partial_delta(&sys, &target, did, sk);
            sigs.extend(d.signatures);
        }

        let combined = RevocationDelta {
            target_did: target.clone(),
            signatures: sigs,
            created_at: current_timestamp_micros(),
        };

        let status = sys
            .process_incoming_delta(&combined, &mut noop_gossip, &mut noop_cce)
            .expect("should not error with M-1 sigs");

        assert!(
            matches!(status, RevocationStatus::Pending { .. }),
            "expected Pending with M-1 sigs, got: {status:?}"
        );
        // Device must NOT be revoked.
        assert!(
            sys.device_status(&target).is_none()
                || sys.device_status(&target).unwrap().last_known_trust_level != TrustLevel::Revoked,
            "target must not be REVOKED with M-1 sigs"
        );
    }

    // ─── Test 4: 1-of-1 configuration ─────────────────────────────────────────

    #[test]
    fn test_1_of_1_revocation_applied() {
        let mut sys = make_subsystem(1, 1);
        let target = "did:key:z6MkTarget444444444444444444444444444".to_string();

        let (mgr_did, mgr_sk) = make_manager();
        let delta = partial_delta(&sys, &target, &mgr_did, &mgr_sk);

        let mut gossip_called = false;
        let mut cce_called = false;

        let status = sys
            .process_incoming_delta(
                &delta,
                &mut |_did, _d| { gossip_called = true; },
                &mut |_did, _ids| { cce_called = true; },
            )
            .expect("1-of-1 revocation should succeed");

        assert_eq!(status, RevocationStatus::Applied);
        assert!(gossip_called, "gossip callback must be invoked");
        // CCE not called because no DAG nodes exist for the target in this test.
        let device_st = sys.device_status(&target).unwrap();
        assert_eq!(device_st.last_known_trust_level, TrustLevel::Revoked);
    }

    // ─── Test 5: 1-of-1 warning ────────────────────────────────────────────────

    #[test]
    fn test_1_of_1_warning_emitted() {
        let sys = make_subsystem(1, 1);
        let warning = sys.check_1_of_1_warning();
        assert!(warning.is_some(), "1-of-1 should emit a warning");
        let msg = warning.unwrap();
        assert!(
            msg.contains("unilateral") || msg.contains("WARNING"),
            "warning should mention unilateral power: {msg}"
        );
    }

    #[test]
    fn test_no_1_of_1_warning_for_2_of_3() {
        let sys = make_subsystem(2, 3);
        assert!(sys.check_1_of_1_warning().is_none());
    }

    // ─── Test 6: Signing-key-is-REVOKED rejection ─────────────────────────────

    #[test]
    fn test_revoked_signing_key_rejected() {
        let mut sys = make_subsystem(1, 2);
        let target = "did:key:z6MkTarget555555555555555555555555555".to_string();

        // First revoke manager A.
        let (mgr_a_did, mgr_a_sk) = make_manager();
        let delta_a = partial_delta(&sys, &mgr_a_did, &mgr_a_did, &mgr_a_sk);
        // This revokes mgr_a_did (i.e., mgr_a becomes revoked by itself — unusual but tests the guard)
        let _ = sys.process_incoming_delta(&delta_a, &mut noop_gossip, &mut noop_cce);
        // mgr_a_did is now in revoked_dids.

        // Now mgr_a tries to contribute a signature toward revoking a different target.
        let (target_did2, _) = make_manager();
        let payload = RevocationDelta::signing_payload(&target_did2);
        let sig = keypair::sign(&mgr_a_sk, &payload).expect("sign");
        let bad_delta = RevocationDelta {
            target_did: target_did2.clone(),
            signatures: vec![ManagerSignature {
                manager_did: mgr_a_did.clone(),
                signature: sig,
            }],
            created_at: current_timestamp_micros(),
        };

        // The revoked manager's signature must be silently skipped (not crash).
        // process_incoming_delta should return ThresholdNotMet because no valid sig got through.
        let result = sys.process_incoming_delta(&bad_delta, &mut noop_gossip, &mut noop_cce);
        // The revoked sig is filtered out; we have 0 valid sigs vs threshold_m=1 → ThresholdNotMet.
        assert!(
            matches!(result, Err(TirBaseError::ThresholdNotMet { got: 0, .. })),
            "revoked signing key should yield ThresholdNotMet, got: {result:?}"
        );
    }

    // ─── Test 7: Tampered signature rejected ──────────────────────────────────

    #[test]
    fn test_tampered_manager_signature_rejected() {
        let mut sys = make_subsystem(1, 1);
        let target = "did:key:z6MkTarget666666666666666666666666666".to_string();

        let (mgr_did, mgr_sk) = make_manager();
        let mut delta = partial_delta(&sys, &target, &mgr_did, &mgr_sk);

        // Flip the first byte of the signature.
        if let Some(first) = delta.signatures[0].signature.0.first_mut() {
            *first ^= 0xFF;
        }

        let result = sys.process_incoming_delta(&delta, &mut noop_gossip, &mut noop_cce);
        // Tampered sig fails crypto verification — threshold not met.
        assert!(
            matches!(result, Err(TirBaseError::ThresholdNotMet { got: 0, .. })),
            "tampered signature must not count toward threshold, got: {result:?}"
        );
    }

    // ─── Test 8: Duplicate Manager DID rejected ───────────────────────────────

    #[test]
    fn test_duplicate_manager_did_not_double_counted() {
        let mut sys = make_subsystem(2, 3);
        let target = "did:key:z6MkTarget777777777777777777777777777".to_string();

        let (mgr_did, mgr_sk) = make_manager();
        let d1 = partial_delta(&sys, &target, &mgr_did, &mgr_sk);
        let d2 = partial_delta(&sys, &target, &mgr_did, &mgr_sk); // same manager

        let combined = RevocationDelta {
            target_did: target.clone(),
            signatures: [d1.signatures, d2.signatures].concat(),
            created_at: current_timestamp_micros(),
        };

        let status = sys
            .process_incoming_delta(&combined, &mut noop_gossip, &mut noop_cce)
            .expect("process should not hard-fail on duplicate");

        // Should still be Pending because only 1 unique manager contributed.
        assert!(
            matches!(status, RevocationStatus::Pending { collected: 1, .. }),
            "duplicate manager should not count twice, got: {status:?}"
        );
    }

    // ─── Test 9: validate_revocation_delta ────────────────────────────────────

    #[test]
    fn test_validate_revocation_delta_pass() {
        let sys = make_subsystem(2, 3);
        let target = "did:key:z6MkTarget888888888888888888888888888".to_string();

        let (mgr1_did, mgr1_sk) = make_manager();
        let (mgr2_did, mgr2_sk) = make_manager();

        let d1 = partial_delta(&sys, &target, &mgr1_did, &mgr1_sk);
        let d2 = partial_delta(&sys, &target, &mgr2_did, &mgr2_sk);

        let combined = RevocationDelta {
            target_did: target.clone(),
            signatures: [d1.signatures, d2.signatures].concat(),
            created_at: current_timestamp_micros(),
        };

        sys.validate_revocation_delta(&combined)
            .expect("validation should pass with M valid sigs");
    }

    #[test]
    fn test_validate_revocation_delta_fail_insufficient_sigs() {
        let sys = make_subsystem(2, 3);
        let target = "did:key:z6MkTarget999999999999999999999999999".to_string();

        let (mgr1_did, mgr1_sk) = make_manager();
        let d1 = partial_delta(&sys, &target, &mgr1_did, &mgr1_sk);

        let result = sys.validate_revocation_delta(&d1);
        assert!(
            matches!(result, Err(TirBaseError::ThresholdNotMet { got: 1, need: 2 })),
            "should fail with 1/2 sigs, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_revocation_delta_empty_target_fails() {
        let sys = make_subsystem(1, 1);
        let delta = RevocationDelta {
            target_did: "".to_string(),
            signatures: vec![],
            created_at: 0,
        };
        let result = sys.validate_revocation_delta(&delta);
        assert!(
            matches!(result, Err(TirBaseError::DeltaMalformed { .. })),
            "empty target_did must return DeltaMalformed"
        );
    }

    // ─── Test 10: device_status returns None before any receipt ───────────────

    #[test]
    fn test_device_status_none_before_receipt() {
        let sys = make_subsystem(2, 3);
        let unknown = "did:key:z6MkUnknown".to_string();
        assert!(
            sys.device_status(&unknown).is_none(),
            "no status before any RevocationDelta received"
        );
    }

    // ─── Test 11: Idempotent — second identical delta doesn't retrigger ────────

    #[test]
    fn test_applied_delta_idempotent() {
        let mut sys = make_subsystem(1, 1);
        let target = "did:key:z6MkTargetAAA".to_string();

        let (mgr_did, mgr_sk) = make_manager();
        let delta = partial_delta(&sys, &target, &mgr_did, &mgr_sk);

        let mut gossip_count = 0usize;
        let mut cce_count = 0usize;

        sys.process_incoming_delta(
            &delta,
            &mut |_, _| { gossip_count += 1; },
            &mut |_, _| { cce_count += 1; },
        )
        .unwrap();

        // Replay the same delta.
        let _ = sys.process_incoming_delta(
            &delta,
            &mut |_, _| { gossip_count += 1; },
            &mut |_, _| { cce_count += 1; },
        );

        // Gossip must only be called once.
        assert_eq!(gossip_count, 1, "gossip must only trigger once");
    }

    // ─── Test 12: CCE trigger callback receives authored delta IDs ────────────

    #[test]
    fn test_cce_trigger_receives_authored_delta_ids() {
        let conn = open_conn();

        // Pre-insert some dag_nodes authored by our target.
        {
            let lock = conn.lock().unwrap();
            lock.execute(
                "INSERT OR IGNORE INTO dag_nodes \
                 (id, payload, lamport, schema_hash, compacted, author_did, tags_json) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![
                    [0x01u8; 32].as_ref(),
                    b"payload1".as_ref(),
                    1i64,
                    [0u8; 32].as_ref(),
                    0i64,
                    "did:key:z6MkVictim",
                    "[]"
                ],
            )
            .expect("insert dag_node");

            lock.execute(
                "INSERT OR IGNORE INTO dag_nodes \
                 (id, payload, lamport, schema_hash, compacted, author_did, tags_json) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![
                    [0x02u8; 32].as_ref(),
                    b"payload2".as_ref(),
                    2i64,
                    [0u8; 32].as_ref(),
                    0i64,
                    "did:key:z6MkVictim",
                    "[]"
                ],
            )
            .expect("insert dag_node 2");
        }

        let mut sys = RevocationSubsystem::new(1, 1, conn);

        let (mgr_did, mgr_sk) = make_manager();
        let target = "did:key:z6MkVictim".to_string();
        let delta = sys
            .produce_partial_delta(target.clone(), mgr_did.clone(), &mgr_sk)
            .unwrap();

        let mut cce_ids: Vec<DeltaId> = Vec::new();
        sys.process_incoming_delta(
            &delta,
            &mut noop_gossip,
            &mut |_did, ids| { cce_ids = ids; },
        )
        .unwrap();

        assert_eq!(cce_ids.len(), 2, "CCE must receive both authored Delta IDs");
        assert!(cce_ids.contains(&[0x01u8; 32]));
        assert!(cce_ids.contains(&[0x02u8; 32]));
    }

    // ─── Test 13: PendingRevocationStore — low-level unit tests ──────────────

    #[test]
    fn test_store_add_signature_verified_and_counted() {
        let mut store = PendingRevocationStore::default();
        let (mgr_did, mgr_sk) = make_manager();
        let target = "did:key:z6MkStoreTgt".to_string();

        let payload = RevocationDelta::signing_payload(&target);
        let sig = keypair::sign(&mgr_sk, &payload).expect("sign");
        let ms = ManagerSignature { manager_did: mgr_did.clone(), signature: sig };

        let status = store.add_signature(target.clone(), ms, 2, 3, &[])
            .expect("should accept valid signature");

        assert!(
            matches!(status, RevocationStatus::Pending { collected: 1, required: 2 }),
            "got: {status:?}"
        );
    }

    #[test]
    fn test_store_rejects_revoked_signing_key() {
        let mut store = PendingRevocationStore::default();
        let (mgr_did, mgr_sk) = make_manager();
        let target = "did:key:z6MkStoreTgt2".to_string();

        let payload = RevocationDelta::signing_payload(&target);
        let sig = keypair::sign(&mgr_sk, &payload).unwrap();
        let ms = ManagerSignature { manager_did: mgr_did.clone(), signature: sig };

        // Mark mgr_did as revoked.
        let revoked = vec![mgr_did.clone()];
        let result = store.add_signature(target.clone(), ms, 1, 1, &revoked);

        assert!(
            matches!(result, Err(TirBaseError::AuthorisationFailed { .. })),
            "revoked signing key should be rejected: {result:?}"
        );
    }

    #[test]
    fn test_store_rejects_bad_signature() {
        let mut store = PendingRevocationStore::default();
        let (mgr_did, _mgr_sk) = make_manager();
        let target = "did:key:z6MkStoreTgt3".to_string();

        // Produce a signature over the WRONG payload.
        let (_, other_sk) = make_manager();
        let wrong_payload = b"not a revocation payload";
        let bad_sig = keypair::sign(&other_sk, wrong_payload).unwrap();
        let ms = ManagerSignature { manager_did: mgr_did.clone(), signature: bad_sig };

        let result = store.add_signature(target.clone(), ms, 1, 1, &[]);
        assert!(
            result.is_err(),
            "signature over wrong payload should be rejected"
        );
    }

    // ─── Test 14: Produce and verify full round-trip ──────────────────────────

    #[test]
    fn test_produce_partial_delta_verifies_cleanly() {
        let sys = make_subsystem(1, 1);
        let (mgr_did, mgr_sk) = make_manager();
        let target = "did:key:z6MkRoundTrip".to_string();

        let delta = sys
            .produce_partial_delta(target.clone(), mgr_did.clone(), &mgr_sk)
            .expect("produce_partial_delta should succeed");

        assert_eq!(delta.target_did, target);
        assert_eq!(delta.signatures.len(), 1);
        assert_eq!(delta.signatures[0].manager_did, mgr_did);

        // Validate it passes the verification gate.
        sys.validate_revocation_delta(&delta)
            .expect("produced delta should validate cleanly");
    }
}

// ─── No-std / non-native tests ────────────────────────────────────────────────

#[cfg(all(test, not(feature = "native")))]
mod non_native_tests {
    use super::*;

    #[test]
    fn test_1_of_1_warning_pure() {
        let warning = PendingRevocationStore::check_1_of_1_warning(1, 1);
        assert!(warning.is_some());
    }

    #[test]
    fn test_no_warning_2_of_3_pure() {
        let warning = PendingRevocationStore::check_1_of_1_warning(2, 3);
        assert!(warning.is_none());
    }
}
