//! Durability Subsystem — two-tier durability, quorum formation, spatial diversity (Req 14–16).
//!
//! # Tier-1 Durability (Req 14.1–14.3)
//!
//! Achieved when K peers return signed `DurabilityReceipt`s for the same state-hash,
//! spanning the required spatial diversity (distinct squad/tunnel_sector tags with no
//! single sector exceeding the configured maximum fraction).
//!
//! # Tier-2 Durability (Req 14.4, 14.7)
//!
//! Achieved when the Cloud Ledger acknowledges the Delta set within a configured timeout.
//!
//! # Tier-1 + Queue Rule (Req 14.8)
//!
//! Tier-1 durability permits compaction of a Delta from the hot read path, but the
//! Delta MUST remain in the cloud outbound queue until Tier-2 is confirmed.
//!
//! # Cloud Outbound Queue (Req 16.6–16.8)
//!
//! Capped at 100,000 Deltas. On overflow, `CloudQueueFull` is returned. Rejected
//! Deltas are retained for retry. Compacted Deltas are re-fetched from receipt-holding
//! peers before cloud sync.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod anchor;
pub mod cloud_ledger;
pub mod cloud_queue;
pub mod quorum;
pub mod receipt;
pub mod spatial;

#[cfg(test)]
mod integration_tests;

use crate::api::types::DurabilityTier;
use crate::crdt::delta::{DeltaId, Did};
use crate::errors::TirBaseError;
use cloud_queue::{CloudOutboundQueue, QueueEntry};
use quorum::{QuorumConfig, Tier1QuorumTracker};
use receipt::{verify_receipt, DurabilityReceipt};
use std::collections::HashMap;

// ─── Tier record ──────────────────────────────────────────────────────────────

/// Per-Delta durability state tracked by the subsystem.
#[derive(Debug, Clone)]
struct DeltaDurabilityState {
    /// The expected state-hash that receipts must match for this Delta.
    state_hash: [u8; 32],
    /// Current durability tier.
    tier: DurabilityTier,
    /// Ed25519 public keys of known peers, keyed by DID.
    /// Used to verify incoming receipt signatures (Req 14.6).
    peer_public_keys: HashMap<Did, [u8; 32]>,
    /// Tier-1 quorum tracker.
    quorum: Tier1QuorumTracker,
    /// Whether this Delta may be compacted from the hot path (set when Tier-1 reached).
    compaction_permitted: bool,
}

impl DeltaDurabilityState {
    fn new(
        state_hash: [u8; 32],
        quorum_config: QuorumConfig,
        peer_public_keys: HashMap<Did, [u8; 32]>,
    ) -> Self {
        Self {
            state_hash,
            tier: DurabilityTier::Uncommitted,
            peer_public_keys,
            quorum: Tier1QuorumTracker::new(quorum_config),
            compaction_permitted: false,
        }
    }
}

// ─── DurabilitySubsystem ──────────────────────────────────────────────────────

/// The Durability Subsystem manages Tier-1 and Tier-2 durability tracking,
/// quorum formation, spatial diversity enforcement, and Cloud Ledger sync queueing.
pub struct DurabilitySubsystem {
    /// Quorum configuration applied to all Delta sets.
    quorum_config: QuorumConfig,
    /// Per-Delta durability states.
    states: HashMap<DeltaId, DeltaDurabilityState>,
    /// Cloud outbound queue (capped at 100,000 entries — Req 16.6).
    cloud_queue: CloudOutboundQueue,
    /// Optional application-layer listener invoked when a Delta's durability
    /// tier transitions (Tier-1 via quorum receipts, Tier-2 via a Cloud Ledger
    /// ack — Req 14.7).
    ///
    /// Registered by [`CoreHandle::init`](crate::api::CoreHandle::init) so the
    /// transition is surfaced to the host application through
    /// [`CoreHandle::subscribe_durability_events`](crate::api::CoreHandle::subscribe_durability_events)
    /// on native builds.  Subsystem-level unit tests construct the subsystem
    /// without a listener; the crate-global `notify_tier_changed` (stderr log,
    /// WASM event queue) fires regardless.
    tier_changed_listener: Option<TierChangedListener>,
}

/// Application-layer callback for a durability tier transition
/// `(delta_id, previous_tier, new_tier)` (Req 14.7).
///
/// `Send + Sync` so the subsystem (and the `CoreHandle` hosting it) can be
/// shared across the production background loops.  The listener must not lock
/// the Durability Subsystem itself — it is invoked while the subsystem is
/// already locked — so `CoreHandle::init` registers a listener that only
/// forwards onto a non-blocking broadcast channel.
type TierChangedListener = Box<dyn Fn(DeltaId, DurabilityTier, DurabilityTier) + Send + Sync>;

impl DurabilitySubsystem {
    /// Create a new subsystem with the given quorum configuration.
    pub fn new(quorum_config: QuorumConfig) -> Self {
        Self {
            quorum_config,
            states: HashMap::new(),
            cloud_queue: CloudOutboundQueue::new(),
            tier_changed_listener: None,
        }
    }

    /// Register an application-layer listener for durability tier transitions
    /// (Tier-1 quorum reached, Tier-2 Cloud Ledger ack — Req 14.7).
    ///
    /// Production caller: [`CoreHandle::init`](crate::api::CoreHandle::init),
    /// which attaches a listener forwarding transitions to the handle's
    /// durability event broadcast channel (Subphase 4.2).  The listener is
    /// invoked while the subsystem mutex is held, so it must not re-enter the
    /// subsystem.
    pub fn set_tier_changed_listener(
        &mut self,
        listener: TierChangedListener,
    ) {
        self.tier_changed_listener = Some(listener);
    }

    /// Emit a tier transition to the crate-global notifier (stderr on native,
    /// `DurabilityTierChanged` WASM event queue on the SDK target) and, when
    /// registered, to the instance-level listener (Req 14.7).
    fn emit_tier_changed(
        &self,
        delta_id: DeltaId,
        previous_tier: DurabilityTier,
        new_tier: DurabilityTier,
    ) {
        notify_tier_changed(delta_id, new_tier);
        if let Some(listener) = &self.tier_changed_listener {
            listener(delta_id, previous_tier, new_tier);
        }
    }

    // ─── Delta registration ───────────────────────────────────────────────────

    /// Register a newly committed Delta set for durability tracking.
    ///
    /// The caller provides:
    /// - `delta_id` — identifier of the Delta set.
    /// - `state_hash` — SHA-256 of the committed Delta set; receipts must match.
    /// - `serialised_bytes` — serialised Delta bytes for cloud sync.
    /// - `causal_parents` — for topological ordering in the cloud queue.
    /// - `peer_public_keys` — Ed25519 public keys of candidate receipt-issuing peers.
    ///
    /// The Delta is enqueued in the cloud outbound queue (Req 16.3, 14.8).
    pub fn register_delta(
        &mut self,
        delta_id: DeltaId,
        state_hash: [u8; 32],
        serialised_bytes: Vec<u8>,
        causal_parents: Vec<DeltaId>,
        peer_public_keys: HashMap<Did, [u8; 32]>,
    ) -> Result<(), TirBaseError> {
        let state = DeltaDurabilityState::new(
            state_hash,
            self.quorum_config.clone(),
            peer_public_keys,
        );
        self.states.insert(delta_id, state);

        // Enqueue for cloud sync (Req 14.8 — stays in queue until Tier-2).
        let entry = QueueEntry::new(delta_id, serialised_bytes, causal_parents);
        self.cloud_queue.enqueue(entry)?;

        Ok(())
    }

    // ─── Receipt handling ─────────────────────────────────────────────────────

    /// Receive a signed `DurabilityReceipt` from a peer.
    ///
    /// Performs the two required checks before counting toward Quorum (Req 14.6):
    /// 1. Ed25519 signature verification.
    /// 2. State-hash match.
    ///
    /// If both checks pass, the receipt is forwarded to the `Tier1QuorumTracker`.
    /// When K valid receipts spanning spatial diversity are collected, the Delta is
    /// marked Tier-1 durable and compaction is permitted (Req 14.2, 14.8).
    ///
    /// Returns:
    /// - `Ok(true)`  — this receipt caused Tier-1 durability to be achieved.
    /// - `Ok(false)` — receipt accepted or rejected; Tier-1 not yet reached.
    pub fn receive_receipt(
        &mut self,
        receipt: DurabilityReceipt,
        delta_id: &DeltaId,
    ) -> Result<bool, TirBaseError> {
        let state = match self.states.get_mut(delta_id) {
            Some(s) => s,
            None => {
                // Unknown Delta — silently ignore the receipt.
                return Ok(false);
            }
        };

        // Look up the issuer's public key.
        let public_key = match state.peer_public_keys.get(&receipt.issuer_did) {
            Some(pk) => *pk,
            None => {
                let reason = format!(
                    "no known public key for issuer {} (delta {})",
                    receipt.issuer_did,
                    hex::encode(delta_id)
                );
                eprintln!("[durability] receipt rejected: {reason}");
                return Err(TirBaseError::SignatureVerificationFailed { reason });
            }
        };

        // Verify signature + state-hash (Req 14.6).
        verify_receipt(&receipt, &public_key, &state.state_hash)?;

        // Forward verified receipt to the quorum tracker.
        let issuer_did = receipt.issuer_did.clone();
        let tier1_achieved = state.quorum.add_receipt(receipt)?;

        if tier1_achieved && state.tier == DurabilityTier::Uncommitted {
            state.tier = DurabilityTier::Tier1;
            // Permit hot-path compaction (Req 14.8) — Delta stays in cloud queue.
            state.compaction_permitted = true;

            // Track the receipt holder on the cloud queue entry for re-fetch (Req 16.8).
            self.cloud_queue.add_receipt_holder(delta_id, issuer_did);

            self.emit_tier_changed(
                *delta_id,
                DurabilityTier::Uncommitted,
                DurabilityTier::Tier1,
            );
            return Ok(true);
        }

        // Also track receipt holders even before Tier-1 (for re-fetch on partial quorum).
        self.cloud_queue.add_receipt_holder(delta_id, issuer_did);

        Ok(false)
    }

    // ─── Tier-2 ───────────────────────────────────────────────────────────────

    /// Called when the Cloud Ledger acknowledges a Delta set (Req 14.4, 14.7).
    ///
    /// Marks the Delta as Tier-2 durable and removes it from the cloud queue
    /// (the removal is idempotent — safe when the sync loop already removed
    /// the entry).  Also notifies the application layer of the transition, so
    /// the Delta's durability tier — the state backing
    /// `WriteResult::durability_tier` — no longer stays `Uncommitted` forever
    /// after a real cloud ack.
    ///
    /// Production caller: `crate::api::CoreHandle::run_cloud_sync_cycle`, which
    /// invokes this once per Delta ID the cloud sync loop freshly acknowledged
    /// (Subphase 4.2).
    pub fn on_cloud_ack(&mut self, delta_id: &DeltaId) -> Result<(), TirBaseError> {
        let previous_tier = self
            .states
            .get(delta_id)
            .map(|s| s.tier)
            .unwrap_or(DurabilityTier::Uncommitted);

        if let Some(state) = self.states.get_mut(delta_id) {
            state.tier = DurabilityTier::Tier2;
        }
        // Remove from cloud queue — Tier-2 confirmed (Req 16.3).
        self.cloud_queue.acknowledge(delta_id);
        self.emit_tier_changed(*delta_id, previous_tier, DurabilityTier::Tier2);
        Ok(())
    }

    // ─── Queries ─────────────────────────────────────────────────────────────

    /// Report the current durability tier of a Delta set (Req 14.7).
    pub fn durability_tier(&self, delta_id: &DeltaId) -> DurabilityTier {
        self.states
            .get(delta_id)
            .map(|s| s.tier)
            .unwrap_or(DurabilityTier::Uncommitted)
    }

    /// Whether hot-path compaction is permitted for this Delta (Req 14.8).
    ///
    /// Tier-1 durability is required; the Delta must still remain in the cloud
    /// outbound queue until Tier-2 is confirmed.
    pub fn compaction_permitted(&self, delta_id: &DeltaId) -> bool {
        self.states
            .get(delta_id)
            .map(|s| s.compaction_permitted)
            .unwrap_or(false)
    }

    /// Current cloud outbound queue depth.
    pub fn cloud_queue_depth(&self) -> usize {
        self.cloud_queue.depth()
    }

    /// Mutable access to the cloud queue for the sync loop.
    pub fn cloud_queue_mut(&mut self) -> &mut CloudOutboundQueue {
        &mut self.cloud_queue
    }
}

// ─── Internal notification ────────────────────────────────────────────────────

/// Notify the application layer of a durability tier change (Req 14.7).
///
/// On native builds this writes to stderr. On WASM builds this pushes a
/// `DurabilityTierChanged` event to the WASM event queue, which the TypeScript
/// SDK drains via `core_poll_events()` and dispatches to `durability-tier-changed`
/// event listeners (implemented in T31).
fn notify_tier_changed(delta_id: DeltaId, tier: DurabilityTier) {
    eprintln!(
        "[durability] tier-changed: delta={}, tier={tier:?}",
        hex::encode(delta_id)
    );
    #[cfg(feature = "wasm")]
    {
        // Map tier to string names matching TypeScript DurabilityTier.
        let tier_str = match tier {
            DurabilityTier::Uncommitted => "UNCOMMITTED",
            DurabilityTier::Tier1 => "TIER1",
            DurabilityTier::Tier2 => "TIER2",
        };
        // Infer the previous tier from the new tier (this function is only called
        // at Tier-1 and Tier-2 transition points).
        let previous_str = match tier {
            DurabilityTier::Tier1 => "UNCOMMITTED",
            DurabilityTier::Tier2 => "TIER1",
            DurabilityTier::Uncommitted => "UNCOMMITTED",
        };
        crate::push_wasm_event(crate::WasmEvent::DurabilityTierChanged {
            delta_id: hex::encode(delta_id),
            previous_tier: previous_str.to_string(),
            new_tier: tier_str.to_string(),
        });
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::DurabilityTier;
    use crate::durability::receipt::{receipt_signing_payload, DurabilityReceipt};
    use crate::identity::keypair::{generate_keypair, sign};
    use uuid::Uuid;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_quorum_k2() -> QuorumConfig {
        QuorumConfig {
            k: 2,
            n: 5,
            spatial_diversity_min: 1,
            max_single_sector_fraction: 1.0,
        }
    }

    fn make_quorum_k3_div2() -> QuorumConfig {
        QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 2,
            max_single_sector_fraction: 0.6,
        }
    }

    fn make_signed_receipt(
        state_hash: [u8; 32],
        secret: &[u8; 32],
        did: &str,
        spatial_tag: Option<&str>,
    ) -> DurabilityReceipt {
        let id = Uuid::now_v7();
        let payload = receipt_signing_payload(&state_hash, &id);
        let sig = sign(secret, &payload).unwrap();
        DurabilityReceipt {
            id,
            state_hash,
            issuer_did: did.to_string(),
            issuer_signature: sig,
            spatial_tag: spatial_tag.map(|s| s.to_string()),
            beacon_token: None,
            issued_at: 0,
        }
    }

    // ── Tier-1 formation ──────────────────────────────────────────────────────

    #[test]
    fn tier1_achieved_at_k_receipts() {
        let delta_id = [0xAA; 32];
        let state_hash = [0xBB; 32];

        let (s1, p1) = generate_keypair().unwrap();
        let (s2, p2) = generate_keypair().unwrap();

        let mut peers = HashMap::new();
        peers.insert("did:key:p1".to_string(), p1);
        peers.insert("did:key:p2".to_string(), p2);

        let mut sys = DurabilitySubsystem::new(make_quorum_k2());
        sys.register_delta(delta_id, state_hash, vec![0u8; 4], vec![], peers)
            .unwrap();

        assert_eq!(sys.durability_tier(&delta_id), DurabilityTier::Uncommitted);

        let r1 = make_signed_receipt(state_hash, &s1, "did:key:p1", Some("sq-a"));
        let tier1 = sys.receive_receipt(r1, &delta_id).unwrap();
        assert!(!tier1, "not yet at K=2 receipts");
        assert_eq!(sys.durability_tier(&delta_id), DurabilityTier::Uncommitted);

        let r2 = make_signed_receipt(state_hash, &s2, "did:key:p2", Some("sq-a"));
        let tier1 = sys.receive_receipt(r2, &delta_id).unwrap();
        assert!(tier1, "should achieve Tier-1 at K=2 receipts");
        assert_eq!(sys.durability_tier(&delta_id), DurabilityTier::Tier1);
        assert!(sys.compaction_permitted(&delta_id));
    }

    #[test]
    fn below_k_receipts_does_not_achieve_tier1() {
        let delta_id = [0x11; 32];
        let state_hash = [0x22; 32];

        let (s1, p1) = generate_keypair().unwrap();
        let mut peers = HashMap::new();
        peers.insert("did:key:p1".to_string(), p1);

        let mut sys = DurabilitySubsystem::new(make_quorum_k2()); // K=2
        sys.register_delta(delta_id, state_hash, vec![], vec![], peers).unwrap();

        let r1 = make_signed_receipt(state_hash, &s1, "did:key:p1", None);
        let tier1 = sys.receive_receipt(r1, &delta_id).unwrap();
        assert!(!tier1);
        assert_eq!(sys.durability_tier(&delta_id), DurabilityTier::Uncommitted);
    }

    // ── State-hash mismatch ────────────────────────────────────────────────────

    #[test]
    fn receipt_with_wrong_state_hash_is_rejected() {
        let delta_id = [0x33; 32];
        let state_hash = [0x44; 32];

        let (s1, p1) = generate_keypair().unwrap();
        let mut peers = HashMap::new();
        peers.insert("did:key:p1".to_string(), p1);

        let mut sys = DurabilitySubsystem::new(make_quorum_k2());
        sys.register_delta(delta_id, state_hash, vec![], vec![], peers).unwrap();

        // Receipt signed over wrong state_hash.
        let wrong_hash = [0xFF; 32];
        let receipt = make_signed_receipt(wrong_hash, &s1, "did:key:p1", None);
        let result = sys.receive_receipt(receipt, &delta_id);
        assert!(result.is_err(), "wrong state hash must be rejected");
    }

    // ── Unknown issuer ─────────────────────────────────────────────────────────

    #[test]
    fn receipt_from_unknown_issuer_is_rejected() {
        let delta_id = [0x55; 32];
        let state_hash = [0x66; 32];

        let (s_unknown, _) = generate_keypair().unwrap();
        let (_s_registered, p_registered) = generate_keypair().unwrap();
        let mut peers = HashMap::new();
        peers.insert("did:key:registered".to_string(), p_registered);

        let mut sys = DurabilitySubsystem::new(make_quorum_k2());
        sys.register_delta(delta_id, state_hash, vec![], vec![], peers).unwrap();

        // Receipt from DID not in the peer registry.
        let receipt =
            make_signed_receipt(state_hash, &s_unknown, "did:key:unknown-peer", None);
        let result = sys.receive_receipt(receipt, &delta_id);
        assert!(result.is_err(), "unknown issuer DID must be rejected");
    }

    // ── Tier-2 ───────────────────────────────────────────────────────────────

    #[test]
    fn on_cloud_ack_advances_to_tier2_and_removes_from_queue() {
        let delta_id = [0x77; 32];
        let state_hash = [0x88; 32];

        let mut sys = DurabilitySubsystem::new(make_quorum_k2());
        sys.register_delta(delta_id, state_hash, vec![1, 2, 3], vec![], HashMap::new())
            .unwrap();

        assert_eq!(sys.cloud_queue_depth(), 1);
        sys.on_cloud_ack(&delta_id).unwrap();

        assert_eq!(sys.durability_tier(&delta_id), DurabilityTier::Tier2);
        assert_eq!(sys.cloud_queue_depth(), 0, "Delta removed from queue on Tier-2 ack");
    }

    #[test]
    fn tier_changed_listener_fires_on_cloud_ack_transition() {
        let delta_id = [0x1A; 32];
        let state_hash = [0x2B; 32];

        let mut sys = DurabilitySubsystem::new(make_quorum_k2());
        let calls: std::sync::Arc<std::sync::Mutex<Vec<(DeltaId, DurabilityTier, DurabilityTier)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls_clone = std::sync::Arc::clone(&calls);
        sys.set_tier_changed_listener(Box::new(move |id, prev, new| {
            calls_clone.lock().unwrap().push((id, prev, new));
        }));

        sys.register_delta(delta_id, state_hash, vec![], vec![], HashMap::new())
            .unwrap();
        sys.on_cloud_ack(&delta_id).unwrap();

        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "the instance listener must fire exactly once per transition"
        );
        assert_eq!(calls[0], (delta_id, DurabilityTier::Uncommitted, DurabilityTier::Tier2));
    }

    // ── Tier-1 does not remove from cloud queue ───────────────────────────────

    #[test]
    fn tier1_does_not_remove_delta_from_cloud_queue() {
        let delta_id = [0x99; 32];
        let state_hash = [0xAA; 32];

        let (s1, p1) = generate_keypair().unwrap();
        let (s2, p2) = generate_keypair().unwrap();

        let mut peers = HashMap::new();
        peers.insert("did:key:t1".to_string(), p1);
        peers.insert("did:key:t2".to_string(), p2);

        let mut sys = DurabilitySubsystem::new(make_quorum_k2());
        sys.register_delta(delta_id, state_hash, vec![0u8; 8], vec![], peers).unwrap();

        let r1 = make_signed_receipt(state_hash, &s1, "did:key:t1", Some("sq-a"));
        let r2 = make_signed_receipt(state_hash, &s2, "did:key:t2", Some("sq-a"));
        sys.receive_receipt(r1, &delta_id).unwrap();
        sys.receive_receipt(r2, &delta_id).unwrap();

        // Tier-1 reached — but Delta must stay in cloud queue until Tier-2.
        assert_eq!(sys.durability_tier(&delta_id), DurabilityTier::Tier1);
        assert_eq!(
            sys.cloud_queue_depth(),
            1,
            "Delta must remain in cloud queue after Tier-1 (not yet Tier-2)"
        );
    }

    // ── Spatial diversity ─────────────────────────────────────────────────────

    #[test]
    fn spatial_diversity_enforcement_prevents_tier1_when_single_sector_exceeds_fraction() {
        // K=3, max_fraction=0.5 → at most ceil(0.5*3)=2 from one sector.
        // Three receipts all from "sector-x" → 100% in one sector → Tier-1 blocked.
        let cfg = QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 1,
            max_single_sector_fraction: 0.5,
        };
        let delta_id = [0xCC; 32];
        let state_hash = [0xDD; 32];

        let mut peers = HashMap::new();
        let mut secrets = vec![];
        for i in 0..3u8 {
            let (s, p) = generate_keypair().unwrap();
            let did = format!("did:key:sp{i}");
            peers.insert(did, p);
            secrets.push(s);
        }

        let mut sys = DurabilitySubsystem::new(cfg);
        sys.register_delta(delta_id, state_hash, vec![], vec![], peers).unwrap();

        for (i, s) in secrets.iter().enumerate() {
            let did = format!("did:key:sp{i}");
            let r = make_signed_receipt(state_hash, s, &did, Some("sector-x"));
            let t1 = sys.receive_receipt(r, &delta_id).unwrap();
            assert!(!t1, "single-sector excess should block Tier-1");
        }
        assert_eq!(sys.durability_tier(&delta_id), DurabilityTier::Uncommitted);
    }

    // ── Cloud queue cap ───────────────────────────────────────────────────────

    #[test]
    fn cloud_queue_overflow_returns_queue_full() {
        let mut sys = DurabilitySubsystem::new(make_quorum_k2());

        // Register MAX_QUEUE_DEPTH Deltas.
        for i in 0..cloud_queue::MAX_QUEUE_DEPTH {
            let id: [u8; 32] = {
                let mut arr = [0u8; 32];
                let bytes = i.to_le_bytes();
                arr[..bytes.len()].copy_from_slice(&bytes);
                arr
            };
            sys.register_delta(id, [0u8; 32], vec![], vec![], HashMap::new())
                .unwrap();
        }
        assert_eq!(sys.cloud_queue_depth(), cloud_queue::MAX_QUEUE_DEPTH);

        // One more must fail.
        let overflow_id = [0xFF; 32];
        let result = sys.register_delta(overflow_id, [0u8; 32], vec![], vec![], HashMap::new());
        assert!(
            matches!(result, Err(TirBaseError::CloudQueueFull { .. })),
            "overflow must return CloudQueueFull"
        );
    }
}
