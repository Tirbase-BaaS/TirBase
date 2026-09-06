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
use anchor::{AnchorAttestedLocation, AnchorMode};
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
    ///
    /// Seeded at registration and extended dynamically when a receipt arrives
    /// from an issuer whose self-certifying `did:key:` DID resolves to its
    /// public key (Subphase 4.5 — see
    /// [`DurabilitySubsystem::register_peer_key`]).
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
    /// Optional Anchor_Attested_Location verifier (Req 15).
    ///
    /// Subphase 4.3: when a deployment enables `anchor_attested_location`,
    /// `CoreHandle::init` constructs an [`AnchorAttestedLocation`] from the
    /// configured beacon public keys and installs it here.  While the anchor
    /// operates in [`AnchorMode::BeaconAttested`], `receive_receipt` requires
    /// every incoming `DurabilityReceipt` to carry a valid current-epoch beacon
    /// token and counts the receipt toward Spatial_Diversity under its
    /// beacon-verified location claim — never the spoofable self-declared squad
    /// tag (Req 15.2).  `None` (or SquadTagFallback mode after beacon signal
    /// loss, Req 15.4) means receipts are counted by their declared squad tag,
    /// the historical behaviour.
    anchor: Option<AnchorAttestedLocation>,
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
        Self::with_anchor(quorum_config, None)
    }

    /// Create a new subsystem with an optional Anchor_Attested_Location verifier.
    ///
    /// Production caller: [`CoreHandle::init`](crate::api::CoreHandle::init),
    /// which passes a configured [`AnchorAttestedLocation`] when the deployment
    /// enables `anchor_attested_location` (Subphase 4.3).
    pub(crate) fn with_anchor(
        quorum_config: QuorumConfig,
        anchor: Option<AnchorAttestedLocation>,
    ) -> Self {
        Self {
            quorum_config,
            states: HashMap::new(),
            anchor,
            cloud_queue: CloudOutboundQueue::new(),
            tier_changed_listener: None,
        }
    }

    /// The configured anchor verifier, when Anchor_Attested_Location is enabled
    /// (`pub(crate)`: introspection for in-crate callers/tests; the anchor is
    /// deployment configuration, not external API surface).
    pub(crate) fn anchor(&self) -> Option<&AnchorAttestedLocation> {
        self.anchor.as_ref()
    }

    /// Mutable access to the anchor verifier (production monitoring loop — Req 15.4).
    ///
    /// `pub(crate)`: the beacon signal-loss monitoring loop in
    /// `CoreHandle::init` locks the `DurabilitySubsystem` and calls
    /// [`AnchorAttestedLocation::check_signal_loss`] /
    /// [`AnchorAttestedLocation::on_beacon_signal_lost`] on the anchor — no
    /// external API surface needed.
    pub(crate) fn anchor_mut(&mut self) -> Option<&mut AnchorAttestedLocation> {
        self.anchor.as_mut()
    }

    /// The quorum configuration this subsystem applies to every Delta set
    /// (as resolved from `DeploymentConfig` by `CoreHandle::init`).
    ///
    /// `pub(crate)`: introspection for in-crate callers/tests; quorum policy is
    /// deployment configuration, not external API surface.
    pub(crate) fn quorum_config(&self) -> &QuorumConfig {
        &self.quorum_config
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
    ///   Subphase 4.5: this map is a seed, not a fixed roster — a receipt from
    ///   an issuer not listed here is still accepted when its self-certifying
    ///   `did:key:` DID resolves to the key that verifies its signature
    ///   ([`DurabilitySubsystem::register_peer_key`]).
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

    /// Register (or refresh) the Ed25519 public key of a receipt-issuing peer
    /// for a specific Delta set, resolved from the peer's self-certifying
    /// `did:key:` DID (Req 14.6 — the issuer's key must be known before its
    /// receipt can be verified).
    ///
    /// Subphase 4.5: the inbound receipt path resolves `receipt.issuer_did`
    /// (a `did:key:` DID *is* the public key) and registers it here before
    /// calling [`DurabilitySubsystem::receive_receipt`], so a genuine receipt
    /// exchanged between two live devices is verified against the key its
    /// issuer self-certifies — no pre-provisioned peer roster required.  The
    /// receipt's Ed25519 signature must still verify against the resolved key,
    /// so registration grants no trust by itself: only the device that holds
    /// the key can produce a verifiable receipt for it.
    ///
    /// `pub(crate)`: peer-key learning is internal durability policy, not
    /// external API surface.
    ///
    /// Production callers: `crate::api::CoreHandle::receive_inbound` and
    /// `receive_inbound_wasm` — the native/WASM inbound pipelines every
    /// incoming `GossipMessage::InboundDurabilityReceipt` flows through.
    pub(crate) fn register_peer_key(
        &mut self,
        delta_id: &DeltaId,
        peer_did: &Did,
        public_key: [u8; 32],
    ) {
        if let Some(state) = self.states.get_mut(delta_id) {
            state.peer_public_keys.insert(peer_did.clone(), public_key);
        }
    }

    // ─── Receipt handling ─────────────────────────────────────────────────────

    /// Receive a signed `DurabilityReceipt` from a peer.
    ///
    /// Performs the required checks before counting toward Quorum:
    /// 1. The issuer has a known Ed25519 public key (Req 14.6).
    /// 2. Ed25519 signature verification + state-hash match (Req 14.6).
    /// 3. WHEN Anchor_Attested_Location is enabled and in BeaconAttested mode:
    ///    the receipt carries a beacon token that verifies against the
    ///    deployment beacon registry; the receipt is then counted toward
    ///    Spatial_Diversity under the beacon-verified location claim (Req 15.2).
    ///
    /// If all checks pass, the receipt is forwarded to the `Tier1QuorumTracker`.
    /// When K valid receipts spanning spatial diversity are collected, the Delta is
    /// marked Tier-1 durable and compaction is permitted (Req 14.2, 14.8).
    ///
    /// Returns:
    /// - `Ok(true)`  — this receipt caused Tier-1 durability to be achieved.
    /// - `Ok(false)` — receipt accepted; Tier-1 not yet reached.
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

        // Anchor_Attested_Location gate (Req 15.2, 15.3): while the anchor is in
        // BeaconAttested mode, a receipt contributes to Quorum only when it
        // carries a beacon token that verifies against the deployment beacon
        // registry (registered beacon DID, current-epoch token, valid beacon
        // signature).  Such a receipt is then counted toward Spatial_Diversity
        // under the beacon-verified location claim, never the spoofable
        // self-declared squad tag.  Receipts without a valid token are excluded
        // from Quorum formation entirely and the rejection is logged with the
        // issuer DID and reason (Req 14.6 pattern).  After beacon signal loss
        // (SquadTagFallback — Req 15.4) or when the feature is disabled, the
        // historical squad-tag accounting applies unchanged.
        let now_secs = crate::api::now_secs();
        let diversity_tag: Option<String> =
            match self.anchor.as_ref().map(AnchorAttestedLocation::mode) {
                Some(AnchorMode::BeaconAttested) => {
                    let token = receipt.beacon_token.as_ref().ok_or_else(|| {
                        let reason = format!(
                            "peer {} sent a DurabilityReceipt with no beacon token; \
                             Anchor_Attested_Location is enabled — peer not counted toward \
                             Spatial_Diversity (Req 15.2; delta {})",
                            receipt.issuer_did,
                            hex::encode(delta_id)
                        );
                        eprintln!("[durability] receipt rejected: {reason}");
                        TirBaseError::SignatureVerificationFailed { reason }
                    })?;
                    self.anchor
                        .as_mut()
                        .expect("anchor present in BeaconAttested branch")
                        .verify_beacon_token(token, now_secs)
                        .map_err(|e| {
                            let reason = format!(
                                "beacon token from peer {} rejected: {e} (delta {})",
                                receipt.issuer_did,
                                hex::encode(delta_id)
                            );
                            eprintln!("[durability] receipt rejected: {reason}");
                            TirBaseError::SignatureVerificationFailed { reason }
                        })?;
                    // Verified: diversity is counted under the attested location claim.
                    Some(token.location_claim.clone())
                }
                // Feature disabled or squad-tag fallback after signal loss (Req 15.4):
                // count the receipt's own declared squad tag, as before.
                _ => None,
            };

        // Forward verified receipt to the quorum tracker.  In BeaconAttested mode
        // the diversity tag was derived from the verified beacon token above;
        // otherwise the tracker falls back to the receipt's declared spatial tag.
        let issuer_did = receipt.issuer_did.clone();
        let tier1_achieved = state
            .quorum
            .add_receipt_with_tag(receipt, diversity_tag.as_deref())?;

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
    use crate::durability::anchor::{beacon_token_signing_payload, BeaconRegistryEntry};
    use crate::durability::receipt::{receipt_signing_payload, BeaconToken, DurabilityReceipt};
    use crate::identity::did::derive_did;
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

    /// QuorumConfig with K=1 — a single accepted receipt declares Tier-1.
    fn make_quorum_k1() -> QuorumConfig {
        QuorumConfig {
            k: 1,
            n: 5,
            spatial_diversity_min: 1,
            max_single_sector_fraction: 1.0,
        }
    }

    /// A registered-beacon entry derived from a fresh beacon keypair.
    fn make_beacon_entry(public: &[u8; 32]) -> BeaconRegistryEntry {
        BeaconRegistryEntry {
            beacon_did: derive_did(public),
            public_key: *public,
        }
    }

    /// Sign a `BeaconToken` for `beacon_secret` over the canonical payload
    /// `epoch || location_claim` (mirrors the beacon issuance format).
    fn make_beacon_token(
        beacon_secret: &[u8; 32],
        beacon_did: &str,
        epoch: u64,
        location_claim: &str,
    ) -> BeaconToken {
        let payload = beacon_token_signing_payload(epoch, location_claim);
        let sig = sign(beacon_secret, &payload).expect("sign beacon token");
        BeaconToken {
            beacon_did: beacon_did.to_string(),
            beacon_signature: sig,
            epoch,
            location_claim: location_claim.to_string(),
            issued_at: 0,
        }
    }

    fn make_signed_receipt_with_token(
        state_hash: [u8; 32],
        secret: &[u8; 32],
        did: &str,
        spatial_tag: Option<&str>,
        beacon_token: Option<BeaconToken>,
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
            beacon_token,
            issued_at: 0,
        }
    }

    fn make_signed_receipt(
        state_hash: [u8; 32],
        secret: &[u8; 32],
        did: &str,
        spatial_tag: Option<&str>,
    ) -> DurabilityReceipt {
        make_signed_receipt_with_token(state_hash, secret, did, spatial_tag, None)
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

    // ── Anchor-Attested Location (Req 15.2, 15.3 — Subphase 4.3) ──────────────

    #[test]
    fn anchor_is_absent_when_anchor_attested_location_not_enabled() {
        let sys = DurabilitySubsystem::new(make_quorum_k2());
        assert!(
            sys.anchor().is_none(),
            "feature-disabled construction must carry no anchor verifier"
        );
    }

    #[test]
    fn anchor_mode_counts_verified_beacon_claims_toward_diversity_and_reaches_tier1() {
        // K=2, spatial_diversity_min=2: two receipts attested to *different*
        // sectors by the deployment beacons must form Tier-1.
        let cfg = QuorumConfig {
            k: 2,
            n: 5,
            spatial_diversity_min: 2,
            max_single_sector_fraction: 0.6,
        };
        let delta_id = [0x01; 32];
        let state_hash = [0x02; 32];

        let (b_secret_a, b_public_a) = generate_keypair().unwrap();
        let (b_secret_b, b_public_b) = generate_keypair().unwrap();
        let beacon_did_a = derive_did(&b_public_a);
        let beacon_did_b = derive_did(&b_public_b);

        let (s1, p1) = generate_keypair().unwrap();
        let (s2, p2) = generate_keypair().unwrap();
        let mut peers = HashMap::new();
        peers.insert("did:key:peer1".to_string(), p1);
        peers.insert("did:key:peer2".to_string(), p2);

        let mut sys = DurabilitySubsystem::with_anchor(
            cfg,
            Some(AnchorAttestedLocation::new(
                vec![make_beacon_entry(&b_public_a), make_beacon_entry(&b_public_b)],
                0,
            )),
        );
        sys.register_delta(delta_id, state_hash, vec![], vec![], peers).unwrap();

        let r1 = make_signed_receipt_with_token(
            state_hash,
            &s1,
            "did:key:peer1",
            Some("sq-a"),
            Some(make_beacon_token(&b_secret_a, &beacon_did_a, 1, "sector-A")),
        );
        assert!(
            !sys.receive_receipt(r1, &delta_id).unwrap(),
            "single attested sector must not reach K=2/min=2"
        );

        let r2 = make_signed_receipt_with_token(
            state_hash,
            &s2,
            "did:key:peer2",
            Some("sq-b"),
            Some(make_beacon_token(&b_secret_b, &beacon_did_b, 1, "sector-B")),
        );
        assert!(
            sys.receive_receipt(r2, &delta_id).unwrap(),
            "two beacon-attested sectors must reach Tier-1"
        );
        assert_eq!(sys.durability_tier(&delta_id), DurabilityTier::Tier1);
    }

    #[test]
    fn anchor_mode_rejects_receipts_with_missing_or_invalid_beacon_tokens() {
        let delta_id = [0x11; 32];
        let state_hash = [0x22; 32];

        let (b_secret, b_public) = generate_keypair().unwrap();
        let beacon_did = derive_did(&b_public);

        // Registered beacon; the anchor's Lamport current epoch is 5.
        let mut sys = DurabilitySubsystem::with_anchor(
            make_quorum_k1(),
            Some(AnchorAttestedLocation::new(vec![make_beacon_entry(&b_public)], 5)),
        );

        let (s_peer, p_peer) = generate_keypair().unwrap();
        let mut peers = HashMap::new();
        peers.insert("did:key:peer".to_string(), p_peer);
        sys.register_delta(delta_id, state_hash, vec![], vec![], peers).unwrap();

        // (a) No beacon token attached → excluded (Req 15.2).
        let no_token = make_signed_receipt(state_hash, &s_peer, "did:key:peer", Some("sq-a"));
        assert!(
            sys.receive_receipt(no_token, &delta_id).is_err(),
            "receipt without a beacon token must be excluded in BeaconAttested mode"
        );

        // (b) Token from an unrecognised beacon (Req 15.1 unknown-beacon).
        let (rogue_secret, rogue_public) = generate_keypair().unwrap();
        let rogue = make_signed_receipt_with_token(
            state_hash,
            &s_peer,
            "did:key:peer",
            Some("sq-a"),
            Some(make_beacon_token(
                &rogue_secret,
                &derive_did(&rogue_public),
                6,
                "sector-rogue",
            )),
        );
        assert!(
            sys.receive_receipt(rogue, &delta_id).is_err(),
            "token from an unregistered beacon must be rejected (Req 15.1)"
        );

        // (c) Stale-epoch replay (Req 15.3).
        let stale = make_signed_receipt_with_token(
            state_hash,
            &s_peer,
            "did:key:peer",
            Some("sq-a"),
            Some(make_beacon_token(&b_secret, &beacon_did, 1, "sector-A")),
        );
        assert!(
            sys.receive_receipt(stale, &delta_id).is_err(),
            "stale-epoch token must be rejected as a replay attempt (Req 15.3)"
        );

        // (d) Tampered beacon signature.
        let mut tampered_token = make_beacon_token(&b_secret, &beacon_did, 6, "sector-A");
        if let Some(byte) = tampered_token.beacon_signature.0.first_mut() {
            *byte ^= 0xFF;
        }
        let tampered = make_signed_receipt_with_token(
            state_hash,
            &s_peer,
            "did:key:peer",
            Some("sq-a"),
            Some(tampered_token),
        );
        assert!(
            sys.receive_receipt(tampered, &delta_id).is_err(),
            "tampered beacon signature must be rejected"
        );

        assert_eq!(
            sys.durability_tier(&delta_id),
            DurabilityTier::Uncommitted,
            "no rejected receipt may contribute toward Tier-1"
        );
    }

    #[test]
    fn anchor_mode_counts_attested_claim_not_declared_squad_tag() {
        // K=3, spatial_diversity_min=1, max 60% per sector.  Three peers are all
        // physically in "sector-X" (their tokens attest the same sector) but
        // self-declare *different* squad tags — a spoofed-diversity attack that
        // must not fabricate Spatial_Diversity (Req 15.2).
        let cfg = QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 1,
            max_single_sector_fraction: 0.6,
        };
        let delta_id = [0x33; 32];
        let state_hash = [0x44; 32];

        let (b_secret, b_public) = generate_keypair().unwrap();
        let beacon_did = derive_did(&b_public);

        let mut peers = HashMap::new();
        let mut secrets = Vec::new();
        for i in 0..3u8 {
            let (s, p) = generate_keypair().unwrap();
            let did = format!("did:key:peer{i}");
            peers.insert(did, p);
            secrets.push(s);
        }

        let mut sys = DurabilitySubsystem::with_anchor(
            cfg,
            Some(AnchorAttestedLocation::new(vec![make_beacon_entry(&b_public)], 0)),
        );
        sys.register_delta(delta_id, state_hash, vec![], vec![], peers).unwrap();

        let declared_tags = ["sq-a", "sq-b", "sq-c"];
        for (i, s) in secrets.iter().enumerate() {
            let did = format!("did:key:peer{i}");
            let r = make_signed_receipt_with_token(
                state_hash,
                s,
                &did,
                Some(declared_tags[i]),
                Some(make_beacon_token(&b_secret, &beacon_did, 1, "sector-X")),
            );
            let t1 = sys.receive_receipt(r, &delta_id).unwrap();
            assert!(
                !t1,
                "all receipts attested to one sector must not fabricate diversity"
            );
        }
        assert_eq!(
            sys.durability_tier(&delta_id),
            DurabilityTier::Uncommitted,
            "single attested sector must block Tier-1 despite distinct declared tags"
        );
    }

    #[test]
    fn squad_tag_fallback_after_signal_loss_skips_beacon_gate() {
        // Req 15.4: after beacon signal loss the anchor reverts to squad-tag mode,
        // so subsequent receipts are counted by their declared squad tags again —
        // no beacon token is required.
        let (_b_secret, b_public) = generate_keypair().unwrap();
        let mut anchor =
            AnchorAttestedLocation::new(vec![make_beacon_entry(&b_public)], 0);
        anchor.on_beacon_signal_lost(0, vec![]).unwrap();
        assert_eq!(anchor.mode(), AnchorMode::SquadTagFallback);

        let delta_id = [0x55; 32];
        let state_hash = [0x66; 32];

        let (s1, p1) = generate_keypair().unwrap();
        let (s2, p2) = generate_keypair().unwrap();
        let mut peers = HashMap::new();
        peers.insert("did:key:peer1".to_string(), p1);
        peers.insert("did:key:peer2".to_string(), p2);

        let mut sys = DurabilitySubsystem::with_anchor(make_quorum_k2(), Some(anchor));
        sys.register_delta(delta_id, state_hash, vec![], vec![], peers).unwrap();

        // No beacon tokens at all — fallback mode must accept by declared tags.
        let r1 = make_signed_receipt(state_hash, &s1, "did:key:peer1", Some("sq-a"));
        assert!(!sys.receive_receipt(r1, &delta_id).unwrap());
        let r2 = make_signed_receipt(state_hash, &s2, "did:key:peer2", Some("sq-b"));
        assert!(
            sys.receive_receipt(r2, &delta_id).unwrap(),
            "squad-tag fallback must reach Tier-1 without beacon tokens (Req 15.4)"
        );
        assert_eq!(sys.durability_tier(&delta_id), DurabilityTier::Tier1);
    }
}
