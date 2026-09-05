//! AnchorAttestedLocation — beacon-signed location tokens for verifiable
//! Spatial_Diversity in high-stakes deployments (Req 15).
//!
//! When enabled, the anchor subsystem:
//! - Verifies beacon-signed location tokens against a registry of trusted beacon public keys.
//! - Rejects tokens from unrecognised beacons (Req 15.1).
//! - Uses Lamport epoch ordering to reject stale replay tokens (Req 15.3).
//! - On beacon signal loss, writes a permanent high-priority Transport Degradation Event
//!   to the append-only log and reverts Spatial_Diversity to squad-tag mode (Req 15.4).

#![allow(dead_code)]

use crate::crdt::delta::Did;
use crate::durability::receipt::BeaconToken;
use crate::errors::TirBaseError;
use crate::identity::did::derive_did;
use crate::identity::keypair;

/// Entry in the beacon public-key registry.
#[derive(Debug, Clone)]
pub struct BeaconRegistryEntry {
    /// DID of the fixed beacon.
    pub beacon_did: Did,
    /// Ed25519 public key (32 bytes) for this beacon.
    pub public_key: [u8; 32],
}

/// Produces the canonical signing payload for a `BeaconToken`.
///
/// `payload = epoch (8 bytes, little-endian) || location_claim (UTF-8 bytes)`
///
/// `pub(crate)`: sibling-module tests (and any future beacon-token issuance
/// path inside the crate) build signed tokens from this canonical payload;
/// the beacon registry is deployment-configured in the api layer.
pub(crate) fn beacon_token_signing_payload(epoch: u64, location_claim: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + location_claim.len());
    payload.extend_from_slice(&epoch.to_le_bytes());
    payload.extend_from_slice(location_claim.as_bytes());
    payload
}

/// Whether beacon-attested location is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorMode {
    /// Beacon tokens are verified; peers without valid tokens are excluded from
    /// spatial diversity count (Req 15.2).
    BeaconAttested,
    /// Signal lost or disabled; fall back to squad/tunnel_sector tag mode (Req 15.4, 15.5).
    SquadTagFallback,
}

/// Verifies and manages beacon-attested location tokens (Req 15.1–15.4).
#[derive(Debug)]
pub struct AnchorAttestedLocation {
    /// Registry of trusted beacon public keys.
    beacon_registry: Vec<BeaconRegistryEntry>,
    /// Current Lamport epoch (for stale replay detection — Req 15.3).
    /// Tokens with `epoch < current_epoch` are rejected as replays.
    current_epoch: u64,
    /// Current operating mode.
    pub mode: AnchorMode,
    /// Append-only log of Transport Degradation Events (Req 15.4).
    degradation_log: Vec<TransportDegradationEvent>,
}

/// A permanent high-priority Transport Degradation Event written on beacon signal loss
/// (Req 15.4).
#[derive(Debug, Clone)]
pub struct TransportDegradationEvent {
    /// UTC timestamp (microseconds) of signal loss.
    pub timestamp: i64,
    /// DIDs of peers whose beacon attestation became unavailable.
    pub affected_peer_dids: Vec<Did>,
    /// Human-readable reason.
    pub reason: String,
}

impl AnchorAttestedLocation {
    /// Create a new instance with the given beacon registry and initial epoch.
    pub fn new(beacon_registry: Vec<BeaconRegistryEntry>, initial_epoch: u64) -> Self {
        Self {
            beacon_registry,
            current_epoch: initial_epoch,
            mode: AnchorMode::BeaconAttested,
            degradation_log: Vec::new(),
        }
    }

    /// Build the verifier from the deployment-configured beacon **public keys**.
    ///
    /// The registry entry DID is derived from each key (`did:key:` — Req 15.1
    /// compares the token's `beacon_did` against these derived DIDs), so the
    /// api layer only needs to expose the raw Ed25519 keys.
    ///
    /// Production caller: `CoreHandle::init` (api/mod.rs), which constructs
    /// this instance from `DeploymentConfig.beacon_public_keys` when
    /// `anchor_attested_location` is enabled (Subphase 4.3).
    pub(crate) fn from_beacon_public_keys(
        beacon_public_keys: &[[u8; 32]],
        initial_epoch: u64,
    ) -> Self {
        let registry = beacon_public_keys
            .iter()
            .map(|public_key| BeaconRegistryEntry {
                beacon_did: derive_did(public_key),
                public_key: *public_key,
            })
            .collect();
        Self::new(registry, initial_epoch)
    }

    /// Advance the current Lamport epoch.
    ///
    /// Tokens issued before the new epoch will be rejected as stale replays (Req 15.3).
    pub fn advance_epoch(&mut self, new_epoch: u64) {
        if new_epoch > self.current_epoch {
            self.current_epoch = new_epoch;
        }
    }

    /// Read the current Lamport epoch (for stale-epoch replay checks — Req 15.3).
    ///
    /// `pub(crate)`: test/introspection access so Subphase 7.6 can assert the
    /// epoch advanced during a simulated partition.  Not exported as external
    /// API surface — the beacon token signature verification is the production
    /// consumer of this value.
    pub(crate) fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Look up a beacon's public key by its DID.
    ///
    /// Returns `None` if the beacon DID is not in the registry.
    fn find_beacon_key(&self, beacon_did: &str) -> Option<[u8; 32]> {
        self.beacon_registry
            .iter()
            .find(|e| e.beacon_did == beacon_did)
            .map(|e| e.public_key)
    }

    /// Validate an incoming beacon token (Req 15.1–15.3).
    ///
    /// Checks (in order):
    /// 1. Beacon DID is in the registered set → `UnknownBeacon` error if not (Req 15.1).
    /// 2. Token epoch is not stale (`epoch >= current_epoch`) → rejected as replay if stale (Req 15.3).
    /// 3. Beacon signature over `beacon_token_signing_payload(epoch, location_claim)` is valid.
    pub fn verify_beacon_token(&self, token: &BeaconToken) -> Result<(), TirBaseError> {
        // Check 1: beacon public key in registry.
        let public_key = self.find_beacon_key(&token.beacon_did).ok_or_else(|| {
            TirBaseError::SignatureVerificationFailed {
                reason: format!(
                    "unrecognised beacon DID: {} — token rejected (unknown-beacon)",
                    token.beacon_did
                ),
            }
        })?;

        // Check 2: stale epoch — replay protection.
        if token.epoch < self.current_epoch {
            return Err(TirBaseError::SignatureVerificationFailed {
                reason: format!(
                    "beacon token epoch {} is stale (current epoch {}); \
                     rejecting as replay attempt",
                    token.epoch, self.current_epoch
                ),
            });
        }

        // Check 3: verify beacon Ed25519 signature.
        let payload = beacon_token_signing_payload(token.epoch, &token.location_claim);
        keypair::verify(&public_key, &payload, &token.beacon_signature).map_err(|e| {
            TirBaseError::SignatureVerificationFailed {
                reason: format!(
                    "beacon token signature invalid for beacon {}: {}",
                    token.beacon_did, e
                ),
            }
        })?;

        Ok(())
    }

    /// Handle beacon signal loss beyond the configured threshold (Req 15.4).
    ///
    /// Writes a permanent high-priority Transport Degradation Event to the
    /// append-only log and reverts Spatial_Diversity to squad-tag mode.
    ///
    /// This reversion is **permanent for the lifetime of this instance** — the
    /// design does not specify an automatic recovery path once signal is lost.
    pub fn on_beacon_signal_lost(
        &mut self,
        timestamp: i64,
        affected_peer_dids: Vec<Did>,
    ) -> Result<(), TirBaseError> {
        let event = TransportDegradationEvent {
            timestamp,
            affected_peer_dids: affected_peer_dids.clone(),
            reason: format!(
                "Beacon signal lost at timestamp {}. Affected peers: [{}]. \
                 Reverting Spatial_Diversity to squad-tag mode.",
                timestamp,
                affected_peer_dids.join(", ")
            ),
        };

        // Log the event (permanent, high-priority — Req 15.4).
        log_transport_degradation_event(&event);

        // Append to the append-only in-memory log.
        self.degradation_log.push(event);

        // Revert to squad-tag spatial diversity mode (Req 15.4).
        self.mode = AnchorMode::SquadTagFallback;

        Ok(())
    }

    /// Read the append-only degradation event log.
    pub fn degradation_log(&self) -> &[TransportDegradationEvent] {
        &self.degradation_log
    }

    /// Whether a peer's token is valid for the current epoch and should be counted
    /// toward spatial diversity. Returns `false` if verification fails or if the
    /// subsystem is in SquadTagFallback mode (Req 15.2, 15.4).
    pub fn peer_has_valid_token(&self, token: &BeaconToken) -> bool {
        if self.mode == AnchorMode::SquadTagFallback {
            return false;
        }
        self.verify_beacon_token(token).is_ok()
    }

    /// Current operating mode.
    pub fn mode(&self) -> AnchorMode {
        self.mode
    }
}

/// Log a Transport Degradation Event (Req 15.4).
fn log_transport_degradation_event(event: &TransportDegradationEvent) {
    eprintln!(
        "[anchor] HIGH-PRIORITY Transport Degradation Event: {}",
        event.reason
    );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::Ed25519Signature;
    use crate::identity::keypair::{generate_keypair, sign};

    fn make_registry_entry(did: &str, public_key: [u8; 32]) -> BeaconRegistryEntry {
        BeaconRegistryEntry {
            beacon_did: did.to_string(),
            public_key,
        }
    }

    fn make_signed_beacon_token(
        beacon_did: &str,
        secret_key: &[u8; 32],
        epoch: u64,
        location: &str,
    ) -> BeaconToken {
        let payload = beacon_token_signing_payload(epoch, location);
        let sig = sign(secret_key, &payload).expect("sign beacon token");
        BeaconToken {
            beacon_did: beacon_did.to_string(),
            beacon_signature: sig,
            epoch,
            location_claim: location.to_string(),
            issued_at: 1_720_000_000_000_000,
        }
    }

    // ── from_beacon_public_keys ──────────────────────────────────────────────

    #[test]
    fn from_beacon_public_keys_derives_registry_dids() {
        let (_, public_a) = generate_keypair().unwrap();
        let (_, public_b) = generate_keypair().unwrap();

        let anchor = AnchorAttestedLocation::from_beacon_public_keys(&[public_a, public_b], 0);

        assert_eq!(anchor.beacon_registry.len(), 2);
        assert_eq!(anchor.beacon_registry[0].beacon_did, derive_did(&public_a));
        assert_eq!(anchor.beacon_registry[0].public_key, public_a);
        assert_eq!(anchor.beacon_registry[1].beacon_did, derive_did(&public_b));
        assert_eq!(anchor.beacon_registry[1].public_key, public_b);
        assert_eq!(anchor.mode(), AnchorMode::BeaconAttested);
    }

    #[test]
    fn from_beacon_public_keys_empty_gives_empty_registry() {
        let anchor = AnchorAttestedLocation::from_beacon_public_keys(&[], 0);
        assert!(anchor.beacon_registry.is_empty());
    }

    // ── verify_beacon_token ──────────────────────────────────────────────────

    #[test]
    fn verify_valid_beacon_token_passes() {
        let (secret, public) = generate_keypair().unwrap();
        let anchor = AnchorAttestedLocation::new(
            vec![make_registry_entry("did:key:z6MkBeacon1", public)],
            0,
        );
        let token = make_signed_beacon_token("did:key:z6MkBeacon1", &secret, 5, "sector-7G");
        assert!(anchor.verify_beacon_token(&token).is_ok());
    }

    #[test]
    fn verify_unknown_beacon_did_fails() {
        let (_secret, public) = generate_keypair().unwrap();
        let anchor = AnchorAttestedLocation::new(
            vec![make_registry_entry("did:key:z6MkBeacon1", public)],
            0,
        );
        // Token claims to be from an unregistered beacon.
        let token = BeaconToken {
            beacon_did: "did:key:z6MkUnknown".to_string(),
            beacon_signature: Ed25519Signature(vec![0; 64]),
            epoch: 1,
            location_claim: "somewhere".to_string(),
            issued_at: 0,
        };
        let result = anchor.verify_beacon_token(&token);
        assert!(result.is_err(), "unknown beacon DID must be rejected");
    }

    #[test]
    fn verify_stale_epoch_token_is_rejected_as_replay() {
        let (secret, public) = generate_keypair().unwrap();
        let anchor = AnchorAttestedLocation::new(
            vec![make_registry_entry("did:key:z6MkBeacon2", public)],
            10, // current epoch is 10
        );
        // Token has epoch 5 — stale.
        let token = make_signed_beacon_token("did:key:z6MkBeacon2", &secret, 5, "sector-A");
        let result = anchor.verify_beacon_token(&token);
        assert!(result.is_err(), "stale epoch must be rejected as replay");
    }

    #[test]
    fn verify_current_epoch_token_passes() {
        let (secret, public) = generate_keypair().unwrap();
        let anchor = AnchorAttestedLocation::new(
            vec![make_registry_entry("did:key:z6MkBeacon3", public)],
            10,
        );
        // Token has epoch == current_epoch (10).
        let token = make_signed_beacon_token("did:key:z6MkBeacon3", &secret, 10, "sector-B");
        assert!(anchor.verify_beacon_token(&token).is_ok());
    }

    #[test]
    fn verify_tampered_beacon_signature_fails() {
        let (secret, public) = generate_keypair().unwrap();
        let anchor = AnchorAttestedLocation::new(
            vec![make_registry_entry("did:key:z6MkBeacon4", public)],
            0,
        );
        let mut token = make_signed_beacon_token("did:key:z6MkBeacon4", &secret, 1, "sector-C");
        // Tamper with signature.
        if let Some(b) = token.beacon_signature.0.first_mut() {
            *b ^= 0xFF;
        }
        let result = anchor.verify_beacon_token(&token);
        assert!(result.is_err(), "tampered signature must be rejected");
    }

    // ── on_beacon_signal_lost ────────────────────────────────────────────────

    #[test]
    fn signal_loss_reverts_to_squad_tag_mode() {
        let (_secret, public) = generate_keypair().unwrap();
        let mut anchor = AnchorAttestedLocation::new(
            vec![make_registry_entry("did:key:z6MkBeacon5", public)],
            0,
        );
        assert_eq!(anchor.mode(), AnchorMode::BeaconAttested);

        anchor
            .on_beacon_signal_lost(1_720_000_000_000_000, vec!["did:key:z6MkPeer1".to_string()])
            .unwrap();

        assert_eq!(anchor.mode(), AnchorMode::SquadTagFallback);
    }

    #[test]
    fn signal_loss_appends_to_degradation_log() {
        let mut anchor = AnchorAttestedLocation::new(vec![], 0);
        assert_eq!(anchor.degradation_log().len(), 0);

        anchor
            .on_beacon_signal_lost(9_999, vec!["did:key:z6MkX".to_string()])
            .unwrap();

        let log = anchor.degradation_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].timestamp, 9_999);
        assert_eq!(log[0].affected_peer_dids, vec!["did:key:z6MkX".to_string()]);
    }

    #[test]
    fn multiple_signal_loss_events_append_to_log() {
        let mut anchor = AnchorAttestedLocation::new(vec![], 0);
        anchor.on_beacon_signal_lost(1_000, vec![]).unwrap();
        anchor.on_beacon_signal_lost(2_000, vec![]).unwrap();
        assert_eq!(anchor.degradation_log().len(), 2);
    }

    // ── peer_has_valid_token ──────────────────────────────────────────────────

    #[test]
    fn peer_has_valid_token_true_when_beacon_verified() {
        let (secret, public) = generate_keypair().unwrap();
        let anchor = AnchorAttestedLocation::new(
            vec![make_registry_entry("did:key:z6MkBeacon6", public)],
            0,
        );
        let token = make_signed_beacon_token("did:key:z6MkBeacon6", &secret, 0, "sector-X");
        assert!(anchor.peer_has_valid_token(&token));
    }

    #[test]
    fn peer_has_valid_token_false_in_squad_tag_fallback_mode() {
        let (secret, public) = generate_keypair().unwrap();
        let mut anchor = AnchorAttestedLocation::new(
            vec![make_registry_entry("did:key:z6MkBeacon7", public)],
            0,
        );
        // Signal loss puts us in fallback mode.
        anchor.on_beacon_signal_lost(0, vec![]).unwrap();

        let token = make_signed_beacon_token("did:key:z6MkBeacon7", &secret, 0, "sector-Y");
        // Even with a valid token, fallback mode returns false.
        assert!(!anchor.peer_has_valid_token(&token));
    }

    // ── advance_epoch ────────────────────────────────────────────────────────

    #[test]
    fn advance_epoch_only_advances_forward() {
        let mut anchor = AnchorAttestedLocation::new(vec![], 5);
        anchor.advance_epoch(3); // should not decrease
        assert_eq!(anchor.current_epoch, 5);
        anchor.advance_epoch(10);
        assert_eq!(anchor.current_epoch, 10);
    }

    // ── Subphase 7.6: stale-epoch rejection under simulated skew ──────────────
    //
    // A beacon issues location tokens carrying a Lamport epoch.  During a long
    // network partition the beacon keeps advancing its epoch (it is still
    // alive in the quorum), but an isolated device retains only a token from
    // before the partition.  The token's epoch is now *stale relative to the
    // advanced current_epoch*.  On rejoin, the stale token must be rejected as
    // a replay (Req 15.3) — not at a static epoch value, but after the epoch
    // *advanced during the simulated partition*.
    //
    // This is the Subphase 7.6 acceptance criterion #2 test: "anchor-beacon
    // stale-epoch rejection works correctly under simulated skew."
    //
    // Production path exercised:
    //   `AnchorAttestedLocation::verify_beacon_token` (anchor.rs:147)
    //     → stale-epoch check: `token.epoch < self.current_epoch` (anchor.rs:149)
    //   Production caller: `DurabilitySubsystem::receive_receipt`
    //     → `peer_has_valid_token` (anchor.rs:226) (durability/mod.rs:344-347).
    //
    // The existing `verify_stale_epoch_token_is_rejected_as_replay` test covers
    // stale rejection at *static* epoch values (created with token.epoch=5,
    // current_epoch=10).  This test simulates the partition: the token is
    // initially valid, THEN the epoch advances, THEN the token is rejected.

    #[test]
    fn stale_epoch_rejected_after_beacon_advances_during_partition() {
        let (b_secret, b_public) = generate_keypair().expect("beacon keygen");
        let beacon_did = derive_did(&b_public);

        // Anchor starts at epoch 0 — the beacon's epoch before the partition.
        // The device holds a token at epoch 3 (issued before the partition).
        let mut anchor = AnchorAttestedLocation::new(
            vec![BeaconRegistryEntry {
                beacon_did: beacon_did.clone(),
                public_key: b_public,
            }],
            0,
        );

        // Phase 1: before partition, the epoch-3 token is valid.
        let pre_partition_token = make_signed_beacon_token(&beacon_did, &b_secret, 3, "sector-7G");
        assert!(
            anchor.verify_beacon_token(&pre_partition_token).is_ok(),
            "token at epoch 3 must be valid when current_epoch is 0 (3 >= 0)"
        );

        // Phase 2: simulated long partition — the beacon advances its epoch.
        // During the partition, the beacon keeps operating and its epoch moves
        // forward from 0 → 10.  The isolated device cannot receive the new
        // tokens, so its cached epoch-3 token is now 7 epochs stale.
        anchor.advance_epoch(10);
        assert_eq!(
            anchor.current_epoch, 10,
            "beacon epoch must advance to 10 during the simulated partition"
        );

        // Phase 3: rejoin — the stale token (epoch 3) must be rejected.
        // The stale-epoch check at anchor.rs:149 (`token.epoch < current_epoch`)
        // fires: 3 < 10 → StaleEpoch replay rejection (Req 15.3).
        let result = anchor.verify_beacon_token(&pre_partition_token);
        assert!(
            result.is_err(),
            "stale beacon token (epoch 3) must be rejected after the epoch \
             advanced to 10 during the simulated partition — anchor.rs:149"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("stale") || err.contains("replay"),
            "stale-epoch rejection must be reported as a replay/stale error, got: {err}"
        );

        // Phase 4: a fresh token at the current epoch (10) verifies normally.
        // The stale-epoch rejection must not poison future valid tokens.
        let fresh_token = make_signed_beacon_token(&beacon_did, &b_secret, 10, "sector-7G");
        assert!(
            anchor.verify_beacon_token(&fresh_token).is_ok(),
            "fresh token at epoch 10 must verify after rejoin"
        );

        // Phase 5: the stale token is permanently stale — it must still be
        // rejected even after a fresh token is accepted.  The check is purely
        // `token.epoch < current_epoch`, which is token-state-driven.
        let still_stale = anchor.verify_beacon_token(&pre_partition_token);
        assert!(
            still_stale.is_err(),
            "the pre-partition stale token must remain rejected even after a fresh token is accepted"
        );
    }

    /// Companion: verify `peer_has_valid_token` (the production gate used by
    /// `DurabilitySubsystem::receive_receipt` at durability/mod.rs:344-347)
    /// also rejects stale-epoch tokens under simulated skew — not just
    /// `verify_beacon_token`.  This closes the production-caller coverage gap:
    /// `receive_receipt` delegates to `peer_has_valid_token`, so the stale-epoch
    /// rejection must propagate through that path too.
    #[test]
    fn peer_has_valid_token_rejects_stale_epoch_under_simulated_skew() {
        let (b_secret, b_public) = generate_keypair().expect("beacon keygen");
        let beacon_did = derive_did(&b_public);

        let mut anchor = AnchorAttestedLocation::new(
            vec![BeaconRegistryEntry {
                beacon_did: beacon_did.clone(),
                public_key: b_public,
            }],
            0,
        );
        assert_eq!(anchor.mode(), AnchorMode::BeaconAttested);

        // Epoch-0 token is valid at the start.
        let stale_token = make_signed_beacon_token(&beacon_did, &b_secret, 0, "sector-A");
        assert!(
            anchor.peer_has_valid_token(&stale_token),
            "token must be valid in peer_has_valid_token before the epoch advances"
        );

        // Beacon advances its epoch during the simulated partition.
        anchor.advance_epoch(5);
        assert_eq!(anchor.current_epoch, 5);

        // After the epoch advance, the stale epoch-0 token is rejected — the
        // production `peer_has_valid_token` gate (anchor.rs:226) must return
        // false, which is the exact path `receive_receipt` checks.
        assert!(
            !anchor.peer_has_valid_token(&stale_token),
            "peer_has_valid_token must reject the stale-epoch token after the \
             beacon's epoch advances during a simulated partition (Req 15.3)"
        );
    }
}
