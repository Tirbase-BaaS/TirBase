//! DurabilityReceipt — peer-signed state-hash receipt for Tier-1 durability (Req 14.6).
//!
//! Provides the data model and signature-verification logic for `DurabilityReceipt`.
//! A receipt is accepted toward Quorum only when both its Ed25519 signature **and**
//! the state-hash match are verified successfully.

#![allow(dead_code)]

use crate::crdt::delta::{Did, Ed25519Signature};
use crate::errors::TirBaseError;
use crate::identity::keypair;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a DurabilityReceipt.
pub type ReceiptId = Uuid;

/// A signed acknowledgement from a peer confirming it holds a state-hash of
/// a committed set of Deltas (Req 14.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurabilityReceipt {
    pub id: ReceiptId,
    /// SHA-256 hash of the committed Delta set.
    pub state_hash: [u8; 32],
    /// The peer that issued this receipt.
    pub issuer_did: Did,
    /// Ed25519 signature over `receipt_signing_payload(state_hash, receipt_id)`.
    pub issuer_signature: Ed25519Signature,
    /// Spatial diversity tag of the issuing peer (squad or tunnel_sector).
    pub spatial_tag: Option<String>,
    /// Beacon-attested location token (if Anchor_Attested_Location is enabled).
    pub beacon_token: Option<BeaconToken>,
    /// UTC timestamp (microseconds) when this receipt was issued.
    pub issued_at: i64,
}

/// An optional beacon-signed location token for verifiable Spatial_Diversity (Req 15.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconToken {
    /// DID of the fixed beacon that issued this token.
    pub beacon_did: Did,
    /// Ed25519 signature over the location claim and epoch.
    pub beacon_signature: Ed25519Signature,
    /// Lamport epoch from the beacon (used to reject stale replay tokens — Req 15.3).
    pub epoch: u64,
    /// Human-readable location claim.
    pub location_claim: String,
    /// UTC timestamp (microseconds) when this token was issued.
    pub issued_at: i64,
}

/// Produce the canonical signing payload for a `DurabilityReceipt`.
///
/// `payload = state_hash (32 bytes) || receipt_id_bytes (16 bytes)`
///
/// Using a deterministic, fixed-length payload prevents length-extension
/// attacks and ambiguity between fields.
pub fn receipt_signing_payload(state_hash: &[u8; 32], receipt_id: &ReceiptId) -> Vec<u8> {
    let mut payload = Vec::with_capacity(48);
    payload.extend_from_slice(state_hash);
    payload.extend_from_slice(receipt_id.as_bytes());
    payload
}

/// Verify a `DurabilityReceipt` against a known issuer public key and the
/// expected state hash (Req 14.6).
///
/// Both checks must pass before the receipt is counted toward Quorum:
/// 1. Ed25519 signature over `receipt_signing_payload(state_hash, receipt_id)`.
/// 2. The receipt's `state_hash` matches the `expected_state_hash`.
///
/// On failure the rejection is logged with the peer DID and failure reason,
/// and a `SignatureVerificationFailed` (or distinct) error is returned.
pub fn verify_receipt(
    receipt: &DurabilityReceipt,
    issuer_public_key: &[u8; 32],
    expected_state_hash: &[u8; 32],
) -> Result<(), TirBaseError> {
    // Check 1: state-hash match.
    if &receipt.state_hash != expected_state_hash {
        let reason = format!(
            "state-hash mismatch for peer {}: expected {}, got {}",
            receipt.issuer_did,
            hex::encode(expected_state_hash),
            hex::encode(receipt.state_hash),
        );
        log_receipt_rejection(&receipt.issuer_did, &reason);
        return Err(TirBaseError::SignatureVerificationFailed { reason });
    }

    // Check 2: Ed25519 signature.
    let payload = receipt_signing_payload(&receipt.state_hash, &receipt.id);
    keypair::verify(issuer_public_key, &payload, &receipt.issuer_signature).map_err(|e| {
        let reason = format!(
            "receipt signature invalid for peer {}: {}",
            receipt.issuer_did, e
        );
        log_receipt_rejection(&receipt.issuer_did, &reason);
        TirBaseError::SignatureVerificationFailed { reason }
    })?;

    Ok(())
}

/// Log a receipt rejection (writes to stderr in production; runtime receipt
/// rejection events are not routed through the structured diagnostics channel,
/// which is startup-only in v1).
fn log_receipt_rejection(peer_did: &str, reason: &str) {
    // In v1 this uses eprintln! as the structured diagnostics channel is
    // startup-only (see diagnostics/mod.rs).  The caller is responsible for
    // constructing the full reason string that identifies both the peer DID
    // and the failure reason (Req 14.6).
    eprintln!("[durability] receipt rejected from {peer_did}: {reason}");
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keypair::{generate_keypair, sign};

    /// Create a properly signed receipt for testing.
    fn make_signed_receipt(
        state_hash: [u8; 32],
        secret_key: &[u8; 32],
        public_key_did: &str,
        spatial_tag: Option<&str>,
    ) -> DurabilityReceipt {
        let id = Uuid::now_v7();
        let payload = receipt_signing_payload(&state_hash, &id);
        let signature = sign(secret_key, &payload).expect("sign");
        DurabilityReceipt {
            id,
            state_hash,
            issuer_did: public_key_did.to_string(),
            issuer_signature: signature,
            spatial_tag: spatial_tag.map(|s| s.to_string()),
            beacon_token: None,
            issued_at: 1_720_000_000_000_000,
        }
    }

    #[test]
    fn beacon_token_serde_round_trip() {
        let bt = BeaconToken {
            beacon_did: "did:key:z6MkBeacon".to_string(),
            beacon_signature: Ed25519Signature(vec![0x01; 64]),
            epoch: 42,
            location_claim: "sector-7G".to_string(),
            issued_at: 1_720_000_000_000_000,
        };
        let json = serde_json::to_string(&bt).expect("serialise BeaconToken");
        let decoded: BeaconToken = serde_json::from_str(&json).expect("deserialise BeaconToken");
        assert_eq!(bt.beacon_did, decoded.beacon_did);
        assert_eq!(bt.epoch, decoded.epoch);
        assert_eq!(bt.location_claim, decoded.location_claim);
        assert_eq!(bt.beacon_signature.0, decoded.beacon_signature.0);
    }

    #[test]
    fn durability_receipt_without_beacon_round_trip() {
        let receipt = DurabilityReceipt {
            id: Uuid::now_v7(),
            state_hash: [0xAA; 32],
            issuer_did: "did:key:z6MkPeer".to_string(),
            issuer_signature: Ed25519Signature(vec![0x02; 64]),
            spatial_tag: Some("squad-alpha".to_string()),
            beacon_token: None,
            issued_at: 1_720_000_001_000_000,
        };

        let json = serde_json::to_string(&receipt).expect("serialise receipt");
        let decoded: DurabilityReceipt =
            serde_json::from_str(&json).expect("deserialise receipt");

        assert_eq!(receipt.id, decoded.id);
        assert_eq!(receipt.state_hash, decoded.state_hash);
        assert_eq!(receipt.spatial_tag, decoded.spatial_tag);
        assert!(decoded.beacon_token.is_none());
    }

    #[test]
    fn durability_receipt_with_beacon_round_trip() {
        let bt = BeaconToken {
            beacon_did: "did:key:z6MkBeacon".to_string(),
            beacon_signature: Ed25519Signature(vec![0x01; 64]),
            epoch: 42,
            location_claim: "sector-7G".to_string(),
            issued_at: 1_720_000_000_000_000,
        };
        let receipt = DurabilityReceipt {
            id: Uuid::now_v7(),
            state_hash: [0xBB; 32],
            issuer_did: "did:key:z6MkPeer2".to_string(),
            issuer_signature: Ed25519Signature(vec![0x03; 64]),
            spatial_tag: None,
            beacon_token: Some(bt),
            issued_at: 1_720_000_002_000_000,
        };

        let json = serde_json::to_string(&receipt).expect("serialise receipt with beacon");
        let decoded: DurabilityReceipt =
            serde_json::from_str(&json).expect("deserialise receipt with beacon");

        assert!(decoded.beacon_token.is_some());
        assert_eq!(
            decoded.beacon_token.unwrap().epoch,
            receipt.beacon_token.unwrap().epoch
        );
    }

    // ── verify_receipt ───────────────────────────────────────────────────────

    #[test]
    fn verify_receipt_valid_passes() {
        let (secret, public) = generate_keypair().unwrap();
        let state_hash = [0xDE; 32];
        let receipt = make_signed_receipt(state_hash, &secret, "did:key:z6MkP1", Some("squad-1"));
        assert!(verify_receipt(&receipt, &public, &state_hash).is_ok());
    }

    #[test]
    fn verify_receipt_state_hash_mismatch_fails() {
        let (secret, public) = generate_keypair().unwrap();
        let state_hash = [0xDE; 32];
        let receipt = make_signed_receipt(state_hash, &secret, "did:key:z6MkP2", None);
        let wrong_hash = [0xFF; 32];
        let result = verify_receipt(&receipt, &public, &wrong_hash);
        assert!(result.is_err(), "mismatched state_hash must be rejected");
    }

    #[test]
    fn verify_receipt_tampered_signature_fails() {
        let (secret, public) = generate_keypair().unwrap();
        let state_hash = [0xAB; 32];
        let mut receipt = make_signed_receipt(state_hash, &secret, "did:key:z6MkP3", None);
        // Flip first byte of signature
        if let Some(b) = receipt.issuer_signature.0.first_mut() {
            *b ^= 0xFF;
        }
        let result = verify_receipt(&receipt, &public, &state_hash);
        assert!(result.is_err(), "tampered signature must be rejected");
    }

    #[test]
    fn verify_receipt_wrong_public_key_fails() {
        let (secret, _public) = generate_keypair().unwrap();
        let (_other_secret, other_public) = generate_keypair().unwrap();
        let state_hash = [0xCD; 32];
        let receipt = make_signed_receipt(state_hash, &secret, "did:key:z6MkP4", None);
        let result = verify_receipt(&receipt, &other_public, &state_hash);
        assert!(result.is_err(), "wrong public key must be rejected");
    }
}
