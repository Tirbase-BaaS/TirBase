//! DurabilityReceipt — peer-signed state-hash receipt for Tier-1 durability (Req 14.6).

#![allow(dead_code)]

use crate::crdt::delta::{Did, Ed25519Signature};
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
    /// Ed25519 signature over `(state_hash || delta_set_id)`.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_beacon_token() -> BeaconToken {
        BeaconToken {
            beacon_did: "did:key:z6MkBeacon".to_string(),
            beacon_signature: Ed25519Signature(vec![0x01; 64]),
            epoch: 42,
            location_claim: "sector-7G".to_string(),
            issued_at: 1_720_000_000_000_000,
        }
    }

    #[test]
    fn beacon_token_serde_round_trip() {
        let bt = make_beacon_token();
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
        let receipt = DurabilityReceipt {
            id: Uuid::now_v7(),
            state_hash: [0xBB; 32],
            issuer_did: "did:key:z6MkPeer2".to_string(),
            issuer_signature: Ed25519Signature(vec![0x03; 64]),
            spatial_tag: None,
            beacon_token: Some(make_beacon_token()),
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
}
