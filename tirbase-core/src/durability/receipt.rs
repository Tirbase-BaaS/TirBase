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
