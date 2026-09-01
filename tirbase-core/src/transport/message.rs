//! GossipMessage — deserialized inbound message variants received from the Gossipsub Swarm.
//!
//! All messages flowing into the TirBase mesh are tagged with a variant so the
//! inbound pipeline in `CoreHandle::receive_inbound` can dispatch them to the
//! correct subsystem without additional heuristics.

use crate::auth::RevocationDelta;
use crate::crdt::delta::Delta;
use crate::durability::receipt::DurabilityReceipt;
use crate::migration::migration_delta::{MigrationDelta, MigrationRevocationDelta};
use serde::{Deserialize, Serialize};

/// A typed inbound message received over the Gossipsub mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// An inbound data Delta from a peer (Req 4.3–4.7).
    InboundDelta(Delta),
    /// A signed DurabilityReceipt from a peer (Req 14.6).
    InboundDurabilityReceipt(DurabilityReceipt),
    /// A (possibly partial) RevocationDelta from a peer (Req 9.3).
    InboundRevocationDelta(RevocationDelta),
    /// A schema-migration Delta from a peer (Req 18).
    InboundMigrationDelta(MigrationDelta),
    /// A migration-revocation Delta from a peer (Req 18.5).
    InboundMigrationRevocationDelta(MigrationRevocationDelta),
}

impl GossipMessage {
    /// Attempt to deserialise raw Gossipsub message bytes into a `GossipMessage`.
    ///
    /// Returns `None` if the bytes cannot be parsed into any known variant.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }

    /// Serialise this message to bytes for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::{Ed25519Signature, PriorityClass};

    fn make_delta() -> Delta {
        Delta {
            id: [0u8; 32],
            author_did: "did:key:z6MkTest".to_string(),
            signature: Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![1, 2, 3],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 1_000_000,
        }
    }

    #[test]
    fn gossip_message_inbound_delta_round_trip() {
        let msg = GossipMessage::InboundDelta(make_delta());
        let bytes = msg.to_bytes();
        assert!(!bytes.is_empty(), "serialised message must not be empty");
        let decoded = GossipMessage::from_bytes(&bytes).expect("must deserialise");
        match decoded {
            GossipMessage::InboundDelta(d) => {
                assert_eq!(d.author_did, "did:key:z6MkTest");
                assert_eq!(d.lamport, 1);
            }
            other => panic!("expected InboundDelta, got {other:?}"),
        }
    }

    #[test]
    fn gossip_message_from_invalid_bytes_returns_none() {
        let result = GossipMessage::from_bytes(b"not-valid-json");
        assert!(result.is_none(), "garbage bytes must return None");
    }

    #[test]
    fn gossip_message_from_empty_bytes_returns_none() {
        let result = GossipMessage::from_bytes(b"");
        assert!(result.is_none(), "empty bytes must return None");
    }
}
