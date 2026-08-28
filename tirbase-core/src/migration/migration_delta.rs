//! MigrationDelta and MigrationRevocationDelta structs; CA sig + SHA-256 gate.

#![allow(dead_code)]

use crate::crdt::delta::{Did, Ed25519Signature, PriorityClass};
use crate::schema::hash::SchemaIdentifierHash;
use serde::{Deserialize, Serialize};

/// A unique migration identifier: SHA-256(transform_bytes).
pub type MigrationId = [u8; 32];

/// A CA signature over the transform bytes (serialised as bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CaSignature(#[serde(with = "serde_bytes")] pub Vec<u8>);

use serde_bytes;

/// A Manager DID signature (DID + Ed25519 signature pair).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerSignature {
    pub manager_did: Did,
    pub signature: Ed25519Signature,
}

/// A signed delta that distributes a schema migration transform over the mesh (Req 18).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationDelta {
    /// SHA-256(transform_bytes) — also serves as the migration identifier.
    pub id: MigrationId,
    /// Manager DID that authored this migration.
    pub author_did: Did,
    /// Ed25519 signature over `canonical_bytes()`.
    pub signature: Ed25519Signature,
    /// Source schema version this migration expects to find locally (Req 18.3a).
    pub source_schema_hash: SchemaIdentifierHash,
    /// Target schema version after applying the transform (Req 18.3a).
    pub target_schema_hash: SchemaIdentifierHash,
    /// WASM transform bytecode (never raw JS — Req 18.2).
    pub transform_bytes: Vec<u8>,
    /// CA signature over `transform_bytes` (zero-trust gate — Req 18.2).
    pub ca_signature: CaSignature,
    /// SHA-256 of `transform_bytes` (embedded for integrity — Req 18.2).
    pub transform_sha256: [u8; 32],
    /// Migration Deltas are always MEDIUM priority.
    pub priority: PriorityClass,
    /// Wall-clock creation time (UTC, microseconds).
    pub created_at: i64,
}

/// A revocation delta that halts a migration that was found to be corrupted (Req 18.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRevocationDelta {
    /// The migration script hash to revoke.
    pub target_migration_id: MigrationId,
    /// M-of-N Manager DID signatures (threshold matches deployment config).
    pub signatures: Vec<ManagerSignature>,
    /// Wall-clock creation time (UTC, microseconds).
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::Ed25519Signature;

    fn make_manager_signature(did: &str) -> ManagerSignature {
        ManagerSignature {
            manager_did: did.to_string(),
            signature: Ed25519Signature(vec![0xAAu8; 64]),
        }
    }

    fn make_migration_delta() -> MigrationDelta {
        MigrationDelta {
            id: [0x01u8; 32],
            author_did: "did:key:z6MkMgr1".to_string(),
            signature: Ed25519Signature(vec![0x02u8; 64]),
            source_schema_hash: [0x10u8; 32],
            target_schema_hash: [0x11u8; 32],
            transform_bytes: b"(module)".to_vec(),
            ca_signature: CaSignature(b"ca-sig".to_vec()),
            transform_sha256: [0x20u8; 32],
            priority: PriorityClass::Medium,
            created_at: 1_720_000_000_000_000,
        }
    }

    #[test]
    fn migration_delta_serde_round_trip() {
        let md = make_migration_delta();
        let json = serde_json::to_string(&md).expect("serialise MigrationDelta");
        let decoded: MigrationDelta =
            serde_json::from_str(&json).expect("deserialise MigrationDelta");

        assert_eq!(md.id, decoded.id);
        assert_eq!(md.author_did, decoded.author_did);
        assert_eq!(md.source_schema_hash, decoded.source_schema_hash);
        assert_eq!(md.target_schema_hash, decoded.target_schema_hash);
        assert_eq!(md.transform_bytes, decoded.transform_bytes);
        assert_eq!(md.transform_sha256, decoded.transform_sha256);
        assert_eq!(md.ca_signature.0, decoded.ca_signature.0);
    }

    #[test]
    fn migration_revocation_delta_serde_round_trip() {
        let rev = MigrationRevocationDelta {
            target_migration_id: [0xFFu8; 32],
            signatures: vec![
                make_manager_signature("did:key:z6MkMgr1"),
                make_manager_signature("did:key:z6MkMgr2"),
            ],
            created_at: 1_720_000_005_000_000,
        };

        let json = serde_json::to_string(&rev).expect("serialise revocation delta");
        let decoded: MigrationRevocationDelta =
            serde_json::from_str(&json).expect("deserialise revocation delta");

        assert_eq!(rev.target_migration_id, decoded.target_migration_id);
        assert_eq!(rev.signatures.len(), decoded.signatures.len());
        assert_eq!(rev.signatures[0].manager_did, decoded.signatures[0].manager_did);
    }

    #[test]
    fn ca_signature_default_is_empty() {
        let sig = CaSignature::default();
        assert!(sig.0.is_empty());
    }
}
