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
