//! QuarantineLedger — byte-for-byte raw Delta store for schema-incompatible Deltas (Req 17.4–17.6).
//!
//! SQLite schema:
//! ```sql
//! CREATE TABLE quarantine_ledger (
//!     id           BLOB PRIMARY KEY,
//!     sender_did   TEXT NOT NULL,
//!     raw_bytes    BLOB NOT NULL,
//!     schema_hash  BLOB,
//!     reason       TEXT NOT NULL,
//!     received_at  INTEGER NOT NULL,
//!     migration_id BLOB
//! );
//! ```

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::{Did, DeltaId};
use crate::errors::TirBaseError;
use crate::schema::hash::SchemaIdentifierHash;
use serde::{Deserialize, Serialize};

/// Reason a Delta was quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineReason {
    BreakingSchemaChange,
    UnknownSchemaHash,
    MissingOrMalformedHash,
}

/// A quarantined Delta entry stored byte-for-byte without modification (Req 17.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: DeltaId,
    pub sender_did: Did,
    /// Byte-for-byte copy of the received Delta stream.
    pub raw_bytes: Vec<u8>,
    /// May be None if the hash field was absent or malformed.
    pub schema_hash: Option<SchemaIdentifierHash>,
    pub reason: QuarantineReason,
    /// UTC timestamp (microseconds).
    pub received_at: i64,
    /// Set when a migration is in progress for this hash.
    pub migration_id: Option<[u8; 32]>,
}

/// SQLite-backed store for Deltas blocked by schema incompatibility.
pub struct QuarantineLedger {
    // TODO(task-8): inject LocalStore handle
}

impl QuarantineLedger {
    /// Store a raw incoming Delta without modification (Req 17.5).
    pub fn quarantine(
        &mut self,
        sender_did: Did,
        raw_bytes: Vec<u8>,
        schema_hash: Option<SchemaIdentifierHash>,
        reason: QuarantineReason,
        received_at: i64,
    ) -> Result<DeltaId, TirBaseError> {
        todo!("Task 8: implement with LocalStore")
    }

    /// Return all quarantined entries for a given schema hash.
    pub fn get_by_schema_hash(
        &self,
        hash: &SchemaIdentifierHash,
    ) -> Result<Vec<QuarantineEntry>, TirBaseError> {
        todo!("Task 8: implement with LocalStore")
    }

    /// Release quarantined entries for replay once a valid migration is applied.
    pub fn release_for_migration(
        &mut self,
        schema_hash: &SchemaIdentifierHash,
        migration_id: [u8; 32],
    ) -> Result<Vec<QuarantineEntry>, TirBaseError> {
        todo!("Task 8: implement with LocalStore")
    }
}
