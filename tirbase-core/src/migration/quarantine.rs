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

impl QuarantineReason {
    /// Serialise to the text value stored in SQLite.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BreakingSchemaChange => "BREAKING_CHANGE",
            Self::UnknownSchemaHash => "UNKNOWN_HASH",
            Self::MissingOrMalformedHash => "MISSING_HASH",
        }
    }

    /// Parse from the text value stored in SQLite.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "BREAKING_CHANGE" => Some(Self::BreakingSchemaChange),
            "UNKNOWN_HASH" => Some(Self::UnknownSchemaHash),
            "MISSING_HASH" => Some(Self::MissingOrMalformedHash),
            _ => None,
        }
    }
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

// ─── Native implementation ─────────────────────────────────────────────────

/// SQLite-backed store for Deltas blocked by schema incompatibility.
#[cfg(feature = "native")]
pub struct QuarantineLedger {
    conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
}

#[cfg(feature = "native")]
impl QuarantineLedger {
    /// Create a new QuarantineLedger backed by the given SQLite connection.
    /// The schema tables are assumed to already exist (created by store/sqlite.rs).
    pub fn new(conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>) -> Self {
        Self { conn }
    }

    /// Store a raw incoming Delta without modification (Req 17.5).
    ///
    /// The `id` is computed as SHA-256(raw_bytes) so it's deterministic.
    pub fn quarantine(
        &mut self,
        sender_did: Did,
        raw_bytes: Vec<u8>,
        schema_hash: Option<SchemaIdentifierHash>,
        reason: QuarantineReason,
        received_at: i64,
    ) -> Result<DeltaId, TirBaseError> {
        use sha2::{Digest, Sha256};

        let id: DeltaId = Sha256::digest(&raw_bytes).into();
        let reason_str = reason.as_str();

        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("QuarantineLedger mutex poisoned: {e}"),
        })?;

        conn.execute(
            "INSERT OR IGNORE INTO quarantine_ledger \
             (id, sender_did, raw_bytes, schema_hash, reason, received_at, migration_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            rusqlite::params![
                &id[..],
                &sender_did,
                &raw_bytes[..],
                schema_hash.as_ref().map(|h| &h[..]),
                reason_str,
                received_at,
            ],
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("INSERT quarantine_ledger failed: {e}"),
        })?;

        Ok(id)
    }

    /// Return all quarantined entries for a given schema hash.
    pub fn get_by_schema_hash(
        &self,
        hash: &SchemaIdentifierHash,
    ) -> Result<Vec<QuarantineEntry>, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("QuarantineLedger mutex poisoned: {e}"),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT id, sender_did, raw_bytes, schema_hash, reason, received_at, migration_id \
                 FROM quarantine_ledger WHERE schema_hash = ?1",
            )
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Prepare get_by_schema_hash failed: {e}"),
            })?;

        let entries = stmt
            .query_map(rusqlite::params![&hash[..]], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Query quarantine_ledger failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id_bytes, sender_did, raw_bytes, schema_bytes, reason_str, received_at, migration_bytes)| {
                let id: DeltaId = id_bytes.try_into().ok()?;
                let schema_hash: Option<SchemaIdentifierHash> = schema_bytes
                    .and_then(|b| b.try_into().ok());
                let migration_id: Option<[u8; 32]> = migration_bytes
                    .and_then(|b| b.try_into().ok());
                let reason = QuarantineReason::from_str(&reason_str)?;
                Some(QuarantineEntry {
                    id,
                    sender_did,
                    raw_bytes,
                    schema_hash,
                    reason,
                    received_at,
                    migration_id,
                })
            })
            .collect();

        Ok(entries)
    }

    /// Return all quarantined entries (regardless of schema hash).
    pub fn get_all(&self) -> Result<Vec<QuarantineEntry>, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("QuarantineLedger mutex poisoned: {e}"),
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT id, sender_did, raw_bytes, schema_hash, reason, received_at, migration_id \
                 FROM quarantine_ledger",
            )
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Prepare get_all failed: {e}"),
            })?;

        let entries = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Query quarantine_ledger get_all failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id_bytes, sender_did, raw_bytes, schema_bytes, reason_str, received_at, migration_bytes)| {
                let id: DeltaId = id_bytes.try_into().ok()?;
                let schema_hash: Option<SchemaIdentifierHash> = schema_bytes
                    .and_then(|b| b.try_into().ok());
                let migration_id: Option<[u8; 32]> = migration_bytes
                    .and_then(|b| b.try_into().ok());
                let reason = QuarantineReason::from_str(&reason_str)?;
                Some(QuarantineEntry {
                    id,
                    sender_did,
                    raw_bytes,
                    schema_hash,
                    reason,
                    received_at,
                    migration_id,
                })
            })
            .collect();

        Ok(entries)
    }

    /// Release quarantined entries for replay once a valid migration is applied.
    ///
    /// Sets `migration_id` on all entries matching `schema_hash` and returns them.
    pub fn release_for_migration(
        &mut self,
        schema_hash: &SchemaIdentifierHash,
        migration_id: [u8; 32],
    ) -> Result<Vec<QuarantineEntry>, TirBaseError> {
        // First, update the migration_id field on all matching rows.
        {
            let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("QuarantineLedger mutex poisoned: {e}"),
            })?;

            conn.execute(
                "UPDATE quarantine_ledger SET migration_id = ?1 WHERE schema_hash = ?2",
                rusqlite::params![&migration_id[..], &schema_hash[..]],
            )
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("UPDATE quarantine_ledger migration_id failed: {e}"),
            })?;
        }

        // Then fetch the updated entries.
        self.get_by_schema_hash(schema_hash)
    }

    /// Count all quarantined entries.
    pub fn count(&self) -> Result<usize, TirBaseError> {
        let conn = self.conn.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("QuarantineLedger mutex poisoned: {e}"),
        })?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM quarantine_ledger", [], |row| {
                row.get(0)
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("COUNT quarantine_ledger failed: {e}"),
            })?;

        Ok(count as usize)
    }
}

// ─── WASM stub ─────────────────────────────────────────────────────────────

#[cfg(not(feature = "native"))]
pub struct QuarantineLedger {
    entries: Vec<QuarantineEntry>,
}

#[cfg(not(feature = "native"))]
impl QuarantineLedger {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Store a raw incoming Delta without modification (Req 17.5).
    ///
    /// The `id` is computed as SHA-256(raw_bytes) so it's deterministic.
    pub fn quarantine(
        &mut self,
        sender_did: Did,
        raw_bytes: Vec<u8>,
        schema_hash: Option<SchemaIdentifierHash>,
        reason: QuarantineReason,
        received_at: i64,
    ) -> Result<DeltaId, TirBaseError> {
        use sha2::{Digest, Sha256};
        let id: DeltaId = Sha256::digest(&raw_bytes).into();

        // Deduplicate by id (INSERT OR IGNORE semantics).
        if !self.entries.iter().any(|e| e.id == id) {
            self.entries.push(QuarantineEntry {
                id,
                sender_did,
                raw_bytes,
                schema_hash,
                reason,
                received_at,
                migration_id: None,
            });
        }
        Ok(id)
    }

    pub fn get_by_schema_hash(
        &self,
        hash: &SchemaIdentifierHash,
    ) -> Result<Vec<QuarantineEntry>, TirBaseError> {
        Ok(self
            .entries
            .iter()
            .filter(|e| e.schema_hash.as_ref() == Some(hash))
            .cloned()
            .collect())
    }

    pub fn get_all(&self) -> Result<Vec<QuarantineEntry>, TirBaseError> {
        Ok(self.entries.clone())
    }

    pub fn release_for_migration(
        &mut self,
        schema_hash: &SchemaIdentifierHash,
        migration_id: [u8; 32],
    ) -> Result<Vec<QuarantineEntry>, TirBaseError> {
        for entry in self.entries.iter_mut() {
            if entry.schema_hash.as_ref() == Some(schema_hash) {
                entry.migration_id = Some(migration_id);
            }
        }
        self.get_by_schema_hash(schema_hash)
    }

    pub fn count(&self) -> Result<usize, TirBaseError> {
        Ok(self.entries.len())
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::store::sqlite::CREATE_SCHEMA_SQL;
    use std::sync::{Arc, Mutex};

    fn open_ledger() -> QuarantineLedger {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory DB");
        conn.execute_batch(CREATE_SCHEMA_SQL).expect("create schema");
        let conn = Arc::new(Mutex::new(conn));
        QuarantineLedger::new(conn)
    }

    #[test]
    fn quarantine_stores_entry_without_modification() {
        let mut ledger = open_ledger();
        let raw = b"raw-delta-bytes-exactly-as-received".to_vec();
        let schema_hash: SchemaIdentifierHash = [0xAAu8; 32];

        let id = ledger
            .quarantine(
                "did:key:z6MkSender".to_string(),
                raw.clone(),
                Some(schema_hash),
                QuarantineReason::UnknownSchemaHash,
                1_720_000_000_000_000,
            )
            .expect("quarantine should succeed");

        let entries = ledger
            .get_by_schema_hash(&schema_hash)
            .expect("get_by_schema_hash");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id);
        // Req 17.5: byte-for-byte copy, no modification
        assert_eq!(entries[0].raw_bytes, raw, "raw_bytes must be unmodified");
        assert_eq!(entries[0].sender_did, "did:key:z6MkSender");
        assert_eq!(entries[0].reason, QuarantineReason::UnknownSchemaHash);
        assert_eq!(entries[0].received_at, 1_720_000_000_000_000);
    }

    #[test]
    fn quarantine_missing_hash_stored_with_none() {
        let mut ledger = open_ledger();
        let raw = b"delta-without-hash".to_vec();

        ledger
            .quarantine(
                "did:key:z6MkAnon".to_string(),
                raw.clone(),
                None, // no schema hash
                QuarantineReason::MissingOrMalformedHash,
                0,
            )
            .expect("quarantine with no hash");

        let all = ledger.get_all().expect("get_all");
        assert_eq!(all.len(), 1);
        assert!(all[0].schema_hash.is_none(), "schema_hash must be None");
    }

    #[test]
    fn release_for_migration_sets_migration_id() {
        let mut ledger = open_ledger();
        let schema_hash: SchemaIdentifierHash = [0xBBu8; 32];
        let migration_id: [u8; 32] = [0xCCu8; 32];

        ledger
            .quarantine(
                "did:key:z6MkSender".to_string(),
                b"some-bytes".to_vec(),
                Some(schema_hash),
                QuarantineReason::BreakingSchemaChange,
                0,
            )
            .expect("quarantine");

        let released = ledger
            .release_for_migration(&schema_hash, migration_id)
            .expect("release_for_migration");

        assert_eq!(released.len(), 1);
        assert_eq!(released[0].migration_id, Some(migration_id));
    }

    #[test]
    fn quarantine_deduplication_by_raw_bytes() {
        let mut ledger = open_ledger();
        let raw = b"identical-delta".to_vec();
        let schema_hash: SchemaIdentifierHash = [0xDDu8; 32];

        // Insert same bytes twice — should be idempotent (INSERT OR IGNORE).
        ledger
            .quarantine(
                "did:key:z6MkA".to_string(),
                raw.clone(),
                Some(schema_hash),
                QuarantineReason::UnknownSchemaHash,
                1,
            )
            .expect("first quarantine");

        ledger
            .quarantine(
                "did:key:z6MkA".to_string(),
                raw.clone(),
                Some(schema_hash),
                QuarantineReason::UnknownSchemaHash,
                2,
            )
            .expect("second quarantine (should be deduped)");

        let count = ledger.count().expect("count");
        assert_eq!(count, 1, "identical raw_bytes should be deduplicated (same SHA-256 id)");
    }
}
