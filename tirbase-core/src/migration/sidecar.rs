//! SideCarLedger — preserves writes made against a corrupted schema for replay (Req 19.1–19.6).
//!
//! SQLite schema:
//! ```sql
//! CREATE TABLE sidecar_ledger (
//!     id            BLOB PRIMARY KEY,
//!     migration_id  BLOB NOT NULL,
//!     table_name    TEXT NOT NULL,
//!     delta_bytes   BLOB NOT NULL,
//!     recorded_ts   INTEGER NOT NULL,
//!     replay_status TEXT,        -- NULL | 'REPLAYED' | 'CONFLICT' | 'COMPLETE'
//!     conflict_info TEXT         -- JSON if replay_status = 'CONFLICT'
//! );
//! ```

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::DeltaId;
use crate::errors::TirBaseError;
use crate::migration::migration_delta::MigrationId;
use crate::schema::hash::SchemaIdentifierHash;
use serde::{Deserialize, Serialize};

/// Replay status for a Side-Car entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayStatus {
    /// Not yet replayed.
    Pending,
    /// Successfully applied to the corrected projection.
    Replayed,
    /// Produced a CRDT conflict; row flagged for manual resolution (Req 19.4).
    Conflict { conflict_info: String },
    /// All entries for this migration have been replayed with zero conflicts (Req 19.6).
    Complete,
}

/// A write operation recorded in the Side-Car Ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideCarEntry {
    pub id: DeltaId,
    pub migration_id: MigrationId,
    pub table_name: String,
    /// Raw Delta bytes, no modification (Req 19.2).
    pub delta_bytes: Vec<u8>,
    /// Original timestamp for replay ordering (Req 19.3).
    pub recorded_ts: i64,
    pub replay_status: ReplayStatus,
}

/// SQLite-backed ledger that captures writes made under a corrupted schema.
pub struct SideCarLedger {
    // TODO(task-8): inject LocalStore handle
}

impl SideCarLedger {
    /// Record a write operation in the Side-Car Ledger (Req 19.2).
    pub fn record(
        &mut self,
        migration_id: MigrationId,
        table_name: String,
        delta_bytes: Vec<u8>,
        recorded_ts: i64,
    ) -> Result<DeltaId, TirBaseError> {
        todo!("Task 8: implement with LocalStore")
    }

    /// Replay all Side-Car entries for `migration_id` against the corrected
    /// projection in recorded-timestamp order (Req 19.3–19.6).
    ///
    /// Does **not** abort on CRDT conflicts — each conflict is flagged and
    /// logged, and replay continues to the remaining entries.
    pub fn replay_sidecar(
        &mut self,
        migration_id: MigrationId,
        corrected_schema_hash: SchemaIdentifierHash,
    ) -> Result<ReplaySummary, TirBaseError> {
        todo!("Task 8: implement replay algorithm")
    }
}

/// Summary returned after a Side-Car replay pass.
#[derive(Debug, Clone)]
pub struct ReplaySummary {
    pub total_entries: usize,
    pub replayed: usize,
    pub conflicts: usize,
    /// True only when `conflicts == 0` (Req 19.6).
    pub complete: bool,
}
