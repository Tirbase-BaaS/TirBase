//! Projection — Automerge state → SQLite row materialisation.
//!
//! After each Delta is applied to an Automerge document, the changed keys
//! are projected to SQLite rows for efficient SQL query support.

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;

/// Project the current state of an Automerge document to SQLite rows.
///
/// Called after every `CrdtEngine::apply()` to keep the SQL-queryable
/// view consistent with the CRDT state.
pub fn project_table(table_name: &str) -> Result<(), TirBaseError> {
    todo!("Task 3: implement Automerge → SQLite projection")
}

/// Mark a projected row as CONTAMINATED for UI / query-layer filtering.
pub fn mark_row_contaminated(table: &str, row_key: &str) -> Result<(), TirBaseError> {
    todo!("Task 7: wire contamination flag into projection")
}

/// Clear the CONTAMINATED flag from a projected row (after decontamination).
pub fn clear_row_contamination(table: &str, row_key: &str) -> Result<(), TirBaseError> {
    todo!("Task 7: wire decontamination into projection")
}
