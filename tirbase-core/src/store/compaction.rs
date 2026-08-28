//! CompactionPolicy — aggressive Delta count threshold vs. none (Req 3.4–3.5).

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;
use serde::{Deserialize, Serialize};

/// Per-table compaction policy (design §Schema Object / CompactionPolicy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompactionPolicy {
    /// Compact when the table's Delta record count exceeds `threshold` (unit: whole Delta records).
    Aggressive {
        /// Delta count above which compaction is triggered (Req 3.4).
        threshold: u64,
    },
    /// Never compact; full Delta history preserved (Req 3.4).
    None,
}

/// Check whether compaction should be triggered for a table.
///
/// Returns `true` only when the policy is `Aggressive` and `current_delta_count`
/// exceeds the threshold (Req 3.4).
pub fn should_compact(policy: &CompactionPolicy, current_delta_count: u64) -> bool {
    match policy {
        CompactionPolicy::Aggressive { threshold } => current_delta_count > *threshold,
        CompactionPolicy::None => false,
    }
}

/// Run compaction on an Automerge document.
///
/// On failure: preserves the uncompacted stream, logs `{table, timestamp, error}`,
/// and returns the pre-compaction data without data loss (Req 3.5).
pub fn compact_table(table_name: &str) -> Result<(), TirBaseError> {
    todo!("Task 3: implement Automerge doc.compact() with failure handling")
}
