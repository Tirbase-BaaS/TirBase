//! CompactionPolicy — aggressive Delta count threshold vs. none (Req 3.4–3.5).

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;
use serde::{Deserialize, Serialize};

// Re-export CompactionPolicy so it can be referenced from store/mod.rs
pub use CompactionPolicy::*;

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

/// Run compaction on an Automerge document (native only).
///
/// On success: updates `automerge_docs` with compacted bytes and marks
///   `dag_nodes.compacted = 1` for nodes belonging to this table.
///
/// On failure: preserves the uncompacted stream, logs
///   `[COMPACTION FAIL] table={table_name} ts={unix_ts} error={e}`, and
///   returns `Ok(())` without data loss (Req 3.5).
///
/// This function **never** returns `Err` — compaction failures are non-fatal.
#[cfg(feature = "native")]
pub fn compact_table(
    conn: &rusqlite::Connection,
    table_name: &str,
    doc: &mut automerge::AutoCommit,
) -> Result<(), TirBaseError> {
    // Snapshot the current bytes before compaction.
    let snapshot_bytes = doc.save();

    // Attempt the compacted save. `save()` in automerge always produces a
    // valid full snapshot of the current state.
    let compacted_bytes = doc.save();

    // Persist the compacted bytes back to automerge_docs.
    let update_result = conn.execute(
        "UPDATE automerge_docs SET doc_bytes = ?1 WHERE table_name = ?2;",
        rusqlite::params![compacted_bytes, table_name],
    );

    if let Err(e) = update_result {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        eprintln!("[COMPACTION FAIL] table={table_name} ts={ts} error={e}");
        // Restore snapshot — re-load from snapshot bytes so the in-memory doc
        // reflects pre-compaction state.
        if let Ok(restored) = automerge::AutoCommit::load(&snapshot_bytes) {
            *doc = restored;
        }
        // Non-fatal: return Ok to preserve existing data (Req 3.5).
        return Ok(());
    }

    // Mark dag_nodes as compacted for nodes authored under this table's schema_hash.
    // Best-effort: mark all uncompacted nodes (table-level association is approximate).
    // A more precise association is wired in Task 5 when schema_hash is available.
    let mark_result = conn.execute(
        "UPDATE dag_nodes SET compacted = 1 WHERE compacted = 0;",
        [],
    );

    if let Err(e) = mark_result {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        eprintln!("[COMPACTION FAIL] table={table_name} ts={ts} error=mark_dag_nodes: {e}");
    }

    Ok(())
}
