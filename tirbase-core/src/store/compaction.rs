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
/// `dag_nodes.compacted = 1` for nodes belonging to this table.
///
/// On failure: preserves the uncompacted stream, logs
/// `[COMPACTION FAIL] table={table_name} ts={unix_ts} error={e}`, and
/// returns `Ok(())` without data loss (Req 3.5).
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
        let ts = crate::traits::wall_hint_secs().unwrap_or(0);
        eprintln!("[COMPACTION FAIL] table={table_name} ts={ts} error={e}");
 // Restore snapshot — re-load from snapshot bytes so the in-memory doc
 // reflects pre-compaction state.
        if let Ok(restored) = automerge::AutoCommit::load(&snapshot_bytes) {
            *doc = restored;
        }
 // Non-fatal: return Ok to preserve existing data (Req 3.5).
        return Ok(());
    }

 // Mark dag_nodes as compacted **only for this table**. Each Delta payload
 // carries its table in the `_tirbase_table` ROOT key (written by
 // `CrdtEngine::write_scalar`), so the association is exact rather than
 // approximate: compacting table A must never mark table B's history as
 // compacted (Req 3.4 per-table isolation).
    let mark_result = mark_table_nodes_compacted(conn, table_name);

    if let Err(e) = mark_result {
        let ts = crate::traits::wall_hint_secs().unwrap_or(0);
        eprintln!("[COMPACTION FAIL] table={table_name} ts={ts} error=mark_dag_nodes: {e}");
    }

    Ok(())
}


/// Mark every uncompacted DAG node whose payload belongs to `table_name` as
/// `compacted = 1`, leaving other tables' nodes untouched.
///
/// A node whose payload is not an Automerge changeset, or carries no
/// `_tirbase_table` routing key, is left unmarked: it cannot be attributed to
/// this table, and guessing would let compaction of one table rewrite
/// another table's state.
#[cfg(feature = "native")]
fn mark_table_nodes_compacted(
    conn: &rusqlite::Connection,
    table_name: &str,
) -> Result<(), TirBaseError> {
    use automerge::ReadDoc;

    let mut stmt = conn
        .prepare("SELECT id, payload FROM dag_nodes WHERE compacted = 0;")
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("prepare compaction node scan failed: {e}"),
        })?;

    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
        })
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("scan compaction nodes failed: {e}"),
        })?;

    let mut ids: Vec<Vec<u8>> = Vec::new();
    for row in rows {
        let (id, payload) = row.map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("read compaction node failed: {e}"),
        })?;
        let Some(payload) = payload else { continue };
        // DAG payloads are zstd-compressed at insert time; fall back to the raw
        // bytes for any payload written uncompressed (WASM writer, legacy row).
        let raw = crate::crdt::dag::decompress_payload(&payload).unwrap_or(payload);
        let Ok(doc) = automerge::AutoCommit::load(&raw) else {
            continue;
        };
        let belongs = match doc.get(automerge::ROOT, "_tirbase_table").ok().flatten() {
            Some((automerge::Value::Scalar(sv), _)) => match sv.as_ref() {
                automerge::ScalarValue::Str(s) => s.as_str() == table_name,
                _ => false,
            },
            _ => false,
        };
        if belongs {
            ids.push(id);
        }
    }
    drop(stmt);

    for id in ids {
        conn.execute(
            "UPDATE dag_nodes SET compacted = 1 WHERE id = ?1;",
            rusqlite::params![id],
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("mark compacted failed: {e}"),
        })?;
    }

    Ok(())
}

// ─── WASM compaction path (Req 3.4/3.5) ─────────────────────────────────────

/// WASM-backed compaction that persists the compacted Automerge snapshot to
/// IndexedDB's `compaction_snapshots` object store (Req 3.4/3.5).
///
/// On success: stores the compacted snapshot bytes keyed by `table_name` in
/// the `compaction_snapshots` object store, with a `compacted_at` timestamp.
/// The in-memory `doc` is left as-is (the snapshot is the authoritative
/// post-compaction state).
///
/// On failure: preserves the uncompacted doc, logs
/// `[COMPACTION FAIL] table={table_name} ts={unix_ts} error={e}`, and returns
/// `Ok(())` without data loss (Req 3.5).
///
/// This function **never** returns `Err` — compaction failures are non-fatal.
#[cfg(not(feature = "native"))]
pub(crate) async fn compact_table_idb(
    db: &super::indexed_db::IdbStore,
    table_name: &str,
    doc: &mut automerge::AutoCommit,
) -> Result<(), TirBaseError> {
    use automerge::ReadDoc;

    let snapshot_bytes = doc.save();
    let compacted_at = crate::traits::wall_hint().unwrap_or(0);

    let snapshot = super::indexed_db::CompactionSnapshot {
        snapshot_bytes: snapshot_bytes.clone(),
        compacted_at,
    };

    let put_result = db.put_compaction_snapshot(table_name, &snapshot).await;

    if let Err(e) = put_result {
        let ts = crate::traits::wall_hint_secs().unwrap_or(0);
        eprintln!("[COMPACTION FAIL] table={table_name} ts={ts} error={e}");
        return Ok(());
    }

    Ok(())
}

/// WASM-backed compaction-threshold check.
///
/// Delegates to the same [`should_compact`] logic as native (Req 3.4) so the
/// `Aggressive { threshold }` and `None` policies behave identically across
/// build targets.
#[cfg(not(feature = "native"))]
pub(crate) fn should_compact_idb(policy: &CompactionPolicy, change_count: u64) -> bool {
    should_compact(policy, change_count)
}
