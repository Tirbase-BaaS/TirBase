//! Taint propagation — BFS walk helpers and tag-append logic (Req 10.2).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::contamination::incident::{IncidentContextObject, IncidentId, TaintSource};
use crate::crdt::delta::{DeltaId, DeltaTag};
use crate::errors::TirBaseError;

// ─── SQLite tag-append helper ─────────────────────────────────────────────────

/// Append a single `DeltaTag` to the `tags_json` column of `dag_nodes`.
///
/// This is the **only** write path for tag data — the array only grows; no entry
/// is ever removed or modified (Req 10.4).
#[cfg(feature = "native")]
pub(crate) fn append_tag_to_db(
    conn: &rusqlite::Connection,
    delta_id: &DeltaId,
    tag: DeltaTag,
) -> Result<(), TirBaseError> {
    // Read existing tags, deserialise, push, serialise back.
    let existing_json: String = conn
        .query_row(
            "SELECT tags_json FROM dag_nodes WHERE id = ?1",
            rusqlite::params![delta_id.as_ref()],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| "[]".to_string());

    let mut tags: Vec<DeltaTag> = serde_json::from_str(&existing_json).unwrap_or_default();
    tags.push(tag);

    let new_json = serde_json::to_string(&tags).map_err(|e| {
        TirBaseError::LocalStoreWriteFailed {
            reason: format!("tags_json serialise failed: {e}"),
        }
    })?;

    conn.execute(
        "UPDATE dag_nodes SET tags_json = ?1 WHERE id = ?2",
        rusqlite::params![new_json, delta_id.as_ref()],
    )
    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
        reason: format!("UPDATE dag_nodes tags_json failed: {e}"),
    })?;

    Ok(())
}

/// Read the current `tags_json` array for a Delta from `dag_nodes`.
#[cfg(feature = "native")]
pub(crate) fn read_tags_from_db(
    conn: &rusqlite::Connection,
    delta_id: &DeltaId,
) -> Result<Vec<DeltaTag>, TirBaseError> {
    let json: Option<String> = conn
        .query_row(
            "SELECT tags_json FROM dag_nodes WHERE id = ?1",
            rusqlite::params![delta_id.as_ref()],
            |row| row.get(0),
        )
        .ok();

    Ok(json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default())
}

// ─── Append-only wrapper (public interface used by resolution) ─────────────────

/// Append a `DeltaTag` entry to the tag log of the given Delta.
///
/// This operation is **append-only** — existing tags are never modified (Req 10.4).
///
/// On native this writes directly to `dag_nodes.tags_json`.  On WASM this is a
/// stub until Task 14 wires the bridge.
#[cfg(feature = "native")]
pub(crate) fn append_tag(
    conn: &rusqlite::Connection,
    delta_id: &DeltaId,
    tag: DeltaTag,
) -> Result<(), TirBaseError> {
    append_tag_to_db(conn, delta_id, tag)
}

#[cfg(not(feature = "native"))]
pub(crate) fn append_tag(
    delta_id: &DeltaId,
    tag: DeltaTag,
) -> Result<(), TirBaseError> {
    todo!("Task 14: wire WASM append_tag bridge")
}

// ─── BFS walk helper ──────────────────────────────────────────────────────────

/// BFS walk from `root_delta_id` following forward child edges in the DAG.
///
/// Returns all reachable descendant Delta IDs (inclusive of root).
/// Delegates to `ChangesetDag::bfs_descendants` which is already implemented.
#[cfg(feature = "native")]
pub(crate) fn walk_dag_descendants(
    dag: &crate::crdt::dag::ChangesetDag,
    root_delta_id: &DeltaId,
) -> Result<Vec<DeltaId>, TirBaseError> {
    dag.bfs_descendants(root_delta_id)
}

#[cfg(not(feature = "native"))]
pub(crate) fn walk_dag_descendants(
    root_delta_id: &DeltaId,
) -> Result<Vec<DeltaId>, TirBaseError> {
    todo!("Task 14: wire WASM walk_dag_descendants bridge")
}

// ─── Affected row resolver ────────────────────────────────────────────────────

/// Resolve all projection rows that should be marked contaminated for a given set
/// of contaminated Delta IDs.
///
/// Implementation (v1 conservative approach):
/// - Queries `sqlite_master` for every `proj_*` table.
/// - Selects all row keys from each table.
/// - Records each as an `AffectedRow` attributed to `root_delta_id`.
///
/// This is intentionally conservative: if any projection table exists and has rows,
/// all of them are considered potentially affected by the contamination event.
/// A future task can refine this using a `last_delta_id` column in the projection
/// tables to narrow the scope to rows actually written by contaminated deltas.
#[cfg(feature = "native")]
pub(crate) fn resolve_affected_rows(
    conn: &rusqlite::Connection,
    _delta_ids: &[DeltaId],
    root_delta_id: DeltaId,
) -> Result<Vec<crate::contamination::incident::AffectedRow>, TirBaseError> {
    use crate::contamination::incident::AffectedRow;

    // 1. Enumerate all projection tables.
    let proj_tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type='table' AND name LIKE 'proj_%'",
            )
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("sqlite_master query failed: {e}"),
            })?;
        let tables: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("sqlite_master iterate failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .collect();
        tables
    };

    // 2. For each projection table, collect all row keys.
    let mut affected = Vec::new();
    for proj_table in &proj_tables {
        let logical_table = proj_table.strip_prefix("proj_").unwrap_or(proj_table);
        let sql = format!("SELECT key FROM \"{proj_table}\"");
        let mut stmt = conn.prepare(&sql).map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("SELECT key from {proj_table} failed: {e}"),
        })?;
        let keys: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("iterate {proj_table} keys failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .collect();
        for key in keys {
            affected.push(AffectedRow {
                table: logical_table.to_string(),
                row_key: key,
                delta_id: root_delta_id,
            });
        }
    }

    Ok(affected)
}
