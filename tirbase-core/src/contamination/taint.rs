//! Taint propagation — BFS walk helpers and tag-append logic (Req 10.2).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::contamination::incident::{IncidentContextObject, IncidentId, TaintSource};
use crate::crdt::delta::{DeltaId, DeltaTag};
use crate::errors::TirBaseError;

// ─── WASM in-memory tag store ─────────────────────────────────────────────────

// Thread-local in-memory tag store for WASM builds.
//
// The native build writes tags directly to `dag_nodes.tags_json` in SQLite.
// On WASM there is no SQLite, so we keep tags here.  The tag log is still
// append-only — entries are pushed but never removed (Req 10.4).
#[cfg(not(feature = "native"))]
thread_local! {
    static WASM_TAG_STORE: std::cell::RefCell<
        std::collections::HashMap<DeltaId, Vec<DeltaTag>>
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

// WASM in-memory projection contamination store (table → key → contaminated flag).
#[cfg(not(feature = "native"))]
thread_local! {
    pub(crate) static WASM_PROJ_STORE: std::cell::RefCell<
        std::collections::HashMap<String, std::collections::HashMap<String, bool>>
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

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

    let new_json =
        serde_json::to_string(&tags).map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("tags_json serialise failed: {e}"),
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
/// On native this writes directly to `dag_nodes.tags_json`.  On WASM this stores
/// tags in a thread-local HashMap so the signature stays compatible with how the
/// CCE calls it.
#[cfg(feature = "native")]
pub(crate) fn append_tag(
    conn: &rusqlite::Connection,
    delta_id: &DeltaId,
    tag: DeltaTag,
) -> Result<(), TirBaseError> {
    append_tag_to_db(conn, delta_id, tag)
}

#[cfg(not(feature = "native"))]
pub(crate) fn append_tag(delta_id: &DeltaId, tag: DeltaTag) -> Result<(), TirBaseError> {
    WASM_TAG_STORE.with(|store| {
        store.borrow_mut().entry(*delta_id).or_default().push(tag);
    });
    Ok(())
}

/// Read the current tag list for a Delta from the WASM thread-local tag store.
#[cfg(not(feature = "native"))]
pub(crate) fn read_tags_from_mem(delta_id: &DeltaId) -> Vec<DeltaTag> {
    WASM_TAG_STORE.with(|store| store.borrow().get(delta_id).cloned().unwrap_or_default())
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
    dag: &crate::crdt::dag::ChangesetDag,
    root_delta_id: &DeltaId,
) -> Result<Vec<DeltaId>, TirBaseError> {
    dag.bfs_descendants(root_delta_id)
}

/// BFS walk from `root_delta_id` following forward child edges in the DAG,
/// using a raw `rusqlite::Connection` instead of `ChangesetDag`.
///
/// This is needed because `ChangesetDag::bfs_descendants` internally locks the
/// shared `Arc<Mutex<Connection>>`, which deadlocks when the connection is
/// already locked by the caller (e.g. inside `verify_data` where the CCE holds
/// `conn_guard` across the `resolution::verify_data` call).  This variant
/// queries `dag_edges` directly on the already-locked connection, avoiding the
/// re-entrant lock.
#[cfg(feature = "native")]
pub(crate) fn bfs_descendants_raw(
    conn: &rusqlite::Connection,
    root_delta_id: &DeltaId,
) -> Result<Vec<DeltaId>, TirBaseError> {
    use std::collections::{HashSet, VecDeque};

    let mut visited: HashSet<DeltaId> = HashSet::new();
    let mut queue: VecDeque<DeltaId> = VecDeque::new();
    let mut result: Vec<DeltaId> = Vec::new();

    queue.push_back(*root_delta_id);

    while let Some(current) = queue.pop_front() {
        if !visited.insert(current) {
            continue;
        }
        result.push(current);

        // Query children of `current` from the dag_edges table.
        let mut stmt = conn
            .prepare("SELECT child_id FROM dag_edges WHERE parent_id = ?1")
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("prepare bfs children query failed: {e}"),
            })?;
        let children: Vec<DeltaId> = stmt
            .query_map(rusqlite::params![current.as_ref()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("query bfs children failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .filter_map(|b| b.try_into().ok())
            .collect();

        for child in children {
            if !visited.contains(&child) {
                queue.push_back(child);
            }
        }
    }

    Ok(result)
}

// ─── Late-arrival walk helper ────────────────────────────────────────────────────

/// Late-arrival taint walk (Req 10.3 gap fix).
///
/// When a contamination root is resolved (or remains unresolved) via `verify_data`,
/// Deltas that descended from the root **after** the initial `tag_contamination_root`
/// snapshot was taken are neither contaminated nor decontaminated during the
/// snapshot-based walk.  This function performs a second live walk against the
/// current DAG to find those late-arriving descendants.
///
/// * `root_delta_id`  — the resolved (or still-unresolved) contamination root.
/// * `dag`            — the live `ChangesetDag` (used only for its schema; the
///   actual BFS uses `conn` directly to avoid re-entrant locking — see note on
///   `decompose_composites_if_needed`).
/// * `snapshot_deltas` — the `contaminated_deltas` snapshot captured at tag-time.
///   Descendants already present in this set are skipped (they already carry
///   their tags from the initial walk).
/// * `resolved`       — if `true`, late arrivals receive `DeltaTag::Decontaminated`;
///   if `false`, late arrivals receive `DeltaTag::Contaminated`.
/// * `conn`           — SQLite connection for tag writes and live DAG queries.
/// * `incident_id`    — the ICO these deltas belong to.
///
/// Returns the subset of descendants that were actually tagged by this call
/// (i.e. those not already in `snapshot_deltas`).
#[cfg(feature = "native")]
pub(crate) fn walk_late_arrival_descendants(
    root_delta_id: &DeltaId,
    _dag: &crate::crdt::dag::ChangesetDag,
    snapshot_deltas: &std::collections::BTreeSet<DeltaId>,
    resolved: bool,
    conn: &rusqlite::Connection,
    incident_id: IncidentId,
) -> Result<Vec<DeltaId>, TirBaseError> {
    use std::collections::HashSet;

    // 1. Query the live DAG for all descendants of the root using the raw
    //    connection (avoids re-entrant Mutex lock — see decompose_composites_if_needed).
    let live_descendants = bfs_descendants_raw(conn, root_delta_id)?;

    // 2. Determine which descendants are late arrivals (not in the snapshot).
    let snapshot_set: HashSet<DeltaId> = snapshot_deltas.iter().copied().collect();
    let late_arrivals: Vec<DeltaId> = live_descendants
        .iter()
        .copied()
        .filter(|d| !snapshot_set.contains(d))
        .collect();

    // 3. Tag each late arrival.
    let at = crate::contamination::resolution::now_micros();
    for delta_id in &late_arrivals {
        if resolved {
            let _ = append_tag(
                conn,
                delta_id,
                DeltaTag::Decontaminated {
                    incident_id,
                    resolved_at: at,
                },
            );
        } else {
            let _ = append_tag(
                conn,
                delta_id,
                DeltaTag::Contaminated {
                    root_id: *root_delta_id,
                    incident_id,
                },
            );
        }
    }

    Ok(late_arrivals)
}

/// WASM-compatible late-arrival taint walk.
///
/// Same logic as the native `walk_late_arrival_descendants` but uses the
/// thread-local tag store (`append_tag` / `read_tags_from_mem`) instead of
/// SQLite.  The `dag` is the in-memory WASM `ChangesetDag`.
#[cfg(not(feature = "native"))]
pub(crate) fn walk_late_arrival_descendants(
    root_delta_id: &DeltaId,
    dag: &crate::crdt::dag::ChangesetDag,
    snapshot_deltas: &std::collections::BTreeSet<DeltaId>,
    resolved: bool,
    incident_id: IncidentId,
) -> Result<Vec<DeltaId>, TirBaseError> {
    use std::collections::HashSet;

    let live_descendants = dag.descendants_of(root_delta_id)?;

    let snapshot_set: HashSet<DeltaId> = snapshot_deltas.iter().copied().collect();
    let late_arrivals: Vec<DeltaId> = live_descendants
        .iter()
        .copied()
        .filter(|d| !snapshot_set.contains(d))
        .collect();

    let at = crate::contamination::resolution::now_micros();
    for delta_id in &late_arrivals {
        if resolved {
            let _ = append_tag(
                delta_id,
                DeltaTag::Decontaminated {
                    incident_id,
                    resolved_at: at,
                },
            );
        } else {
            let _ = append_tag(
                delta_id,
                DeltaTag::Contaminated {
                    root_id: *root_delta_id,
                    incident_id,
                },
            );
        }
    }

    Ok(late_arrivals)
}

// ─── Affected row resolver ────────────────────────────────────────

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
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
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

/// WASM implementation of `resolve_affected_rows`.
///
/// Queries the `WASM_DELTA_INDEX` in `store/projection` to find all
/// `(table, row_key)` pairs recorded for each delta in `delta_ids`.
/// Deduplicates by `(table, row_key)` — the first delta_id encountered wins.
///
/// Satisfies Req 10.7: the ICO `affected_rows` is populated on WASM builds
/// whenever `record_delta_row` has been called to track projection writes.
#[cfg(not(feature = "native"))]
pub(crate) fn resolve_affected_rows(
    delta_ids: &[DeltaId],
    root_delta_id: DeltaId,
) -> Result<Vec<crate::contamination::incident::AffectedRow>, TirBaseError> {
    use crate::contamination::incident::AffectedRow;
    use std::collections::HashMap;

    // Map (table, row_key) -> most-recent delta_id for deduplication.
    let mut seen: HashMap<(String, String), DeltaId> = HashMap::new();

    for &delta_id in delta_ids {
        let rows = crate::store::projection::rows_by_delta_id(&delta_id);
        for (table, row_key) in rows {
            // First writer wins for the delta_id association.
            seen.entry((table, row_key)).or_insert(delta_id);
        }
    }

    let affected = seen
        .into_iter()
        .map(|((table, row_key), delta_id)| AffectedRow {
            table,
            row_key,
            delta_id,
        })
        .collect();

    Ok(affected)
}
