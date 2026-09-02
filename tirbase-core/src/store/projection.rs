//! Projection — Automerge state → SQLite row materialisation.
//!
//! After each Delta is applied to an Automerge document, the changed keys
//! are projected to SQLite rows for efficient SQL query support.

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;

/// Project the current state of an Automerge document to SQLite rows.
///
/// Walks all keys at `automerge::ROOT` in the doc and upserts each into
/// `proj_{table_name}` with its JSON-serialised value.
///
/// Called after every `CrdtEngine::apply()` to keep the SQL-queryable
/// view consistent with the CRDT state.
#[cfg(feature = "native")]
pub fn project_table(
    conn: &rusqlite::Connection,
    table_name: &str,
    doc: &automerge::AutoCommit,
) -> Result<(), TirBaseError> {
    use automerge::{ReadDoc, Value, ROOT};

    let proj_table = format!("proj_{table_name}");

    // Ensure the projection table exists.
    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS \"{proj_table}\" \
         (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, contaminated INTEGER NOT NULL DEFAULT 0);"
    );
    conn.execute_batch(&create_sql)
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("CREATE TABLE {proj_table} failed: {e}"),
        })?;

    // Walk all keys at ROOT in the automerge doc.
    let items: Vec<(String, String)> = doc
        .map_range(ROOT, ..)
        .filter_map(|item| {
            // Convert the automerge Value to a JSON string.
            let json_val = match &item.value {
                Value::Scalar(scalar) => {
                    use automerge::ScalarValue;
                    match scalar.as_ref() {
                        ScalarValue::Str(s)       => serde_json::Value::String(s.to_string()),
                        ScalarValue::Int(n)       => serde_json::Value::Number((*n).into()),
                        ScalarValue::Uint(n)      => serde_json::Value::Number((*n).into()),
                        ScalarValue::F64(f)       => serde_json::json!(f),
                        ScalarValue::Boolean(b)   => serde_json::Value::Bool(*b),
                        ScalarValue::Null         => serde_json::Value::Null,
                        ScalarValue::Bytes(b)     => {
                            serde_json::Value::String(hex::encode(b))
                        }
                        ScalarValue::Counter(c)   => {
                            serde_json::Value::Number(i64::from(c.clone()).into())
                        }
                        ScalarValue::Timestamp(t) => {
                            serde_json::Value::Number((*t).into())
                        }
                        ScalarValue::Unknown { type_code, bytes } => {
                            serde_json::json!({
                                "type_code": type_code,
                                "bytes": hex::encode(bytes)
                            })
                        }
                    }
                }
                Value::Object(_) => {
                    // Composite objects are not projected to flat rows in Task 3.
                    // Task 5 (CRDT Engine) will handle nested structures.
                    serde_json::Value::Null
                }
            };
            let json_str = serde_json::to_string(&json_val).ok()?;
            Some((item.key.to_string(), json_str))
        })
        .collect();

    // Upsert each (key, json) pair into the projection table.
    let upsert_sql = format!(
        "INSERT INTO \"{proj_table}\" (key, data_json) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET data_json = excluded.data_json;"
    );
    for (key, json_str) in items {
        conn.execute(&upsert_sql, rusqlite::params![key, json_str])
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("Projection upsert into {proj_table} key={key} failed: {e}"),
            })?;
    }

    Ok(())
}

/// WASM stub for project_table — no-op (no automerge-to-SQLite projection on WASM).
#[cfg(not(feature = "native"))]
pub fn project_table(table_name: &str) -> Result<(), TirBaseError> {
    Ok(())
}

/// Mark a projected row as CONTAMINATED (contaminated=1) for query-layer filtering.
///
/// Creates `proj_{table}` with the standard DDL if it does not yet exist (idempotent).
/// The UPDATE affects 0 rows if the key is absent — that is not an error.
/// Returns `LocalStoreWriteFailed` on any SQL error (Req 10.2, 10.7).
#[cfg(feature = "native")]
pub fn mark_row_contaminated(
    conn: &rusqlite::Connection,
    table: &str,
    row_key: &str,
) -> Result<(), TirBaseError> {
    let proj_table = format!("proj_{table}");

    // Ensure the projection table exists (idempotent — same DDL as project_table).
    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS \"{proj_table}\" \
         (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, \
          contaminated INTEGER NOT NULL DEFAULT 0);"
    );
    conn.execute_batch(&create_sql)
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("CREATE TABLE {proj_table} failed: {e}"),
        })?;

    let update_sql = format!(
        "UPDATE \"{proj_table}\" SET contaminated = 1 WHERE key = ?1"
    );
    conn.execute(&update_sql, rusqlite::params![row_key])
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!(
                "mark_row_contaminated on {proj_table} key={row_key} failed: {e}"
            ),
        })?;

    Ok(())
}

/// Clear the CONTAMINATED flag from a projected row (contaminated=0).
///
/// If the row does not exist the UPDATE affects 0 rows — that is a no-op, not an error.
/// Returns `LocalStoreWriteFailed` on any SQL error (Req 11.1).
#[cfg(feature = "native")]
pub fn clear_row_contamination(
    conn: &rusqlite::Connection,
    table: &str,
    row_key: &str,
) -> Result<(), TirBaseError> {
    let proj_table = format!("proj_{table}");

    let update_sql = format!(
        "UPDATE \"{proj_table}\" SET contaminated = 0 WHERE key = ?1"
    );
    conn.execute(&update_sql, rusqlite::params![row_key])
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!(
                "clear_row_contamination on {proj_table} key={row_key} failed: {e}"
            ),
        })?;

    Ok(())
}

#[cfg(not(feature = "native"))]
pub fn mark_row_contaminated(table: &str, row_key: &str) -> Result<(), TirBaseError> {
    crate::contamination::taint::WASM_PROJ_STORE.with(|store| {
        store
            .borrow_mut()
            .entry(table.to_string())
            .or_default()
            .insert(row_key.to_string(), true);
    });
    Ok(())
}

#[cfg(not(feature = "native"))]
pub fn clear_row_contamination(table: &str, row_key: &str) -> Result<(), TirBaseError> {
    crate::contamination::taint::WASM_PROJ_STORE.with(|store| {
        if let Some(t) = store.borrow_mut().get_mut(table) {
            t.insert(row_key.to_string(), false);
        }
    });
    Ok(())
}

// ─── WASM delta-row index ─────────────────────────────────────────────────────

// Maps `delta_id -> Vec<(table, row_key)>` so `resolve_affected_rows` can look
// up which rows were last written by a given delta on the WASM build.
//
// Written to by `record_delta_row`; read by `rows_by_delta_id`.
// The index is append-only per delta — entries are never removed.
#[cfg(not(feature = "native"))]
thread_local! {
    pub(crate) static WASM_DELTA_INDEX: std::cell::RefCell<
        std::collections::HashMap<crate::crdt::delta::DeltaId, Vec<(String, String)>>
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Record that `delta_id` wrote `(table, row_key)` into the WASM in-memory
/// projection store.
///
/// Call this whenever a WASM projection upsert occurs so that the CCE can
/// later resolve which rows are affected by a contaminated delta (Req 10.7).
/// Calling this multiple times with the same `(delta_id, table, row_key)` is
/// idempotent — duplicates are deduplicated before storage.
#[cfg(not(feature = "native"))]
pub fn record_delta_row(
    delta_id: &crate::crdt::delta::DeltaId,
    table: &str,
    row_key: &str,
) {
    WASM_DELTA_INDEX.with(|idx| {
        let mut map = idx.borrow_mut();
        let entry = map.entry(*delta_id).or_default();
        let pair = (table.to_string(), row_key.to_string());
        if !entry.contains(&pair) {
            entry.push(pair);
        }
    });
}

/// Return all `(table, row_key)` pairs that were written by `delta_id` in the
/// WASM in-memory projection store.
///
/// Returns an empty vec if `delta_id` has no recorded rows.
#[cfg(not(feature = "native"))]
pub fn rows_by_delta_id(
    delta_id: &crate::crdt::delta::DeltaId,
) -> Vec<(String, String)> {
    WASM_DELTA_INDEX.with(|idx| {
        idx.borrow().get(delta_id).cloned().unwrap_or_default()
    })
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open_conn() -> Connection {
        Connection::open_in_memory().expect("in-memory SQLite")
    }

    // ─── Test 1: mark_row_contaminated sets contaminated=1 ───────────────────

    #[test]
    fn test_mark_row_contaminated_sets_flag() {
        let conn = open_conn();
        conn.execute_batch(
            "CREATE TABLE proj_reports \
             (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, \
              contaminated INTEGER NOT NULL DEFAULT 0); \
             INSERT INTO proj_reports (key, data_json) VALUES ('row-1', '\"hello\"');",
        )
        .unwrap();

        mark_row_contaminated(&conn, "reports", "row-1").unwrap();

        let contaminated: i64 = conn
            .query_row(
                "SELECT contaminated FROM proj_reports WHERE key = 'row-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(contaminated, 1, "contaminated flag should be 1 after mark");
    }

    // ─── Test 2: clear_row_contamination resets contaminated=0 ───────────────

    #[test]
    fn test_clear_row_contamination_clears_flag() {
        let conn = open_conn();
        conn.execute_batch(
            "CREATE TABLE proj_tasks \
             (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, \
              contaminated INTEGER NOT NULL DEFAULT 0); \
             INSERT INTO proj_tasks (key, data_json, contaminated) \
             VALUES ('task-1', '\"data\"', 1);",
        )
        .unwrap();

        clear_row_contamination(&conn, "tasks", "task-1").unwrap();

        let contaminated: i64 = conn
            .query_row(
                "SELECT contaminated FROM proj_tasks WHERE key = 'task-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(contaminated, 0, "contaminated flag should be 0 after clear");
    }

    // ─── Test 3: clear_row_contamination is a no-op for non-existent row ─────

    #[test]
    fn test_clear_row_contamination_nonexistent_is_noop() {
        let conn = open_conn();
        conn.execute_batch(
            "CREATE TABLE proj_logs \
             (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, \
              contaminated INTEGER NOT NULL DEFAULT 0);",
        )
        .unwrap();

        // Should not error even though the row doesn't exist.
        let result = clear_row_contamination(&conn, "logs", "nonexistent-key");
        assert!(
            result.is_ok(),
            "clear on nonexistent row should be a no-op, not an error"
        );
    }

    // ─── Test 4: mark_row_contaminated creates table if missing ──────────────

    #[test]
    fn test_mark_row_contaminated_creates_table_if_missing() {
        let conn = open_conn();
        // proj_new_table does NOT exist yet — the function must create it.
        let result = mark_row_contaminated(&conn, "new_table", "row-x");
        assert!(
            result.is_ok(),
            "should succeed even when the projection table doesn't exist yet"
        );

        // Table must now exist.
        let table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' \
                 AND name='proj_new_table'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_exists, 1, "proj_new_table must be created by mark_row_contaminated");
    }

    // ─── Test 5: mark then clear round-trip ──────────────────────────────────

    #[test]
    fn test_mark_then_clear_round_trip() {
        let conn = open_conn();
        conn.execute_batch(
            "CREATE TABLE proj_users \
             (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, \
              contaminated INTEGER NOT NULL DEFAULT 0); \
             INSERT INTO proj_users (key, data_json) VALUES ('user-1', '\"alice\"');",
        )
        .unwrap();

        mark_row_contaminated(&conn, "users", "user-1").unwrap();
        let after_mark: i64 = conn
            .query_row(
                "SELECT contaminated FROM proj_users WHERE key = 'user-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_mark, 1, "must be 1 after mark");

        clear_row_contamination(&conn, "users", "user-1").unwrap();
        let after_clear: i64 = conn
            .query_row(
                "SELECT contaminated FROM proj_users WHERE key = 'user-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_clear, 0, "must be 0 after clear");
    }
}

#[cfg(all(test, not(feature = "native")))]
mod wasm_tests {
    use super::*;
    use crate::contamination::taint::resolve_affected_rows;

    // ─── Helper: clear the WASM_DELTA_INDEX between tests ────────────────────
    fn clear_delta_index() {
        WASM_DELTA_INDEX.with(|idx| idx.borrow_mut().clear());
    }

    // ─── Test 1: record_delta_row then rows_by_delta_id returns correct row ──

    #[test]
    fn test_record_and_lookup_single_delta() {
        clear_delta_index();

        let delta_id = [0x01u8; 32];
        record_delta_row(&delta_id, "reports", "row-1");

        let rows = rows_by_delta_id(&delta_id);
        assert_eq!(rows.len(), 1, "one row must be returned");
        assert_eq!(rows[0], ("reports".to_string(), "row-1".to_string()));
    }

    // ─── Test 2: unknown delta_id returns empty vec ───────────────────────────

    #[test]
    fn test_rows_by_delta_id_unknown_returns_empty() {
        clear_delta_index();

        let unknown = [0xFFu8; 32];
        let rows = rows_by_delta_id(&unknown);
        assert!(rows.is_empty(), "unknown delta must yield empty vec");
    }

    // ─── Test 3: resolve_affected_rows with single delta ─────────────────────
    //
    // **Validates: Requirements 10.7**

    #[test]
    fn test_resolve_affected_rows_single_delta() {
        clear_delta_index();

        let delta_id = [0x02u8; 32];
        record_delta_row(&delta_id, "orders", "order-1");

        let result = resolve_affected_rows(&[delta_id], delta_id)
            .expect("resolve_affected_rows must succeed");

        assert_eq!(result.len(), 1, "one AffectedRow expected");
        let row = &result[0];
        assert_eq!(row.table, "orders");
        assert_eq!(row.row_key, "order-1");
        assert_eq!(row.delta_id, delta_id);
    }

    // ─── Test 4: deduplication — two deltas writing the same row ─────────────
    //
    // The first delta_id in the slice wins for the delta_id association.
    // Only one AffectedRow must be returned.
    //
    // **Validates: Requirements 10.7**

    #[test]
    fn test_resolve_affected_rows_deduplication() {
        clear_delta_index();

        let delta_a = [0x0Au8; 32];
        let delta_b = [0x0Bu8; 32];

        // Both deltas wrote the same (table, row_key).
        record_delta_row(&delta_a, "users", "user-1");
        record_delta_row(&delta_b, "users", "user-1");

        let result = resolve_affected_rows(&[delta_a, delta_b], delta_a)
            .expect("resolve must succeed");

        assert_eq!(
            result.len(),
            1,
            "two deltas writing the same row must produce one AffectedRow"
        );
        // First writer (delta_a) should be the attributed delta_id.
        assert_eq!(result[0].delta_id, delta_a);
        assert_eq!(result[0].table, "users");
        assert_eq!(result[0].row_key, "user-1");
    }

    // ─── Test 5: multiple deltas across multiple tables ───────────────────────
    //
    // **Validates: Requirements 10.7**

    #[test]
    fn test_resolve_affected_rows_multiple_deltas_multiple_tables() {
        clear_delta_index();

        let delta_x = [0x10u8; 32];
        let delta_y = [0x11u8; 32];

        record_delta_row(&delta_x, "products", "prod-1");
        record_delta_row(&delta_x, "products", "prod-2");
        record_delta_row(&delta_y, "shipments", "ship-1");

        let result = resolve_affected_rows(&[delta_x, delta_y], delta_x)
            .expect("resolve must succeed");

        assert_eq!(result.len(), 3, "three distinct (table, row_key) pairs expected");

        // All three rows must appear.
        let contains = |table: &str, key: &str| {
            result.iter().any(|r| r.table == table && r.row_key == key)
        };
        assert!(contains("products", "prod-1"), "prod-1 missing");
        assert!(contains("products", "prod-2"), "prod-2 missing");
        assert!(contains("shipments", "ship-1"), "ship-1 missing");
    }

    // ─── Test 6: record_delta_row is idempotent ───────────────────────────────

    #[test]
    fn test_record_delta_row_idempotent() {
        clear_delta_index();

        let delta_id = [0x20u8; 32];

        // Record the same row three times.
        record_delta_row(&delta_id, "items", "item-1");
        record_delta_row(&delta_id, "items", "item-1");
        record_delta_row(&delta_id, "items", "item-1");

        let rows = rows_by_delta_id(&delta_id);
        assert_eq!(rows.len(), 1, "duplicate records must not accumulate");
    }

    // ─── Test 7: resolve_affected_rows with empty delta list ─────────────────

    #[test]
    fn test_resolve_affected_rows_empty_delta_list() {
        clear_delta_index();

        let result = resolve_affected_rows(&[], [0x00u8; 32])
            .expect("resolve with empty list must succeed");

        assert!(result.is_empty(), "empty delta list must produce no AffectedRows");
    }
}
