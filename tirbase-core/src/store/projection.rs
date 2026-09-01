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
