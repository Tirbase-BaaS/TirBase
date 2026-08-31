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

/// WASM stub for project_table.
#[cfg(not(feature = "native"))]
pub fn project_table(table_name: &str) -> Result<(), TirBaseError> {
    todo!("Task 14: wire WASM projection")
}

/// Mark a projected row as CONTAMINATED for UI / query-layer filtering.
pub fn mark_row_contaminated(table: &str, row_key: &str) -> Result<(), TirBaseError> {
    todo!("Task 7: wire contamination flag into projection")
}

/// Clear the CONTAMINATED flag from a projected row (after decontamination).
pub fn clear_row_contamination(table: &str, row_key: &str) -> Result<(), TirBaseError> {
    todo!("Task 7: wire decontamination into projection")
}
