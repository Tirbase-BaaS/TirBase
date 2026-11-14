// SPDX-License-Identifier: AGPL-3.0-only

//! Logical-dump equivalence helper for primary.db recovery tests (CLAIM-32.2,
//! PV-9.5). Dumps queryable state in a deterministic, schema-aware form so WAL
//! page layout differences do not affect equivalence.
use rusqlite::{types::ValueRef, Connection};
use std::collections::BTreeMap;

/// Canonical logical dump: `table -> sorted rows -> column=value` strings.
/// Excludes `sqlite_*` internal tables and `schema_migrations.applied_at`
/// wall-clock bookkeeping (idempotent migration *result* is what matters).
pub fn logical_dump(
    conn: &Connection,
) -> Result<BTreeMap<String, Vec<BTreeMap<String, String>>>, String> {
    let mut out = BTreeMap::new();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| format!("list tables: {e}"))?;
    let tables = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| format!("query tables: {e}"))?;
    for t in tables {
        let table = t.map_err(|e| format!("table name: {e}"))?;
        let mut pragma = conn
            .prepare(&format!(
                "PRAGMA table_info(\"{}\")",
                table.replace('"', "\"\"")
            ))
            .map_err(|e| format!("pragma {table}: {e}"))?;
        let cols: Vec<String> = pragma
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(|e| format!("pragma rows {table}: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("pragma col {table}: {e}"))?;
        let order = if cols.is_empty() {
            String::new()
        } else {
            format!(
                " ORDER BY {}",
                cols.iter()
                    .map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let sql = format!("SELECT * FROM \"{}\"{order}", table.replace('"', "\"\""));
        let mut q = conn
            .prepare(&sql)
            .map_err(|e| format!("select {table}: {e}"))?;
        let col_names: Vec<String> = q.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows_out = Vec::new();
        let mut rows = q.query([]).map_err(|e| format!("query {table}: {e}"))?;
        while let Some(row) = rows.next().map_err(|e| format!("row {table}: {e}"))? {
            let mut m = BTreeMap::new();
            for (i, c) in col_names.iter().enumerate() {
                if table == "schema_migrations" && c == "applied_at" {
                    m.insert(c.clone(), "<ts>".to_string());
                    continue;
                }
                let v = row
                    .get_ref(i)
                    .map_err(|e| format!("get {table}.{c}: {e}"))?;
                let s = match v {
                    ValueRef::Null => "NULL".to_string(),
                    ValueRef::Integer(n) => n.to_string(),
                    ValueRef::Real(f) => format!("{f}"),
                    ValueRef::Text(t) => String::from_utf8_lossy(t).to_string(),
                    ValueRef::Blob(b) => format!("x'{}'", hex::encode(b)),
                };
                m.insert(c.clone(), s);
            }
            rows_out.push(m);
        }
        out.insert(table, rows_out);
    }
    Ok(out)
}

/// Human-readable diff summary for assertion messages.
pub fn diff_summary(
    a: &BTreeMap<String, Vec<BTreeMap<String, String>>>,
    b: &BTreeMap<String, Vec<BTreeMap<String, String>>>,
) -> String {
    let mut lines = Vec::new();
    for k in a.keys().chain(b.keys()) {
        if a.get(k) != b.get(k) {
            lines.push(format!(
                "table {k}: a={:?} b={:?}",
                a.get(k).map(|v| v.len()),
                b.get(k).map(|v| v.len())
            ));
        }
    }
    if lines.is_empty() {
        "equivalent".into()
    } else {
        lines.join("\n")
    }
}

/// Best-effort logical dump export for a corrupt/unopenable primary DB path.
/// Writes a JSON snapshot next to the DB for operator forensics (CLAIM-31.5).
pub fn export_primary_corruption_snapshot(
    db_path: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let export_path = db_path.with_extension("corrupt.logical-dump.json");
    let conn = Connection::open(db_path).map_err(|e| format!("open for logical dump: {e}"))?;
    let dump = logical_dump(&conn)?;
    let json =
        serde_json::to_string_pretty(&dump).map_err(|e| format!("serialize logical dump: {e}"))?;
    std::fs::write(&export_path, json)
        .map_err(|e| format!("write {}: {e}", export_path.display()))?;
    Ok(export_path)
}
