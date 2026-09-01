//! SQLite connection pool and schema creation (Req 3.1).
//!
//! The LocalStore SQLite schema:
//!   - automerge_docs  — one Automerge doc per table (design §Per-Table Layout)
//!   - dag_nodes       — ChangesetDag node storage
//!   - dag_edges       — parent→child causal edge table
//!   - quarantine_ledger
//!   - sidecar_ledger

#![allow(dead_code, unused_variables, unused_imports)]

use crate::errors::TirBaseError;

/// SQL DDL statements to create the LocalStore schema on first open.
pub const CREATE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS automerge_docs (
    table_name  TEXT PRIMARY KEY,
    doc_bytes   BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS dag_nodes (
    id          BLOB PRIMARY KEY,
    payload     BLOB NOT NULL,
    lamport     INTEGER NOT NULL,
    schema_hash BLOB NOT NULL,
    compacted   INTEGER NOT NULL DEFAULT 0,
    author_did  TEXT NOT NULL,
    tags_json   TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS dag_edges (
    parent_id   BLOB NOT NULL,
    child_id    BLOB NOT NULL,
    PRIMARY KEY (parent_id, child_id)
);

CREATE TABLE IF NOT EXISTS quarantine_ledger (
    id           BLOB PRIMARY KEY,
    sender_did   TEXT NOT NULL,
    raw_bytes    BLOB NOT NULL,
    schema_hash  BLOB,
    reason       TEXT NOT NULL,
    received_at  INTEGER NOT NULL,
    migration_id BLOB
);

CREATE TABLE IF NOT EXISTS sidecar_ledger (
    id            BLOB PRIMARY KEY,
    migration_id  BLOB NOT NULL,
    table_name    TEXT NOT NULL,
    delta_bytes   BLOB NOT NULL,
    recorded_ts   INTEGER NOT NULL,
    replay_status TEXT,
    conflict_info TEXT
);

CREATE TABLE IF NOT EXISTS device_identity (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    did           TEXT NOT NULL,
    keypair_bytes BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dag_edges_parent ON dag_edges (parent_id);
CREATE INDEX IF NOT EXISTS idx_dag_edges_child  ON dag_edges (child_id);
CREATE INDEX IF NOT EXISTS idx_sidecar_migration ON sidecar_ledger (migration_id, recorded_ts);
CREATE INDEX IF NOT EXISTS idx_quarantine_schema  ON quarantine_ledger (schema_hash);
"#;

/// Open (or create) the SQLite database at `path` and run schema creation.
///
/// Uses the `rusqlite/bundled` feature on native builds so no system SQLite is required.
/// Enables WAL journal mode for improved concurrent access.
#[cfg(feature = "native")]
pub fn open(path: &str) -> Result<rusqlite::Connection, TirBaseError> {
    let conn = rusqlite::Connection::open(path).map_err(|e| TirBaseError::LocalStoreWriteFailed {
        reason: format!("SQLite open failed at {path}: {e}"),
    })?;

    // Enable WAL journal mode for better concurrent read/write performance.
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("PRAGMA journal_mode=WAL failed: {e}"),
        })?;

    // Enable foreign key enforcement.
    conn.execute_batch("PRAGMA foreign_keys=ON;")
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("PRAGMA foreign_keys=ON failed: {e}"),
        })?;

    // Create all tables on first open.
    conn.execute_batch(CREATE_SCHEMA_SQL)
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("Schema creation failed: {e}"),
        })?;

    Ok(conn)
}

/// WASM stub — on WASM the LocalStore uses an in-memory HashMap; there is no
/// SQLite connection.  This function is a no-op placeholder so callers that
/// are guarded by `#[cfg(not(feature = "native"))]` can still reference the
/// module without a build error.
#[cfg(not(feature = "native"))]
pub fn open(_path: &str) -> Result<(), TirBaseError> {
    Ok(())
}
