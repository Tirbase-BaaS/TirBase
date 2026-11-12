//! SQLite connection pool and schema creation (Req 3.1).
//!
//! The LocalStore SQLite schema:
//! - automerge_docs — one Automerge doc per table (design §Per-Table Layout)
//! - dag_nodes — ChangesetDag node storage
//! - dag_edges — parent→child causal edge table
//! - quarantine_ledger
//! - sidecar_ledger

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
    delta_bytes BLOB,
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

-- PV-6.7 / task 23: replayable CRDT schema quarantine (core-local mirror of derived.db shape).
CREATE TABLE IF NOT EXISTS schema_quarantine (
    id           BLOB PRIMARY KEY,
    sender_did   TEXT NOT NULL,
    raw_bytes    BLOB NOT NULL,
    schema_hash  BLOB,
    reason       TEXT NOT NULL,
    received_at  INTEGER NOT NULL,
    detail       TEXT
);

-- PV-6.7 / task 23.4: non-replayable rate/oversize quarantine summaries.
CREATE TABLE IF NOT EXISTS rate_quarantine_summary (
    sender_did     TEXT NOT NULL,
    window_start   INTEGER NOT NULL,
    rejected_count INTEGER NOT NULL,
    PRIMARY KEY (sender_did, window_start)
);

-- CLAIM-31.3 (PV-9.1): ICO / CCE index persistence. CCE loads from these
-- tables on construction so open incidents survive a simulated crash.
-- STATE-INVENTORY: PERSISTED cce_incidents, cce_composite_incidents, cce_contaminated_rows
CREATE TABLE IF NOT EXISTS cce_incidents (
    id        TEXT PRIMARY KEY,
    ico_json  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cce_composite_incidents (
    id                TEXT PRIMARY KEY,
    composite_json    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cce_contaminated_rows (
    table_name  TEXT NOT NULL,
    row_key     TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    PRIMARY KEY (table_name, row_key)
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
CREATE INDEX IF NOT EXISTS idx_schema_quarantine_received ON schema_quarantine (received_at);
CREATE INDEX IF NOT EXISTS idx_schema_quarantine_sender ON schema_quarantine (sender_did);
CREATE INDEX IF NOT EXISTS idx_rate_quarantine_window ON rate_quarantine_summary (window_start);
"#;

/// Open (or create) the SQLite database at `path` and run schema creation.
///
/// Uses the `rusqlite/bundled` feature on native builds so no system SQLite is required.
/// Enables WAL journal mode for improved concurrent access.
#[cfg(feature = "native")]
pub fn open(path: &str) -> Result<rusqlite::Connection, TirBaseError> {
    let conn =
        rusqlite::Connection::open(path).map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("SQLite open failed at {path}: {e}"),
        })?;

 // Enable WAL journal mode for better concurrent read/write performance.
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("PRAGMA journal_mode=WAL failed: {e}"),
        })?;

 // Enable foreign key enforcement.
    conn.execute_batch("PRAGMA foreign_keys=ON;").map_err(|e| {
        TirBaseError::LocalStoreWriteFailed {
            reason: format!("PRAGMA foreign_keys=ON failed: {e}"),
        }
    })?;

 // Create all tables on first open.
    conn.execute_batch(CREATE_SCHEMA_SQL)
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("Schema creation failed: {e}"),
        })?;

 // ── Boot recovery (Subphase 7.3, CLAIM-31.4 / PV-9.2) ────────────────────
 //
 // WAL mode keeps committed data in `*-wal` and `*-shm` sidecar files. If
 // the process was killed mid-transaction (between BEGIN and COMMIT), SQLite
 // replays the WAL on the next `open()` transparently — an incomplete
 // transaction is rolled back automatically, so no partial rows survive
 // (Req 3.2 atomicity). We run `wal_checkpoint(TRUNCATE)` to fold the
 // recovered WAL back into the main database file. Boot uses
 // `PRAGMA quick_check` (fast) on all ledgers; full `PRAGMA integrity_check`
 // is deferred to the maintenance window and must not be required to
 // complete within 30 seconds (CLAIM-31.4).
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("WAL checkpoint failed during boot recovery: {e}"),
        })?;

    boot_quick_check(&conn)?;

    Ok(conn)
}

/// Fast boot-time integrity gate (CLAIM-31.4, PV-9.2).
///
/// Production caller: core SQLite open / boot recovery. Full
/// `integrity_check` is exposed separately for the maintenance window.
#[cfg(feature = "native")]
pub(crate) fn boot_quick_check(conn: &rusqlite::Connection) -> Result<(), TirBaseError> {
    let result = conn
        .query_row("PRAGMA quick_check;", [], |row| row.get::<_, String>(0))
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("quick_check could not run: {e}"),
        })?;
    if result.trim() != "ok" {
        return Err(TirBaseError::LocalStoreWriteFailed {
            reason: format!("SQLite quick_check failed at boot: {result}"),
        });
    }
    Ok(())
}

/// Full integrity check for the maintenance window (CLAIM-31.4, PV-9.2).
/// Must not be required to complete within 30 seconds at boot.
#[cfg(feature = "native")]
pub fn maintenance_integrity_check(conn: &rusqlite::Connection) -> Result<(), TirBaseError> {
    let integrity = conn
        .query_row("PRAGMA integrity_check;", [], |row| row.get::<_, String>(0))
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("integrity_check could not run: {e}"),
        })?;
    if integrity.trim() != "ok" {
        return Err(TirBaseError::LocalStoreWriteFailed {
            reason: format!("SQLite integrity_check failed during maintenance: {integrity}"),
        });
    }
    Ok(())
}

/// Re-run boot recovery steps against an already-open connection.
///
/// `LocalStore::open` runs this once when a DB file is first opened; this helper
/// exposes the same WAL-checkpoint + quick-check sequence so callers that
/// reopen a long-lived connection (e.g. after a forked child process crashed
/// mid-write) can verify the on-disk DB is consistent before proceeding.
///
/// Native-only: the WASM build has no SQLite connection.
#[cfg(feature = "native")]
pub(crate) fn recover_from_crash(conn: &rusqlite::Connection) -> Result<(), TirBaseError> {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("WAL checkpoint failed during boot recovery: {e}"),
        })?;
    boot_quick_check(conn)
}

/// WASM stub — on WASM the LocalStore is IndexedDB-backed (Subphase 6.3, see
/// `store::indexed_db`); there is no SQLite connection. This function is a
/// no-op placeholder so callers that are guarded by
/// `#[cfg(not(feature = "native"))]` can still reference the module without a
/// build error.
#[cfg(not(feature = "native"))]
pub fn open(_path: &str) -> Result<(), TirBaseError> {
    Ok(())
}
