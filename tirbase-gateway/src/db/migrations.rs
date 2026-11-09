//! SQLite schema migrations for gateway `primary.db` and `derived.db`
//! (tasks 18.1–18.3, 32.1 — CLAIM-18.1, CLAIM-18.2, CLAIM-18.3, CLAIM-32.1,
//! PV-9.3, PV-9.4).
//!
//! Migrations are idempotent, applied in ascending version order, and the
//! current schema version is queryable at runtime.  Migrations run before the
//! database is opened for reads or writes.
//!
//! Each ledger has its own `schema_migrations` table so versions advance
//! independently.  Table-creation tasks create their tables through this
//! framework by adding/appending migrations here.

use std::path::Path;

use rusqlite::Connection;

use crate::db::sqlite_errors::{apply_hardening_pragmas, DbKind, SqliteErrorAction};

/// A single, idempotent schema migration.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Monotonically increasing version (starts at 1).
    pub version: i64,
    /// Short stable name for diagnostics.
    pub name: &'static str,
    /// SQL batch applied inside a transaction.  Must be idempotent
    /// (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, additive
    /// `ALTER TABLE ... ADD COLUMN` guards, etc.).
    pub sql: &'static str,
}

/// Result of applying migrations to one database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub db_kind: DbKind,
    pub from_version: i64,
    pub to_version: i64,
    pub applied: Vec<i64>,
}

const MIGRATIONS_TABLE: &str = "schema_migrations";

fn ensure_migrations_table_kind(conn: &Connection, kind: DbKind) -> Result<(), SqliteErrorAction> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {MIGRATIONS_TABLE} (
             version    INTEGER PRIMARY KEY,
             name       TEXT NOT NULL,
             applied_at INTEGER NOT NULL
         );"
    ))
    .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "create schema_migrations"))
}

/// Current schema version (0 when no migrations have been applied).
pub fn schema_version(conn: &Connection, kind: DbKind) -> Result<i64, SqliteErrorAction> {
    ensure_migrations_table_kind(conn, kind)?;
    let v: i64 = conn
        .query_row(
            &format!("SELECT COALESCE(MAX(version), 0) FROM {MIGRATIONS_TABLE}"),
            [],
            |row| row.get(0),
        )
        .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "query schema version"))?;
    Ok(v)
}

/// Apply `migrations` in ascending version order.  Idempotent: versions already
/// present in `schema_migrations` are skipped.  Each migration runs in its own
/// transaction.
pub fn apply_migrations(
    conn: &Connection,
    kind: DbKind,
    migrations: &[Migration],
) -> Result<MigrationReport, SqliteErrorAction> {
    let mut ordered: Vec<&Migration> = migrations.iter().collect();
    ordered.sort_by_key(|m| m.version);

    ensure_migrations_table_kind(conn, kind)?;
    let from_version = schema_version(conn, kind)?;
    let mut applied = Vec::new();
    let now = now_secs();

    for migration in ordered {
        let exists: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {MIGRATIONS_TABLE} WHERE version = ?1"),
                [migration.version],
                |row| row.get(0),
            )
            .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "check migration version"))?;
        if exists > 0 {
            continue;
        }

        let tx = conn.unchecked_transaction().map_err(|e| {
            SqliteErrorAction::from_rusqlite(kind, &e, "begin migration transaction")
        })?;
        tx.execute_batch(migration.sql).map_err(|e| {
            SqliteErrorAction::from_rusqlite(
                kind,
                &e,
                &format!("apply migration {} ({})", migration.version, migration.name),
            )
        })?;
        tx.execute(
            &format!(
                "INSERT INTO {MIGRATIONS_TABLE} (version, name, applied_at) VALUES (?1, ?2, ?3)"
            ),
            rusqlite::params![migration.version, migration.name, now],
        )
        .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "record migration"))?;
        tx.commit()
            .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "commit migration"))?;
        applied.push(migration.version);
    }

    ensure_task25_checkpoint_hash_column(conn, kind)?;
    let to_version = schema_version(conn, kind)?;
    Ok(MigrationReport {
        db_kind: kind,
        from_version,
        to_version,
        applied,
    })
}

/// 25.3/25.4: ensure `security_events.checkpoint_hash` exists for DBs created
/// before migration v3 or with older v1 DDL. Idempotent.
fn ensure_task25_checkpoint_hash_column(
    conn: &Connection,
    kind: DbKind,
) -> Result<(), SqliteErrorAction> {
    if kind != DbKind::Primary {
        return Ok(());
    }
    let has_table: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='security_events'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "check security_events table"))?;
    if has_table == 0 {
        return Ok(());
    }
    let has_col: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('security_events') WHERE name='checkpoint_hash'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "check checkpoint_hash column"))?;
    if has_col == 0 {
        conn.execute_batch("ALTER TABLE security_events ADD COLUMN checkpoint_hash BLOB;")
            .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "add checkpoint_hash"))?;
    }
    Ok(())
}

fn now_secs() -> i64 {
    // Best-effort wall hint; migration bookkeeping is not security-critical.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn injected_action(kind: DbKind) -> Option<SqliteErrorAction> {
    let var = match kind {
        DbKind::Primary => "TIRBASE_TEST_INJECT_PRIMARY_SQLITE",
        DbKind::Derived => "TIRBASE_TEST_INJECT_DERIVED_SQLITE",
    };
    let raw = std::env::var(var).ok()?;
    let code = match raw.trim().to_ascii_uppercase().as_str() {
        "IOERR" | "SQLITE_IOERR" => rusqlite::ffi::SQLITE_IOERR,
        "FULL" | "SQLITE_FULL" => rusqlite::ffi::SQLITE_FULL,
        "CORRUPT" | "SQLITE_CORRUPT" => rusqlite::ffi::SQLITE_CORRUPT,
        _ => return None,
    };
    Some(crate::db::sqlite_errors::action_for_primary_code(
        kind,
        code,
        "test injection",
    ))
}

fn record_boot_check(kind: DbKind, check: &str) {
    if let Ok(path) = std::env::var("TIRBASE_TEST_RECORD_BOOT_CHECK") {
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "{}:{check}", kind.as_str())
            });
    }
}

fn boot_quick_check(conn: &Connection, kind: DbKind) -> Result<(), SqliteErrorAction> {
    // CLAIM-31.4 wiring mutation guard: test can force the wrong boot check to
    // prove a startup-time test fails when integrity_check runs at boot.
    if std::env::var("TIRBASE_TEST_BOOT_USES_INTEGRITY_CHECK")
        .ok()
        .as_deref()
        == Some("1")
    {
        record_boot_check(kind, "integrity_check");
        return maintenance_integrity_check(conn, kind);
    }
    record_boot_check(kind, "quick_check");
    let result: String = conn
        .query_row("PRAGMA quick_check;", [], |row| row.get(0))
        .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "PRAGMA quick_check"))?;
    if result.trim() != "ok" {
        return Err(SqliteErrorAction::EnterRestrictedCorrupt {
            kind,
            detail: format!(
                "{kind} quick_check failed at boot: {result}",
                kind = kind.as_str()
            ),
        });
    }
    Ok(())
}

/// Full integrity check for maintenance window (CLAIM-31.4). Not required within 30s at boot.
pub fn maintenance_integrity_check(
    conn: &Connection,
    kind: DbKind,
) -> Result<(), SqliteErrorAction> {
    record_boot_check(kind, "maintenance_integrity_check");
    let result: String = conn
        .query_row("PRAGMA integrity_check;", [], |row| row.get(0))
        .map_err(|e| SqliteErrorAction::from_rusqlite(kind, &e, "PRAGMA integrity_check"))?;
    if result.trim() != "ok" {
        return Err(SqliteErrorAction::EnterRestrictedCorrupt {
            kind,
            detail: format!(
                "{kind} integrity_check failed: {result}",
                kind = kind.as_str()
            ),
        });
    }
    Ok(())
}

/// Open `primary.db`, apply hardening + migrations (CLAIM-18.1, 18.3, 32.1).
/// STATE-INVENTORY: PERSISTED primary.db (CLAIM-31.1, PV-9.1)
pub fn open_primary(path: impl AsRef<Path>) -> Result<Connection, SqliteErrorAction> {
    let path = path.as_ref();
    ensure_parent(path, DbKind::Primary)?;
    let conn = Connection::open(path)
        .map_err(|e| SqliteErrorAction::from_rusqlite(DbKind::Primary, &e, "open primary.db"))?;
    // WAL + synchronous=FULL before migrations (CLAIM-18.1).  journal_mode is a
    // persistent DB property but we set it explicitly so a fresh or copied DB
    // is always in the required mode.
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| {
            SqliteErrorAction::from_rusqlite(DbKind::Primary, &e, "set journal_mode=WAL")
        })?;
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(|e| {
            SqliteErrorAction::from_rusqlite(DbKind::Primary, &e, "set synchronous=FULL")
        })?;
    apply_hardening_pragmas(&conn, DbKind::Primary)?;
    apply_migrations(&conn, DbKind::Primary, primary_migrations())?;
    boot_quick_check(&conn, DbKind::Primary)?; // CLAIM-31.4, PV-9.2
    if let Some(action) = injected_action(DbKind::Primary) {
        return Err(action);
    }
    Ok(conn)
}

/// Open `derived.db`, apply hardening + migrations (CLAIM-18.2, 18.3, 32.1).
/// STATE-INVENTORY: PERSISTED derived.db (CLAIM-31.1, PV-9.1)
pub fn open_derived(path: impl AsRef<Path>) -> Result<Connection, SqliteErrorAction> {
    let path = path.as_ref();
    ensure_parent(path, DbKind::Derived)?;
    let conn = Connection::open(path)
        .map_err(|e| SqliteErrorAction::from_rusqlite(DbKind::Derived, &e, "open derived.db"))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| {
            SqliteErrorAction::from_rusqlite(DbKind::Derived, &e, "set journal_mode=WAL")
        })?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| {
            SqliteErrorAction::from_rusqlite(DbKind::Derived, &e, "set synchronous=NORMAL")
        })?;
    apply_hardening_pragmas(&conn, DbKind::Derived)?;
    apply_migrations(&conn, DbKind::Derived, derived_migrations())?;
    boot_quick_check(&conn, DbKind::Derived)?; // CLAIM-31.4, PV-9.2
    if let Some(action) = injected_action(DbKind::Derived) {
        return Err(action);
    }
    Ok(conn)
}

fn ensure_parent(path: &Path, kind: DbKind) -> Result<(), SqliteErrorAction> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| SqliteErrorAction::IoError {
                kind,
                context: format!("create directory {}", parent.display()),
                detail: e.to_string(),
            })?;
        }
    }
    Ok(())
}

/// PrimaryLedger migrations (design.md §DB Schema, primary.db).
///
/// NOTE: `pending_approvals` in this migration uses the design.md shape
/// (approval_id/kind/payload_hash/co_signatures_json/...). The existing
/// `SqlitePendingApprovalsStore` (task 12.8) uses an op_id/op_type layout;
/// both are kept compatible by creating the task-12.8 table via its own
/// helper when that store is opened. Migration v1 owns the design-mandated
/// table names so task 18's "all PrimaryLedger tables exist" requirement is
/// satisfied at boot; schema harmonization is tracked by follow-on tasks.
pub fn primary_migrations() -> &'static [Migration] {
    &PRIMARY_MIGRATIONS
}

/// DerivedLedger migrations (design.md §DB Schema, derived.db).
pub fn derived_migrations() -> &'static [Migration] {
    &DERIVED_MIGRATIONS
}

const PRIMARY_MIGRATIONS: [Migration; 3] = [
    Migration {
        version: 1,
        name: "task18_primary_ledger_tables",
        sql: r#"
-- Applied_Effects_Ledger (PrimaryLedger) (PV-5.1)
CREATE TABLE IF NOT EXISTS applied_effects_ledger (
    entry_id          BLOB PRIMARY KEY,
    issuer_did        TEXT NOT NULL,
    target_id         TEXT NOT NULL,
    param             TEXT NOT NULL,
    desired_mantissa  INTEGER NOT NULL,
    desired_exponent  INTEGER NOT NULL,
    desired_unit_id   INTEGER NOT NULL,
    sequence_number   INTEGER NOT NULL,
    idempotency_key   BLOB NOT NULL,
    expiry_est        INTEGER NOT NULL,
    policy_version    INTEGER NOT NULL,
    enrollment_epoch  INTEGER NOT NULL DEFAULT 0,
    state             TEXT NOT NULL,
    actuating_ts      INTEGER NOT NULL,
    completion_ts     INTEGER,
    driver_response   BLOB
);
CREATE INDEX IF NOT EXISTS idx_aef_state  ON applied_effects_ledger(state);
CREATE INDEX IF NOT EXISTS idx_aef_target ON applied_effects_ledger(target_id, state);

-- Anti-replay window store (PrimaryLedger) (PV-5.5, PV-5.7)
CREATE TABLE IF NOT EXISTS anti_replay_windows (
    issuer_did        TEXT NOT NULL,
    target_id         TEXT NOT NULL,
    enrollment_epoch  INTEGER NOT NULL DEFAULT 0,
    highest_seen      INTEGER NOT NULL DEFAULT 0,
    seen_bitmap       BLOB NOT NULL,
    forward_gap       INTEGER NOT NULL DEFAULT 1024,
    PRIMARY KEY (issuer_did, target_id, enrollment_epoch)
);

-- Decided-outcome cache (PrimaryLedger). Schema matches
-- `SqliteDecidedOutcomesStore` / Stage 16 guard (CLAIM-14.11, PV-5).
CREATE TABLE IF NOT EXISTS decided_outcomes (
    issuer_did        TEXT NOT NULL,
    target_id         TEXT NOT NULL,
    sequence_number   INTEGER NOT NULL,
    enrollment_epoch  INTEGER NOT NULL,
    accepted          INTEGER NOT NULL,
    rejection_category TEXT,
    detail            TEXT,
    PRIMARY KEY (issuer_did, target_id, sequence_number, enrollment_epoch)
);

-- Idempotency keys scoped to (issuer_did, target_id)
CREATE TABLE IF NOT EXISTS idempotency_keys (
    issuer_did       TEXT NOT NULL,
    target_id        TEXT NOT NULL,
    idempotency_key  BLOB NOT NULL,
    original_result  TEXT NOT NULL,
    recorded_at_est  INTEGER NOT NULL,
    expires_at_est   INTEGER NOT NULL,
    PRIMARY KEY (issuer_did, target_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_idem_expiry ON idempotency_keys(expires_at_est);

-- SingleWriterLease store (PrimaryLedger) (PV-5.8)
CREATE TABLE IF NOT EXISTS single_writer_leases (
    target_id              TEXT PRIMARY KEY,
    issuer_did             TEXT NOT NULL,
    expires_mono           INTEGER NOT NULL,
    consecutive_renewals   INTEGER NOT NULL DEFAULT 0,
    cooldown_until_mono    INTEGER
);

-- Policy bundles store (PrimaryLedger) (PV-4.8)
CREATE TABLE IF NOT EXISTS policy_bundles (
    version             INTEGER PRIMARY KEY,
    prev_version_hash   BLOB NOT NULL,
    envelope_bytes      BLOB NOT NULL,
    co_signatures_json  TEXT NOT NULL DEFAULT '[]',
    timelock_until_est  INTEGER,
    kind                TEXT,
    accepted_at_est     INTEGER NOT NULL,
    anti_rollback_seq   INTEGER NOT NULL
);

-- Pending multi-party approvals. Schema matches `SqlitePendingApprovalsStore`
-- (task 12.8, CLAIM-12.8, PV-4.10).
CREATE TABLE IF NOT EXISTS pending_approvals (
    op_id               TEXT PRIMARY KEY,
    op_type             TEXT NOT NULL,
    target              TEXT,
    payload_json        TEXT NOT NULL,
    required_m          INTEGER NOT NULL,
    required_n          INTEGER NOT NULL,
    timelock_until_est  INTEGER,
    cancel_deadline_est INTEGER,
    created_est         INTEGER NOT NULL,
    status              TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_approval_signatures (
    op_id          TEXT NOT NULL,
    signer_did     TEXT NOT NULL,
    signature_json TEXT NOT NULL,
    role           TEXT,
    PRIMARY KEY (op_id, signer_did)
);

-- Security event log (PrimaryLedger) (PV-7.2)
CREATE TABLE IF NOT EXISTS security_events (
    seq                  INTEGER PRIMARY KEY,
    segment_id           INTEGER NOT NULL DEFAULT 1,
    category             TEXT NOT NULL,
    severity             TEXT NOT NULL,
    actor_did            TEXT,
    target               TEXT,
    reason_code          TEXT NOT NULL,
    best_effort_wall_ts  INTEGER NOT NULL,
    time_source_flag     TEXT NOT NULL,
    prev_hash            BLOB NOT NULL,
    is_checkpoint        INTEGER NOT NULL DEFAULT 0,
    checkpoint_signature BLOB,
    checkpoint_hash      BLOB
);

-- Security event segments (PV-7.4)
CREATE TABLE IF NOT EXISTS security_event_segments (
    segment_id     INTEGER PRIMARY KEY,
    started_at_seq INTEGER NOT NULL,
    ended_at_seq   INTEGER,
    start_hash     BLOB NOT NULL,
    reason         TEXT NOT NULL
);

-- Personal fields salted commitments side-car (PV-7.7, RD-3)
CREATE TABLE IF NOT EXISTS security_event_personal_fields (
    seq        INTEGER NOT NULL,
    field_name TEXT NOT NULL,
    salt       BLOB NOT NULL,
    plaintext  BLOB NOT NULL,
    PRIMARY KEY (seq, field_name),
    FOREIGN KEY (seq) REFERENCES security_events(seq)
);

-- Peer checkpoint witnesses (PV-7.10)
CREATE TABLE IF NOT EXISTS peer_checkpoint_witnesses (
    peer_did          TEXT NOT NULL,
    checkpoint_seq    INTEGER NOT NULL,
    checkpoint_hash   BLOB NOT NULL,
    witnessed_at_mono INTEGER NOT NULL,
    PRIMARY KEY (peer_did, checkpoint_seq)
);

-- Monotonic counters / hw binding state (PrimaryLedger) (PV-9.8, RD-2).
-- Key-value layout compatible with `HardwareCounterBinding`.
CREATE TABLE IF NOT EXISTS monotonic_counters (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);

-- TimeRatchet persisted state (PV-22.2)
CREATE TABLE IF NOT EXISTS time_ratchet (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    last_beacon_time INTEGER NOT NULL DEFAULT 0,
    mono_at_beacon   INTEGER NOT NULL DEFAULT 0,
    beacon_boot_id   INTEGER NOT NULL DEFAULT 0,
    persisted_floor  INTEGER NOT NULL DEFAULT 0,
    updated_at_mono  INTEGER NOT NULL DEFAULT 0
);

-- Per-device epoch (PV-5.5, PV-9.8)
CREATE TABLE IF NOT EXISTS device_epoch (
    device_id     TEXT PRIMARY KEY,
    epoch         INTEGER NOT NULL DEFAULT 0,
    bumped_at_est INTEGER NOT NULL,
    co_sig_pa     BLOB,
    co_sig_rm     BLOB
);

-- Enrollment nonces (PV-3.13). Schema matches `SqliteEnrollmentNonceStore`
-- (task 8.5, CLAIM-8.5).
CREATE TABLE IF NOT EXISTS enrollment_nonces (
    nonce           BLOB PRIMARY KEY,
    recorded_at_est INTEGER NOT NULL,
    expires_at_est  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS enrollment_nonces_expires
    ON enrollment_nonces(expires_at_est);

-- Challenge nonces for critical params in UNVERIFIED freshness (PV-22.3)
CREATE TABLE IF NOT EXISTS challenge_nonces (
    device_id        TEXT NOT NULL,
    param            TEXT NOT NULL,
    nonce            BLOB NOT NULL,
    issued_at_mono   INTEGER NOT NULL,
    expires_at_mono  INTEGER NOT NULL,
    issuer_did       TEXT NOT NULL,
    target_id        TEXT NOT NULL,
    consumed         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (nonce)
);
CREATE INDEX IF NOT EXISTS idx_challenge_nonces_device_param
    ON challenge_nonces(device_id, target_id, param, issued_at_mono);

-- Drift and rate history per (issuer, target, param) (PV-4.7)
CREATE TABLE IF NOT EXISTS drift_rate_history (
    issuer_did     TEXT NOT NULL,
    target_id      TEXT NOT NULL,
    param          TEXT NOT NULL,
    mono_secs      INTEGER NOT NULL,
    value_mantissa INTEGER NOT NULL,
    exponent       INTEGER NOT NULL,
    unit_id        INTEGER NOT NULL,
    PRIMARY KEY (issuer_did, target_id, param, mono_secs)
);
CREATE INDEX IF NOT EXISTS idx_drift_lookup
    ON drift_rate_history(issuer_did, target_id, param, mono_secs);
"#,
    },
    Migration {
        version: 2,
        name: "task21_single_writer_target_state_drift",
        sql: r#"
CREATE TABLE IF NOT EXISTS single_writer_leases (
    target_id              TEXT PRIMARY KEY,
    issuer_did             TEXT NOT NULL,
    expires_mono           INTEGER NOT NULL,
    consecutive_renewals   INTEGER NOT NULL DEFAULT 0,
    cooldown_until_mono    INTEGER
);
CREATE TABLE IF NOT EXISTS target_state (
    target_id       TEXT NOT NULL,
    param           TEXT NOT NULL,
    value_mantissa  INTEGER NOT NULL,
    value_exponent  INTEGER NOT NULL,
    value_unit_id   INTEGER NOT NULL,
    PRIMARY KEY (target_id, param)
);
CREATE TABLE IF NOT EXISTS drift_rate_summary (
    target_id                 TEXT NOT NULL,
    param                     TEXT NOT NULL,
    last_accepted_est         INTEGER NOT NULL,
    last_accepted_mono        INTEGER NOT NULL,
    last_value_mantissa       INTEGER NOT NULL,
    last_value_exponent       INTEGER NOT NULL,
    last_value_unit_id        INTEGER NOT NULL,
    window_start_est          INTEGER NOT NULL DEFAULT 0,
    cumulative_delta_mantissa INTEGER NOT NULL DEFAULT 0,
    last_change_mono          INTEGER NOT NULL,
    last_deactivation_mono    INTEGER,
    PRIMARY KEY (target_id, param)
);
"#,
    },
    Migration {
        version: 3,
        name: "task25_security_events_checkpoint_hash",
        sql: r#"
-- 25.3/25.4: checkpoint_hash column for signed checkpoint records (PV-7.3).
-- v1 now creates the column for fresh DBs; this migration is a compatibility
-- marker for the framework. The runtime also ensures the column exists.
SELECT 1;
"#,
    },
];

const DERIVED_MIGRATIONS: [Migration; 1] = [Migration {
    version: 1,
    name: "task18_derived_ledger_tables",
    sql: r#"
-- Automerge documents (DerivedLedger)
CREATE TABLE IF NOT EXISTS automerge_docs (
    table_name  TEXT PRIMARY KEY,
    doc_bytes   BLOB NOT NULL
);

-- DAG nodes (DerivedLedger)
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

-- DAG edges (DerivedLedger)
CREATE TABLE IF NOT EXISTS dag_edges (
    parent_id   BLOB NOT NULL,
    child_id    BLOB NOT NULL,
    PRIMARY KEY (parent_id, child_id)
);
CREATE INDEX IF NOT EXISTS idx_dag_edges_parent ON dag_edges(parent_id);
CREATE INDEX IF NOT EXISTS idx_dag_edges_child  ON dag_edges(child_id);

-- Schema quarantine (replayable) (PV-6.7)
CREATE TABLE IF NOT EXISTS schema_quarantine (
    id           BLOB PRIMARY KEY,
    sender_did   TEXT NOT NULL,
    raw_bytes    BLOB NOT NULL,
    reason       TEXT NOT NULL,
    received_at  INTEGER NOT NULL,
    migration_id BLOB,
    replay_status TEXT,
    replay_ts    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sq_sender ON schema_quarantine(sender_did, received_at);

-- Rate quarantine summary rows (PV-6.7)
CREATE TABLE IF NOT EXISTS rate_quarantine_summary (
    sender_did      TEXT NOT NULL,
    window_start    INTEGER NOT NULL,
    rejected_count  INTEGER NOT NULL,
    PRIMARY KEY (sender_did, window_start)
);

-- Sidecar ledger (DerivedLedger)
CREATE TABLE IF NOT EXISTS sidecar_ledger (
    id            BLOB PRIMARY KEY,
    migration_id  BLOB NOT NULL,
    table_name    TEXT NOT NULL,
    delta_bytes   BLOB NOT NULL,
    recorded_ts   INTEGER NOT NULL,
    replay_status TEXT,
    conflict_info TEXT
);
CREATE INDEX IF NOT EXISTS idx_sidecar_migration ON sidecar_ledger(migration_id, recorded_ts);

-- Device identity (DerivedLedger / gateway copy)
CREATE TABLE IF NOT EXISTS device_identity (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    did           TEXT NOT NULL,
    keypair_bytes BLOB NOT NULL
);
"#,
}];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let u = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("tirbase-mig-{tag}-{}-{u}.db", std::process::id()))
    }

    #[test]
    fn migrations_are_idempotent_and_version_queryable() {
        let db = tmp("idempotent");
        {
            let conn = open_primary(&db).expect("open primary");
            assert!(schema_version(&conn, DbKind::Primary).unwrap() >= 2);
        }
        {
            let conn = open_primary(&db).expect("reopen primary");
            let report = apply_migrations(&conn, DbKind::Primary, primary_migrations()).unwrap();
            assert!(
                report.applied.is_empty(),
                "second run must not reapply: {report:?}"
            );
            assert!(report.to_version >= 2);
        }
        let _ = std::fs::remove_file(db);
    }
}
