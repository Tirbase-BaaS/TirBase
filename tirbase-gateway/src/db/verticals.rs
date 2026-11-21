// SPDX-License-Identifier: AGPL-3.0-only

//! F-07 per-vertical schemas with forward and backward migrations.
//!
//! Core `primary.db`/`derived.db` schemas are owned by
//! [`crate::db::migrations`]. A vertical (cold-chain, POS, venue, ...) ships its
//! own additive DDL and advances independently in
//! `vertical_schema_versions`. Each step is transactional and has an explicit
//! `down_sql`, so a failed forward migration leaves the previous vertical
//! version usable and a rollback is deliberate and recorded.

use rusqlite::Connection;

/// One versioned vertical schema step.
#[derive(Debug, Clone, Copy)]
pub struct VerticalMigration {
    pub version: i64,
    pub name: &'static str,
    /// Additive DDL (`CREATE TABLE/INDEX IF NOT EXISTS`, guarded ALTERs).
    pub sql: &'static str,
    /// Reverses `sql`. Destructive; called only by an explicit rollback.
    pub down_sql: &'static str,
}

fn ensure_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS vertical_schema_versions (
            vertical       TEXT NOT NULL,
            version        INTEGER NOT NULL,
            name           TEXT NOT NULL,
            applied_at_est INTEGER NOT NULL,
            PRIMARY KEY (vertical, version)
         );",
    )
    .map_err(|e| format!("ensure vertical schema table: {e}"))
}

pub fn vertical_version(conn: &Connection, vertical: &str) -> Result<i64, String> {
    ensure_table(conn)?;
    conn.query_row(
        "SELECT COALESCE(MAX(version),0) FROM vertical_schema_versions WHERE vertical=?1",
        [vertical],
        |r| r.get(0),
    )
    .map_err(|e| format!("vertical version: {e}"))
}

/// Apply missing vertical migrations in ascending order.
pub fn apply_vertical_migrations(
    conn: &Connection,
    vertical: &str,
    migrations: &[VerticalMigration],
) -> Result<i64, String> {
    ensure_table(conn)?;
    let mut ordered: Vec<&VerticalMigration> = migrations.iter().collect();
    ordered.sort_by_key(|m| m.version);
    let now = tirbase_core::traits::wall_hint_secs().unwrap_or(0);
    for migration in ordered {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vertical_schema_versions WHERE vertical=?1 AND version=?2",
                rusqlite::params![vertical, migration.version],
                |r| r.get(0),
            )
            .map_err(|e| format!("vertical migration check: {e}"))?;
        if exists > 0 {
            continue;
        }
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("begin vertical migration: {e}"))?;
        tx.execute_batch(migration.sql).map_err(|e| {
            format!(
                "vertical {vertical} migration {} ({}) failed: {e}",
                migration.version, migration.name
            )
        })?;
        tx.execute(
            "INSERT INTO vertical_schema_versions(vertical,version,name,applied_at_est)
             VALUES (?1,?2,?3,?4)",
            rusqlite::params![vertical, migration.version, migration.name, now],
        )
        .map_err(|e| format!("record vertical migration: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit vertical migration: {e}"))?;
    }
    vertical_version(conn, vertical)
}

/// Roll a vertical back to `target_version` (exclusive of higher versions).
pub fn rollback_vertical_migrations(
    conn: &Connection,
    vertical: &str,
    migrations: &[VerticalMigration],
    target_version: i64,
) -> Result<i64, String> {
    ensure_table(conn)?;
    let current = vertical_version(conn, vertical)?;
    if target_version >= current {
        return Ok(current);
    }
    let mut ordered: Vec<&VerticalMigration> = migrations.iter().collect();
    ordered.sort_by_key(|m| std::cmp::Reverse(m.version));
    for migration in ordered {
        if migration.version <= target_version || migration.version > current {
            continue;
        }
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vertical_schema_versions WHERE vertical=?1 AND version=?2",
                rusqlite::params![vertical, migration.version],
                |r| r.get(0),
            )
            .map_err(|e| format!("vertical rollback check: {e}"))?;
        if exists == 0 {
            continue;
        }
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("begin vertical rollback: {e}"))?;
        tx.execute_batch(migration.down_sql).map_err(|e| {
            format!(
                "vertical {vertical} rollback {} ({}) failed: {e}",
                migration.version, migration.name
            )
        })?;
        tx.execute(
            "DELETE FROM vertical_schema_versions WHERE vertical=?1 AND version=?2",
            rusqlite::params![vertical, migration.version],
        )
        .map_err(|e| format!("remove vertical migration row: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit vertical rollback: {e}"))?;
    }
    vertical_version(conn, vertical)
}
