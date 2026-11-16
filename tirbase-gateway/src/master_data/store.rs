// SPDX-License-Identifier: AGPL-3.0-only

//! SQLite persistence for the master data service (CC-15).
//!
//! Two tables, created idempotently on open:
//!
//! - `master_data_versions` — one immutable row per `(kind, id, version)`. The
//!   effective range is half-open, `[effective_from_est, effective_to_est)`, with
//!   `effective_to_est` NULL while the version is the newest. A revision never
//!   rewrites a row's content: it inserts the next version and closes the
//!   previous range at the new start.
//! - `master_data_audit` — append-only history of every create and revision,
//!   with the actor, the reason, the content digest and a detail object.
//!
//! Reads are by entity or by "everything effective at `at_est`", which is what
//! resolves a historical event without consulting current master data.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::master_data::{
    AuditAction, AuditEntry, EntityKind, LifecycleStatus, MasterAttributes, MasterDataError,
    MasterVersion,
};

const COLUMNS: &str = "kind, id, version, effective_from_est, effective_to_est, status, \
     parent_id, site_id, attributes_json, digest, actor_did, created_est";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS master_data_versions (
    kind                TEXT    NOT NULL,
    id                  TEXT    NOT NULL,
    version             INTEGER NOT NULL,
    effective_from_est  INTEGER NOT NULL,
    effective_to_est    INTEGER,
    status              TEXT    NOT NULL,
    parent_id           TEXT,
    site_id             TEXT,
    attributes_json     TEXT    NOT NULL,
    digest              TEXT    NOT NULL,
    actor_did           TEXT    NOT NULL,
    created_est         INTEGER NOT NULL,
    PRIMARY KEY (kind, id, version)
);
CREATE INDEX IF NOT EXISTS idx_master_data_pending
    ON master_data_versions(kind, id, effective_to_est);
CREATE INDEX IF NOT EXISTS idx_master_data_site
    ON master_data_versions(kind, site_id);

CREATE TABLE IF NOT EXISTS master_data_audit (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL,
    id          TEXT    NOT NULL,
    version     INTEGER NOT NULL,
    action      TEXT    NOT NULL,
    actor_did   TEXT    NOT NULL,
    at_est      INTEGER NOT NULL,
    digest      TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    detail_json TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_master_data_audit_entity
    ON master_data_audit(kind, id, seq);
"#;

fn store_error(error: impl std::fmt::Display) -> MasterDataError {
    MasterDataError::Store(error.to_string())
}

/// Durable store for versioned master data.
#[derive(Debug)]
pub struct MasterDataStore {
    conn: Connection,
}

impl MasterDataStore {
    /// Open the store at `path`, applying the gateway hardening pragmas.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MasterDataError> {
        let conn = crate::db::open_primary(path)
            .map_err(|error| MasterDataError::Store(format!("open primary db: {error:?}")))?;
        Self::from_connection(conn)
    }

    /// Open an in-memory store (tests, ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, MasterDataError> {
        let conn = Connection::open_in_memory().map_err(store_error)?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, MasterDataError> {
        conn.execute_batch(SCHEMA).map_err(|error| {
            MasterDataError::Store(format!("create master data schema: {error}"))
        })?;
        Ok(Self { conn })
    }

    /// Insert one immutable version. Fails if the row already exists.
    pub fn insert_version(&self, version: &MasterVersion) -> Result<(), MasterDataError> {
        let attributes = serde_json::to_string(&version.attributes)
            .map_err(|error| MasterDataError::Store(format!("encode attributes: {error}")))?;
        self.conn
            .execute(
                "INSERT INTO master_data_versions (kind, id, version, effective_from_est, \
                 effective_to_est, status, parent_id, site_id, attributes_json, digest, \
                 actor_did, created_est) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    version.kind.as_str(),
                    version.id,
                    version.version,
                    version.effective_from_est,
                    version.effective_to_est,
                    version.status.as_str(),
                    version.parent_id,
                    version.site_id,
                    attributes,
                    version.digest,
                    version.actor_did,
                    version.created_est,
                ],
            )
            .map_err(|error| MasterDataError::Store(format!("insert version: {error}")))?;
        Ok(())
    }

    /// Close a version's effective range at `effective_to_est`.
    pub fn close_version(
        &self,
        kind: EntityKind,
        id: &str,
        version: u32,
        effective_to_est: i64,
    ) -> Result<(), MasterDataError> {
        self.conn
            .execute(
                "UPDATE master_data_versions SET effective_to_est=?1 \
                 WHERE kind=?2 AND id=?3 AND version=?4",
                params![effective_to_est, kind.as_str(), id, version],
            )
            .map_err(|error| MasterDataError::Store(format!("close version: {error}")))?;
        Ok(())
    }

    /// Every version of one entity, oldest first.
    pub fn versions(
        &self,
        kind: EntityKind,
        id: &str,
    ) -> Result<Vec<MasterVersion>, MasterDataError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM master_data_versions WHERE kind=?1 AND id=?2 ORDER BY version"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params![kind.as_str(), id], row_to_version)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// The newest version of one entity, whatever its effective range.
    pub fn latest(
        &self,
        kind: EntityKind,
        id: &str,
    ) -> Result<Option<MasterVersion>, MasterDataError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM master_data_versions WHERE kind=?1 AND id=?2 \
             ORDER BY version DESC LIMIT 1"
        );
        self.conn
            .query_row(&sql, params![kind.as_str(), id], row_to_version)
            .optional()
            .map_err(store_error)
    }

    /// The version in force at `at_est`, if any.
    pub fn at(
        &self,
        kind: EntityKind,
        id: &str,
        at_est: i64,
    ) -> Result<Option<MasterVersion>, MasterDataError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM master_data_versions \
             WHERE kind=?1 AND id=?2 AND effective_from_est<=?3 \
             AND (effective_to_est IS NULL OR effective_to_est > ?3) \
             ORDER BY version DESC LIMIT 1"
        );
        self.conn
            .query_row(&sql, params![kind.as_str(), id, at_est], row_to_version)
            .optional()
            .map_err(store_error)
    }

    /// Every version in force at `at_est`, ordered by kind then id.
    pub fn all_at(&self, at_est: i64) -> Result<Vec<MasterVersion>, MasterDataError> {
        let sql = format!(
            "SELECT {COLUMNS} FROM master_data_versions \
             WHERE effective_from_est<=?1 AND (effective_to_est IS NULL OR effective_to_est > ?1) \
             ORDER BY kind, id"
        );
        let mut statement = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = statement
            .query_map(params![at_est], row_to_version)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Append one audit row and return its sequence number.
    pub fn append_audit(&self, entry: &AuditEntry) -> Result<i64, MasterDataError> {
        let detail = serde_json::to_string(&entry.detail)
            .map_err(|error| MasterDataError::Store(format!("encode audit detail: {error}")))?;
        self.conn
            .execute(
                "INSERT INTO master_data_audit (kind, id, version, action, actor_did, at_est, \
                 digest, reason, detail_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    entry.kind.as_str(),
                    entry.id,
                    entry.version,
                    entry.action.as_str(),
                    entry.actor_did,
                    entry.at_est,
                    entry.digest,
                    entry.reason,
                    detail,
                ],
            )
            .map_err(|error| MasterDataError::Store(format!("append audit: {error}")))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Audit history for one entity, oldest first.
    pub fn audit(&self, kind: EntityKind, id: &str) -> Result<Vec<AuditEntry>, MasterDataError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT seq, kind, id, version, action, actor_did, at_est, digest, reason, \
                 detail_json FROM master_data_audit WHERE kind=?1 AND id=?2 ORDER BY seq",
            )
            .map_err(store_error)?;
        let rows = statement
            .query_map(params![kind.as_str(), id], row_to_audit)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }
}

fn row_to_version(row: &Row<'_>) -> rusqlite::Result<MasterVersion> {
    let kind: String = row.get(0)?;
    let status: String = row.get(5)?;
    let attributes: String = row.get(8)?;
    Ok(MasterVersion {
        kind: EntityKind::parse(&kind).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown master data kind {kind}"),
                )),
            )
        })?,
        id: row.get(1)?,
        version: row.get(2)?,
        effective_from_est: row.get(3)?,
        effective_to_est: row.get(4)?,
        status: LifecycleStatus::parse(&status).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown lifecycle status {status}"),
                )),
            )
        })?,
        parent_id: row.get(6)?,
        site_id: row.get(7)?,
        attributes: serde_json::from_str::<MasterAttributes>(&attributes).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                8,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("decode attributes: {error}"),
                )),
            )
        })?,
        digest: row.get(9)?,
        actor_did: row.get(10)?,
        created_est: row.get(11)?,
    })
}

fn row_to_audit(row: &Row<'_>) -> rusqlite::Result<AuditEntry> {
    let kind: String = row.get(1)?;
    let action: String = row.get(4)?;
    let detail: String = row.get(9)?;
    Ok(AuditEntry {
        seq: row.get(0)?,
        kind: EntityKind::parse(&kind).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown master data kind {kind}"),
                )),
            )
        })?,
        id: row.get(2)?,
        version: row.get(3)?,
        action: AuditAction::parse(&action).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown audit action {action}"),
                )),
            )
        })?,
        actor_did: row.get(5)?,
        at_est: row.get(6)?,
        digest: row.get(7)?,
        reason: row.get(8)?,
        detail: serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
    })
}
