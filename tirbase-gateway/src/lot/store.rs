// SPDX-License-Identifier: AGPL-3.0-only

//! SQLite persistence for lot and batch traceability (CC-12).
//!
//! Four tables, created idempotently on open:
//!
//! - `lot_records` — one row per lot/batch identity: tenant, kind, label, site,
//!   location, device links, time window, ledger links, quantity and unit.
//! - `lot_edges` — the parent/child graph. `(parent_id, child_id, kind)` is the
//!   primary key, so the same relationship cannot be recorded twice. The edge
//!   direction is always *downstream*: the child is derived from, produced by,
//!   repacked from, or aggregated out of the parent.
//! - `lot_operations` — the idempotency ledger for split/merge/repack. The
//!   `operation_id` is the key; a replay of the same request finds the row and
//!   returns it instead of writing anything.
//! - `lot_dispositions` — recall/disposition links recorded against a lot
//!   (`(lot_id, record_id)` key), so a recalled lot can report the verdict that
//!   was reached for it.
//!
//! Statements are issued one at a time. Multi-row operations (split, merge,
//! repack) go through [`LotStore::commit_operation`], which writes the operation
//! row, the new lot rows and the edges inside a single transaction, so a crash
//! leaves either the whole derived lot lineage or none of it.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::lot::{
    EdgeKind, LedgerLink, LotEdge, LotError, LotKind, LotOperation, LotRecord, OpKind, TimeWindow,
};

const LOT_COLUMNS: &str = "lot_id, tenant, kind, label, site_id, location_id, device_ids_json, \
     window_start_est, window_end_est, ledger_entries_json, quantity, uom, created_est, \
     updated_est, revision";

const EDGE_COLUMNS: &str = "parent_id, child_id, kind, operation_id, created_est";

const OPERATION_COLUMNS: &str =
    "operation_id, kind, inputs_json, outputs_json, request_digest, at_est";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS lot_records (
    lot_id              TEXT PRIMARY KEY,
    tenant              TEXT NOT NULL,
    kind                TEXT NOT NULL,
    label               TEXT NOT NULL,
    site_id             TEXT NOT NULL,
    location_id         TEXT NOT NULL,
    device_ids_json     TEXT NOT NULL,
    window_start_est    INTEGER NOT NULL,
    window_end_est      INTEGER,
    ledger_entries_json TEXT NOT NULL,
    quantity            INTEGER NOT NULL,
    uom                 TEXT NOT NULL,
    created_est         INTEGER NOT NULL,
    updated_est         INTEGER NOT NULL,
    revision            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lot_records_site
    ON lot_records(tenant, site_id, location_id);
CREATE INDEX IF NOT EXISTS idx_lot_records_window
    ON lot_records(tenant, window_start_est);

CREATE TABLE IF NOT EXISTS lot_edges (
    parent_id    TEXT NOT NULL,
    child_id     TEXT NOT NULL,
    kind         TEXT NOT NULL,
    operation_id TEXT,
    created_est  INTEGER NOT NULL,
    PRIMARY KEY (parent_id, child_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_lot_edges_child ON lot_edges(child_id);

CREATE TABLE IF NOT EXISTS lot_operations (
    operation_id   TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    inputs_json    TEXT NOT NULL,
    outputs_json   TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    at_est         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS lot_dispositions (
    lot_id      TEXT NOT NULL,
    record_id   TEXT NOT NULL,
    disposition TEXT NOT NULL,
    reason      TEXT NOT NULL,
    decided_est INTEGER NOT NULL,
    PRIMARY KEY (lot_id, record_id)
);
"#;

fn store_error(error: impl std::fmt::Display) -> LotError {
    LotError::Store(error.to_string())
}

/// Durable store for lot identities, lineage edges, operations and dispositions.
#[derive(Debug)]
pub struct LotStore {
    conn: Connection,
}

impl LotStore {
    /// Open the store at `path`, applying the gateway hardening pragmas.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LotError> {
        let conn = crate::db::open_primary(path)
            .map_err(|error| LotError::Store(format!("open primary db: {error:?}")))?;
        Self::from_connection(conn)
    }

    /// Open an in-memory store (tests, ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, LotError> {
        let conn = Connection::open_in_memory().map_err(store_error)?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, LotError> {
        conn.execute_batch(SCHEMA)
            .map_err(|error| LotError::Store(format!("create lot schema: {error}")))?;
        Ok(Self { conn })
    }

    // -----------------------------------------------------------------------
    // Lot identities
    // -----------------------------------------------------------------------

    /// Insert a lot identity. Fails when the id already exists.
    pub fn insert_lot(&self, lot: &LotRecord) -> Result<(), LotError> {
        insert_lot(&self.conn, lot)
    }

    /// Replace every mutable column of an existing lot identity.
    pub fn update_lot(&self, lot: &LotRecord) -> Result<(), LotError> {
        self.conn
            .execute(
                "UPDATE lot_records SET tenant=?2, kind=?3, label=?4, site_id=?5, \
                 location_id=?6, device_ids_json=?7, window_start_est=?8, window_end_est=?9, \
                 ledger_entries_json=?10, quantity=?11, uom=?12, created_est=?13, \
                 updated_est=?14, revision=?15 WHERE lot_id=?1",
                params![
                    lot.lot_id,
                    lot.tenant,
                    lot.kind.as_str(),
                    lot.label,
                    lot.site_id,
                    lot.location_id,
                    serde_json::to_string(&lot.device_ids).map_err(store_error)?,
                    lot.window.start_est,
                    lot.window.end_est,
                    serde_json::to_string(&lot.ledger_entries).map_err(store_error)?,
                    i64::try_from(lot.quantity).map_err(|_| LotError::Store(
                        "lot quantity does not fit in i64".to_string()
                    ))?,
                    lot.uom,
                    lot.created_est,
                    lot.updated_est,
                    i64::try_from(lot.revision).unwrap_or(i64::MAX),
                ],
            )
            .map_err(|error| LotError::Store(format!("update lot: {error}")))?;
        Ok(())
    }

    /// Load one lot identity, if it exists.
    pub fn load_lot(&self, lot_id: &str) -> Result<Option<LotRecord>, LotError> {
        let sql = format!("SELECT {LOT_COLUMNS} FROM lot_records WHERE lot_id=?1");
        self.conn
            .query_row(&sql, params![lot_id], row_to_lot)
            .optional()
            .map_err(|error| LotError::Store(format!("load lot: {error}")))
    }

    /// List every lot of a tenant (all tenants when `None`), oldest window first.
    pub fn list_lots(&self, tenant: Option<&str>) -> Result<Vec<LotRecord>, LotError> {
        let sql = match tenant {
            Some(_) => format!(
                "SELECT {LOT_COLUMNS} FROM lot_records WHERE tenant=?1 \
                 ORDER BY window_start_est ASC, lot_id ASC"
            ),
            None => format!(
                "SELECT {LOT_COLUMNS} FROM lot_records \
                 ORDER BY window_start_est ASC, lot_id ASC"
            ),
        };
        let mut stmt = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = match tenant {
            Some(tenant) => stmt.query_map(params![tenant], row_to_lot),
            None => stmt.query_map([], row_to_lot),
        }
        .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Every lot identity at all (all tenants).
    pub fn all_lots(&self) -> Result<Vec<LotRecord>, LotError> {
        self.list_lots(None)
    }

    // -----------------------------------------------------------------------
    // Lineage edges
    // -----------------------------------------------------------------------

    /// Insert one edge, ignoring an exact duplicate relationship.
    ///
    /// # Errors
    /// Only storage failures; the caller checks cycles before writing.
    pub fn insert_edge(&self, edge: &LotEdge) -> Result<(), LotError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO lot_edges \
                 (parent_id, child_id, kind, operation_id, created_est) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    edge.parent_id,
                    edge.child_id,
                    edge.kind.as_str(),
                    edge.operation_id,
                    edge.created_est,
                ],
            )
            .map_err(|error| LotError::Store(format!("insert lot edge: {error}")))?;
        Ok(())
    }

    /// Outgoing edges of `parent_id`: everything derived from it.
    pub fn edges_from(&self, parent_id: &str) -> Result<Vec<LotEdge>, LotError> {
        let sql = format!(
            "SELECT {EDGE_COLUMNS} FROM lot_edges WHERE parent_id=?1 \
             ORDER BY child_id ASC, kind ASC"
        );
        let mut stmt = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = stmt
            .query_map(params![parent_id], row_to_edge)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Incoming edges of `child_id`: everything it was derived from.
    pub fn edges_to(&self, child_id: &str) -> Result<Vec<LotEdge>, LotError> {
        let sql = format!(
            "SELECT {EDGE_COLUMNS} FROM lot_edges WHERE child_id=?1 \
             ORDER BY parent_id ASC, kind ASC"
        );
        let mut stmt = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = stmt
            .query_map(params![child_id], row_to_edge)
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Every edge, ordered deterministically.
    pub fn all_edges(&self) -> Result<Vec<LotEdge>, LotError> {
        let sql = format!(
            "SELECT {EDGE_COLUMNS} FROM lot_edges \
             ORDER BY parent_id ASC, child_id ASC, kind ASC"
        );
        let mut stmt = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = stmt.query_map([], row_to_edge).map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Operations (idempotency ledger)
    // -----------------------------------------------------------------------

    /// Load a committed operation by id.
    pub fn load_operation(&self, operation_id: &str) -> Result<Option<LotOperation>, LotError> {
        let sql = format!("SELECT {OPERATION_COLUMNS} FROM lot_operations WHERE operation_id=?1");
        self.conn
            .query_row(&sql, params![operation_id], row_to_operation)
            .optional()
            .map_err(|error| LotError::Store(format!("load lot operation: {error}")))
    }

    /// Every committed operation, oldest first.
    pub fn all_operations(&self) -> Result<Vec<LotOperation>, LotError> {
        let sql = format!(
            "SELECT {OPERATION_COLUMNS} FROM lot_operations \
             ORDER BY at_est ASC, operation_id ASC"
        );
        let mut stmt = self.conn.prepare(&sql).map_err(store_error)?;
        let rows = stmt.query_map([], row_to_operation).map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }

    /// Commit one derived-lineage operation atomically.
    ///
    /// The operation row is written first; its primary key is what makes a
    /// concurrent duplicate commit fail instead of duplicating children.
    pub fn commit_operation(
        &self,
        operation: &LotOperation,
        created: &[LotRecord],
        updated: &[LotRecord],
        edges: &[LotEdge],
    ) -> Result<(), LotError> {
        let tx = self.conn.unchecked_transaction().map_err(store_error)?;
        tx.execute(
            "INSERT INTO lot_operations \
             (operation_id, kind, inputs_json, outputs_json, request_digest, at_est) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                operation.operation_id,
                operation.kind.as_str(),
                serde_json::to_string(&operation.inputs).map_err(store_error)?,
                serde_json::to_string(&operation.outputs).map_err(store_error)?,
                operation.request_digest,
                operation.at_est,
            ],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                LotError::Conflict(format!(
                    "operation {} was already committed",
                    operation.operation_id
                ))
            } else {
                LotError::Store(format!("insert lot operation: {error}"))
            }
        })?;

        for lot in created {
            insert_lot(&tx, lot)?;
        }
        for lot in updated {
            tx.execute(
                "UPDATE lot_records SET updated_est=?2, window_end_est=?3, revision=?4, \
                 device_ids_json=?5, ledger_entries_json=?6 WHERE lot_id=?1",
                params![
                    lot.lot_id,
                    lot.updated_est,
                    lot.window.end_est,
                    i64::try_from(lot.revision).unwrap_or(i64::MAX),
                    serde_json::to_string(&lot.device_ids).map_err(store_error)?,
                    serde_json::to_string(&lot.ledger_entries).map_err(store_error)?,
                ],
            )
            .map_err(|error| LotError::Store(format!("update parent lot: {error}")))?;
        }
        for edge in edges {
            tx.execute(
                "INSERT OR IGNORE INTO lot_edges \
                 (parent_id, child_id, kind, operation_id, created_est) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    edge.parent_id,
                    edge.child_id,
                    edge.kind.as_str(),
                    edge.operation_id,
                    edge.created_est,
                ],
            )
            .map_err(|error| LotError::Store(format!("insert lot edge: {error}")))?;
        }
        tx.commit().map_err(store_error)
    }

    // -----------------------------------------------------------------------
    // Dispositions
    // -----------------------------------------------------------------------

    /// Attach (or re-attach) one disposition link. Returns `true` when a row was
    /// inserted and `false` when an identical one already existed.
    pub fn attach_disposition(
        &self,
        lot_id: &str,
        record_id: &str,
        disposition: &str,
        reason: &str,
        decided_est: i64,
    ) -> Result<bool, LotError> {
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO lot_dispositions \
                 (lot_id, record_id, disposition, reason, decided_est) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![lot_id, record_id, disposition, reason, decided_est],
            )
            .map_err(store_error)?;
        Ok(changed == 1)
    }

    /// Read one disposition link.
    pub fn load_disposition(
        &self,
        lot_id: &str,
        record_id: &str,
    ) -> Result<Option<(String, String, i64)>, LotError> {
        self.conn
            .query_row(
                "SELECT disposition, reason, decided_est FROM lot_dispositions \
                 WHERE lot_id=?1 AND record_id=?2",
                params![lot_id, record_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(store_error)
    }

    /// Every disposition link of one lot, newest decision first.
    pub fn dispositions_of(
        &self,
        lot_id: &str,
    ) -> Result<Vec<(String, String, String, i64)>, LotError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT record_id, disposition, reason, decided_est FROM lot_dispositions \
                 WHERE lot_id=?1 ORDER BY decided_est DESC, record_id ASC",
            )
            .map_err(store_error)?;
        let rows = stmt
            .query_map(params![lot_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(store_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(store_error)
    }
}

fn insert_lot(conn: &Connection, lot: &LotRecord) -> Result<(), LotError> {
    let quantity = i64::try_from(lot.quantity)
        .map_err(|_| LotError::InvalidRequest("lot quantity does not fit in i64".to_string()))?;
    conn.execute(
        "INSERT INTO lot_records (lot_id, tenant, kind, label, site_id, location_id, \
         device_ids_json, window_start_est, window_end_est, ledger_entries_json, quantity, uom, \
         created_est, updated_est, revision) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            lot.lot_id,
            lot.tenant,
            lot.kind.as_str(),
            lot.label,
            lot.site_id,
            lot.location_id,
            serde_json::to_string(&lot.device_ids).map_err(store_error)?,
            lot.window.start_est,
            lot.window.end_est,
            serde_json::to_string(&lot.ledger_entries).map_err(store_error)?,
            quantity,
            lot.uom,
            lot.created_est,
            lot.updated_est,
            i64::try_from(lot.revision).unwrap_or(i64::MAX),
        ],
    )
    .map_err(|error| {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
            LotError::AlreadyExists(lot.lot_id.clone())
        } else {
            LotError::Store(format!("insert lot: {error}"))
        }
    })?;
    Ok(())
}

fn row_to_lot(row: &Row<'_>) -> rusqlite::Result<LotRecord> {
    let kind: String = row.get(2)?;
    let kind = LotKind::parse(&kind).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown lot kind {kind:?}"),
            )),
        )
    })?;
    let device_ids: String = row.get(6)?;
    let device_ids: Vec<String> = serde_json::from_str(&device_ids).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let ledger_entries: String = row.get(9)?;
    let ledger_entries: Vec<LedgerLink> =
        serde_json::from_str(&ledger_entries).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                9,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    let quantity: i64 = row.get(10)?;
    let quantity = u64::try_from(quantity).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            10,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "negative lot quantity",
            )),
        )
    })?;
    Ok(LotRecord {
        lot_id: row.get(0)?,
        tenant: row.get(1)?,
        kind,
        label: row.get(3)?,
        site_id: row.get(4)?,
        location_id: row.get(5)?,
        device_ids,
        window: TimeWindow {
            start_est: row.get(7)?,
            end_est: row.get(8)?,
        },
        ledger_entries,
        quantity,
        uom: row.get(11)?,
        created_est: row.get(12)?,
        updated_est: row.get(13)?,
        revision: row.get::<_, i64>(14)? as u64,
    })
}

fn row_to_edge(row: &Row<'_>) -> rusqlite::Result<LotEdge> {
    let kind: String = row.get(2)?;
    let kind = EdgeKind::parse(&kind).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown lot edge kind {kind:?}"),
            )),
        )
    })?;
    Ok(LotEdge {
        parent_id: row.get(0)?,
        child_id: row.get(1)?,
        kind,
        operation_id: row.get(3)?,
        created_est: row.get(4)?,
    })
}

fn row_to_operation(row: &Row<'_>) -> rusqlite::Result<LotOperation> {
    let kind: String = row.get(1)?;
    let kind = OpKind::parse(&kind).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown lot operation kind {kind:?}"),
            )),
        )
    })?;
    let inputs: String = row.get(2)?;
    let inputs: Vec<String> = serde_json::from_str(&inputs).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let outputs: String = row.get(3)?;
    let outputs: Vec<String> = serde_json::from_str(&outputs).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(LotOperation {
        operation_id: row.get(0)?,
        kind,
        inputs,
        outputs,
        request_digest: row.get(4)?,
        at_est: row.get(5)?,
    })
}
