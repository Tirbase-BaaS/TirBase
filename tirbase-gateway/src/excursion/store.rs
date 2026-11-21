// SPDX-License-Identifier: AGPL-3.0-only

//! SQLite persistence for the excursion workflow (CC-11).
//!
//! Three tables, created idempotently on open:
//!
//! - `excursion_records` — one row per excursion, with the state, the revision
//!   (view version), the detection evidence and the optional disposition and
//!   signed resolution serialized as JSON.
//! - `excursion_events` — append-only transition history per record, used by
//!   audit and by tests that assert the state machine only ever moved forward.
//! - `excursion_notifications` — the durable outbox. A row exists before any
//!   transport is called, and `delivered_est` is only set after a channel
//!   accepts the notification, which is what makes delivery at-least-once
//!   across a crash.
//!
//! Statements are issued one at a time so a caller can decide where a crash
//! boundary sits; the workflow writes the state row and the outbox rows as
//! separate statements and depends on idempotent reads (`pending_notifications`,
//! `enqueue_notification`) to make the interrupted case recoverable.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::excursion::notifier::{ExcursionNotification, NotificationEvent};
use crate::excursion::{
    DetectionOutcome, DispositionRecord, ExcursionError, ExcursionHistoryEntry, ExcursionRecord,
    ExcursionState, SignedResolution,
};

const RECORD_COLUMNS: &str = "record_id, tenant, site_id, device_id, lot_id, state, state_rank, \
     opened_est, updated_est, revision, detection_json, disposition_json, resolution_json, \
     closed_est";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS excursion_records (
    record_id        TEXT PRIMARY KEY,
    tenant           TEXT NOT NULL,
    site_id          TEXT NOT NULL,
    device_id        TEXT NOT NULL,
    lot_id           TEXT,
    state            TEXT NOT NULL,
    state_rank       INTEGER NOT NULL,
    opened_est       INTEGER NOT NULL,
    updated_est      INTEGER NOT NULL,
    revision         INTEGER NOT NULL,
    detection_json   TEXT NOT NULL,
    disposition_json TEXT,
    resolution_json  TEXT,
    closed_est       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_excursion_records_state
    ON excursion_records(tenant, state_rank, opened_est);

CREATE TABLE IF NOT EXISTS excursion_events (
    record_id   TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    event       TEXT NOT NULL,
    at_est      INTEGER NOT NULL,
    detail_json TEXT NOT NULL,
    PRIMARY KEY (record_id, seq)
);

CREATE TABLE IF NOT EXISTS excursion_notifications (
    record_id       TEXT NOT NULL,
    channel         TEXT NOT NULL,
    event           TEXT NOT NULL,
    notification_id TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    enqueued_est    INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    delivered_est   INTEGER,
    last_error      TEXT,
    PRIMARY KEY (record_id, channel, event)
);
CREATE INDEX IF NOT EXISTS idx_excursion_notifications_pending
    ON excursion_notifications(delivered_est, record_id, channel);
"#;

/// Durable store for excursion records, history, and the notification outbox.
#[derive(Debug)]
pub struct ExcursionStore {
    conn: Connection,
}

impl ExcursionStore {
    /// Open the store at `path`, applying the gateway hardening pragmas.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ExcursionError> {
        let conn = crate::db::open_primary(path)
            .map_err(|error| ExcursionError::Store(format!("open primary db: {error:?}")))?;
        Self::from_connection(conn)
    }

    /// Open an in-memory store (tests, ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, ExcursionError> {
        let conn = Connection::open_in_memory()
            .map_err(|error| ExcursionError::Store(format!("open in-memory db: {error}")))?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, ExcursionError> {
        conn.execute_batch(SCHEMA)
            .map_err(|error| ExcursionError::Store(format!("create excursion schema: {error}")))?;
        Ok(Self { conn })
    }

    /// Insert a new record. Fails when the id already exists.
    pub fn insert(&self, record: &ExcursionRecord) -> Result<(), ExcursionError> {
        self.conn
            .execute(
                "INSERT INTO excursion_records (record_id, tenant, site_id, device_id, lot_id, \
                 state, state_rank, opened_est, updated_est, revision, detection_json, \
                 disposition_json, resolution_json, closed_est) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    record.record_id,
                    record.tenant,
                    record.site_id,
                    record.device_id,
                    record.lot_id,
                    record.state.as_str(),
                    record.state.rank(),
                    record.opened_est,
                    record.updated_est,
                    record.revision as i64,
                    serde_json::to_string(&record.detection)
                        .map_err(|error| ExcursionError::Store(error.to_string()))?,
                    record
                        .disposition
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|error| ExcursionError::Store(error.to_string()))?,
                    record
                        .resolution
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|error| ExcursionError::Store(error.to_string()))?,
                    record.closed_est,
                ],
            )
            .map_err(|error| ExcursionError::Store(format!("insert excursion record: {error}")))?;
        Ok(())
    }

    /// Update an existing record (state, revision, payloads).
    pub fn update(&self, record: &ExcursionRecord) -> Result<(), ExcursionError> {
        self.conn
            .execute(
                "UPDATE excursion_records SET state=?2, state_rank=?3, updated_est=?4, \
                 revision=?5, detection_json=?6, disposition_json=?7, resolution_json=?8, \
                 closed_est=?9 WHERE record_id=?1",
                params![
                    record.record_id,
                    record.state.as_str(),
                    record.state.rank(),
                    record.updated_est,
                    record.revision as i64,
                    serde_json::to_string(&record.detection)
                        .map_err(|error| ExcursionError::Store(error.to_string()))?,
                    record
                        .disposition
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|error| ExcursionError::Store(error.to_string()))?,
                    record
                        .resolution
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|error| ExcursionError::Store(error.to_string()))?,
                    record.closed_est,
                ],
            )
            .map_err(|error| ExcursionError::Store(format!("update excursion record: {error}")))?;
        Ok(())
    }

    /// Load one record, if it exists.
    pub fn load(&self, record_id: &str) -> Result<Option<ExcursionRecord>, ExcursionError> {
        let sql = format!("SELECT {RECORD_COLUMNS} FROM excursion_records WHERE record_id=?1");
        self.conn
            .query_row(&sql, params![record_id], row_to_record)
            .optional()
            .map_err(|error| ExcursionError::Store(format!("load excursion record: {error}")))
    }

    /// List records newest-first, optionally filtered by tenant and state.
    pub fn list(
        &self,
        tenant: Option<&str>,
        state: Option<ExcursionState>,
    ) -> Result<Vec<ExcursionRecord>, ExcursionError> {
        let mut sql = format!("SELECT {RECORD_COLUMNS} FROM excursion_records WHERE 1=1");
        if tenant.is_some() {
            sql.push_str(" AND tenant=?1");
        }
        if state.is_some() {
            sql.push_str(if tenant.is_some() {
                " AND state=?2"
            } else {
                " AND state=?1"
            });
        }
        sql.push_str(" ORDER BY opened_est DESC, record_id ASC");

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|error| ExcursionError::Store(format!("prepare list: {error}")))?;
        let rows = match (tenant, state) {
            (Some(tenant), Some(state)) => stmt
                .query_map(params![tenant, state.as_str()], row_to_record)
                .map_err(|error| ExcursionError::Store(format!("list records: {error}")))?
                .collect::<Result<Vec<_>, _>>(),
            (Some(tenant), None) => stmt
                .query_map(params![tenant], row_to_record)
                .map_err(|error| ExcursionError::Store(format!("list records: {error}")))?
                .collect::<Result<Vec<_>, _>>(),
            (None, Some(state)) => stmt
                .query_map(params![state.as_str()], row_to_record)
                .map_err(|error| ExcursionError::Store(format!("list records: {error}")))?
                .collect::<Result<Vec<_>, _>>(),
            (None, None) => stmt
                .query_map([], row_to_record)
                .map_err(|error| ExcursionError::Store(format!("list records: {error}")))?
                .collect::<Result<Vec<_>, _>>(),
        };
        rows.map_err(|error| ExcursionError::Store(format!("list excursion records: {error}")))
    }

    /// Append one history entry; the sequence number is assigned here.
    pub fn append_event(
        &self,
        record_id: &str,
        event: &str,
        at_est: i64,
        detail: serde_json::Value,
    ) -> Result<(), ExcursionError> {
        let next: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM excursion_events WHERE record_id=?1",
                params![record_id],
                |row| row.get(0),
            )
            .map_err(|error| ExcursionError::Store(format!("next event seq: {error}")))?;
        self.conn
            .execute(
                "INSERT INTO excursion_events (record_id, seq, event, at_est, detail_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![record_id, next, event, at_est, detail.to_string()],
            )
            .map_err(|error| ExcursionError::Store(format!("append event: {error}")))?;
        Ok(())
    }

    /// Read a record's history in order.
    pub fn events(&self, record_id: &str) -> Result<Vec<ExcursionHistoryEntry>, ExcursionError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, event, at_est, detail_json FROM excursion_events \
                 WHERE record_id=?1 ORDER BY seq ASC",
            )
            .map_err(|error| ExcursionError::Store(format!("prepare history: {error}")))?;
        let rows = stmt
            .query_map(params![record_id], |row| {
                let detail: String = row.get(3)?;
                Ok(ExcursionHistoryEntry {
                    seq: row.get::<_, i64>(0)? as u64,
                    event: row.get(1)?,
                    at_est: row.get(2)?,
                    detail: serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
                })
            })
            .map_err(|error| ExcursionError::Store(format!("history rows: {error}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| ExcursionError::Store(format!("history rows: {error}")))
    }

    /// Write an outbox row. Returns `false` when it already existed.
    pub fn enqueue_notification(
        &self,
        notification: &ExcursionNotification,
        now_est: i64,
    ) -> Result<bool, ExcursionError> {
        let payload = serde_json::to_string(notification)
            .map_err(|error| ExcursionError::Store(error.to_string()))?;
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO excursion_notifications (record_id, channel, event, \
                 notification_id, payload_json, enqueued_est, attempts, delivered_est, last_error) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, NULL)",
                params![
                    notification.record_id,
                    notification.channel,
                    notification.event.as_str(),
                    notification.notification_id,
                    payload,
                    now_est,
                ],
            )
            .map_err(|error| ExcursionError::Store(format!("enqueue notification: {error}")))?;
        Ok(changed == 1)
    }

    /// Undelivered outbox rows, oldest first, optionally for one record.
    pub fn pending_notifications(
        &self,
        record_id: Option<&str>,
    ) -> Result<Vec<ExcursionNotification>, ExcursionError> {
        let sql = match record_id {
            Some(_) => {
                "SELECT payload_json FROM excursion_notifications \
                 WHERE delivered_est IS NULL AND record_id=?1 ORDER BY enqueued_est ASC, channel ASC"
            }
            None => {
                "SELECT payload_json FROM excursion_notifications \
                 WHERE delivered_est IS NULL ORDER BY enqueued_est ASC, record_id ASC, channel ASC"
            }
        };
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|error| ExcursionError::Store(format!("prepare pending: {error}")))?;
        let map = |row: &Row<'_>| {
            let payload: String = row.get(0)?;
            serde_json::from_str::<ExcursionNotification>(&payload).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        };
        let rows = match record_id {
            Some(record_id) => stmt
                .query_map(params![record_id], map)
                .map_err(|error| ExcursionError::Store(format!("pending rows: {error}")))?,
            None => stmt
                .query_map([], map)
                .map_err(|error| ExcursionError::Store(format!("pending rows: {error}")))?,
        };
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| ExcursionError::Store(format!("pending rows: {error}")))
    }

    /// Attempts already made for one outbox row.
    pub fn notification_attempts(
        &self,
        record_id: &str,
        channel: &str,
        event: NotificationEvent,
    ) -> Result<u32, ExcursionError> {
        let attempts: i64 = self
            .conn
            .query_row(
                "SELECT attempts FROM excursion_notifications \
                 WHERE record_id=?1 AND channel=?2 AND event=?3",
                params![record_id, channel, event.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| ExcursionError::Store(format!("notification attempts: {error}")))?
            .unwrap_or(0);
        Ok(attempts as u32)
    }

    /// Mark one outbox row delivered.
    pub fn mark_delivered(
        &self,
        record_id: &str,
        channel: &str,
        now_est: i64,
    ) -> Result<(), ExcursionError> {
        self.conn
            .execute(
                "UPDATE excursion_notifications SET delivered_est=?3, attempts=attempts+1, \
                 last_error=NULL WHERE record_id=?1 AND channel=?2 AND delivered_est IS NULL",
                params![record_id, channel, now_est],
            )
            .map_err(|error| ExcursionError::Store(format!("mark delivered: {error}")))?;
        Ok(())
    }

    /// Record one failed delivery attempt, leaving the row pending.
    pub fn record_failure(
        &self,
        record_id: &str,
        channel: &str,
        event: NotificationEvent,
        error: &str,
    ) -> Result<(), ExcursionError> {
        self.conn
            .execute(
                "UPDATE excursion_notifications SET attempts=attempts+1, last_error=?4 \
                 WHERE record_id=?1 AND channel=?2 AND event=?3 AND delivered_est IS NULL",
                params![record_id, channel, event.as_str(), error],
            )
            .map_err(|error| ExcursionError::Store(format!("record failure: {error}")))?;
        Ok(())
    }

    /// Delivered outbox rows for a record (used by tests and audit reads).
    pub fn delivered_notifications(
        &self,
        record_id: &str,
    ) -> Result<Vec<ExcursionNotification>, ExcursionError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT payload_json FROM excursion_notifications \
                 WHERE record_id=?1 AND delivered_est IS NOT NULL ORDER BY channel ASC",
            )
            .map_err(|error| ExcursionError::Store(format!("prepare delivered: {error}")))?;
        let rows = stmt
            .query_map(params![record_id], |row| {
                let payload: String = row.get(0)?;
                serde_json::from_str::<ExcursionNotification>(&payload).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .map_err(|error| ExcursionError::Store(format!("delivered rows: {error}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| ExcursionError::Store(format!("delivered rows: {error}")))
    }
}

fn row_to_record(row: &Row<'_>) -> rusqlite::Result<ExcursionRecord> {
    let state: String = row.get(5)?;
    let state = ExcursionState::all()
        .into_iter()
        .find(|candidate| candidate.as_str() == state)
        .ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown excursion state {state:?}"),
                )),
            )
        })?;
    let detection_json: String = row.get(10)?;
    let detection: DetectionOutcome = serde_json::from_str(&detection_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let disposition_json: Option<String> = row.get(11)?;
    let disposition: Option<DispositionRecord> = disposition_json
        .map(|json| serde_json::from_str(&json))
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                11,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    let resolution_json: Option<String> = row.get(12)?;
    let resolution: Option<SignedResolution> = resolution_json
        .map(|json| serde_json::from_str(&json))
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                12,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;

    Ok(ExcursionRecord {
        record_id: row.get(0)?,
        tenant: row.get(1)?,
        site_id: row.get(2)?,
        device_id: row.get(3)?,
        lot_id: row.get(4)?,
        state,
        opened_est: row.get(7)?,
        updated_est: row.get(8)?,
        revision: row.get::<_, i64>(9)? as u64,
        detection,
        disposition,
        resolution,
        closed_est: row.get(13)?,
    })
}
