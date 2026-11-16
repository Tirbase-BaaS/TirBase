// SPDX-License-Identifier: AGPL-3.0-only

//! SQLite persistence for alerts (CC-17).
//!
//! Four tables, created idempotently on open:
//!
//! * `alert_records` — one row per alert, unique on `(tenant, dedup_key)` so a
//!   repeated event cannot become a second alert.
//! * `alert_deliveries` — one row per `(alert, channel, address, level)`, written
//!   before the first transport call and unique on that tuple so a repeated or
//!   escalated attempt cannot become a second page.
//! * `alert_dead_letters` — deliveries that will not be attempted again.
//! * `alert_audit` — append-only history: raised, queued, delivered, retry,
//!   dead_letter, escalated, acknowledged, unrouted.
//!
//! Only secret *references* are stored. A channel's secret is resolved by the
//! transport at delivery time.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use tirbase_notify::SecretRef;

use crate::alerts::{Alert, AlertError, AlertRecord, AuditEntry, DeadLetter, DeliveryRecord};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS alert_records (
    alert_id         TEXT PRIMARY KEY,
    tenant           TEXT NOT NULL,
    dedup_key        TEXT NOT NULL,
    rule_id          TEXT NOT NULL,
    severity         TEXT NOT NULL,
    severity_rank    INTEGER NOT NULL,
    site_id          TEXT NOT NULL,
    title            TEXT NOT NULL,
    body             TEXT NOT NULL,
    labels_json      TEXT NOT NULL,
    occurred_est     INTEGER NOT NULL,
    ack_required     INTEGER NOT NULL,
    acknowledged_est INTEGER,
    acknowledged_by  TEXT,
    escalation_level INTEGER NOT NULL,
    state            TEXT NOT NULL,
    created_est      INTEGER NOT NULL,
    UNIQUE (tenant, dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_alert_records_open
    ON alert_records(state, ack_required, acknowledged_est);

CREATE TABLE IF NOT EXISTS alert_deliveries (
    delivery_id      TEXT PRIMARY KEY,
    alert_id         TEXT NOT NULL,
    channel          TEXT NOT NULL,
    address          TEXT NOT NULL,
    role             TEXT NOT NULL,
    level            INTEGER NOT NULL,
    secret_ref       TEXT,
    state            TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_est INTEGER NOT NULL,
    last_error       TEXT,
    created_est      INTEGER NOT NULL,
    delivered_est    INTEGER,
    UNIQUE (alert_id, channel, address, level)
);
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_due
    ON alert_deliveries(state, next_attempt_est);

CREATE TABLE IF NOT EXISTS alert_dead_letters (
    delivery_id TEXT PRIMARY KEY,
    alert_id    TEXT NOT NULL,
    channel     TEXT NOT NULL,
    address     TEXT NOT NULL,
    role        TEXT NOT NULL,
    level       INTEGER NOT NULL,
    attempts    INTEGER NOT NULL,
    last_error  TEXT NOT NULL,
    created_est INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_audit (
    seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    at_est   INTEGER NOT NULL,
    kind     TEXT NOT NULL,
    detail   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_audit_alert ON alert_audit(alert_id, seq);
"#;

const RECORD_COLUMNS: &str =
    "alert_id, tenant, dedup_key, rule_id, severity, site_id, title, body, \
     labels_json, occurred_est, ack_required, acknowledged_est, acknowledged_by, \
     escalation_level, state, created_est";

const DELIVERY_COLUMNS: &str = "delivery_id, alert_id, channel, address, role, level, secret_ref, \
     state, attempts, next_attempt_est, last_error, created_est, delivered_est";

/// Durable alert store.
pub struct AlertStore {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for AlertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertStore").finish_non_exhaustive()
    }
}

impl AlertStore {
    /// Open (or create) the alert tables in the gateway's primary database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AlertError> {
        let conn = crate::db::open_primary(path)
            .map_err(|error| AlertError::Store(format!("open primary db: {error:?}")))?;
        Self::from_connection(conn)
    }

    /// An in-memory store (tests and ephemeral nodes).
    pub fn open_in_memory() -> Result<Self, AlertError> {
        let conn = Connection::open_in_memory()
            .map_err(|error| AlertError::Store(format!("open in-memory db: {error}")))?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, AlertError> {
        conn.execute_batch(SCHEMA)
            .map_err(|error| AlertError::Store(format!("create alert schema: {error}")))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn with_connection<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, AlertError>,
    ) -> Result<T, AlertError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AlertError::Store("alert store lock poisoned".to_string()))?;
        f(&conn)
    }

    /// Insert an alert unless its `(tenant, dedup_key)` is already known.
    ///
    /// Returns `true` when this call created the row, `false` when the alert was
    /// already raised.
    pub fn insert_alert(
        &self,
        alert: &Alert,
        dedup_key: &str,
        at_est: i64,
    ) -> Result<bool, AlertError> {
        let labels = serde_json::to_string(&alert.labels)
            .map_err(|error| AlertError::Store(format!("labels: {error}")))?;
        self.with_connection(|conn| {
            let inserted = conn
                .execute(
                    "INSERT OR IGNORE INTO alert_records (alert_id, tenant, dedup_key, rule_id, \
                     severity, severity_rank, site_id, title, body, labels_json, occurred_est, \
                     ack_required, escalation_level, state, created_est) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, 'open', ?13)",
                    params![
                        alert.alert_id,
                        alert.tenant,
                        dedup_key,
                        alert.rule_id,
                        alert.severity.as_str(),
                        alert.severity.rank() as i64,
                        alert.site_id,
                        alert.title,
                        alert.body,
                        labels,
                        alert.occurred_est,
                        alert.ack_required as i64,
                        at_est,
                    ],
                )
                .map_err(|error| AlertError::Store(format!("insert alert: {error}")))?;
            Ok(inserted > 0)
        })
    }

    /// Look up an alert by its deduplication identity.
    pub fn find_by_dedup(
        &self,
        tenant: &str,
        dedup_key: &str,
    ) -> Result<Option<AlertRecord>, AlertError> {
        self.with_connection(|conn| {
            conn.query_row(
                &format!(
                    "SELECT {RECORD_COLUMNS} FROM alert_records WHERE tenant=?1 AND dedup_key=?2"
                ),
                params![tenant, dedup_key],
                record_row,
            )
            .optional()
            .map_err(|error| AlertError::Store(format!("find alert: {error}")))
        })
    }

    /// One alert.
    pub fn record(&self, alert_id: &str) -> Result<Option<AlertRecord>, AlertError> {
        self.with_connection(|conn| {
            conn.query_row(
                &format!("SELECT {RECORD_COLUMNS} FROM alert_records WHERE alert_id=?1"),
                params![alert_id],
                record_row,
            )
            .optional()
            .map_err(|error| AlertError::Store(format!("load alert: {error}")))
        })
    }

    /// Every alert for a tenant, newest first.
    pub fn alerts(&self, tenant: &str) -> Result<Vec<AlertRecord>, AlertError> {
        self.with_connection(|conn| {
            let mut statement = conn
                .prepare(&format!(
                    "SELECT {RECORD_COLUMNS} FROM alert_records WHERE tenant=?1 \
                     ORDER BY occurred_est DESC, alert_id ASC"
                ))
                .map_err(|error| AlertError::Store(format!("alert query: {error}")))?;
            let rows = statement
                .query_map(params![tenant], record_row)
                .map_err(|error| AlertError::Store(format!("alert rows: {error}")))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| AlertError::Store(format!("alert row: {error}")))
        })
    }

    /// Open alerts for a tenant that nobody acknowledged.
    pub fn open_alerts(&self, tenant: &str) -> Result<Vec<AlertRecord>, AlertError> {
        Ok(self
            .alerts(tenant)?
            .into_iter()
            .filter(|record| record.is_open() && !record.is_acknowledged())
            .collect())
    }

    /// Open alerts across tenants, for the escalation scan.
    pub fn open_alerts_all(&self) -> Result<Vec<AlertRecord>, AlertError> {
        self.with_connection(|conn| {
            let mut statement = conn
                .prepare(&format!(
                    "SELECT {RECORD_COLUMNS} FROM alert_records \
                     WHERE state='open' AND acknowledged_est IS NULL \
                     ORDER BY occurred_est ASC, alert_id ASC"
                ))
                .map_err(|error| AlertError::Store(format!("open alert query: {error}")))?;
            let rows = statement
                .query_map([], record_row)
                .map_err(|error| AlertError::Store(format!("open alert rows: {error}")))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| AlertError::Store(format!("open alert row: {error}")))
        })
    }

    /// Raise the recorded escalation level.
    pub fn set_escalation_level(&self, alert_id: &str, level: u32) -> Result<(), AlertError> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE alert_records SET escalation_level=?2 WHERE alert_id=?1",
                params![alert_id, level as i64],
            )
            .map_err(|error| AlertError::Store(format!("set escalation level: {error}")))?;
            Ok(())
        })
    }

    /// Record an acknowledgement and close the alert.
    pub fn acknowledge(&self, alert_id: &str, by: &str, at_est: i64) -> Result<(), AlertError> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE alert_records SET acknowledged_est=?2, acknowledged_by=?3, state='acknowledged' \
                 WHERE alert_id=?1",
                params![alert_id, at_est, by],
            )
            .map_err(|error| AlertError::Store(format!("acknowledge alert: {error}")))?;
            Ok(())
        })
    }

    /// Queue a delivery unless that `(alert, channel, address, level)` exists.
    pub fn insert_delivery(&self, delivery: &DeliveryRecord) -> Result<bool, AlertError> {
        self.with_connection(|conn| {
            let inserted = conn
                .execute(
                    "INSERT OR IGNORE INTO alert_deliveries (delivery_id, alert_id, channel, \
                     address, role, level, secret_ref, state, attempts, next_attempt_est, \
                     created_est) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        delivery.delivery_id,
                        delivery.alert_id,
                        delivery.channel,
                        delivery.address,
                        delivery.role,
                        delivery.level as i64,
                        delivery.secret_ref.as_ref().map(|r| r.as_str().to_string()),
                        delivery.state,
                        delivery.attempts as i64,
                        delivery.next_attempt_est,
                        delivery.created_est,
                    ],
                )
                .map_err(|error| AlertError::Store(format!("insert delivery: {error}")))?;
            Ok(inserted > 0)
        })
    }

    /// Deliveries for an alert, in escalation and queue order.
    pub fn deliveries(&self, alert_id: &str) -> Result<Vec<DeliveryRecord>, AlertError> {
        self.with_connection(|conn| {
            let mut statement = conn
                .prepare(&format!(
                    "SELECT {DELIVERY_COLUMNS} FROM alert_deliveries WHERE alert_id=?1 \
                     ORDER BY level ASC, channel ASC, address ASC"
                ))
                .map_err(|error| AlertError::Store(format!("delivery query: {error}")))?;
            let rows = statement
                .query_map(params![alert_id], delivery_row)
                .map_err(|error| AlertError::Store(format!("delivery rows: {error}")))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| AlertError::Store(format!("delivery row: {error}")))
        })
    }

    /// Number of deliveries queued for an alert.
    pub fn delivery_count(&self, alert_id: &str) -> Result<usize, AlertError> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM alert_deliveries WHERE alert_id=?1",
                    params![alert_id],
                    |row| row.get(0),
                )
                .map_err(|error| AlertError::Store(format!("delivery count: {error}")))?;
            Ok(count as usize)
        })
    }

    /// Deliveries whose next attempt is due.
    pub fn due_deliveries(&self, now_est: i64) -> Result<Vec<DeliveryRecord>, AlertError> {
        self.with_connection(|conn| {
            let mut statement = conn
                .prepare(&format!(
                    "SELECT {DELIVERY_COLUMNS} FROM alert_deliveries \
                     WHERE state='pending' AND next_attempt_est <= ?1 \
                     ORDER BY next_attempt_est ASC, delivery_id ASC"
                ))
                .map_err(|error| AlertError::Store(format!("due delivery query: {error}")))?;
            let rows = statement
                .query_map(params![now_est], delivery_row)
                .map_err(|error| AlertError::Store(format!("due delivery rows: {error}")))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| AlertError::Store(format!("due delivery row: {error}")))
        })
    }

    /// Mark a delivery accepted.
    pub fn mark_delivered(&self, delivery_id: &str, at_est: i64) -> Result<(), AlertError> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE alert_deliveries SET state='delivered', attempts=attempts+1, \
                 delivered_est=?2, last_error=NULL WHERE delivery_id=?1",
                params![delivery_id, at_est],
            )
            .map_err(|error| AlertError::Store(format!("mark delivered: {error}")))?;
            Ok(())
        })
    }

    /// Record a retriable failure and schedule the next attempt.
    pub fn record_retry(
        &self,
        delivery_id: &str,
        attempts: u32,
        next_attempt_est: i64,
        error: &str,
    ) -> Result<(), AlertError> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE alert_deliveries SET attempts=?2, next_attempt_est=?3, last_error=?4 \
                 WHERE delivery_id=?1",
                params![delivery_id, attempts as i64, next_attempt_est, error],
            )
            .map_err(|error| AlertError::Store(format!("record retry: {error}")))?;
            Ok(())
        })
    }

    /// Move a delivery to the dead-letter table.
    pub fn dead_letter(
        &self,
        delivery: &DeliveryRecord,
        attempts: u32,
        error: &str,
    ) -> Result<(), AlertError> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE alert_deliveries SET state='dead_letter', attempts=?2, last_error=?3 \
                 WHERE delivery_id=?1",
                params![delivery.delivery_id, attempts as i64, error],
            )
            .map_err(|error| AlertError::Store(format!("dead-letter delivery: {error}")))?;
            conn.execute(
                "INSERT OR REPLACE INTO alert_dead_letters (delivery_id, alert_id, channel, \
                 address, role, level, attempts, last_error, created_est) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    delivery.delivery_id,
                    delivery.alert_id,
                    delivery.channel,
                    delivery.address,
                    delivery.role,
                    delivery.level as i64,
                    attempts as i64,
                    error,
                    delivery.created_est,
                ],
            )
            .map_err(|error| AlertError::Store(format!("insert dead letter: {error}")))?;
            Ok(())
        })
    }

    /// Every dead letter, oldest first.
    pub fn dead_letters(&self) -> Result<Vec<DeadLetter>, AlertError> {
        self.with_connection(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT delivery_id, alert_id, channel, address, role, level, attempts, \
                     last_error, created_est FROM alert_dead_letters \
                     ORDER BY created_est ASC, delivery_id ASC",
                )
                .map_err(|error| AlertError::Store(format!("dead letter query: {error}")))?;
            let rows = statement
                .query_map([], |row| {
                    Ok(DeadLetter {
                        delivery_id: row.get(0)?,
                        alert_id: row.get(1)?,
                        channel: row.get(2)?,
                        address: row.get(3)?,
                        role: row.get(4)?,
                        level: row.get::<_, i64>(5)? as u32,
                        attempts: row.get::<_, i64>(6)? as u32,
                        last_error: row.get(7)?,
                        created_est: row.get(8)?,
                    })
                })
                .map_err(|error| AlertError::Store(format!("dead letter rows: {error}")))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| AlertError::Store(format!("dead letter row: {error}")))
        })
    }

    /// Append an audit row.
    pub fn audit(
        &self,
        alert_id: &str,
        at_est: i64,
        kind: &str,
        detail: &str,
    ) -> Result<(), AlertError> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO alert_audit (alert_id, at_est, kind, detail) VALUES (?1, ?2, ?3, ?4)",
                params![alert_id, at_est, kind, detail],
            )
            .map_err(|error| AlertError::Store(format!("append audit: {error}")))?;
            Ok(())
        })
    }

    /// Audit rows for an alert, oldest first.
    pub fn audit_entries(&self, alert_id: &str) -> Result<Vec<AuditEntry>, AlertError> {
        self.with_connection(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT seq, alert_id, at_est, kind, detail FROM alert_audit \
                     WHERE alert_id=?1 ORDER BY seq ASC",
                )
                .map_err(|error| AlertError::Store(format!("audit query: {error}")))?;
            let rows = statement
                .query_map(params![alert_id], |row| {
                    Ok(AuditEntry {
                        seq: row.get(0)?,
                        alert_id: row.get(1)?,
                        at_est: row.get(2)?,
                        kind: row.get(3)?,
                        detail: row.get(4)?,
                    })
                })
                .map_err(|error| AlertError::Store(format!("audit rows: {error}")))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| AlertError::Store(format!("audit row: {error}")))
        })
    }
}

fn record_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRecord> {
    let labels_json: String = row.get(8)?;
    let labels: BTreeMap<String, String> = serde_json::from_str(&labels_json).unwrap_or_default();
    let severity: String = row.get(4)?;
    Ok(AlertRecord {
        alert_id: row.get(0)?,
        tenant: row.get(1)?,
        dedup_key: row.get(2)?,
        rule_id: row.get(3)?,
        severity: tirbase_notify::Severity::parse(&severity).ok_or_else(|| {
            rusqlite::Error::InvalidColumnType(4, severity, rusqlite::types::Type::Text)
        })?,
        site_id: row.get(5)?,
        title: row.get(6)?,
        body: row.get(7)?,
        labels,
        occurred_est: row.get(9)?,
        ack_required: row.get::<_, i64>(10)? != 0,
        acknowledged_est: row.get(11)?,
        acknowledged_by: row.get(12)?,
        escalation_level: row.get::<_, i64>(13)? as u32,
        state: row.get(14)?,
        created_est: row.get(15)?,
    })
}

fn delivery_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeliveryRecord> {
    let secret_ref: Option<String> = row.get(6)?;
    let secret_ref = secret_ref
        .map(|name| {
            SecretRef::new(name).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        error.to_string(),
                    )),
                )
            })
        })
        .transpose()?;
    Ok(DeliveryRecord {
        delivery_id: row.get(0)?,
        alert_id: row.get(1)?,
        channel: row.get(2)?,
        address: row.get(3)?,
        role: row.get(4)?,
        level: row.get::<_, i64>(5)? as u32,
        secret_ref,
        state: row.get(7)?,
        attempts: row.get::<_, i64>(8)? as u32,
        next_attempt_est: row.get(9)?,
        last_error: row.get(10)?,
        created_est: row.get(11)?,
        delivered_est: row.get(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_notify::Severity;

    fn alert() -> Alert {
        Alert::critical("alert-1", "excursion", "tenant-a", "site-1", "too warm")
            .with_label("record_id", "rec-1")
            .observed_at(1_000)
    }

    #[test]
    fn the_same_deduplication_key_cannot_create_two_alerts() {
        let store = AlertStore::open_in_memory().expect("store");
        let alert = alert();
        assert!(store.insert_alert(&alert, "key-1", 1_000).expect("insert"));
        assert!(!store.insert_alert(&alert, "key-1", 1_000).expect("insert"));
        let found = store
            .find_by_dedup("tenant-a", "key-1")
            .expect("find")
            .expect("found");
        assert_eq!(found.alert_id, "alert-1");
        assert_eq!(found.severity, Severity::Critical);
        assert_eq!(found.labels.get("record_id"), Some(&"rec-1".to_string()));
        assert!(found.ack_required);
        assert!(found.is_open());
        assert!(!found.is_acknowledged());
    }

    #[test]
    fn a_delivery_is_unique_per_alert_channel_address_and_level() {
        let store = AlertStore::open_in_memory().expect("store");
        store
            .insert_alert(&alert(), "key-1", 1_000)
            .expect("insert");
        let delivery = DeliveryRecord {
            delivery_id: "d-1".to_string(),
            alert_id: "alert-1".to_string(),
            channel: "console".to_string(),
            address: "-".to_string(),
            role: "cold-chain".to_string(),
            level: 1,
            secret_ref: None,
            state: "pending".to_string(),
            attempts: 0,
            next_attempt_est: 1_000,
            last_error: None,
            created_est: 1_000,
            delivered_est: None,
        };
        assert!(store.insert_delivery(&delivery).expect("insert"));
        assert!(!store.insert_delivery(&delivery).expect("insert"));
        assert_eq!(store.delivery_count("alert-1").expect("count"), 1);
        assert_eq!(store.due_deliveries(1_000).expect("due").len(), 1);
        assert!(store.due_deliveries(999).expect("due").is_empty());
    }

    #[test]
    fn retries_escalations_acks_and_dead_letters_round_trip() {
        let store = AlertStore::open_in_memory().expect("store");
        store
            .insert_alert(&alert(), "key-1", 1_000)
            .expect("insert");
        store.set_escalation_level("alert-1", 2).expect("level");
        store.acknowledge("alert-1", "ana", 1_100).expect("ack");
        let record = store.record("alert-1").expect("record").expect("found");
        assert_eq!(record.escalation_level, 2);
        assert_eq!(record.acknowledged_by.as_deref(), Some("ana"));
        assert!(!record.is_open());
        assert!(store.open_alerts("tenant-a").expect("open").is_empty());
        assert!(store.open_alerts_all().expect("open").is_empty());

        let delivery = DeliveryRecord {
            delivery_id: "d-1".to_string(),
            alert_id: "alert-1".to_string(),
            channel: "webhook".to_string(),
            address: "https://hooks.example.com/x".to_string(),
            role: "cold-chain".to_string(),
            level: 1,
            secret_ref: Some(SecretRef::new("webhook/alerting").expect("ref")),
            state: "pending".to_string(),
            attempts: 1,
            next_attempt_est: 1_030,
            last_error: Some("HTTP 503".to_string()),
            created_est: 1_000,
            delivered_est: None,
        };
        store.insert_delivery(&delivery).expect("insert");
        let stored = &store.deliveries("alert-1").expect("deliveries")[0];
        assert_eq!(stored.attempts, 1);
        assert_eq!(
            stored
                .secret_ref
                .as_ref()
                .map(|reference| reference.as_str()),
            Some("webhook/alerting")
        );
        store
            .dead_letter(stored, 6, "webhook HTTP 503")
            .expect("dead letter");
        let dead = store.dead_letters().expect("dead letters");
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].attempts, 6);
        assert!(dead[0].last_error.contains("503"));
        assert!(store.deliveries("alert-1").expect("deliveries")[0].state == "dead_letter");

        store
            .audit("alert-1", 1_000, "raised", "rule=r")
            .expect("audit");
        let audit = store.audit_entries("alert-1").expect("audit");
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].kind, "raised");
    }
}
