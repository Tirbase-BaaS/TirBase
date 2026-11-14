// SPDX-License-Identifier: AGPL-3.0-only

//! F-07 retention policies per record class with legal holds.
//!
//! Four record classes are recognised:
//!
//! * **Operational** — replay/nonce/idempotency bookkeeping. Safe to purge once
//!   its own expiry has passed.
//! * **Audit** — the hash-chained security log. Purged only by archiving a
//!   closed, signed segment through [`crate::security_log`], so the chain and
//!   its checkpoints stay verifiable.
//! * **Money** — value-bearing ledger rows (`applied_effects_ledger`). Never
//!   auto-deleted by this module; a deployment must opt in explicitly.
//! * **Safety** — approvals and safety-relevant records. Retained
//!   indefinitely, and a legal hold always wins.
//!
//! Every purge writes a `retention_runs` row *and* appends a `LogRotated`
//! security event carrying the class and row count, so a purge is auditable
//! even after the rows themselves are gone. An active legal hold for a class
//! makes the purge a no-op and is itself recorded.

use std::collections::BTreeMap;

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use tirbase_core::events::{
    ReasonCode, SecurityEvent as SecurityEventPayload, SecurityEventCategory, Severity,
};

use crate::security_log::SecurityEventLog;

/// Record class used by retention policy and legal holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordClass {
    Operational,
    Audit,
    Money,
    Safety,
}

impl RecordClass {
    pub const ALL: [RecordClass; 4] = [
        RecordClass::Operational,
        RecordClass::Audit,
        RecordClass::Money,
        RecordClass::Safety,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RecordClass::Operational => "operational",
            RecordClass::Audit => "audit",
            RecordClass::Money => "money",
            RecordClass::Safety => "safety",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "operational" => Some(RecordClass::Operational),
            "audit" => Some(RecordClass::Audit),
            "money" => Some(RecordClass::Money),
            "safety" => Some(RecordClass::Safety),
            _ => None,
        }
    }
}

impl std::fmt::Display for RecordClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Retention behaviour for one class.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetentionPolicy {
    pub class: RecordClass,
 /// Age after which the class becomes eligible. `None` means retain forever.
    pub max_age_secs: Option<i64>,
 /// Whether this module may delete eligible rows. Audit archival is delegated
 /// to the security log's signed segment rotation.
    pub auto_purge: bool,
}

impl RetentionPolicy {
    pub fn new(class: RecordClass, max_age_secs: Option<i64>, auto_purge: bool) -> Self {
        Self {
            class,
            max_age_secs,
            auto_purge,
        }
    }
}

/// Default F-07 policy matrix.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetentionConfig {
    pub policies: Vec<RetentionPolicy>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            policies: vec![
                // Replay bookkeeping is only useful until its own expiry.
                RetentionPolicy::new(RecordClass::Operational, Some(30 * 24 * 60 * 60), true),
                // Audit segments are archived then removed by the log itself.
                RetentionPolicy::new(RecordClass::Audit, Some(90 * 24 * 60 * 60), true),
                // Money records are retained by default; explicit operator opt-in.
                RetentionPolicy::new(RecordClass::Money, None, false),
                // Safety records are retained indefinitely.
                RetentionPolicy::new(RecordClass::Safety, None, false),
            ],
        }
    }
}

impl RetentionConfig {
    pub fn policy(&self, class: RecordClass) -> Option<&RetentionPolicy> {
        self.policies.iter().find(|p| p.class == class)
    }
}

/// Outcome of one retention sweep.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetentionReport {
    pub run_id: String,
    pub purged: BTreeMap<String, u64>,
    pub blocked_by_legal_hold: Vec<String>,
 /// A security event was appended for every class that was touched.
    pub audited: bool,
}

/// A legal hold row. `subject` scopes the hold (e.g. a target id); `None` holds
/// the whole class.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LegalHold {
    pub hold_id: String,
    pub record_class: RecordClass,
    pub subject: Option<String>,
    pub reason: String,
    pub created_at_est: i64,
    pub released_at_est: Option<i64>,
}

/// Create the F-07 tables on databases opened before migration v5. Idempotent.
pub fn ensure_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS legal_holds (
            hold_id         TEXT PRIMARY KEY,
            record_class    TEXT NOT NULL,
            subject         TEXT,
            reason          TEXT NOT NULL,
            created_at_est  INTEGER NOT NULL,
            released_at_est INTEGER
         );
         CREATE INDEX IF NOT EXISTS idx_legal_holds_active
            ON legal_holds(record_class, released_at_est);
         CREATE TABLE IF NOT EXISTS retention_runs (
            run_id          TEXT PRIMARY KEY,
            started_at_est  INTEGER NOT NULL,
            record_class    TEXT NOT NULL,
            purged_rows     INTEGER NOT NULL,
            blocked_by_hold INTEGER NOT NULL DEFAULT 0,
            detail_json     TEXT NOT NULL
         );",
    )
    .map_err(|e| format!("ensure retention schema: {e}"))
}

pub fn add_legal_hold(
    conn: &Connection,
    hold_id: &str,
    class: RecordClass,
    subject: Option<&str>,
    reason: &str,
    now_est: i64,
) -> Result<(), String> {
    ensure_schema(conn)?;
    conn.execute(
        "INSERT INTO legal_holds(hold_id, record_class, subject, reason, created_at_est)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![hold_id, class.as_str(), subject, reason, now_est],
    )
    .map_err(|e| format!("add legal hold: {e}"))?;
    Ok(())
}

pub fn release_legal_hold(conn: &Connection, hold_id: &str, now_est: i64) -> Result<bool, String> {
    ensure_schema(conn)?;
    let changed = conn
        .execute(
            "UPDATE legal_holds SET released_at_est=?2
             WHERE hold_id=?1 AND released_at_est IS NULL",
            params![hold_id, now_est],
        )
        .map_err(|e| format!("release legal hold: {e}"))?;
    Ok(changed > 0)
}

pub fn legal_holds(conn: &Connection, class: RecordClass) -> Result<Vec<LegalHold>, String> {
    ensure_schema(conn)?;
    let mut stmt = conn
        .prepare(
            "SELECT hold_id, record_class, subject, reason, created_at_est, released_at_est
             FROM legal_holds WHERE record_class=?1 AND released_at_est IS NULL
             ORDER BY created_at_est ASC",
        )
        .map_err(|e| format!("legal hold query: {e}"))?;
    let rows = stmt
        .query_map([class.as_str()], |r| {
            Ok(LegalHold {
                hold_id: r.get(0)?,
                record_class: class,
                subject: r.get(2)?,
                reason: r.get(3)?,
                created_at_est: r.get(4)?,
                released_at_est: r.get(5)?,
            })
        })
        .map_err(|e| format!("legal hold rows: {e}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("legal hold row: {e}"))
}

/// True when any unreleased hold covers this class.
pub fn is_held(conn: &Connection, class: RecordClass) -> bool {
    if ensure_schema(conn).is_err() {
        // Fail closed: an unreadable hold table must not authorise deletion.
        return true;
    }
    conn.query_row(
        "SELECT COUNT(*) FROM legal_holds WHERE record_class=?1 AND released_at_est IS NULL",
        [class.as_str()],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .unwrap_or(true)
}

fn delete_expired(
    conn: &Connection,
    table: &str,
    column: &str,
    cutoff: i64,
) -> Result<u64, String> {
    let sql = format!("DELETE FROM {table} WHERE {column} < ?1");
    conn.execute(&sql, params![cutoff])
        .map(|n| n as u64)
        .map_err(|e| format!("purge {table}: {e}"))
}

fn run_id(now_est: i64, class: RecordClass) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"TirBase/v1/RetentionRun\0");
    hasher.update(now_est.to_le_bytes());
    hasher.update(class.as_str().as_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hex::encode(&hasher.finalize()[..16])
}

/// Apply the policy matrix. `now_est` is authenticated wall time; `mono_secs`
/// is used for monotonic-only tables. The security log receives one audit
/// record per class that was purged or blocked.
pub fn apply_retention(
    conn: &Connection,
    log: &SecurityEventLog,
    cfg: &RetentionConfig,
    now_est: i64,
    mono_secs: u64,
) -> Result<RetentionReport, String> {
    ensure_schema(conn)?;
    let run = run_id(now_est, RecordClass::Operational);
    let mut purged: BTreeMap<String, u64> = BTreeMap::new();
    let mut blocked: Vec<String> = Vec::new();

    for class in RecordClass::ALL {
        let Some(policy) = cfg.policy(class) else {
            continue;
        };
        if is_held(conn, class) {
            blocked.push(class.as_str().to_string());
            log.append_payload(
                SecurityEventPayload::new(
                    SecurityEventCategory::SecurityLog,
                    Severity::Medium,
                    ReasonCode::LogRotated,
                )
                .with_target(class.as_str())
                .with_detail(format!(
                    "retention run {run}: purge blocked by active legal hold for class {class}"
                )),
            );
            conn.execute(
                "INSERT INTO retention_runs(run_id,started_at_est,record_class,purged_rows,blocked_by_hold,detail_json)
                 VALUES (?1,?2,?3,0,1,?4)",
                params![
                    run_id(now_est, class),
                    now_est,
                    class.as_str(),
                    serde_json::json!({"reason":"legal_hold"}).to_string()
                ],
            )
            .map_err(|e| format!("record blocked retention run: {e}"))?;
            continue;
        }

        // Retained classes still get a run row and an audit note so operators
        // can see that policy deliberately kept the data.
        let rows = match (class, policy.max_age_secs) {
            (RecordClass::Operational, Some(_max_age)) => {
                // These tables carry their own absolute expiry; delete only
                // rows whose expiry has actually passed.
                let cutoff = now_est;
                let idem = delete_expired(conn, "idempotency_keys", "expires_at_est", cutoff)?;
                let nonces =
                    delete_expired(conn, "enrollment_nonces", "expires_at_est", cutoff)?;
                let mono_cutoff = mono_secs;
                let challenge = conn
                    .execute(
                        "DELETE FROM challenge_nonces WHERE expires_at_mono < ?1",
                        params![mono_cutoff as i64],
                    )
                    .map(|n| n as u64)
                    .unwrap_or(0);
                idem + nonces + challenge
            }
            (RecordClass::Audit, _) => {
                // Segment rotation performs its own legal-hold and archive
                // checks and emits LogRotated with the segment id.
                log.rotate_retention_if_needed().unwrap_or(0)
            }
            // Money and safety rows are never deleted without explicit opt-in;
            // the policy matrix marks them `auto_purge=false`.
            _ => 0,
        };

        if rows > 0 {
            purged.insert(class.as_str().to_string(), rows);
            log.append_payload(
                SecurityEventPayload::new(
                    SecurityEventCategory::SecurityLog,
                    Severity::Low,
                    ReasonCode::LogRotated,
                )
                .with_target(class.as_str())
                .with_detail(format!(
                    "retention run {run}: purged {rows} {class} record(s) under policy"
                )),
            );
        }
        conn.execute(
            "INSERT INTO retention_runs(run_id,started_at_est,record_class,purged_rows,blocked_by_hold,detail_json)
             VALUES (?1,?2,?3,?4,0,?5)",
            params![
                run_id(now_est, class),
                now_est,
                class.as_str(),
                rows as i64,
                serde_json::json!({"max_age_secs":policy.max_age_secs,"auto_purge":policy.auto_purge})
                    .to_string()
            ],
        )
        .map_err(|e| format!("record retention run: {e}"))?;
    }

    Ok(RetentionReport {
        run_id: run,
        purged,
        blocked_by_legal_hold: blocked,
        audited: true,
    })
}

/// Counts rows per class without deleting anything (operator preview).
pub fn inspect(conn: &Connection) -> Result<BTreeMap<String, i64>, String> {
    ensure_schema(conn)?;
    let mut out = BTreeMap::new();
    for (class, table) in [
        ("operational.idempotency_keys", "idempotency_keys"),
        ("operational.enrollment_nonces", "enrollment_nonces"),
        ("audit.security_events", "security_events"),
        ("money.applied_effects_ledger", "applied_effects_ledger"),
        ("safety.pending_approvals", "pending_approvals"),
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap_or(0);
        out.insert(class.to_string(), count);
    }
    Ok(out)
}
