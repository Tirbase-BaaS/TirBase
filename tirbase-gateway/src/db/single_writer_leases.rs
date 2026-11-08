//! `single_writer_leases` SQLite store (PV-5.8, CLAIM-15.1/21.1-21.5, INV-13).
//! Lease duration uses monotonic time (`CLOCK_BOOTTIME` domain), not `now_est`.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};

pub const SINGLE_WRITER_LEASES_TABLE: &str = "single_writer_leases";
pub const DEFAULT_LEASE_DURATION_MONO_SECS: i64 = 30;
pub const DEFAULT_MAX_CONSECUTIVE_RENEWALS: u32 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    pub target_id: String,
    pub issuer_did: String,
    pub expires_mono: i64,
    pub consecutive_renewals: u32,
    pub cooldown_until_mono: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseAcquireError {
    HeldByOther { holder: String },
    Cooldown { until_mono: i64 },
    Store(String),
}

impl std::fmt::Display for LeaseAcquireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseAcquireError::HeldByOther { holder } => write!(f, "lease held by {holder}"),
            LeaseAcquireError::Cooldown { until_mono } => {
                write!(f, "issuer in cooldown until mono {until_mono}")
            }
            LeaseAcquireError::Store(e) => write!(f, "lease store: {e}"),
        }
    }
}
impl std::error::Error for LeaseAcquireError {}

pub fn create_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {SINGLE_WRITER_LEASES_TABLE} (
            target_id              TEXT PRIMARY KEY,
            issuer_did             TEXT NOT NULL,
            expires_mono           INTEGER NOT NULL,
            consecutive_renewals   INTEGER NOT NULL DEFAULT 0,
            cooldown_until_mono    INTEGER
        );"
    ))
    .map_err(|e| format!("create single_writer_leases: {e}"))
}

pub fn load_tx(tx: &Transaction<'_>, target_id: &str) -> Result<Option<LeaseRow>, String> {
    tx.query_row(
        &format!("SELECT target_id,issuer_did,expires_mono,consecutive_renewals,cooldown_until_mono FROM {SINGLE_WRITER_LEASES_TABLE} WHERE target_id=?1"),
        params![target_id],
        |row| Ok(LeaseRow {
            target_id: row.get(0)?,
            issuer_did: row.get(1)?,
            expires_mono: row.get(2)?,
            consecutive_renewals: row.get::<_, i64>(3)? as u32,
            cooldown_until_mono: row.get(4)?,
        }),
    ).optional().map_err(|e| format!("load lease: {e}"))
}

pub fn acquire_tx(
    tx: &Transaction<'_>,
    target_id: &str,
    issuer_did: &str,
    now_mono_secs: i64,
    lease_duration_secs: i64,
    max_consecutive_renewals: u32,
) -> Result<(), LeaseAcquireError> {
    let existing = load_tx(tx, target_id).map_err(LeaseAcquireError::Store)?;
    let mut renewals = 0u32;
    if let Some(row) = existing {
        let expired = row.expires_mono <= now_mono_secs;
        if !expired && row.issuer_did != issuer_did {
            return Err(LeaseAcquireError::HeldByOther {
                holder: row.issuer_did,
            });
        }
        if row.issuer_did == issuer_did {
            if let Some(cooldown) = row.cooldown_until_mono {
                if cooldown > now_mono_secs {
                    return Err(LeaseAcquireError::Cooldown {
                        until_mono: cooldown,
                    });
                }
            }
            renewals = if expired {
                0
            } else {
                row.consecutive_renewals.saturating_add(1)
            };
            if renewals >= max_consecutive_renewals {
                // enter cooldown, do not grant lease now (S21 / CLAIM-21.4)
                let cooldown_until = now_mono_secs.saturating_add(lease_duration_secs);
                tx.execute(
                    &format!("INSERT OR REPLACE INTO {SINGLE_WRITER_LEASES_TABLE} (target_id,issuer_did,expires_mono,consecutive_renewals,cooldown_until_mono) VALUES (?1,?2,?3,?4,?5)"),
                    params![target_id, issuer_did, now_mono_secs, renewals, cooldown_until],
                ).map_err(|e| LeaseAcquireError::Store(format!("set cooldown: {e}")))?;
                return Err(LeaseAcquireError::Cooldown {
                    until_mono: cooldown_until,
                });
            }
        }
    }
    let expires = now_mono_secs.saturating_add(lease_duration_secs);
    tx.execute(
        &format!("INSERT OR REPLACE INTO {SINGLE_WRITER_LEASES_TABLE} (target_id,issuer_did,expires_mono,consecutive_renewals,cooldown_until_mono) VALUES (?1,?2,?3,?4,NULL)"),
        params![target_id, issuer_did, expires, renewals],
    ).map_err(|e| LeaseAcquireError::Store(format!("acquire lease: {e}")))?;
    Ok(())
}

pub fn release_tx(tx: &Transaction<'_>, target_id: &str, issuer_did: &str) -> Result<(), String> {
    tx.execute(
        &format!("DELETE FROM {SINGLE_WRITER_LEASES_TABLE} WHERE target_id=?1 AND issuer_did=?2"),
        params![target_id, issuer_did],
    )
    .map_err(|e| format!("release lease: {e}"))?;
    Ok(())
}

/// Task 21.5: release all leases at boot (stale leases are expired/released).
pub fn release_all_at_boot(conn: &Connection) -> Result<usize, String> {
    let deleted = conn
        .execute(&format!("DELETE FROM {SINGLE_WRITER_LEASES_TABLE}"), [])
        .map_err(|e| format!("release all leases at boot: {e}"))?;
    Ok(deleted)
}

/// Task 21.2: M-of-N preemption by RevocationManager + PolicyAuthority joint op.
/// Production caller: gateway admin path.
pub fn preempt_tx(
    tx: &Transaction<'_>,
    target_id: &str,
    new_issuer_did: Option<&str>,
    now_mono_secs: i64,
    lease_duration_secs: i64,
) -> Result<Option<String>, String> {
    let prior = load_tx(tx, target_id)?.map(|r| r.issuer_did);
    if let Some(issuer) = new_issuer_did {
        let expires = now_mono_secs.saturating_add(lease_duration_secs);
        tx.execute(
            &format!("INSERT OR REPLACE INTO {SINGLE_WRITER_LEASES_TABLE} (target_id,issuer_did,expires_mono,consecutive_renewals,cooldown_until_mono) VALUES (?1,?2,?3,0,NULL)"),
            params![target_id, issuer, expires],
        )
        .map_err(|e| format!("preempt lease: {e}"))?;
    } else {
        tx.execute(
            &format!("DELETE FROM {SINGLE_WRITER_LEASES_TABLE} WHERE target_id=?1"),
            params![target_id],
        )
        .map_err(|e| format!("preempt release lease: {e}"))?;
    }
    emit(
        SecurityEvent::new(
            SecurityEventCategory::Revocation,
            Severity::Medium,
            ReasonCode::RevocationLeaseReleased,
        )
        .with_target(target_id)
        .with_detail(format!(
            "lease preempted prior_holder={:?} new_issuer={:?}",
            prior, new_issuer_did
        )),
    );
    Ok(prior)
}

/// Task 21.3: release all leases held by a revoked DID.
pub fn release_all_for_issuer_did(conn: &Connection, issuer_did: &str) -> Result<usize, String> {
    let deleted = conn
        .execute(
            &format!("DELETE FROM {SINGLE_WRITER_LEASES_TABLE} WHERE issuer_did=?1"),
            params![issuer_did],
        )
        .map_err(|e| format!("release leases for revoked DID: {e}"))?;
    if deleted > 0 {
        emit(
            SecurityEvent::new(
                SecurityEventCategory::Revocation,
                Severity::Medium,
                ReasonCode::RevocationLeaseReleased,
            )
            .with_actor(issuer_did)
            .with_detail(format!(
                "released {deleted} lease(s) for revoked issuer DID"
            )),
        );
    }
    Ok(deleted)
}

#[derive(Debug)]
pub struct SqliteLeaseStore {
    conn: Mutex<Connection>,
}
impl SqliteLeaseStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| format!("create {parent:?}: {e}"))?;
            }
        }
        let conn = Connection::open(path).map_err(|e| format!("open: {e}"))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("journal_mode: {e}"))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| format!("synchronous: {e}"))?;
        create_table(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
    pub fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }
    pub fn release_all_at_boot(&self) -> Result<usize, String> {
        release_all_at_boot(&self.connection())
    }
    pub fn release_all_for_issuer_did(&self, issuer_did: &str) -> Result<usize, String> {
        release_all_for_issuer_did(&self.connection(), issuer_did)
    }
    pub fn preempt(
        &self,
        target_id: &str,
        new_issuer_did: Option<&str>,
        now_mono_secs: i64,
        lease_duration_secs: i64,
    ) -> Result<Option<String>, String> {
        let mut conn = self.connection();
        let tx = conn.transaction().map_err(|e| format!("begin: {e}"))?;
        let prior = preempt_tx(
            &tx,
            target_id,
            new_issuer_did,
            now_mono_secs,
            lease_duration_secs,
        )?;
        tx.commit().map_err(|e| format!("commit: {e}"))?;
        Ok(prior)
    }
}
