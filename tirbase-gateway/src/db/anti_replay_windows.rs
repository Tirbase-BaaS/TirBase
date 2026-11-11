//! `anti_replay_windows` SQLite store (PV-5.5, CLAIM-15.1/20.x, INV-10).
//!
//! Sliding bitmap per `(issuer_did, target_id, enrollment_epoch)`.
//! W=64 (configurable via caller) and forward gap G=1024.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

pub const ANTI_REPLAY_WINDOWS_TABLE: &str = "anti_replay_windows";
pub const DEFAULT_WINDOW_W: u64 = 64;
pub const DEFAULT_FORWARD_GAP_G: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiReplayWindowRow {
    pub issuer_did: String,
    pub target_id: String,
    pub enrollment_epoch: u64,
    pub highest_seen: u64,
    pub seen_bitmap: Vec<u8>,
    pub forward_gap: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiReplayCheck {
    Accepted { new_highest: u64, new_bitmap: u64 },
    Replay,
    OutsideWindow,
}

fn bitmap_get(bitmap: u64, highest: u64, seq: u64, w: u64) -> bool {
    if seq > highest {
        return false;
    }
    let delta = highest - seq;
    if delta >= w {
        return false;
    }
    (bitmap & (1u64 << delta)) != 0
}

fn bitmap_set(bitmap: u64, highest: u64, seq: u64, w: u64) -> Option<(u64, u64)> {
    if seq > highest {
        let shift = seq - highest;
        let new_bitmap = if shift >= 64 {
            1u64
        } else {
            (bitmap << shift) | 1u64
        };
        return Some((seq, new_bitmap));
    }
    let delta = highest - seq;
    if delta >= w {
        return None;
    }
    let mask = 1u64 << delta;
    if (bitmap & mask) != 0 {
        return None;
    }
    Some((highest, bitmap | mask))
}

pub fn check_and_advance(
    row: Option<&AntiReplayWindowRow>,
    seq: u64,
    w: u64,
    g: u64,
) -> AntiReplayCheck {
    let (highest, bitmap, gap) = match row {
        Some(r) => (
            r.highest_seen,
            u64::from_le_bytes(
                r.seen_bitmap
                    .get(..8)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or([0; 8]),
            ),
            r.forward_gap.max(g),
        ),
        None => (0u64, 0u64, g),
    };
    if highest == 0 && bitmap == 0 && row.is_none() {
        return AntiReplayCheck::Accepted {
            new_highest: seq,
            new_bitmap: 1,
        };
    }
    let lower = highest.saturating_sub(w);
    let upper = highest.saturating_add(gap);
    if seq < lower || seq > upper {
        return AntiReplayCheck::OutsideWindow;
    }
    if bitmap_get(bitmap, highest, seq, w) {
        return AntiReplayCheck::Replay;
    }
    match bitmap_set(bitmap, highest, seq, w) {
        Some((nh, nb)) => AntiReplayCheck::Accepted {
            new_highest: nh,
            new_bitmap: nb,
        },
        None => AntiReplayCheck::Replay,
    }
}

pub fn load_window_tx(
    tx: &Transaction<'_>,
    issuer_did: &str,
    target_id: &str,
    enrollment_epoch: u64,
) -> Result<Option<AntiReplayWindowRow>, String> {
    tx.query_row(
        &format!("SELECT issuer_did,target_id,enrollment_epoch,highest_seen,seen_bitmap,forward_gap FROM {ANTI_REPLAY_WINDOWS_TABLE} WHERE issuer_did=?1 AND target_id=?2 AND enrollment_epoch=?3"),
        params![issuer_did, target_id, enrollment_epoch as i64],
        |row| Ok(AntiReplayWindowRow {
            issuer_did: row.get(0)?,
            target_id: row.get(1)?,
            enrollment_epoch: row.get::<_, i64>(2)? as u64,
            highest_seen: row.get::<_, i64>(3)? as u64,
            seen_bitmap: row.get(4)?,
            forward_gap: row.get::<_, i64>(5)? as u64,
        }),
    ).optional().map_err(|e| format!("load anti_replay_window: {e}"))
}

pub fn upsert_window_tx(
    tx: &Transaction<'_>,
    issuer_did: &str,
    target_id: &str,
    enrollment_epoch: u64,
    highest_seen: u64,
    seen_bitmap: u64,
    forward_gap: u64,
) -> Result<(), String> {
    tirbase_core::fail_crate::fail_point!("fp_anti_replay_window_upsert", |_| Err(
        "failpoint fp_anti_replay_window_upsert".to_string()
    ));
    tx.execute(
        &format!("INSERT INTO {ANTI_REPLAY_WINDOWS_TABLE} (issuer_did,target_id,enrollment_epoch,highest_seen,seen_bitmap,forward_gap)
                  VALUES (?1,?2,?3,?4,?5,?6)
                  ON CONFLICT(issuer_did,target_id,enrollment_epoch) DO UPDATE SET
                    highest_seen=excluded.highest_seen, seen_bitmap=excluded.seen_bitmap, forward_gap=excluded.forward_gap"),
        params![issuer_did, target_id, enrollment_epoch as i64, highest_seen as i64, seen_bitmap.to_le_bytes().to_vec(), forward_gap as i64],
    ).map_err(|e| format!("upsert anti_replay_window: {e}"))?;
    Ok(())
}

pub fn create_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {ANTI_REPLAY_WINDOWS_TABLE} (
            issuer_did        TEXT NOT NULL,
            target_id         TEXT NOT NULL,
            enrollment_epoch  INTEGER NOT NULL DEFAULT 0,
            highest_seen      INTEGER NOT NULL DEFAULT 0,
            seen_bitmap       BLOB NOT NULL,
            forward_gap       INTEGER NOT NULL DEFAULT 1024,
            PRIMARY KEY (issuer_did, target_id, enrollment_epoch)
        );"
    ))
    .map_err(|e| format!("create anti_replay_windows: {e}"))
}

#[derive(Debug)]
pub struct SqliteAntiReplayStore {
    conn: Mutex<Connection>,
}
impl SqliteAntiReplayStore {
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
}

/// Reset the window baseline (PA-signed sequence reset, CLAIM-20.3). Clears bitmap.
pub fn reset_window_baseline_tx(
    tx: &Transaction<'_>,
    issuer_did: &str,
    target_id: &str,
    enrollment_epoch: u64,
    new_baseline: u64,
    forward_gap: u64,
) -> Result<(), String> {
    upsert_window_tx(
        tx,
        issuer_did,
        target_id,
        enrollment_epoch,
        new_baseline,
        1u64,
        forward_gap.max(DEFAULT_FORWARD_GAP_G),
    )
}

impl SqliteAntiReplayStore {
    pub fn reset_baseline(
        &self,
        issuer_did: &str,
        target_id: &str,
        enrollment_epoch: u64,
        new_baseline: u64,
    ) -> Result<(), String> {
        let mut conn = self.connection();
        let tx = conn
            .transaction()
            .map_err(|e| format!("begin reset: {e}"))?;
        reset_window_baseline_tx(
            &tx,
            issuer_did,
            target_id,
            enrollment_epoch,
            new_baseline,
            DEFAULT_FORWARD_GAP_G,
        )?;
        tx.commit().map_err(|e| format!("commit reset: {e}"))
    }
}
