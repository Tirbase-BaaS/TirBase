//! Rate_Quarantine — in-memory per-sender counters with periodic summary rows
//! to `derived.db` (PV-6.7, CLAIM-23.4, CLAIM-23.5).
//!
//! Rate and size violations (RATE_EXCEEDED, OVERSIZE) are non-replayable. The
//! in-memory store is lossy by design; summary rows are written to
//! `rate_quarantine_summary(sender_did, window_start, rejected_count)` and
//! evicted after a 7-day TTL.

use std::collections::BTreeMap;
#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection};

use crate::errors::TirBaseError;
use crate::events::{emit_crdt, ReasonCode, Severity};

/// Sink for the periodic summary rows (`rate_quarantine_summary`).
///
/// The summary DB is SQLite, so it exists only on the native build. WASM gets
/// a never-constructible placeholder rather than a differently-shaped API, so
/// every call site stays identical across targets (the WASM ledger is in-memory
/// and lossy by design, per PV-6.7).
#[cfg(feature = "native")]
pub type SummaryDb = Connection;

/// WASM stand-in for [`SummaryDb`]: no SQLite in the browser build.
#[cfg(not(feature = "native"))]
#[derive(Debug)]
pub enum SummaryDb {}

pub const RATE_QUARANTINE_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// Global Rate_Quarantine limit (entries/senders tracked in summary context).
pub const RATE_QUARANTINE_GLOBAL_ENTRIES: usize = 100_000;
pub const RATE_QUARANTINE_GLOBAL_BYTES: usize = 256 * 1024 * 1024;
/// Summary window size for derived.db rows.
pub const RATE_SUMMARY_WINDOW_SECS: i64 = 60;

// Per-DID rate limits ()
pub const PER_DID_RATE_OPS_PER_SEC: u64 = 100;
pub const PER_DID_RATE_BURST: u64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateQuarantineReason {
    RateExceeded,
    Oversize,
}

impl RateQuarantineReason {
    pub fn reason_code(self) -> ReasonCode {
        match self {
            Self::RateExceeded => ReasonCode::RateExceeded,
            Self::Oversize => ReasonCode::Oversize,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RateExceeded => "RATE_EXCEEDED",
            Self::Oversize => "OVERSIZE",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SenderCounter {
    count: u32,
    last_reset_mono: u64,
    window_start: i64,
    window_count: u32,
}

/// In-memory per-sender rate/size quarantine counters plus optional summary
/// persistence to `derived.db`.
#[derive(Debug, Default)]
pub struct RateQuarantineLedger {
    counters: BTreeMap<String, SenderCounter>,
    total_rejections: u64,
}

impl RateQuarantineLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn total_rejections(&self) -> u64 {
        self.total_rejections
    }

    pub fn sender_rejections(&self, did: &str) -> u32 {
        self.counters.get(did).map(|c| c.count).unwrap_or(0)
    }

 /// Record a rate/size violation (non-replayable). Emits a security event
 /// and optionally flushes a periodic summary row.
    pub fn record(
        &mut self,
        sender_did: &str,
        reason: RateQuarantineReason,
        now_mono: u64,
        now_wall_secs: i64,
        detail: &str,
        summary_db: Option<&SummaryDb>,
    ) -> Result<(), TirBaseError> {
 // The summary sink only exists on native builds; on WASM the ledger is
 // purely in-memory (lossy by design).
        #[cfg(not(feature = "native"))]
        let _ = summary_db;
        let window_start = (now_wall_secs / RATE_SUMMARY_WINDOW_SECS) * RATE_SUMMARY_WINDOW_SECS;
        let counter = self
            .counters
            .entry(sender_did.to_string())
            .or_insert_with(|| SenderCounter {
                count: 0,
                last_reset_mono: now_mono,
                window_start,
                window_count: 0,
            });
        let window_changed = counter.window_start != window_start;
        if window_changed {
            #[cfg(feature = "native")]
            if let Some(db) = summary_db {
                Self::flush_summary(
                    db,
                    sender_did,
                    counter.window_start,
                    counter.window_count,
                    now_wall_secs,
                )?;
            }
            counter.window_start = window_start;
            counter.window_count = 0;
        }
        counter.count = counter.count.saturating_add(1);
        counter.window_count = counter.window_count.saturating_add(1);
        counter.last_reset_mono = now_mono;
        self.total_rejections = self.total_rejections.saturating_add(1);

        emit_crdt(
            Severity::Medium,
            reason.reason_code(),
            None,
            format!(
                "rate_quarantine reason={} sender={} count={} detail={}",
                reason.as_str(),
                sender_did,
                counter.count,
                detail
            ),
        );

 // Periodic flush (every window boundary handled above; also flush on a
 // small cadence to survive crashes in lossy mode).
        #[cfg(feature = "native")]
        if let Some(db) = summary_db {
            if counter.window_count == 1 || counter.window_count % 50 == 0 {
                Self::flush_summary(
                    db,
                    sender_did,
                    window_start,
                    counter.window_count,
                    now_wall_secs,
                )?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "native")]
    fn flush_summary(
        db: &SummaryDb,
        sender_did: &str,
        window_start: i64,
        rejected_count: u32,
        now_wall_secs: i64,
    ) -> Result<(), TirBaseError> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS rate_quarantine_summary (
                sender_did      TEXT NOT NULL,
                window_start    INTEGER NOT NULL,
                rejected_count  INTEGER NOT NULL,
                PRIMARY KEY (sender_did, window_start)
            );",
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("create rate_quarantine_summary: {e}"),
        })?;
        db.execute(
            "INSERT INTO rate_quarantine_summary (sender_did, window_start, rejected_count)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(sender_did, window_start) DO UPDATE SET rejected_count = excluded.rejected_count",
            params![sender_did, window_start, rejected_count as i64],
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("upsert rate_quarantine_summary: {e}"),
        })?;
        let cutoff = now_wall_secs.saturating_sub(RATE_QUARANTINE_TTL_SECS);
        let _ = db.execute(
            "DELETE FROM rate_quarantine_summary WHERE window_start < ?1",
            params![cutoff],
        );
        Ok(())
    }

    #[cfg(feature = "native")]
    pub fn open_summary_db(path: impl AsRef<Path>) -> Result<SummaryDb, TirBaseError> {
        let conn = Connection::open(path).map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("open rate quarantine summary db: {e}"),
        })?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS rate_quarantine_summary (
                sender_did      TEXT NOT NULL,
                window_start    INTEGER NOT NULL,
                rejected_count  INTEGER NOT NULL,
                PRIMARY KEY (sender_did, window_start)
            );",
        )
        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("init rate_quarantine_summary: {e}"),
        })?;
        Ok(conn)
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    #[test]
    fn records_and_flushes_summary() {
        let db = Connection::open_in_memory().unwrap();
        let mut rq = RateQuarantineLedger::new();
        rq.record(
            "did:a",
            RateQuarantineReason::RateExceeded,
            10,
            120,
            "test",
            Some(&db),
        )
        .unwrap();
        assert_eq!(rq.sender_rejections("did:a"), 1);
        let n: i64 = db
            .query_row("SELECT COUNT(*) FROM rate_quarantine_summary", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(n >= 1);
    }
}

#[derive(Debug)]
pub struct PerDidRateLimiter {
    rate: u64,
    burst: u64,
    tokens: std::collections::BTreeMap<String, (u64, std::time::Instant)>,
}

impl Default for PerDidRateLimiter {
    fn default() -> Self {
        Self {
            rate: PER_DID_RATE_OPS_PER_SEC,
            burst: PER_DID_RATE_BURST,
            tokens: std::collections::BTreeMap::new(),
        }
    }
}

impl PerDidRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_consume(&mut self, did: &str, now: std::time::Instant) -> bool {
        let entry = self
            .tokens
            .entry(did.to_string())
            .or_insert((self.burst, now));
 // refill
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        let refill = (elapsed * self.rate as f64) as u64;
        entry.0 = (entry.0 + refill).min(self.burst);
        entry.1 = now;
        if entry.0 == 0 {
            false
        } else {
            entry.0 -= 1;
            true
        }
    }
}
