//! Boot crash reconciliation for `applied_effects_ledger` (19.2/19.3,
//! PV-5.3, INV-11, INV-12).
//!
//! Runs at gateway boot before accepting commands:
//! 1. Scan for pre-Actuating legacy states and mark `Failed` with
//!    `OLD_SCHEMA_ENTRY` (19.3). `Actuating` is never treated as pre-Actuating.
//! 2. Scan `Actuating` entries and perform driver read-back (30s timeout);
//!    mark `Complete`, `Failed`, or `Unknown` (19.2).
//! 3. Emit `ReconciliationComplete` or `ReconciliationTimeout`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use tirbase_core::events::{emit, ReasonCode, SecurityEvent, SecurityEventCategory, Severity};

use super::applied_effects_ledger::{
    self, ActuatingEntry, ReadBackOutcome, ReconciliationSummary, RECONCILE_READBACK_TIMEOUT,
};

/// Driver read-back interface used by boot reconciliation.
/// Production deployments wire this to real driver proxies; tests inject outcomes.
pub trait LedgerReadBack: Send + Sync {
    fn read_back(&self, entry: &ActuatingEntry, timeout: Duration) -> ReadBackOutcome;
}

/// Default read-back: if no driver integration is wired, conservatively mark
/// `Unknown` so INV-11 blocks new commands until operator resolution.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDriverReadBack;

impl LedgerReadBack for NoDriverReadBack {
    fn read_back(&self, _entry: &ActuatingEntry, _timeout: Duration) -> ReadBackOutcome {
        ReadBackOutcome::Timeout
    }
}

/// Run boot reconciliation (19.2 + 19.3). This is the production caller path
/// invoked from `tirbase-gateway::main` boot init.
pub fn reconcile_on_boot(
    conn: &Connection,
    read_back: &dyn LedgerReadBack,
    completion_ts: i64,
) -> Result<ReconciliationSummary, String> {
    if tirbase_core::fail_crate::eval("aef_reconcile_boot", |_| ()).is_some() {
        return Err(format!("failpoint {}", "aef_reconcile_boot"));
    }
    let mut summary = ReconciliationSummary::default();

    // 19.3: pre-Actuating legacy states (e.g. `Intent` from older schema) ->
    // Failed/OLD_SCHEMA_ENTRY. Must not touch Actuating.
    let pre = applied_effects_ledger::mark_pre_actuating_as_old_schema_failed(conn, completion_ts)?;
    summary.pre_actuating_marked_failed = pre;
    if pre > 0 {
        emit(
            SecurityEvent::new(
                SecurityEventCategory::EffectsLedger,
                Severity::High,
                ReasonCode::OldSchemaEntry,
            )
            .with_detail(format!(
                "marked {pre} pre-Actuating legacy ledger entries Failed (OLD_SCHEMA_ENTRY)"
            )),
        );
    }

    // 19.2: resolve Actuating entries via driver read-back (30s timeout each).
    let actuating = applied_effects_ledger::list_actuating(conn)?;
    let started = Instant::now();
    for entry in actuating {
        let remaining = RECONCILE_READBACK_TIMEOUT.saturating_sub(started.elapsed());
        let outcome = if remaining.is_zero() {
            summary.timed_out = true;
            ReadBackOutcome::Timeout
        } else {
            read_back.read_back(&entry, remaining.min(RECONCILE_READBACK_TIMEOUT))
        };
        let timed_out = matches!(outcome, ReadBackOutcome::Timeout);
        let state = applied_effects_ledger::apply_reconciliation_outcome(
            conn,
            &entry.entry_id,
            &outcome,
            completion_ts,
        )?;
        match state {
            applied_effects_ledger::EffectState::Complete => summary.actuating_complete += 1,
            applied_effects_ledger::EffectState::Failed => summary.actuating_failed += 1,
            applied_effects_ledger::EffectState::Unknown => {
                summary.actuating_unknown += 1;
                if timed_out {
                    summary.timed_out = true;
                }
            }
            applied_effects_ledger::EffectState::Actuating => {}
        }
    }

    let (reason, severity) = if summary.resolved_all() {
        (ReasonCode::ReconciliationComplete, Severity::Low)
    } else {
        (ReasonCode::ReconciliationTimeout, Severity::High)
    };
    emit(
        SecurityEvent::new(SecurityEventCategory::EffectsLedger, severity, reason).with_detail(
            format!(
                "pre_actuating_failed={}, complete={}, failed={}, unknown={}, timed_out={}",
                summary.pre_actuating_marked_failed,
                summary.actuating_complete,
                summary.actuating_failed,
                summary.actuating_unknown,
                summary.timed_out
            ),
        ),
    );

    Ok(summary)
}

/// Convenience wrapper used by gateway boot: opens no driver read-back (marks
/// unresolved actuating entries Unknown after timeout semantics) and returns
/// the summary. Kept infallible-ish for boot plumbing; caller logs errors.
pub fn reconcile_primary_db_at_boot(
    primary_db_path: impl AsRef<std::path::Path>,
    completion_ts: i64,
) -> Result<ReconciliationSummary, String> {
    let conn = Connection::open(primary_db_path.as_ref())
        .map_err(|e| format!("open primary.db for reconciliation: {e}"))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| format!("wal: {e}"))?;
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(|e| format!("sync: {e}"))?;
    applied_effects_ledger::create_table(&conn)?;
    reconcile_on_boot(&conn, &NoDriverReadBack, completion_ts)
}

/// Test helper: reconcile using an injected read-back provider.
pub fn reconcile_with_readback(
    conn: &Connection,
    read_back: Arc<dyn LedgerReadBack>,
    completion_ts: i64,
) -> Result<ReconciliationSummary, String> {
    reconcile_on_boot(conn, read_back.as_ref(), completion_ts)
}
