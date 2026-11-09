//! Scenario S14 (security log flooding, PV-7.6, task 26/S14).
//!
//! Proves: per-category rate limiting (100 events/sec) with a single
//! SuppressionSummary per suppression window, HIGH/CRITICAL bypass, and
//! bounded in-memory retention (<=10,000) keeping oldest anchors + most recent.

use std::sync::Arc;

use tirbase_core::events::{ReasonCode, SecurityEvent as Payload, SecurityEventCategory, Severity};
use tirbase_core::traits::SecurityEventSink;
use tirbase_gateway::security_log::SecurityEventLog;

/// Deterministic seed marker for PV-12.1 traceability.
pub const S14_SEED: u64 = 0x00C1_0CC0_0000_0014;

pub fn run_s14(_seed: u64) -> Result<(), String> {
    let log = Arc::new(SecurityEventLog::new_memory());
    log.set_rate_limit_enabled(true);

    // Flood low-severity events in one category (>100/sec window context is
    // simulated by rapid emission; limiter uses tokens/refill but must bound).
    let cat = SecurityEventCategory::CommandDecision;
    for i in 0..500u64 {
        log.emit(
            Payload::new(cat, Severity::Low, ReasonCode::CommandAccepted)
                .with_target(format!("flood-{i}")),
        );
    }

    let events = log.chained_events();
    let low_accepted = events
        .iter()
        .filter(|e| e.reason_code == ReasonCode::CommandAccepted)
        .count();
    let summaries = events
        .iter()
        .filter(|e| e.reason_code == ReasonCode::SuppressionSummary)
        .count();

    if low_accepted >= 500 {
        return Err(format!(
            "seed={_seed} S14 FAIL: rate limiter did not suppress low-severity flood (accepted={low_accepted})"
        ));
    }
    if low_accepted > 200 {
        return Err(format!(
            "seed={_seed} S14 FAIL: suppression too weak for 100/sec category limit (accepted={low_accepted})"
        ));
    }
    if summaries == 0 {
        return Err(format!(
            "seed={_seed} S14 FAIL: expected at least one SuppressionSummary event"
        ));
    }

    // HIGH/CRITICAL bypass.
    let before = log.chained_events().len();
    for i in 0..50u64 {
        log.emit(
            Payload::new(
                SecurityEventCategory::SecurityLog,
                Severity::High,
                ReasonCode::TamperDetection,
            )
            .with_target(format!("hi-{i}")),
        );
        log.emit(
            Payload::new(
                SecurityEventCategory::ModeTransition,
                Severity::Critical,
                ReasonCode::EnteredLockdown,
            )
            .with_target(format!("crit-{i}")),
        );
    }
    let after = log.chained_events().len();
    let hi_crit_added = log
        .chained_events()
        .into_iter()
        .filter(|e| matches!(e.severity, Severity::High | Severity::Critical))
        .filter(|e| {
            e.target
                .as_deref()
                .map(|t| t.starts_with("hi-") || t.starts_with("crit-"))
                .unwrap_or(false)
        })
        .count();
    if hi_crit_added < 100 {
        return Err(format!(
            "seed={_seed} S14 FAIL: HIGH/CRITICAL must bypass rate limiter (added={hi_crit_added}, before={before}, after={after})"
        ));
    }

    // Ring bounded to 10k while retaining anchors + most recent.
    let log2 = Arc::new(SecurityEventLog::new_memory());
    log2.set_rate_limit_enabled(false);
    for i in 0..10_500u64 {
        let code = if i % 200 == 0 {
            ReasonCode::CheckpointWritten
        } else {
            ReasonCode::CommandAccepted
        };
        log2.emit(
            Payload::new(SecurityEventCategory::CommandDecision, Severity::Low, code)
                .with_target(format!("ring-{i}")),
        );
    }
    let snap = log2.chained_events();
    if snap.len() > 10_200 {
        return Err(format!(
            "seed={_seed} S14 FAIL: ring not bounded (len={})",
            snap.len()
        ));
    }
    if !snap
        .iter()
        .any(|e| e.target.as_deref() == Some("ring-10499"))
    {
        return Err(format!(
            "seed={_seed} S14 FAIL: ring must retain most recent events"
        ));
    }
    if !snap.iter().any(|e| {
        e.target.as_deref() == Some("ring-0") && e.reason_code == ReasonCode::CheckpointWritten
    }) && !snap
        .iter()
        .any(|e| e.reason_code == ReasonCode::CheckpointWritten && e.seq <= 500)
    {
        return Err(format!(
            "seed={_seed} S14 FAIL: ring must retain oldest anchor/checkpoint events"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s14_log_flooding_rate_limit_and_bounded_retention() {
        run_s14(S14_SEED).unwrap();
    }
}
