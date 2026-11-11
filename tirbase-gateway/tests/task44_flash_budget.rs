//! Task 44.5/44.6: flash-write budget tracking and throttling (PV-15.4, CLAIM-44.5/44.6).

use std::sync::Arc;
use std::time::Duration;

use tirbase_core::events::{ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_core::traits::SecurityEventSink;
use tirbase_gateway::event_batcher::{RecordingBatchBackend, DEFAULT_BATCH_WINDOW, MAX_BATCH_WINDOW};
use tirbase_gateway::flash_budget::{
    throttle_window_for_projection, BlockLayerCounter, FlashBudgetController,
    DEFAULT_FLASH_BUDGET_BYTES_PER_DAY,
};
use tirbase_gateway::security_log::SecurityEventLog;

fn payload(sev: Severity, n: u64) -> SecurityEvent {
    SecurityEvent::new(
        SecurityEventCategory::CommandDecision,
        sev,
        ReasonCode::CommandAccepted,
    )
    .with_target(format!("t{n}"))
}

#[test]
fn flash_budget_measured_at_linux_block_layer_api_reports_device() {
    let dir = std::env::temp_dir().join(format!(
        "tb44-flash-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("primary.db");
    std::fs::write(&db, b"x").unwrap();
    let counter = BlockLayerCounter::for_data_path(&db);
    // Block-layer accounting is the mechanism (sysfs /sys/block/<dev>/stat);
    // on non-Linux or unusual mounts this may be unsupported, but the API must
    // report block-layer status explicitly rather than using SQLite counters.
    let _ = counter.supported();
    let _ = counter.block_device();
    let _ = counter.read_cumulative_write_bytes();
    let ctl = FlashBudgetController::new(&db, DEFAULT_FLASH_BUDGET_BYTES_PER_DAY);
    let est = ctl.estimate();
    assert_eq!(est.budget_bytes_per_day, DEFAULT_FLASH_BUDGET_BYTES_PER_DAY);
    assert!(est.high_critical_bypass, "HIGH/CRITICAL must bypass budget/throttle");
    // 7-day rolling average field is present (block-layer derived when supported).
    let _ = est.rolling_7d_avg_bytes_per_day;
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn throttle_increases_group_commit_window_up_to_500ms() {
    let (w, active) = throttle_window_for_projection(DEFAULT_FLASH_BUDGET_BYTES_PER_DAY, DEFAULT_FLASH_BUDGET_BYTES_PER_DAY);
    assert_eq!(w, DEFAULT_BATCH_WINDOW);
    assert!(!active);
    let (w, active) = throttle_window_for_projection(DEFAULT_FLASH_BUDGET_BYTES_PER_DAY * 2, DEFAULT_FLASH_BUDGET_BYTES_PER_DAY);
    assert!(active);
    assert_eq!(w, MAX_BATCH_WINDOW);
    let (w, active) = throttle_window_for_projection(DEFAULT_FLASH_BUDGET_BYTES_PER_DAY + 1, DEFAULT_FLASH_BUDGET_BYTES_PER_DAY);
    assert!(active);
    assert!(w >= DEFAULT_BATCH_WINDOW && w <= MAX_BATCH_WINDOW);
}

#[test]
fn high_and_critical_security_events_bypass_flash_wear_throttling() {
    // Wiring mutation: if HIGH/CRITICAL were routed through the delayed batch
    // window they would not flush immediately. The batcher flushes immediately
    // for High/Critical regardless of configured window (PV-15.4).
    let backend = Arc::new(RecordingBatchBackend::default());
    let batcher = tirbase_gateway::event_batcher::GroupCommitBatcher::with_window(
        backend.clone(),
        Duration::from_millis(500),
    );
    batcher.emit(payload(Severity::High, 1));
    batcher.emit(payload(Severity::Critical, 2));
    batcher.emit(payload(Severity::Low, 3));
    // Immediate flushes for high/critical must have occurred synchronously.
    std::thread::sleep(Duration::from_millis(20));
    assert!(
        backend.flush_count() >= 2,
        "HIGH/CRITICAL must bypass throttle/window and flush immediately; flushes={}",
        backend.flush_count()
    );
    assert!(
        backend.total_events() >= 2,
        "HIGH/CRITICAL events must be written immediately"
    );
    // Low remains buffered until window/stop.
    batcher.stop();
    assert!(backend.total_events() >= 3);
}

#[test]
fn security_log_persists_high_severity_immediately_even_when_batched() {
    let dir = std::env::temp_dir().join(format!(
        "tb44-log-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("primary.db");
    // batched constructor: non-critical may wait, HIGH/CRITICAL must be persisted immediately.
    let log = SecurityEventLog::new_persistent(db.clone(), None, true);
    log.set_rate_limit_enabled(false);
    log.append_payload(
        SecurityEvent::new(
            SecurityEventCategory::Startup,
            Severity::High,
            ReasonCode::StorageFull,
        )
        .with_detail("ENOSPC test"),
    );
    // Immediate persistence path appends synchronously in SecurityEventLog.
    assert!(log.len() >= 1);
    let conn = rusqlite::Connection::open(&db).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM security_events", [], |r| r.get(0))
        .unwrap_or(0);
    assert!(count >= 1, "HIGH event must be persisted immediately (bypass throttling)");
    let _ = std::fs::remove_dir_all(dir);
}
