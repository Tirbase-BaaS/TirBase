//! Scenario S24 — Crash-loop escalation (task 13.6, CLAIM-13.6, PV-1.11).
//!
//! Supervisor restart semantics: a crash reconciles to Normal; N crashes within
//! the configurable window escalate to security LOCKDOWN.

use tirbase_guard::lockdown::{
    apply_crash_decision, CrashLoopEscalation, CrashLoopTracker, InMemoryLockdownStore,
    LockdownStore,
};
use tirbase_guard::node_mode::{NodeMode, NodeModeState};

/// S24: 3 crashes within 5 minutes escalate to LOCKDOWN; fewer/outside do not.
pub fn s24_crash_loop_escalates_to_lockdown_within_window() {
    let store = InMemoryLockdownStore::new();
    let mode = NodeModeState::new(NodeMode::Starting);
    let mut tracker = CrashLoopTracker::new(3, 300);

    let d1 = tracker.record_crash(10);
    assert_eq!(
        d1,
        CrashLoopEscalation::RestartNormal {
            crashes_in_window: 1
        }
    );
    apply_crash_decision(d1, &store, &mode).unwrap();
    assert_eq!(mode.get(), NodeMode::Normal);
    assert!(!store.is_lockdown().unwrap());

    let d2 = tracker.record_crash(120);
    assert_eq!(
        d2,
        CrashLoopEscalation::RestartNormal {
            crashes_in_window: 2
        }
    );
    apply_crash_decision(d2, &store, &mode).unwrap();
    assert_eq!(mode.get(), NodeMode::Normal);

    let d3 = tracker.record_crash(200);
    assert_eq!(
        d3,
        CrashLoopEscalation::EscalateLockdown {
            crashes_in_window: 3
        }
    );
    apply_crash_decision(d3, &store, &mode).unwrap();
    assert_eq!(mode.get(), NodeMode::Lockdown);
    assert!(
        store.is_lockdown().unwrap(),
        "S24: crash-loop must escalate to LOCKDOWN"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn s24_crash_loop_escalation() {
        s24_crash_loop_escalates_to_lockdown_within_window();
    }
}
