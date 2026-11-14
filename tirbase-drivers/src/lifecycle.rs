// SPDX-License-Identifier: AGPL-3.0-only

//! Driver process lifecycle and crash accounting (CLAIM-33.7, PV-10, S24).
//!
//! The guard/gateway owns the persistent driver child and feeds crash decisions
//! into supervisor escalation accounting. Restart policy: exponential backoff
//! starting at 1s, capped at 60s, with at most 5 retries in the bounded policy
//! window; crash accounting is surfaced so the supervisor can enter LOCKDOWN.

use core::fmt;
use std::time::Duration;

pub const DRIVER_RESTART_INITIAL: Duration = Duration::from_secs(1);
pub const DRIVER_RESTART_MAX: Duration = Duration::from_secs(60);
pub const DRIVER_RESTART_MAX_RETRIES: u32 = 5;

/// Supervisor-visible decision for a driver crash/restart cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverRestartDecision {
    /// Restart the persistent child after `backoff`.
    Restart { attempt: u32, backoff: Duration },
    /// Bounded retries exhausted; escalate to supervisor LOCKDOWN accounting.
    EscalateLockdown { attempts: u32 },
}

impl DriverRestartDecision {
    pub fn feeds_supervisor_lockdown(self) -> bool {
        matches!(self, DriverRestartDecision::EscalateLockdown { .. })
    }
}

/// Tracks persistent child crashes and computes exponential backoff (CLAIM-33.7).
#[derive(Debug, Clone)]
pub struct DriverLifecycle {
    consecutive_crashes: u32,
    max_retries: u32,
    initial: Duration,
    max_backoff: Duration,
}

impl Default for DriverLifecycle {
    fn default() -> Self {
        Self::new(
            DRIVER_RESTART_INITIAL,
            DRIVER_RESTART_MAX,
            DRIVER_RESTART_MAX_RETRIES,
        )
    }
}

impl DriverLifecycle {
    pub fn new(initial: Duration, max_backoff: Duration, max_retries: u32) -> Self {
        Self {
            consecutive_crashes: 0,
            max_retries,
            initial,
            max_backoff,
        }
    }

    pub fn consecutive_crashes(&self) -> u32 {
        self.consecutive_crashes
    }

    /// Records a child crash and returns the next action.
    ///
    /// After `max_retries` crashes, the decision is `EscalateLockdown` so the
    /// guard supervisor can apply crash-loop LOCKDOWN escalation (S24).
    pub fn record_crash(&mut self) -> DriverRestartDecision {
        self.consecutive_crashes = self.consecutive_crashes.saturating_add(1);
        if self.consecutive_crashes > self.max_retries {
            return DriverRestartDecision::EscalateLockdown {
                attempts: self.consecutive_crashes,
            };
        }
        let exp = self.consecutive_crashes.saturating_sub(1);
        let factor = 1_u32.checked_shl(exp.min(16)).unwrap_or(u32::MAX);
        let backoff = self.initial.saturating_mul(factor).min(self.max_backoff);
        DriverRestartDecision::Restart {
            attempt: self.consecutive_crashes,
            backoff,
        }
    }

    /// Resets crash accounting after a healthy/stable child period.
    pub fn record_stable(&mut self) {
        self.consecutive_crashes = 0;
    }
}

/// Guard-side crash accounting hook (CLAIM-33.7, PV-10).
///
/// Implementations feed driver crash decisions into the supervisor/lockdown
/// escalation path (e.g., `tirbase-guard` crash-loop tracker). `tirbase-drivers`
/// depends only on `tirbase-types`, so this trait carries the integration
/// contract used by `tirbase-guard::driver_proxy` / gateway runtime.
pub trait DriverCrashSupervisor: Send + Sync {
    fn on_driver_restart(&self, attempt: u32, backoff: Duration);
    fn on_driver_escalate_lockdown(&self, attempts: u32);
}

/// Applies a restart decision and reports it to supervisor accounting.
pub fn apply_restart_decision<S: DriverCrashSupervisor + ?Sized>(
    decision: DriverRestartDecision,
    supervisor: &S,
) {
    match decision {
        DriverRestartDecision::Restart { attempt, backoff } => {
            supervisor.on_driver_restart(attempt, backoff)
        }
        DriverRestartDecision::EscalateLockdown { attempts } => {
            supervisor.on_driver_escalate_lockdown(attempts)
        }
    }
}

/// Lifecycle configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleConfigError(pub String);

impl fmt::Display for LifecycleConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "driver lifecycle config error: {}", self.0)
    }
}

impl std::error::Error for LifecycleConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Sup {
        events: Mutex<Vec<(u32, u64, bool)>>,
    }
    impl DriverCrashSupervisor for Sup {
        fn on_driver_restart(&self, attempt: u32, backoff: Duration) {
            self.events
                .lock()
                .unwrap()
                .push((attempt, backoff.as_secs(), false));
        }
        fn on_driver_escalate_lockdown(&self, attempts: u32) {
            self.events.lock().unwrap().push((attempts, 0, true));
        }
    }

    // [CLAIM-33.7] 1s initial, 60s max, 5 retries, escalation feeds supervisor.
    #[test]
    fn exponential_backoff_and_lockdown_escalation() {
        let mut lc = DriverLifecycle::default();
        assert_eq!(
            lc.record_crash(),
            DriverRestartDecision::Restart {
                attempt: 1,
                backoff: Duration::from_secs(1)
            }
        );
        assert_eq!(
            lc.record_crash(),
            DriverRestartDecision::Restart {
                attempt: 2,
                backoff: Duration::from_secs(2)
            }
        );
        assert_eq!(
            lc.record_crash(),
            DriverRestartDecision::Restart {
                attempt: 3,
                backoff: Duration::from_secs(4)
            }
        );
        assert_eq!(
            lc.record_crash(),
            DriverRestartDecision::Restart {
                attempt: 4,
                backoff: Duration::from_secs(8)
            }
        );
        assert_eq!(
            lc.record_crash(),
            DriverRestartDecision::Restart {
                attempt: 5,
                backoff: Duration::from_secs(16)
            }
        );
        let esc = lc.record_crash();
        assert_eq!(esc, DriverRestartDecision::EscalateLockdown { attempts: 6 });
        assert!(esc.feeds_supervisor_lockdown());
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut lc = DriverLifecycle::new(Duration::from_secs(1), Duration::from_secs(60), 10);
        let mut last = Duration::ZERO;
        for _ in 0..10 {
            if let DriverRestartDecision::Restart { backoff, .. } = lc.record_crash() {
                assert!(backoff <= Duration::from_secs(60));
                last = backoff;
            }
        }
        assert_eq!(last, Duration::from_secs(60));
    }

    #[test]
    fn apply_decision_feeds_supervisor() {
        let sup = Arc::new(Sup::default());
        apply_restart_decision(
            DriverRestartDecision::Restart {
                attempt: 1,
                backoff: Duration::from_secs(1),
            },
            &*sup,
        );
        apply_restart_decision(
            DriverRestartDecision::EscalateLockdown { attempts: 6 },
            &*sup,
        );
        let ev = sup.events.lock().unwrap();
        assert_eq!(ev[0], (1, 1, false));
        assert_eq!(ev[1], (6, 0, true));
    }
}
