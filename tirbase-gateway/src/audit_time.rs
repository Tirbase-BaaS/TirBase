// SPDX-License-Identifier: AGPL-3.0-only

//! Ratchet-backed time-confidence evidence for the audit log (F-06).
//!
//! [`RatchetAuditTimeSource`] reads the **existing** `TimeRatchet` — the same
//! authenticated-time authority used for command and approval expiry — and
//! describes the current clock state as `tirbase_core::timesync::TimeEvidence`.
//! It deliberately owns no time state of its own and never advances the
//! ratchet: this is a view, not a second clock.
//!
//! Confidence mapping:
//!
//! * beacon accepted in this boot and still inside the staleness window →
//!   `Verified` with the drift bound applied since the beacon;
//! * beacon accepted in this boot but stale (long offline period) →
//!   `Offline` with the elapsed time since the beacon;
//! * beacon accepted in an earlier boot → `Unverified(Rebooted)`, because the
//!   monotonic subtraction cannot bridge a reboot;
//! * no beacon ever → `Unverified(NoAuthenticatedSource)`.

use std::sync::{Arc, Mutex};

use tirbase_core::timesync::{DriftBound, TimeEvidence, TimeSourceKind, UnverifiedReason};
use tirbase_core::traits::TimeSource;
use tirbase_guard::time::{FreshnessState, TimeRatchet};

use crate::security_log::AuditTimeEvidenceSource;

/// Produces audit time evidence from the gateway's live ratchet.
#[derive(Debug)]
pub struct RatchetAuditTimeSource {
    ratchet: Arc<Mutex<TimeRatchet>>,
    time_source: Arc<dyn TimeSource>,
    drift: DriftBound,
}

impl RatchetAuditTimeSource {
    /// Build a source over the shared ratchet and clock.
    pub fn new(
        ratchet: Arc<Mutex<TimeRatchet>>,
        time_source: Arc<dyn TimeSource>,
        drift: DriftBound,
    ) -> Self {
        RatchetAuditTimeSource {
            ratchet,
            time_source,
            drift,
        }
    }
}

impl AuditTimeEvidenceSource for RatchetAuditTimeSource {
    fn evidence(&self) -> TimeEvidence {
        let ts = self.time_source.as_ref();
        let ratchet = match self.ratchet.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mono_secs = ts.monotonic_now() / 1_000_000;
        let boot_id = ts.boot_id();
        let now_est = ratchet.now_est(ts);
        let floor = ratchet.persisted_floor();

        if ratchet.beacon_boot_id() == 0 {
            return TimeEvidence::unverified(
                now_est,
                mono_secs,
                boot_id,
                floor,
                UnverifiedReason::NoAuthenticatedSource,
            );
        }
        if ratchet.beacon_boot_id() != boot_id {
            return TimeEvidence::unverified(
                now_est,
                mono_secs,
                boot_id,
                floor,
                UnverifiedReason::Rebooted,
            );
        }

        let elapsed_since_anchor_secs =
            ts.monotonic_now().saturating_sub(ratchet.mono_at_beacon()) / 1_000_000;
        let elapsed_since_anchor_secs =
            i64::try_from(elapsed_since_anchor_secs).unwrap_or(i64::MAX);

        if ratchet.freshness(ts) == FreshnessState::Verified {
            TimeEvidence::verified(
                now_est,
                mono_secs,
                boot_id,
                floor,
                TimeSourceKind::GatewayBeacon,
                self.drift.uncertainty_after(elapsed_since_anchor_secs),
            )
        } else {
            TimeEvidence::offline(
                now_est,
                mono_secs,
                boot_id,
                floor,
                elapsed_since_anchor_secs,
                self.drift,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tirbase_guard::time::{
        TimeRatchetConfig, TimeRatchetError, TimeRatchetRecord, TimeRatchetStore,
    };

    #[derive(Debug, Default)]
    struct MemoryStore {
        record: Mutex<Option<TimeRatchetRecord>>,
    }

    impl TimeRatchetStore for MemoryStore {
        fn load(&self) -> Result<Option<TimeRatchetRecord>, TimeRatchetError> {
            Ok(*self.record.lock().unwrap())
        }

        fn save(&self, record: &TimeRatchetRecord) -> Result<(), TimeRatchetError> {
            *self.record.lock().unwrap() = Some(*record);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FixedClock {
        mono_us: u64,
        wall_secs: i64,
        boot: u64,
    }

    impl TimeSource for FixedClock {
        fn monotonic_now(&self) -> u64 {
            self.mono_us
        }

        fn wall_hint(&self) -> Option<i64> {
            Some(self.wall_secs * 1_000_000)
        }

        fn boot_id(&self) -> u64 {
            self.boot
        }
    }

    #[test]
    fn no_beacon_is_unverified() {
        let ratchet = Arc::new(Mutex::new(
            TimeRatchet::open(
                Arc::new(MemoryStore::default()),
                TimeRatchetConfig::default(),
            )
            .expect("ratchet"),
        ));
        let clock: Arc<dyn TimeSource> = Arc::new(FixedClock {
            mono_us: 5_000_000,
            wall_secs: 1_800_000_000,
            boot: 7,
        });
        let source = RatchetAuditTimeSource::new(ratchet, clock, DriftBound::default());
        let evidence = source.evidence();
        assert_eq!(evidence.confidence.marker(), "unverified");
    }
}
