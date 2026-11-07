//! System time source backed by `CLOCK_BOOTTIME` (PV-3.8, PV-3.9, CLAIM-5.1).
//!
//! This is the gateway's concrete [`TimeSource`] implementation.  It is
//! installed into `tirbase-core`'s process-wide slot at boot, so every core
//! subsystem (delta timestamps, token issuance, transport bookkeeping) reads
//! time through this one implementation.
//!
//! The portable reader lives in `tirbase_core::traits::SystemTimeSource`; task
//! 7.1 replaces the delegation below with a direct `CLOCK_BOOTTIME` read on
//! Linux (`/proc` boot id is already used by the core fallback).

use std::sync::Arc;

use tirbase_core::traits::{SystemTimeSource as CoreTimeSource, TimeSource};

/// System time source backed by the platform monotonic/wall clocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTimeSource {
    inner: CoreTimeSource,
}

impl SystemTimeSource {
    /// Construct a new `SystemTimeSource`.
    pub fn new() -> Self {
        SystemTimeSource {
            inner: CoreTimeSource::new(),
        }
    }

    /// Install this source as the process-wide time source used by all
    /// `tirbase-core` subsystems, returning the shared handle.
    pub fn install(self) -> Arc<dyn TimeSource> {
        let source: Arc<dyn TimeSource> = Arc::new(self);
        tirbase_core::traits::install_time_source(source.clone());
        source
    }
}

impl TimeSource for SystemTimeSource {
    fn monotonic_now(&self) -> u64 {
        self.inner.monotonic_now()
    }

    fn wall_hint(&self) -> Option<i64> {
        self.inner.wall_hint()
    }

    fn boot_id(&self) -> u64 {
        self.inner.boot_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guards tests that swap the process-wide core time source.
    static TIME_SOURCE_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Debug)]
    struct FixedTimeSource {
        monotonic: u64,
        wall: i64,
        boot: u64,
    }

    impl TimeSource for FixedTimeSource {
        fn monotonic_now(&self) -> u64 {
            self.monotonic
        }
        fn wall_hint(&self) -> Option<i64> {
            Some(self.wall)
        }
        fn boot_id(&self) -> u64 {
            self.boot
        }
    }

    #[test]
    fn system_time_source_is_monotonic_and_reports_a_boot_id() {
        let source = SystemTimeSource::new();
        let first = source.monotonic_now();
        let second = source.monotonic_now();
        assert!(second >= first);
        assert!(source.wall_hint().is_some());
        assert_ne!(source.boot_id(), 0);
    }

    #[test]
    fn injected_gateway_time_source_is_used_by_all_core_subsystems() {
        let _guard = TIME_SOURCE_LOCK.lock().unwrap();
        let fixed: Arc<dyn TimeSource> = Arc::new(FixedTimeSource {
            monotonic: 777_000,
            wall: 1_800_000_000_000_000,
            boot: 9,
        });
        let previous = tirbase_core::traits::install_time_source(fixed);

        // These are the exact accessors every core subsystem uses.
        assert_eq!(tirbase_core::traits::monotonic_now(), 777_000);
        assert_eq!(
            tirbase_core::traits::wall_hint(),
            Some(1_800_000_000_000_000)
        );
        assert_eq!(
            tirbase_core::traits::wall_hint_secs(),
            Some(1_800_000_000)
        );
        assert_eq!(tirbase_core::traits::time_source().boot_id(), 9);

        if let Some(previous) = previous {
            tirbase_core::traits::install_time_source(previous);
        }
    }
}
