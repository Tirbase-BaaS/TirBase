//! System time source backed by `CLOCK_BOOTTIME`, `CLOCK_REALTIME`, and the
//! kernel boot id (task 7.1 — CLAIM-7.1, PV-3.8).
//!
//! This is the gateway's concrete [`TimeSource`]:
//!
//! * `monotonic_now` reads **`CLOCK_BOOTTIME`** directly, which keeps advancing
//!   while the system is suspended (unlike `CLOCK_MONOTONIC`) and is unaffected
//!   by wall-clock adjustment.  It is the authoritative domain for leases, rate
//!   limits and the `TimeRatchet`'s elapsed-time arithmetic.
//! * `wall_hint` reads **`CLOCK_REALTIME`** in microseconds since the Unix
//!   epoch.  It is explicitly untrusted and used only for human-facing
//!   timestamps.
//! * `boot_id` hashes `/proc/sys/kernel/random/boot_id`, so the ratchet can tell
//!   "the monotonic clock advanced" from "the device rebooted".
//!
//! Non-Linux hosts (developer machines, macOS CI) fall back to the portable
//! `tirbase_core::traits::SystemTimeSource`, which approximates the same domains
//! with `std::time::Instant` and a process-scoped boot identifier.
//!
//! # Simulation hooks
//!
//! Two environment variables exist for fault-injection and integration tests
//! (the same pattern as `TIRBASE_SIMULATED_HW_COUNTER`).  They are **not**
//! production configuration:
//!
//! * `TIRBASE_BOOT_ID` — override the boot identifier, so a test can model
//!   "same boot, new gateway process" on hosts without a kernel boot id, or
//!   "simulated reboot" by changing it.
//! * `TIRBASE_TIME_SIM_OFFSET_SECS` — advance the monotonic domain by a fixed
//!   number of seconds, modelling elapsed time without sleeping.

use std::sync::Arc;

use tirbase_core::traits::{SystemTimeSource as CoreTimeSource, TimeSource};

/// Boot-identifier override used by simulated-reboot tests.
pub const BOOT_ID_ENV: &str = "TIRBASE_BOOT_ID";

/// Monotonic-domain offset (seconds) used by simulated-time-advance tests.
pub const MONOTONIC_OFFSET_ENV: &str = "TIRBASE_TIME_SIM_OFFSET_SECS";

/// System time source backed by the platform monotonic/wall clocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTimeSource {
    inner: CoreTimeSource,
    monotonic_offset_micros: u64,
}

impl SystemTimeSource {
    /// Construct a new `SystemTimeSource`.
    pub fn new() -> Self {
        SystemTimeSource {
            inner: CoreTimeSource::new(),
            monotonic_offset_micros: Self::simulated_offset_micros(),
        }
    }

    /// Construct a source whose monotonic domain is advanced by `micros`.
    ///
    /// Used by tests and `tirbase-sim` to model elapsed time deterministically.
    pub fn with_monotonic_offset(micros: u64) -> Self {
        SystemTimeSource {
            inner: CoreTimeSource::new(),
            monotonic_offset_micros: micros,
        }
    }

    /// Install this source as the process-wide time source used by all
    /// `tirbase-core` subsystems, returning the shared handle.
    pub fn install(self) -> Arc<dyn TimeSource> {
        let source: Arc<dyn TimeSource> = Arc::new(self);
        tirbase_core::traits::install_time_source(source.clone());
        source
    }

    /// The `TIRBASE_TIME_SIM_OFFSET_SECS` value, in microseconds.
    fn simulated_offset_micros() -> u64 {
        std::env::var(MONOTONIC_OFFSET_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_mul(1_000_000)
    }

    /// `TIRBASE_BOOT_ID` override, when set to a valid integer.
    fn environment_boot_id() -> Option<u64> {
        std::env::var(BOOT_ID_ENV)
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
    }
}

impl TimeSource for SystemTimeSource {
    fn monotonic_now(&self) -> u64 {
        let base = platform_boottime_micros().unwrap_or_else(|| self.inner.monotonic_now());
        base.saturating_add(self.monotonic_offset_micros)
    }

    fn wall_hint(&self) -> Option<i64> {
        platform_realtime_micros().or_else(|| self.inner.wall_hint())
    }

    fn boot_id(&self) -> u64 {
        SystemTimeSource::environment_boot_id()
            .or_else(platform_boot_id)
            .unwrap_or_else(|| self.inner.boot_id())
    }
}

// ─── Linux platform clocks ───────────────────────────────────────────────────

/// Read a `clock_gettime` clock in microseconds.
#[cfg(target_os = "linux")]
fn clock_micros(clock: libc::clockid_t) -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes into the `timespec` we own, and the clock
    // ids passed in are libc constants (CLOCK_BOOTTIME / CLOCK_REALTIME) that
    // are valid for this target.
    let rc = unsafe { libc::clock_gettime(clock, &mut ts) };
    if rc != 0 {
        return None;
    }
    let secs = u64::try_from(ts.tv_sec).ok()?;
    let nanos = u64::try_from(ts.tv_nsec).ok()?;
    Some(secs.saturating_mul(1_000_000).saturating_add(nanos / 1_000))
}

#[cfg(target_os = "linux")]
fn platform_boottime_micros() -> Option<u64> {
    clock_micros(libc::CLOCK_BOOTTIME)
}

#[cfg(not(target_os = "linux"))]
fn platform_boottime_micros() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn platform_realtime_micros() -> Option<i64> {
    clock_micros(libc::CLOCK_REALTIME).map(|micros| micros as i64)
}

#[cfg(not(target_os = "linux"))]
fn platform_realtime_micros() -> Option<i64> {
    None
}

/// Hash the kernel boot identifier into a `u64`.
#[cfg(target_os = "linux")]
fn platform_boot_id() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(fnv1a64(trimmed.as_bytes()))
}

#[cfg(not(target_os = "linux"))]
fn platform_boot_id() -> Option<u64> {
    None
}

/// FNV-1a 64-bit hash (non-cryptographic; the boot id only needs to distinguish
/// boots, and the persisted ratchet never trusts it as a secret).
#[cfg(target_os = "linux")]
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
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
    fn simulated_offset_advances_only_the_monotonic_domain() {
        let base = SystemTimeSource::with_monotonic_offset(0);
        let advanced = SystemTimeSource::with_monotonic_offset(5_000_000);
        let base_now = base.monotonic_now();
        let advanced_now = advanced.monotonic_now();
        assert!(
            advanced_now >= base_now + 5_000_000,
            "offset must advance CLOCK_BOOTTIME ({advanced_now} vs {base_now})"
        );
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
        assert_eq!(tirbase_core::traits::wall_hint_secs(), Some(1_800_000_000));
        assert_eq!(tirbase_core::traits::time_source().boot_id(), 9);

        if let Some(previous) = previous {
            tirbase_core::traits::install_time_source(previous);
        }
    }
}
