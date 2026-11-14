// SPDX-License-Identifier: AGPL-3.0-only

//! Core abstraction traits shared by every TirBase subsystem.
//!
//! These traits are the seams through which the gateway injects platform
//! capabilities (time, keys, anti-rollback counters, the security event log)
//! into `tirbase-core`. Production code must consume these traits rather than
//! calling the platform directly:
//!
//! * [`TimeSource`] — all expiry, replay and rate-limit logic (PV-3.8, PV-3.9,
//! PV-3.12). The workspace `clippy.toml` bans `std::time::Instant::now`,
//! `std::time::SystemTime::now` and `tokio::time::Instant::now`, so a direct
//! clock call fails CI.
//! * [`KeyProvider`] — all signing operations (PV-3.6). Private key material
//! is never returned by the trait.
//! * [`MonotonicCounterTrait`] — anti-rollback counters (PV-9.8).
//! * [`SecurityEventSink`] — typed security event emission (PV-7.1).

use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
// `Instant` is unimplemented on wasm32-unknown-unknown; the WASM clock reads
// `performance.now()` instead (see `SystemTimeSource::monotonic_now`).
#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
use std::time::Instant;

use tirbase_types::{DeviceKeyType, DeviceSignature};

use crate::errors::TirBaseError;
use crate::events::SecurityEvent;

// ═════════════════════════════════════════════════════════════════════════════
// TimeSource (CLAIM-5.1, PV-3.8, PV-3.9)
// ═════════════════════════════════════════════════════════════════════════════

/// Abstraction over the platform clock (PV-3.8, PV-3.9).
///
/// # Clock domains
///
/// `monotonic_now` is the **`CLOCK_BOOTTIME`** domain: it never goes backwards,
/// it keeps advancing while the system is suspended, and it is unaffected by
/// wall-clock adjustments. It is therefore authoritative for rate limits,
/// replay windows, lease expiry and command expiry. The production Linux
/// implementation reads `CLOCK_BOOTTIME` directly (/// `tirbase-gateway::time_source::SystemTimeSource`); the portable
/// [`SystemTimeSource`] in this module approximates it with
/// `std::time::Instant` for development and tests.
///
/// `wall_hint` is the **`CLOCK_REALTIME`** domain expressed as microseconds
/// since the Unix epoch. It is explicitly **untrusted**: it may jump forwards
/// or backwards. It is a hint for human-facing timestamps only — never for a
/// security decision that needs elapsed time.
///
/// `boot_id` identifies the current boot so a caller can tell "the clock
/// advanced" from "the device rebooted". It is stable for the lifetime of a
/// boot and changes across reboots.
pub trait TimeSource: Send + Sync + std::fmt::Debug {
 /// `CLOCK_BOOTTIME` in **microseconds** (monotonic, includes suspend time).
    fn monotonic_now(&self) -> u64;

 /// `CLOCK_REALTIME` in **microseconds** since the Unix epoch, if the
 /// platform exposes a wall clock (explicitly untrusted).
    fn wall_hint(&self) -> Option<i64>;

 /// Identifier of the current boot (stable within one boot, changes across
 /// reboots).
    fn boot_id(&self) -> u64;
}

/// Portable [`TimeSource`] used when no platform implementation is injected.
///
/// On Linux a real gateway installs its `CLOCK_BOOTTIME`-backed
/// [`TimeSource`] at boot; this type is the fallback so that the core library
/// (and unit tests) behave sensibly without one.
///
/// `monotonic_now` is derived from `std::time::Instant`, which is the
/// `CLOCK_MONOTONIC` domain: monotonic and wall-clock-adjustment-proof, but it
/// does not count time spent suspended. That difference is why 
/// supplies a direct `CLOCK_BOOTTIME` reader for production gateways.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTimeSource;

impl SystemTimeSource {
 /// Construct a system time source.
    pub fn new() -> Self {
        SystemTimeSource
    }
}

/// Process-relative monotonic offset. Captured once so
/// [`SystemTimeSource::monotonic_now`] is a cheap subtraction.
///
/// wasm32-unknown-unknown stores the origin in the browser's
/// `performance.now()` domain (milliseconds, `f64`) because `std::time::Instant`
/// is unimplemented there.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
static MONOTONIC_ORIGIN: OnceLock<Instant> = OnceLock::new();
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
static MONOTONIC_ORIGIN: OnceLock<f64> = OnceLock::new();

/// Cached default boot identifier.
static DEFAULT_BOOT_ID: OnceLock<u64> = OnceLock::new();

impl TimeSource for SystemTimeSource {
 // This is the clock boundary the `clippy::disallowed_methods` clock ban
 // (PV-3.12) exists to funnel everything through: `SystemTimeSource` is the
 // one implementation permitted to read the platform primitive, and the
 // allow cannot be removed without making the trait unimplementable. Every
 // other crate must obtain time through `TimeSource`.
    #[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
    #[allow(clippy::disallowed_methods)]
    fn monotonic_now(&self) -> u64 {
        let origin = MONOTONIC_ORIGIN.get_or_init(Instant::now);
        origin.elapsed().as_micros() as u64
    }

 // wasm32-unknown-unknown has no OS clock: `Instant::now()` panics with
 // "time not implemented on this platform". `performance.now()` is the
 // browser's monotonic, high-resolution clock, so the WASM build uses it
 // (falling back to `Date.now()` when there is no `window.performance`,
 // e.g. inside a worker).
    #[cfg(all(target_arch = "wasm32", feature = "wasm"))]
    fn monotonic_now(&self) -> u64 {
        let origin = MONOTONIC_ORIGIN.get_or_init(browser_monotonic_ms);
        let elapsed_ms = browser_monotonic_ms() - origin;
        (elapsed_ms.max(0.0) * 1_000.0) as u64
    }

    fn wall_hint(&self) -> Option<i64> {
        let now = wall_clock_now()?;
        Some(now.duration_since(UNIX_EPOCH).ok()?.as_micros() as i64)
    }

    fn boot_id(&self) -> u64 {
        *DEFAULT_BOOT_ID.get_or_init(default_boot_id)
    }
}

/// Single place in the crate permitted to read the wall clock (PV-3.12).
///
/// As with `monotonic_now`, the `disallowed_methods` allow is intrinsic to this
/// boundary: the lint bans `SystemTime::now` everywhere *except* the one
/// implementation that supplies it to the rest of the workspace.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
#[allow(clippy::disallowed_methods)]
fn wall_clock_now() -> Option<SystemTime> {
    Some(SystemTime::now())
}

/// WASM wall clock: `SystemTime::now()` panics on `wasm32-unknown-unknown`, so
/// the browser clock (`Date.now()`, milliseconds since the epoch) is converted
/// into a `SystemTime` instead. The result is still only ever surfaced as the
/// untrusted `wall_hint`; monotonic time comes from `performance.now()`.
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
fn wall_clock_now() -> Option<SystemTime> {
    let millis = js_sys::Date::now();
    if !millis.is_finite() || millis < 0.0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_millis(millis as u64))
}

/// Browser monotonic clock in milliseconds: `performance.now()` when a
/// `window`/worker exposes it, otherwise `Date.now()`.
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
fn browser_monotonic_ms() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or_else(js_sys::Date::now)
}

/// Derive a stable boot identifier: kernel `boot_id` on Linux, otherwise a
/// process-scoped fallback.
fn default_boot_id() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(raw) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
            return fnv1a64(raw.trim().as_bytes());
        }
    }
 // A browser page load is the WASM analogue of a boot, and both
 // `std::process::id()` and `SystemTime::now()` panic on
 // wasm32-unknown-unknown, so the identifier is derived from the browser
 // clock instead.
    #[cfg(all(target_arch = "wasm32", feature = "wasm"))]
    {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&js_sys::Date::now().to_le_bytes());
        bytes.extend_from_slice(&js_sys::Math::random().to_le_bytes());
        return fnv1a64(&bytes);
    }
 // Non-Linux fallback: the process id plus the monotonic origin. This is
 // stable for the process but not across reboots; the production gateway
 // overrides `boot_id` with a kernel-derived value ().
    #[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
    {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&std::process::id().to_le_bytes());
        bytes.extend_from_slice(&SystemTimeSource::new().monotonic_now().to_le_bytes());
        fnv1a64(&bytes)
    }
}

/// FNV-1a 64-bit hash (small, dependency-free, non-cryptographic).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Process-wide injected time source.
static TIME_SOURCE: RwLock<Option<Arc<dyn TimeSource>>> = RwLock::new(None);

/// Install the process-wide [`TimeSource`], returning the previously installed
/// source (if any).
///
/// The gateway calls this once during boot so every core subsystem — CRDT
/// timestamps, transport bookkeeping, token issuance — reads time through the
/// injected implementation (CLAIM-5.1).
pub fn install_time_source(source: Arc<dyn TimeSource>) -> Option<Arc<dyn TimeSource>> {
    match TIME_SOURCE.write() {
        Ok(mut slot) => slot.replace(source),
        Err(poisoned) => poisoned.into_inner().replace(source),
    }
}

/// The installed [`TimeSource`], or the portable default when none is
/// installed.
pub fn time_source() -> Arc<dyn TimeSource> {
    static DEFAULT: OnceLock<Arc<dyn TimeSource>> = OnceLock::new();

    let installed = match TIME_SOURCE.read() {
        Ok(slot) => slot.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    installed.unwrap_or_else(|| {
        DEFAULT
            .get_or_init(|| Arc::new(SystemTimeSource::new()))
            .clone()
    })
}

/// `CLOCK_BOOTTIME`-domain time in microseconds.
pub fn monotonic_now() -> u64 {
    time_source().monotonic_now()
}

/// Untrusted wall-clock hint in microseconds since the Unix epoch.
pub fn wall_hint() -> Option<i64> {
    time_source().wall_hint()
}

/// Untrusted wall-clock hint in whole seconds since the Unix epoch.
pub fn wall_hint_secs() -> Option<i64> {
    wall_hint().map(|micros| micros.div_euclid(1_000_000))
}

/// Build a `SystemTime` from a wall-clock hint (used where the Biscuit API
/// requires a `SystemTime` value).
pub(crate) fn wall_hint_system_time() -> SystemTime {
    match wall_hint() {
        Some(micros) if micros >= 0 => UNIX_EPOCH + Duration::from_micros(micros as u64),
        _ => UNIX_EPOCH,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// KeyProvider (CLAIM-5.2, PV-3.6)
// ═════════════════════════════════════════════════════════════════════════════

/// Abstraction over a device key (PV-3.6).
///
/// Every signing operation in the system goes through this trait. The trait
/// deliberately exposes **no** way to read private key material: callers can
/// sign, ask for the public key, the key type, and the DID. Key bytes live in
/// the implementation (a file, a TPM, a PKCS#11 token) and never leave it.
///
/// Implementations must be `Send + Sync` so a single provider can be shared
/// across the gateway's Tokio tasks.
#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync + std::fmt::Debug {
 /// Sign `payload`, returning a typed [`DeviceSignature`].
 ///
 /// This is the synchronous path used by code that is not on an async
 /// runtime (delta production, token issuance).
    fn sign(&self, payload: &[u8]) -> Result<DeviceSignature, TirBaseError>;

 /// Async variant for callers on a Tokio task whose provider may need to
 /// await hardware I/O (TPM2 / PKCS#11).
    async fn sign_async(&self, payload: &[u8]) -> Result<DeviceSignature, TirBaseError>;

 /// The public key bytes for this key (raw encoding for
 /// [`DeviceKeyType::Ed25519`], SEC1 uncompressed for
 /// [`DeviceKeyType::P256`]).
    fn public_key_bytes(&self) -> Vec<u8>;

 /// Algorithm of this key.
    fn key_type(&self) -> DeviceKeyType;

 /// The DID bound to this key (`did:key:z6Mk…`).
    fn did(&self) -> &str;
}

// ═════════════════════════════════════════════════════════════════════════════
// MonotonicCounterTrait (CLAIM-5.3, PV-9.8)
// ═════════════════════════════════════════════════════════════════════════════

/// Assurance level of a [`MonotonicCounterTrait`] implementation (PV-9.8, RD-2).
///
/// * [`AssuranceLevel::Level1`] — software counter persisted with SQLite WAL
/// and `synchronous=FULL`. Detects mistakes and non-physical attackers; a
/// restore of an older snapshot is not detectable by the counter alone and is
/// handled by the signed enrollment-epoch bump.
/// * [`AssuranceLevel::Level2`] — hardware non-volatile counter (TPM2 NV index
/// or eMMC RPMB). Required for any documented anti-rollback claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssuranceLevel {
 /// Software-backed counter (WAL + `synchronous=FULL`).
    Level1,
 /// Hardware-backed counter (TPM2 NV index / eMMC RPMB).
    Level2,
}

impl AssuranceLevel {
 /// Canonical string used in the boot diagnostic.
    pub fn as_str(&self) -> &'static str {
        match self {
            AssuranceLevel::Level1 => "Level1",
            AssuranceLevel::Level2 => "Level2",
        }
    }
}

/// Abstraction over the anti-rollback counter (PV-9.8).
///
/// The counter only ever moves forward. `increment` returns the **new** value
/// so a caller can commit the value it must later compare against. Storage
/// failures are reported as `Err` rather than being swallowed: a counter that
/// silently fails to persist is worse than no counter.
pub trait MonotonicCounterTrait: Send + Sync + std::fmt::Debug {
 /// Read the current value without changing it.
    fn read(&self) -> Result<u64, TirBaseError>;

 /// Increment by one and return the new value.
    fn increment(&self) -> Result<u64, TirBaseError>;

 /// Raise the counter to `value` if `value` is greater than the current
 /// value; returns the value now stored. A lower `value` never moves the
 /// counter backwards.
    fn set_if_greater(&self, value: u64) -> Result<u64, TirBaseError>;

 /// Assurance level reported in the gateway boot diagnostic (PV-9.8).
    fn assurance_level(&self) -> AssuranceLevel;
}

// ═════════════════════════════════════════════════════════════════════════════
// SecurityEventSink (CLAIM-5.4, PV-7.1, INV-4)
// ═════════════════════════════════════════════════════════════════════════════

/// Destination for typed [`SecurityEvent`]s (PV-7.1).
///
/// The core emits through the process-wide sink installed by the gateway (see
/// [`crate::events::install_security_event_sink`]). The sink is responsible
/// for serialising events into the hash-chained log (INV-4), assigning
/// sequence numbers, and checkpointing — none of that state lives at the
/// emission site.
pub trait SecurityEventSink: Send + Sync + std::fmt::Debug {
 /// Record one event.
    fn emit(&self, event: SecurityEvent);
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::events::{ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
    use std::sync::Mutex;

    #[test]
    fn default_time_source_is_monotonic_and_has_wall_hint() {
        let source = SystemTimeSource::new();
        let first = source.monotonic_now();
        let second = source.monotonic_now();
        assert!(second >= first, "monotonic_now must not go backwards");
        assert!(
            source.wall_hint().is_some(),
            "portable source has a wall clock"
        );
        assert_ne!(source.boot_id(), 0, "boot id must be a real identifier");
    }

    #[derive(Debug, Default)]
    struct RecordingSink {
        events: Mutex<Vec<SecurityEvent>>,
    }

    impl SecurityEventSink for RecordingSink {
        fn emit(&self, event: SecurityEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn security_event_sink_trait_receives_typed_event() {
        let sink = RecordingSink::default();
        sink.emit(
            SecurityEvent::new(
                SecurityEventCategory::Migration,
                Severity::High,
                ReasonCode::FuelExhausted,
            )
            .with_detail("sandbox ran out of fuel"),
        );
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason_code, ReasonCode::FuelExhausted);
    }

    #[test]
    fn assurance_levels_are_ordered_and_named() {
        assert!(AssuranceLevel::Level2 > AssuranceLevel::Level1);
        assert_eq!(AssuranceLevel::Level1.as_str(), "Level1");
        assert_eq!(AssuranceLevel::Level2.as_str(), "Level2");
    }
}
