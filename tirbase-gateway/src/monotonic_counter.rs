//! Monotonic counters for the gateway binary (PV-9.8, RD-2).
//!
//! * [`SoftwareMonotonicCounter`] — assurance **Level 1**.  Durable SQLite WAL
//!   storage with `PRAGMA synchronous=FULL`, so an increment is fsynced before
//!   it returns (CLAIM-6.5).  The gateway reports `Level1` in its boot
//!   diagnostic.
//! * [`Tpm2MonotonicCounter`] — assurance **Level 2** stub over a TPM2 NV index
//!   or eMMC RPMB (CLAIM-6.6).
//! * [`NullHardwareCounter`] / [`SimulatedHardwareCounter`] — non-TPM
//!   deployments and the fault-injection path used by the rollback test
//!   (CLAIM-6.7a).
//!
//! # Level 1 durability
//!
//! WAL alone does not make a commit durable; `synchronous=FULL` is the pragma
//! that forces an fsync of the WAL on every commit.  The wiring-mutation check
//! for CLAIM-6.5 removes that pragma and requires
//! `software_counter_uses_sqlite_wal_with_synchronous_full` to fail.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};
use tirbase_core::errors::TirBaseError;
use tirbase_core::traits::{AssuranceLevel, MonotonicCounterTrait};

/// SQLite error → core error, preserving the failing operation.
fn db_error(context: &str, error: rusqlite::Error) -> TirBaseError {
    TirBaseError::LocalStoreWriteFailed {
        reason: format!("monotonic counter {context}: {error}"),
    }
}

/// Software-backed monotonic counter (no TPM / secure element required).
///
/// Assurance **Level 1**: the value lives in a SQLite database opened in WAL
/// mode with `synchronous=FULL`.  Every `increment` commits before returning,
/// so the counter survives power loss (a restored older *snapshot* is not
/// detectable by the counter alone — that is what the hardware-counter binding
/// in task 6.7a and the enrollment-epoch bump cover).
#[derive(Debug)]
pub struct SoftwareMonotonicCounter {
    conn: Mutex<Connection>,
}

impl SoftwareMonotonicCounter {
    /// Open (or create) the counter database at `path`, seeding it with
    /// `initial` on first boot.
    pub fn open(path: impl AsRef<Path>, initial: u64) -> Result<Self, TirBaseError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| TirBaseError::LocalStoreWriteFailed {
                    reason: format!(
                        "create monotonic counter directory {}: {error}",
                        parent.display()
                    ),
                })?;
            }
        }

        let conn = Connection::open(path).map_err(|e| db_error("open", e))?;

        // Durability: WAL + synchronous=FULL (CLAIM-6.5).  `pragma_update`
        // fails loudly if SQLite rejects either setting.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| db_error("set journal_mode=WAL", e))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| db_error("set synchronous=FULL", e))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS monotonic_counter (
                 id    INTEGER PRIMARY KEY CHECK (id = 1),
                 value INTEGER NOT NULL
             );",
        )
        .map_err(|e| db_error("create monotonic_counter table", e))?;

        conn.execute(
            "INSERT OR IGNORE INTO monotonic_counter (id, value) VALUES (1, ?1)",
            params![to_i64(initial)?],
        )
        .map_err(|e| db_error("seed monotonic_counter", e))?;

        Ok(SoftwareMonotonicCounter {
            conn: Mutex::new(conn),
        })
    }

    /// The effective `PRAGMA synchronous` value (2 = FULL).  Exposed for the
    /// wiring-mutation test for CLAIM-6.5.
    #[cfg(test)]
    pub fn synchronous_pragma(&self) -> Result<i64, TirBaseError> {
        self.with_conn(|conn| {
            conn.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                .map_err(|e| db_error("read PRAGMA synchronous", e))
        })
    }

    /// The effective `PRAGMA journal_mode` value (expected: `"wal"`).
    #[cfg(test)]
    pub fn journal_mode_pragma(&self) -> Result<String, TirBaseError> {
        self.with_conn(|conn| {
            conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .map_err(|e| db_error("read PRAGMA journal_mode", e))
        })
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T, TirBaseError>,
    ) -> Result<T, TirBaseError> {
        let mut conn = match self.conn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut conn)
    }
}

fn to_i64(value: u64) -> Result<i64, TirBaseError> {
    i64::try_from(value).map_err(|_| TirBaseError::LocalStoreWriteFailed {
        reason: format!("monotonic counter value {value} exceeds i64::MAX"),
    })
}

fn from_i64(value: i64) -> Result<u64, TirBaseError> {
    u64::try_from(value).map_err(|_| TirBaseError::LocalStoreWriteFailed {
        reason: format!("monotonic counter stored negative value {value}"),
    })
}

impl MonotonicCounterTrait for SoftwareMonotonicCounter {
    fn read(&self) -> Result<u64, TirBaseError> {
        self.with_conn(|conn| {
            let value: i64 = conn
                .query_row("SELECT value FROM monotonic_counter WHERE id = 1", [], |row| {
                    row.get(0)
                })
                .map_err(|e| db_error("read", e))?;
            from_i64(value)
        })
    }

    fn increment(&self) -> Result<u64, TirBaseError> {
        self.with_conn(|conn| {
            let tx = conn.transaction().map_err(|e| db_error("begin increment", e))?;
            let current: i64 = tx
                .query_row("SELECT value FROM monotonic_counter WHERE id = 1", [], |row| {
                    row.get(0)
                })
                .map_err(|e| db_error("read for increment", e))?;
            let next = from_i64(current)?.checked_add(1).ok_or_else(|| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: "monotonic counter overflow".to_string(),
                }
            })?;
            tx.execute(
                "UPDATE monotonic_counter SET value = ?1 WHERE id = 1",
                params![to_i64(next)?],
            )
            .map_err(|e| db_error("increment", e))?;
            // Commit under synchronous=FULL: fsynced before returning.
            tx.commit().map_err(|e| db_error("commit increment", e))?;
            Ok(next)
        })
    }

    fn set_if_greater(&self, value: u64) -> Result<u64, TirBaseError> {
        self.with_conn(|conn| {
            let tx = conn.transaction().map_err(|e| db_error("begin set_if_greater", e))?;
            let current: i64 = tx
                .query_row("SELECT value FROM monotonic_counter WHERE id = 1", [], |row| {
                    row.get(0)
                })
                .map_err(|e| db_error("read for set_if_greater", e))?;
            let current = from_i64(current)?;
            let stored = if value > current {
                tx.execute(
                    "UPDATE monotonic_counter SET value = ?1 WHERE id = 1",
                    params![to_i64(value)?],
                )
                .map_err(|e| db_error("set_if_greater", e))?;
                value
            } else {
                current
            };
            tx.commit().map_err(|e| db_error("commit set_if_greater", e))?;
            Ok(stored)
        })
    }

    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::Level1
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Hardware counters
// ═════════════════════════════════════════════════════════════════════════════

/// Placeholder for deployments with no hardware counter.
///
/// Reports Level 1 so the boot binding knows there is no NV counter to write.
#[cfg(not(feature = "tpm2"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct NullHardwareCounter;

#[cfg(not(feature = "tpm2"))]
fn unavailable(provider: &str) -> TirBaseError {
    TirBaseError::KeyProviderUnavailable {
        provider: provider.to_string(),
        reason: "no hardware monotonic counter is configured on this device".to_string(),
    }
}

#[cfg(not(feature = "tpm2"))]
impl MonotonicCounterTrait for NullHardwareCounter {
    fn read(&self) -> Result<u64, TirBaseError> {
        Ok(0)
    }

    fn increment(&self) -> Result<u64, TirBaseError> {
        Err(unavailable("null-hardware-counter"))
    }

    fn set_if_greater(&self, _value: u64) -> Result<u64, TirBaseError> {
        Err(unavailable("null-hardware-counter"))
    }

    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::Level1
    }
}

/// In-memory stand-in used only when `TIRBASE_SIMULATED_HW_COUNTER` is set.
///
/// This is the fault-injection hook the gateway integration test uses to
/// simulate a device whose NV counter advanced while the software counter was
/// rolled back (CLAIM-6.7a, scenario S22).  It reports Level 2 so the boot
/// comparison and checkpoint write paths run, but it is **not** durable and
/// must never be used in production.
#[derive(Debug)]
pub struct SimulatedHardwareCounter {
    value: AtomicU64,
}

impl SimulatedHardwareCounter {
    /// Construct with an initial simulated NV value.
    pub fn new(initial: u64) -> Self {
        SimulatedHardwareCounter {
            value: AtomicU64::new(initial),
        }
    }
}

impl MonotonicCounterTrait for SimulatedHardwareCounter {
    fn read(&self) -> Result<u64, TirBaseError> {
        Ok(self.value.load(Ordering::SeqCst))
    }

    fn increment(&self) -> Result<u64, TirBaseError> {
        Ok(self.value.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn set_if_greater(&self, value: u64) -> Result<u64, TirBaseError> {
        let mut current = self.value.load(Ordering::SeqCst);
        loop {
            if value <= current {
                return Ok(current);
            }
            match self.value.compare_exchange(
                current,
                value,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(value),
                Err(observed) => current = observed,
            }
        }
    }

    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::Level2
    }
}

/// Select the hardware counter for this deployment.
///
/// Priority:
/// 1. `TIRBASE_SIMULATED_HW_COUNTER` — explicit fault-injection/test mode.
/// 2. `feature = "tpm2"` — TPM2 NV counter (Level 2).
/// 3. otherwise [`NullHardwareCounter`] (Level 1: no NV counter).
pub fn default_hardware_counter() -> Arc<dyn MonotonicCounterTrait> {
    if let Ok(raw) = std::env::var("TIRBASE_SIMULATED_HW_COUNTER") {
        if let Ok(value) = raw.trim().parse::<u64>() {
            return Arc::new(SimulatedHardwareCounter::new(value));
        }
    }

    #[cfg(feature = "tpm2")]
    {
        return Arc::new(Tpm2MonotonicCounter::new(0x0150_0002));
    }

    #[cfg(not(feature = "tpm2"))]
    {
        Arc::new(NullHardwareCounter)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// TPM2 / RPMB counter — stub (task 6.6, CLAIM-6.6, PV-9.8, RD-2)
// ═════════════════════════════════════════════════════════════════════════════

/// Level 2 monotonic counter backed by a TPM2 NV index or eMMC RPMB — stub.
///
/// # NV-endurance wear-leveling (design note)
///
/// TPM2 NV indices are rated for roughly 512k write cycles.  Incrementing the
/// NV counter on every command would exhaust that budget in weeks on a busy
/// gateway.  The design therefore binds the **software** counter to the NV
/// counter only at checkpoint cadence:
///
/// ```text
/// hw_counter_value            -- last value written to NV
/// sw_counter_at_last_hw_write -- software counter when NV was last written
/// sw_increment_per_hw_write   -- how far the software counter may advance
///                                before the next NV write (default 1000)
/// ```
///
/// [`crate::hw_counter_binding::HardwareCounterBinding`] performs the write only
/// when `sw_counter - sw_counter_at_last_hw_write >= sw_increment_per_hw_write`.
/// At boot, `hw_counter_value > sw_counter_at_last_hw_write` means the software
/// counter was reset while the hardware counter advanced: a rollback.
#[cfg(feature = "tpm2")]
#[derive(Debug, Clone, Copy)]
pub struct Tpm2MonotonicCounter {
    nv_index: u32,
}

#[cfg(feature = "tpm2")]
impl Tpm2MonotonicCounter {
    /// Address the given TPM2 NV index (or RPMB counter slot).
    pub fn new(nv_index: u32) -> Self {
        Tpm2MonotonicCounter { nv_index }
    }

    /// The NV index this counter would use.
    #[cfg(test)]
    pub fn nv_index(&self) -> u32 {
        self.nv_index
    }
}

#[cfg(feature = "tpm2")]
impl MonotonicCounterTrait for Tpm2MonotonicCounter {
    fn read(&self) -> Result<u64, TirBaseError> {
        Err(TirBaseError::KeyProviderUnavailable {
            provider: "tpm2".to_string(),
            reason: format!(
                "Tpm2MonotonicCounter is a compile-time stub; NV index {:#010x} is not readable yet",
                self.nv_index
            ),
        })
    }

    fn increment(&self) -> Result<u64, TirBaseError> {
        Err(TirBaseError::KeyProviderUnavailable {
            provider: "tpm2".to_string(),
            reason: "Tpm2MonotonicCounter is a compile-time stub".to_string(),
        })
    }

    fn set_if_greater(&self, _value: u64) -> Result<u64, TirBaseError> {
        Err(TirBaseError::KeyProviderUnavailable {
            provider: "tpm2".to_string(),
            reason: "Tpm2MonotonicCounter is a compile-time stub".to_string(),
        })
    }

    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::Level2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tirbase-monotonic-{tag}-{}-{unique}.db",
            std::process::id()
        ))
    }

    #[test]
    fn counter_increments_and_reports_new_value() {
        let path = temp_db("increment");
        let counter = SoftwareMonotonicCounter::open(&path, 0).expect("open counter");

        assert_eq!(MonotonicCounterTrait::read(&counter).unwrap(), 0);
        assert_eq!(counter.increment().unwrap(), 1);
        assert_eq!(counter.increment().unwrap(), 2);
        assert_eq!(counter.read().unwrap(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_if_greater_never_moves_backwards() {
        let path = temp_db("set-if-greater");
        let counter = SoftwareMonotonicCounter::open(&path, 10).expect("open counter");

        assert_eq!(counter.set_if_greater(7).unwrap(), 10);
        assert_eq!(counter.read().unwrap(), 10);

        assert_eq!(counter.set_if_greater(25).unwrap(), 25);
        assert_eq!(counter.read().unwrap(), 25);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn counter_survives_reopen() {
        let path = temp_db("durable");
        {
            let counter = SoftwareMonotonicCounter::open(&path, 0).expect("open counter");
            counter.increment().unwrap();
            counter.increment().unwrap();
        }

        let reopened = SoftwareMonotonicCounter::open(&path, 0).expect("reopen counter");
        assert_eq!(reopened.read().unwrap(), 2, "Level 1 counter is durable");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn software_counter_uses_sqlite_wal_with_synchronous_full() {
        let path = temp_db("pragmas");
        let counter = SoftwareMonotonicCounter::open(&path, 0).expect("open counter");

        assert_eq!(
            counter.journal_mode_pragma().unwrap().to_lowercase(),
            "wal",
            "Level 1 counter must use WAL (CLAIM-6.5)"
        );
        assert_eq!(
            counter.synchronous_pragma().unwrap(),
            2,
            "Level 1 counter must set PRAGMA synchronous=FULL (CLAIM-6.5)"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn assurance_level_is_level1() {
        let path = temp_db("level1");
        let counter = SoftwareMonotonicCounter::open(&path, 0).expect("open counter");
        assert_eq!(counter.assurance_level(), AssuranceLevel::Level1);
        assert_eq!(counter.assurance_level().as_str(), "Level1");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn simulated_hardware_counter_reports_level2_and_is_monotonic() {
        let counter = SimulatedHardwareCounter::new(41);
        assert_eq!(counter.assurance_level(), AssuranceLevel::Level2);
        assert_eq!(counter.read().unwrap(), 41);
        assert_eq!(counter.set_if_greater(40).unwrap(), 41);
        assert_eq!(counter.set_if_greater(42).unwrap(), 42);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tpm2_counter_stub_reports_level2_and_fails_closed() {
        let counter = Tpm2MonotonicCounter::new(0x0150_0002);
        assert_eq!(counter.assurance_level(), AssuranceLevel::Level2);
        assert_eq!(counter.nv_index(), 0x0150_0002);
        assert!(counter.read().is_err());
    }
}
