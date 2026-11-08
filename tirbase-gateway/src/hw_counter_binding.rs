//! Hardware-counter DB-generation binding (task 6.7a — CLAIM-6.7a, PV-9.8, RD-2).
//!
//! A Level 1 software counter lives in `primary.db` (WAL +
//! `synchronous=FULL`) and is therefore durable, but a *restored older
//! snapshot* rolls it back silently.  The hardware counter (TPM2 NV index or
//! eMMC RPMB) cannot be rolled back by a filesystem restore, so binding the
//! two detects the attack:
//!
//! * At each checkpoint cadence the current software value is written to the
//!   hardware NV counter, but only once the software counter has advanced by
//!   `sw_increment_per_hw_write` since the last NV write (NV wear-leveling).
//! * At boot, if `hw_counter > sw_counter_at_last_hw_write`, the software
//!   counter was reset while the hardware counter advanced.  That is a
//!   rollback: emit [`ReasonCode::MonotonicCounterRegression`] and persist
//!   `lockdown_state` so LOCKDOWN survives the crash/reboot.
//!
//! State lives in the `monotonic_counters` table (a PrimaryLedger):
//!
//! | key                          | meaning                                     |
//! |------------------------------|---------------------------------------------|
//! | `hw_counter_value`           | last value written to the hardware counter  |
//! | `sw_counter_at_last_hw_write`| software value at that write                |
//! | `sw_increment_per_hw_write`  | software advance before the next NV write   |
//! | `lockdown_state`             | `1` once a regression has been detected      |

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};
use tirbase_core::errors::TirBaseError;
use tirbase_core::events::{
    ReasonCode, SecurityEvent, SecurityEventCategory, Severity,
};
use tirbase_core::traits::{AssuranceLevel, MonotonicCounterTrait};

/// Default software-counter advance between hardware NV writes.
///
/// TPM2 NV indices are typically rated for ~512k writes.  Writing every 1,000
/// software increments leaves ample headroom for a multi-year deployment even
/// on a busy gateway.
pub const DEFAULT_SW_INCREMENT_PER_HW_WRITE: u64 = 1_000;

/// Table holding the binding state (also used by task 13.2 for `lockdown_state`).
pub const MONOTONIC_COUNTERS_TABLE: &str = "monotonic_counters";

/// Keys used in [`MONOTONIC_COUNTERS_TABLE`].
pub mod keys {
    /// Last value written to the hardware NV counter.
    pub const HW_COUNTER_VALUE: &str = "hw_counter_value";
    /// Software counter value at the last hardware write.
    pub const SW_COUNTER_AT_LAST_HW_WRITE: &str = "sw_counter_at_last_hw_write";
    /// Software-counter advance required before the next hardware write.
    pub const SW_INCREMENT_PER_HW_WRITE: &str = "sw_increment_per_hw_write";
    /// `1` after a rollback has been detected.
    pub const LOCKDOWN_STATE: &str = "lockdown_state";
}

/// Result of the boot comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootCheck {
    /// Hardware and software counters agree (or there is no hardware counter).
    Consistent,
    /// Hardware counter is ahead of the software counter: rollback detected and
    /// LOCKDOWN persisted.
    Regression {
        /// Value read from the hardware NV counter.
        hw_counter: u64,
        /// Software value recorded at the last hardware write.
        sw_counter_at_last_hw_write: u64,
    },
}

impl BootCheck {
    /// True when a rollback was detected.
    #[cfg(test)]
    pub fn is_regression(&self) -> bool {
        matches!(self, BootCheck::Regression { .. })
    }
}

fn db_error(context: &str, error: rusqlite::Error) -> TirBaseError {
    TirBaseError::LocalStoreWriteFailed {
        reason: format!("hardware counter binding {context}: {error}"),
    }
}

fn checked_u64(value: i64) -> Result<u64, TirBaseError> {
    u64::try_from(value).map_err(|_| TirBaseError::LocalStoreWriteFailed {
        reason: format!("hardware counter binding stored negative value {value}"),
    })
}

/// Binds the software monotonic counter to a hardware NV counter.
#[derive(Debug)]
pub struct HardwareCounterBinding {
    conn: Mutex<Connection>,
    hardware: Arc<dyn MonotonicCounterTrait>,
}

impl HardwareCounterBinding {
    /// Open the binding state in the counter database at `db_path`.
    ///
    /// `hardware` normally comes from
    /// [`crate::monotonic_counter::default_hardware_counter`].
    pub fn open(
        db_path: impl AsRef<Path>,
        hardware: Arc<dyn MonotonicCounterTrait>,
        sw_increment_per_hw_write: u64,
    ) -> Result<Self, TirBaseError> {
        let db_path = db_path.as_ref();
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!(
                            "create hardware counter directory {}: {error}",
                            parent.display()
                        ),
                    }
                })?;
            }
        }

        let conn = Connection::open(db_path).map_err(|e| db_error("open", e))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| db_error("set journal_mode=WAL", e))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| db_error("set synchronous=FULL", e))?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {MONOTONIC_COUNTERS_TABLE} (
                 key   TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );"
        ))
        .map_err(|e| db_error("create monotonic_counters table", e))?;

        let binding = HardwareCounterBinding {
            conn: Mutex::new(conn),
            hardware,
        };

        // Record the wear-leveling threshold once, on first open.
        if binding.read_value(keys::SW_INCREMENT_PER_HW_WRITE)?.is_none() {
            binding.write_value(
                keys::SW_INCREMENT_PER_HW_WRITE,
                sw_increment_per_hw_write.max(1),
            )?;
        }

        Ok(binding)
    }

    /// The hardware counter this binding writes to.
    pub fn hardware(&self) -> &Arc<dyn MonotonicCounterTrait> {
        &self.hardware
    }

    /// Compare the hardware counter with the software value recorded at the
    /// last hardware write.
    ///
    /// A regression persists `lockdown_state = 1` and emits a Critical
    /// `MonotonicCounterRegression` security event before returning.
    pub fn check_at_boot(&self) -> Result<BootCheck, TirBaseError> {
        let device_hw = self.hardware.read()?;
        let persisted_hw = self
            .read_value(keys::HW_COUNTER_VALUE)?
            .unwrap_or_default();
        // Use the higher of the live device value and the last persisted value:
        // a restore can drag the DB (and therefore the persisted value) back.
        let hw_counter = device_hw.max(persisted_hw);
        let sw_counter_at_last_hw_write = self
            .read_value(keys::SW_COUNTER_AT_LAST_HW_WRITE)?
            .unwrap_or_default();

        if hw_counter > sw_counter_at_last_hw_write {
            self.write_value(keys::LOCKDOWN_STATE, 1)?;
            tirbase_core::events::emit(
                SecurityEvent::new(
                    SecurityEventCategory::MonotonicCounter,
                    Severity::Critical,
                    ReasonCode::MonotonicCounterRegression,
                )
                .with_detail(format!(
                    "hardware counter {hw_counter} is ahead of software counter \
                     {sw_counter_at_last_hw_write} recorded at the last hardware write; \
                     device rollback detected, entering LOCKDOWN"
                )),
            );
            return Ok(BootCheck::Regression {
                hw_counter,
                sw_counter_at_last_hw_write,
            });
        }

        Ok(BootCheck::Consistent)
    }

    /// Write the software counter to the hardware counter at checkpoint
    /// cadence, subject to the wear-leveling threshold.
    ///
    /// Returns `true` when a hardware write happened.  Level 1 deployments (no
    /// hardware counter) only record the software value.
    pub fn record_checkpoint(&self, sw_counter_value: u64) -> Result<bool, TirBaseError> {
        let increment = self
            .read_value(keys::SW_INCREMENT_PER_HW_WRITE)?
            .unwrap_or(DEFAULT_SW_INCREMENT_PER_HW_WRITE)
            .max(1);
        let last = self
            .read_value(keys::SW_COUNTER_AT_LAST_HW_WRITE)?
            .unwrap_or_default();

        if sw_counter_value.saturating_sub(last) < increment {
            return Ok(false);
        }

        let hw_value = if self.hardware.assurance_level() >= AssuranceLevel::Level2 {
            self.hardware.set_if_greater(sw_counter_value)?
        } else {
            sw_counter_value
        };

        self.write_value(keys::HW_COUNTER_VALUE, hw_value)?;
        self.write_value(keys::SW_COUNTER_AT_LAST_HW_WRITE, sw_counter_value)?;
        Ok(true)
    }

    /// True once a rollback has been detected (LOCKDOWN is persisted).
    pub fn is_lockdown(&self) -> Result<bool, TirBaseError> {
        Ok(self.read_value(keys::LOCKDOWN_STATE)?.unwrap_or_default() == 1)
    }

    /// Read a binding value by key.
    pub fn read_value(&self, key: &str) -> Result<Option<u64>, TirBaseError> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT value FROM {MONOTONIC_COUNTERS_TABLE} WHERE key = ?1"
            ))
            .map_err(|e| db_error("prepare read", e))?;
        let mut rows = stmt
            .query(params![key])
            .map_err(|e| db_error("read value", e))?;
        match rows.next().map_err(|e| db_error("read row", e))? {
            Some(row) => {
                let value: i64 = row.get(0).map_err(|e| db_error("read column", e))?;
                Ok(Some(checked_u64(value)?))
            }
            None => Ok(None),
        }
    }

    /// Upsert a binding value.
    pub fn write_value(&self, key: &str, value: u64) -> Result<(), TirBaseError> {
        let value = i64::try_from(value).map_err(|_| TirBaseError::LocalStoreWriteFailed {
            reason: format!("hardware counter binding value {value} exceeds i64::MAX"),
        })?;
        let conn = self.lock();
        conn.execute(
            &format!(
                "INSERT INTO {MONOTONIC_COUNTERS_TABLE} (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            ),
            params![key, value],
        )
        .map_err(|e| db_error("write value", e))?;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// Level 2 fake hardware counter that counts NV writes.
    #[derive(Debug, Default)]
    struct FakeHardwareCounter {
        value: AtomicU64,
        writes: AtomicUsize,
    }

    impl FakeHardwareCounter {
        fn new(value: u64) -> Self {
            FakeHardwareCounter {
                value: AtomicU64::new(value),
                writes: AtomicUsize::new(0),
            }
        }

        fn writes(&self) -> usize {
            self.writes.load(Ordering::SeqCst)
        }
    }

    impl MonotonicCounterTrait for FakeHardwareCounter {
        fn read(&self) -> Result<u64, TirBaseError> {
            Ok(self.value.load(Ordering::SeqCst))
        }

        fn increment(&self) -> Result<u64, TirBaseError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(self.value.fetch_add(1, Ordering::SeqCst) + 1)
        }

        fn set_if_greater(&self, value: u64) -> Result<u64, TirBaseError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
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

    fn temp_db(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::AtomicU64 as Seq;
        static COUNTER: Seq = Seq::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tirbase-hw-binding-{tag}-{}-{unique}.db",
            std::process::id()
        ))
    }

    fn open(db: &Path, hw: Arc<FakeHardwareCounter>, increment: u64) -> HardwareCounterBinding {
        HardwareCounterBinding::open(db, hw as Arc<dyn MonotonicCounterTrait>, increment)
            .expect("open binding")
    }

    #[test]
    fn fresh_device_is_consistent() {
        let db = temp_db("fresh");
        let binding = open(&db, Arc::new(FakeHardwareCounter::new(0)), 1_000);

        assert_eq!(binding.check_at_boot().unwrap(), BootCheck::Consistent);
        assert!(!binding.is_lockdown().unwrap());
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn hardware_ahead_of_software_is_a_rollback_and_enters_lockdown() {
        let db = temp_db("rollback");
        // Pretend the software counter was reset: 100 recorded at the last NV
        // write, but the NV counter has advanced to 900.
        let binding = open(&db, Arc::new(FakeHardwareCounter::new(900)), 1_000);
        binding
            .write_value(keys::HW_COUNTER_VALUE, 100)
            .unwrap();
        binding
            .write_value(keys::SW_COUNTER_AT_LAST_HW_WRITE, 100)
            .unwrap();

        let check = binding.check_at_boot().unwrap();
        assert!(check.is_regression(), "expected rollback detection");
        assert_eq!(
            check,
            BootCheck::Regression {
                hw_counter: 900,
                sw_counter_at_last_hw_write: 100
            }
        );
        assert!(
            binding.is_lockdown().unwrap(),
            "rollback must persist LOCKDOWN state"
        );

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn hardware_equal_to_software_is_not_a_rollback() {
        let db = temp_db("equal");
        let binding = open(&db, Arc::new(FakeHardwareCounter::new(500)), 1_000);
        binding.write_value(keys::HW_COUNTER_VALUE, 500).unwrap();
        binding
            .write_value(keys::SW_COUNTER_AT_LAST_HW_WRITE, 500)
            .unwrap();

        assert_eq!(binding.check_at_boot().unwrap(), BootCheck::Consistent);
        assert!(!binding.is_lockdown().unwrap());
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn checkpoint_writes_only_at_the_wear_leveling_threshold() {
        let db = temp_db("wear");
        let hw = Arc::new(FakeHardwareCounter::new(0));
        let binding = open(&db, hw.clone(), 1_000);

        assert!(!binding.record_checkpoint(500).unwrap());
        assert_eq!(hw.writes(), 0, "no NV write below the threshold");

        assert!(!binding.record_checkpoint(999).unwrap());
        assert_eq!(hw.writes(), 0);

        assert!(binding.record_checkpoint(1_000).unwrap());
        assert_eq!(hw.writes(), 1, "one NV write at the threshold");
        assert_eq!(hw.read().unwrap(), 1_000);
        assert_eq!(
            binding
                .read_value(keys::SW_COUNTER_AT_LAST_HW_WRITE)
                .unwrap(),
            Some(1_000)
        );

        assert!(!binding.record_checkpoint(1_500).unwrap());
        assert_eq!(hw.writes(), 1, "wear leveling suppresses per-command writes");

        assert!(binding.record_checkpoint(2_000).unwrap());
        assert_eq!(hw.writes(), 2);

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn rollback_detection_emits_the_catalogued_security_event() {
        use std::sync::Mutex;

        #[derive(Debug, Default)]
        struct RecordingSink {
            events: Mutex<Vec<SecurityEvent>>,
        }

        impl tirbase_core::traits::SecurityEventSink for RecordingSink {
            fn emit(&self, event: SecurityEvent) {
                self.events.lock().unwrap().push(event);
            }
        }

        let _guard = crate::EVENT_SINK_TEST_LOCK.lock().unwrap();
        let sink = Arc::new(RecordingSink::default());
        let _previous = tirbase_core::events::install_security_event_sink(sink.clone());

        let db = temp_db("event");
        let binding = open(&db, Arc::new(FakeHardwareCounter::new(900)), 1_000);
        binding
            .write_value(keys::SW_COUNTER_AT_LAST_HW_WRITE, 100)
            .unwrap();
        assert!(binding.check_at_boot().unwrap().is_regression());

        let events = sink.events.lock().unwrap();
        assert!(
            events.iter().any(|event| {
                event.reason_code == ReasonCode::MonotonicCounterRegression
                    && event.category == SecurityEventCategory::MonotonicCounter
                    && event.severity == Severity::Critical
            }),
            "rollback must emit MonotonicCounterRegression: {events:?}"
        );

        let _ = std::fs::remove_file(&db);
    }
}
