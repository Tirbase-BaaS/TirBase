//! Scenario S22 — snapshot restore attack (PV-9.8).
//!
//! Restoring an old database silently rolls back the software counter and
//! enrollment epoch.  Two production controls must catch it:
//!
//! 1. `HardwareCounterBinding::check_at_boot` compares the hardware counter
//!    against the software value recorded at the last hardware write and
//!    persists LOCKDOWN on regression.
//! 2. `EpochRegistry::restore_bump` advances the enrollment epoch so all
//!    prior-epoch commands are rejected; peers that observe the older epoch
//!    emit `EpochRegression`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tirbase_core::errors::TirBaseError;
use tirbase_core::traits::{AssuranceLevel, MonotonicCounterTrait};
use tirbase_gateway::hw_counter_binding::{keys, BootCheck, HardwareCounterBinding};
use tirbase_guard::epoch::{EpochError, EpochRegistry, InMemoryEpochStore};

#[derive(Debug)]
struct MemCounter(AtomicU64);

impl MonotonicCounterTrait for MemCounter {
    fn read(&self) -> Result<u64, TirBaseError> {
        Ok(self.0.load(Ordering::SeqCst))
    }

    fn increment(&self) -> Result<u64, TirBaseError> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn set_if_greater(&self, value: u64) -> Result<u64, TirBaseError> {
        let current = self.0.load(Ordering::SeqCst);
        if value > current {
            self.0.store(value, Ordering::SeqCst);
            Ok(value)
        } else {
            Ok(current)
        }
    }

    fn assurance_level(&self) -> AssuranceLevel {
        AssuranceLevel::Level1
    }
}

fn set_key(connection: &rusqlite::Connection, key: &str, value: i64) -> Result<(), String> {
    connection
        .execute(
            &format!(
                "INSERT OR REPLACE INTO {} (key, value) VALUES (?1, ?2)",
                tirbase_gateway::hw_counter_binding::MONOTONIC_COUNTERS_TABLE
            ),
            rusqlite::params![key, value],
        )
        .map_err(|error| format!("S22 set {key}: {error}"))?;
    Ok(())
}

/// S22 — rollback is detected at boot and prior-epoch commands are rejected.
pub fn run_s22(seed: u64) -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("tirbase-sim-s22-{}-{seed}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|error| format!("S22 tempdir: {error}"))?;
    let db_path = dir.join("primary.db");
    let result = run_s22_inner(seed, &db_path);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn run_s22_inner(seed: u64, db_path: &std::path::Path) -> Result<(), String> {
    let hw_value = 900 + seed % 50;
    let binding = HardwareCounterBinding::open(
        db_path,
        Arc::new(MemCounter(AtomicU64::new(hw_value))),
        1_000,
    )
    .map_err(|error| format!("S22 open binding: {error}"))?;

    // Simulate a restored backup: the database says the last hardware write
    // happened at a much lower software value than the hardware counter.
    let connection =
        rusqlite::Connection::open(db_path).map_err(|error| format!("S22 open db: {error}"))?;
    set_key(
        &connection,
        keys::SW_COUNTER_AT_LAST_HW_WRITE,
        (hw_value.saturating_sub(400)) as i64,
    )?;
    set_key(&connection, keys::HW_COUNTER_VALUE, hw_value as i64)?;

    match binding
        .check_at_boot()
        .map_err(|error| format!("S22 boot check: {error}"))?
    {
        BootCheck::Regression {
            hw_counter,
            sw_counter_at_last_hw_write,
        } => {
            if hw_counter != hw_value || sw_counter_at_last_hw_write >= hw_counter {
                return Err(format!(
                    "S22 FAIL: regression values wrong hw={hw_counter} sw={sw_counter_at_last_hw_write}"
                ));
            }
        }
        BootCheck::Consistent => {
            return Err("S22 FAIL: restored snapshot was accepted at boot".to_string())
        }
    }

    let lockdown: i64 = connection
        .query_row(
            &format!(
                "SELECT value FROM {} WHERE key = ?1",
                tirbase_gateway::hw_counter_binding::MONOTONIC_COUNTERS_TABLE
            ),
            rusqlite::params![keys::LOCKDOWN_STATE],
            |row| row.get(0),
        )
        .map_err(|error| format!("S22 lockdown read: {error}"))?;
    if lockdown != 1 {
        return Err("S22 FAIL: LOCKDOWN was not persisted after regression".to_string());
    }

    // Enrollment epoch bump invalidates every command produced before restore.
    let epochs = EpochRegistry::new(Arc::new(InMemoryEpochStore::default()));
    epochs
        .ensure_enrolled("dev1", 1_000)
        .map_err(|error| format!("S22 enroll: {error:?}"))?;
    let bumped = epochs
        .restore_bump("dev1", "snapshot restore", 2_000)
        .map_err(|error| format!("S22 epoch bump: {error:?}"))?;
    if bumped.epoch != 1 {
        return Err(format!(
            "S22 FAIL: epoch is {} after restore bump",
            bumped.epoch
        ));
    }
    match epochs.check_command_epoch("dev1", 0) {
        Err(EpochError::StaleEpoch { .. }) => {}
        other => {
            return Err(format!(
                "S22 FAIL: prior-epoch command not rejected with StaleEpoch: {other:?}"
            ))
        }
    }

    // A peer that witnessed the pre-restore epoch detects the regression.
    epochs
        .observe_epoch("dev1", 5)
        .map_err(|error| format!("S22 observe high epoch: {error:?}"))?;
    match epochs.observe_epoch("dev1", 2) {
        Err(EpochError::EpochRegression {
            witnessed,
            reported,
            ..
        }) => {
            if witnessed != 5 || reported != 2 {
                return Err(format!(
                    "S22 FAIL: regression reported witnessed={witnessed} reported={reported}"
                ));
            }
        }
        other => {
            return Err(format!(
                "S22 FAIL: peer did not detect epoch regression: {other:?}"
            ))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s22_snapshot_restore_detected() {
        run_s22(1).expect("S22");
    }
}
