//! Software-backed monotonic counter for the gateway binary
//! (PV-9.8, CLAIM-5.3).
//!
//! Implements [`MonotonicCounterTrait`] at assurance **Level 1**: an in-memory
//! atomic counter.  Task 6.5 replaces the storage with SQLite WAL +
//! `synchronous=FULL`, and task 6.6 adds the Level 2 TPM2/RPMB backend.  The
//! gateway reports the level in the boot diagnostic either way.

use std::sync::atomic::{AtomicU64, Ordering};

use tirbase_core::errors::TirBaseError;
use tirbase_core::traits::{AssuranceLevel, MonotonicCounterTrait};

/// Software-backed monotonic counter (no TPM / secure element required).
///
/// This is assurance **Level 1**: backed by an in-memory atomic integer.
/// A durable SQLite WAL backing store will be added in task 6.5 (CLAIM-6.5).
#[derive(Debug)]
pub struct SoftwareMonotonicCounter {
    inner: AtomicU64,
}

impl SoftwareMonotonicCounter {
    /// Construct a new counter initialised to `initial`.
    pub fn new(initial: u64) -> Self {
        SoftwareMonotonicCounter {
            inner: AtomicU64::new(initial),
        }
    }
}

impl MonotonicCounterTrait for SoftwareMonotonicCounter {
    fn read(&self) -> Result<u64, TirBaseError> {
        Ok(self.inner.load(Ordering::SeqCst))
    }

    fn increment(&self) -> Result<u64, TirBaseError> {
        Ok(self.inner.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn set_if_greater(&self, value: u64) -> Result<u64, TirBaseError> {
        let mut current = self.inner.load(Ordering::SeqCst);
        loop {
            if value <= current {
                return Ok(current);
            }
            match self.inner.compare_exchange(
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
        AssuranceLevel::Level1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments_and_reports_new_value() {
        let counter = SoftwareMonotonicCounter::new(0);

        assert_eq!(MonotonicCounterTrait::read(&counter).unwrap(), 0);
        assert_eq!(counter.increment().unwrap(), 1);
        assert_eq!(counter.increment().unwrap(), 2);
        assert_eq!(counter.read().unwrap(), 2);
    }

    #[test]
    fn set_if_greater_never_moves_backwards() {
        let counter = SoftwareMonotonicCounter::new(10);

        assert_eq!(counter.set_if_greater(7).unwrap(), 10);
        assert_eq!(counter.read().unwrap(), 10);

        assert_eq!(counter.set_if_greater(25).unwrap(), 25);
        assert_eq!(counter.read().unwrap(), 25);
    }

    #[test]
    fn assurance_level_is_level1() {
        let counter = SoftwareMonotonicCounter::new(0);
        assert_eq!(counter.assurance_level(), AssuranceLevel::Level1);
        assert_eq!(counter.assurance_level().as_str(), "Level1");
    }
}
