// SPDX-License-Identifier: Apache-2.0

//! Deterministic retry schedule.
//!
//! The runtime persists `attempts` and asks this policy for the delay before the
//! next attempt, so the schedule is reproducible from stored state: the same
//! policy, attempt number and deduplication key always give the same delay. The
//! jitter is derived from the key rather than from a random source for exactly
//! that reason — a restarted runtime must not compute a different deadline than
//! the one it already wrote down.

use sha2::{Digest, Sha256};

/// Bounded exponential backoff with key-derived jitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts before the delivery is dead-lettered.
    pub max_attempts: u32,
    /// First delay, in seconds.
    pub base_secs: i64,
    /// Ceiling for one delay, ignoring jitter.
    pub max_secs: i64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 6,
            base_secs: 15,
            max_secs: 900,
        }
    }
}

impl RetryPolicy {
    /// Validate a policy.
    pub fn new(max_attempts: u32, base_secs: i64, max_secs: i64) -> Result<Self, String> {
        if !(1..=100).contains(&max_attempts) {
            return Err("max_attempts must be between 1 and 100".to_string());
        }
        if base_secs < 1 {
            return Err("base_secs must be at least 1".to_string());
        }
        if max_secs < base_secs {
            return Err("max_secs must not be below base_secs".to_string());
        }
        Ok(Self {
            max_attempts,
            base_secs,
            max_secs,
        })
    }

    /// `true` once `attempts` attempts have already failed.
    pub fn is_exhausted(&self, attempts: u32) -> bool {
        attempts >= self.max_attempts
    }

    /// Delay in seconds before the attempt after `attempts` failures.
    ///
    /// `attempts` is the number of attempts already made (so `1` means "the
    /// first attempt failed"). Attempt zero returns zero delay.
    pub fn delay_secs(&self, attempts: u32, key: &str) -> i64 {
        if attempts == 0 {
            return 0;
        }
        let shift = attempts.saturating_sub(1).min(16);
        let exponential = self.base_secs.saturating_mul(1i64 << shift);
        let capped = exponential.min(self.max_secs);
        capped.saturating_add(self.jitter(attempts, key))
    }

    /// Jitter in `[0, base_secs / 4]`, derived from the key and attempt number.
    fn jitter(&self, attempts: u32, key: &str) -> i64 {
        let bound = (self.base_secs / 4).max(0);
        if bound == 0 {
            return 0;
        }
        let mut hasher = Sha256::new();
        hasher.update(b"TirBase/v1/AlertRetryJitter\0");
        hasher.update(key.as_bytes());
        hasher.update([0u8]);
        hasher.update(attempts.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        (u64::from_le_bytes(bytes) % (bound as u64 + 1)) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_is_deterministic_and_bounded() {
        let policy = RetryPolicy::new(5, 10, 120).expect("policy");
        assert_eq!(policy.delay_secs(0, "k"), 0);
        for attempts in 1..=8 {
            let delay = policy.delay_secs(attempts, "alert-key");
            assert_eq!(delay, policy.delay_secs(attempts, "alert-key"));
            assert!(delay >= 10, "attempt {attempts}: {delay}");
            assert!(delay <= 120 + 10 / 4, "attempt {attempts}: {delay}");
        }
        // Different keys get different jitter, but the exponential part dominates.
        assert!(
            policy.delay_secs(4, "a") >= policy.delay_secs(1, "b"),
            "backoff must grow"
        );
        assert!(policy.is_exhausted(5));
        assert!(!policy.is_exhausted(4));
    }

    #[test]
    fn invalid_policies_are_rejected() {
        assert!(RetryPolicy::new(0, 10, 60).is_err());
        assert!(RetryPolicy::new(101, 10, 60).is_err());
        assert!(RetryPolicy::new(3, 0, 60).is_err());
        assert!(RetryPolicy::new(3, 60, 30).is_err());
    }
}
