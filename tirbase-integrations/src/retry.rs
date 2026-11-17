// SPDX-License-Identifier: Apache-2.0

//! Retry arithmetic.
//!
//! Delays are computed deterministically from the number of failed attempts, so
//! a restarted process schedules the same next attempt as the one that died. No
//! clock and no random source is read here; the engine supplies the instant.

/// Bounded exponential backoff policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts allowed before a record is dead-lettered. At least 1.
    pub max_attempts: u32,
    /// Delay after the first failure, in seconds.
    pub base_delay_secs: u64,
    /// Multiplier applied per further failure.
    pub factor: u32,
    /// Ceiling on any single delay, in seconds.
    pub max_delay_secs: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay_secs: 5,
            factor: 2,
            max_delay_secs: 300,
        }
    }
}

impl RetryPolicy {
    /// Build a policy, clamping it to a sane shape.
    pub fn new(max_attempts: u32, base_delay_secs: u64, factor: u32, max_delay_secs: u64) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            base_delay_secs: base_delay_secs.max(1),
            factor: factor.max(1),
            max_delay_secs: max_delay_secs.max(1),
        }
    }

    /// Delay to wait after `failures` failed attempts (`failures >= 1`).
    ///
    /// Saturating throughout: a large attempt count returns `max_delay_secs`
    /// instead of overflowing.
    pub fn delay_secs(&self, failures: u32) -> u64 {
        let exponent = failures.saturating_sub(1).min(32);
        let mut delay = self.base_delay_secs;
        for _ in 0..exponent {
            match delay.checked_mul(u64::from(self.factor)) {
                Some(next) => delay = next,
                None => return self.max_delay_secs,
            }
            if delay >= self.max_delay_secs {
                return self.max_delay_secs;
            }
        }
        delay.min(self.max_delay_secs)
    }

    /// Whether another attempt is allowed after `failures` failed attempts.
    pub fn allows_attempt(&self, failures: u32) -> bool {
        failures < self.max_attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded_and_monotonic() {
        let policy = RetryPolicy::new(6, 5, 2, 60);
        let delays: Vec<u64> = (1..=8)
            .map(|failures| policy.delay_secs(failures))
            .collect();
        assert_eq!(delays[0], 5);
        assert_eq!(delays[1], 10);
        assert_eq!(delays[2], 20);
        assert_eq!(delays[3], 40);
        assert_eq!(delays[4], 60);
        assert!(delays.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(delays.iter().all(|delay| *delay <= 60));

        assert!(policy.allows_attempt(5));
        assert!(!policy.allows_attempt(6));
        // Degenerate policies are clamped rather than looping or multiplying by
        // zero.
        let degenerate = RetryPolicy::new(0, 0, 0, 0);
        assert_eq!(degenerate.max_attempts, 1);
        assert_eq!(degenerate.delay_secs(1), 1);
        assert!(!degenerate.allows_attempt(1));
    }
}
