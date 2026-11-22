// SPDX-License-Identifier: AGPL-3.0-only

//! Connection health, bounded reconnect backoff and stale-point events.

use crate::ids::PointId;
use crate::point::Protocol;

/// Bounded exponential reconnect policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackoffPolicy {
    pub base_delay_us: i64,
    pub max_delay_us: i64,
    /// Maximum number of consecutive retries before giving up.
    pub max_attempts: u32,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base_delay_us: 1_000_000,
            max_delay_us: 60_000_000,
            max_attempts: 8,
        }
    }
}

impl BackoffPolicy {
    pub fn new(
        base_delay_us: i64,
        max_delay_us: i64,
        max_attempts: u32,
    ) -> Result<Self, crate::error::GatewayError> {
        if base_delay_us <= 0 || max_delay_us < base_delay_us || max_attempts == 0 {
            return Err(crate::error::GatewayError::InvalidConfig(
                "backoff requires base > 0, max >= base and max_attempts > 0",
            ));
        }
        Ok(Self {
            base_delay_us,
            max_delay_us,
            max_attempts,
        })
    }

    /// Deterministic delay for a 1-based attempt number.
    pub fn delay_for_attempt(&self, attempt: u32) -> i64 {
        let shift = attempt.saturating_sub(1).min(62);
        let factor = 1i64.checked_shl(shift).unwrap_or(i64::MAX);
        self.base_delay_us
            .saturating_mul(factor)
            .min(self.max_delay_us)
    }
}

/// Health events raised by the gateway.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum HealthEvent {
    Connected {
        protocol: Protocol,
    },
    ReconnectScheduled {
        protocol: Protocol,
        attempt: u32,
        retry_at_utc_us: i64,
    },
    ReconnectExhausted {
        protocol: Protocol,
        attempts: u32,
    },
    PointStale {
        point_id: PointId,
        last_seen_utc_us: i64,
        stale_after_us: i64,
    },
    PointRecovered {
        point_id: PointId,
        last_seen_utc_us: i64,
    },
}

/// A health event with the time it was raised.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HealthEventRecord {
    pub at_utc_us: i64,
    pub event: HealthEvent,
}

impl HealthEventRecord {
    pub fn new(at_utc_us: i64, event: HealthEvent) -> Self {
        Self { at_utc_us, event }
    }
}

/// Reconnect state for one protocol link.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConnectionSupervisor {
    policy: BackoffPolicy,
    protocol: Protocol,
    connected: bool,
    failures: u32,
    next_retry_at_utc_us: Option<i64>,
    exhausted: bool,
}

impl ConnectionSupervisor {
    pub fn new(protocol: Protocol, policy: BackoffPolicy) -> Self {
        Self {
            policy,
            protocol,
            connected: false,
            failures: 0,
            next_retry_at_utc_us: None,
            exhausted: false,
        }
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn policy(&self) -> BackoffPolicy {
        self.policy
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn next_retry_at_utc_us(&self) -> Option<i64> {
        self.next_retry_at_utc_us
    }

    /// Mark the link up. Emits `Connected` when recovering.
    pub fn connected(&mut self) -> Option<HealthEvent> {
        let recovered = !self.connected || self.failures > 0 || self.exhausted;
        self.connected = true;
        self.failures = 0;
        self.next_retry_at_utc_us = None;
        self.exhausted = false;
        recovered.then_some(HealthEvent::Connected {
            protocol: self.protocol,
        })
    }

    /// Record a failed connection attempt and schedule a bounded retry.
    pub fn disconnected(&mut self, now_utc_us: i64) -> HealthEvent {
        if self.connected {
            self.connected = false;
            self.failures = 0;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures > self.policy.max_attempts {
            self.exhausted = true;
            self.next_retry_at_utc_us = None;
            return HealthEvent::ReconnectExhausted {
                protocol: self.protocol,
                attempts: self.policy.max_attempts,
            };
        }
        let delay = self.policy.delay_for_attempt(self.failures);
        let retry_at = now_utc_us.saturating_add(delay);
        self.next_retry_at_utc_us = Some(retry_at);
        HealthEvent::ReconnectScheduled {
            protocol: self.protocol,
            attempt: self.failures,
            retry_at_utc_us: retry_at,
        }
    }

    /// True when the scheduled retry is due.
    pub fn retry_due(&self, now_utc_us: i64) -> bool {
        !self.connected
            && !self.exhausted
            && self
                .next_retry_at_utc_us
                .map(|retry_at| now_utc_us >= retry_at)
                .unwrap_or(false)
    }

    /// Consume the scheduled retry slot before attempting to connect.
    pub fn start_retry(&mut self) {
        self.next_retry_at_utc_us = None;
    }
}
