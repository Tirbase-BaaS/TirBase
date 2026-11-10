//! InboundCaps configuration and enforcement (PV-6.3, task 24.1).
//!
//! Enforces caps on inbound deltas: per-DID rate limits (100 ops/s, burst 500),
//! delta size (1 MiB), op count (1000), batch size (50 changes), heads (20),
//! deps per change (50), traversal budget (10,000 node visits), connections (10).
//! Reject with per-type quarantine reason code.

use crate::events::ReasonCode;

pub const INBOUND_CAP_RATE_OPS_PER_SEC: u64 = 100;
pub const INBOUND_CAP_RATE_BURST: u64 = 500;
pub const INBOUND_CAP_DELTA_SIZE_BYTES: usize = 1024 * 1024; // 1 MiB
pub const INBOUND_CAP_OP_COUNT: u64 = 1000;
pub const INBOUND_CAP_BATCH_CHANGES: usize = 50;
pub const INBOUND_CAP_HEADS: usize = 20;
pub const INBOUND_CAP_DEPS_PER_CHANGE: usize = 50;
pub const INBOUND_CAP_TRAVERSAL_BUDGET: u64 = 10_000;
pub const INBOUND_CAP_CONNECTIONS: usize = 10;

#[derive(Debug, Clone)]
pub struct InboundCaps {
    pub rate_ops_per_sec: u64,
    pub rate_burst: u64,
    pub delta_size_bytes: usize,
    pub op_count: u64,
    pub batch_changes: usize,
    pub heads: usize,
    pub deps_per_change: usize,
    pub traversal_budget: u64,
    pub connections: usize,
}

impl Default for InboundCaps {
    fn default() -> Self {
        Self {
            rate_ops_per_sec: INBOUND_CAP_RATE_OPS_PER_SEC,
            rate_burst: INBOUND_CAP_RATE_BURST,
            delta_size_bytes: INBOUND_CAP_DELTA_SIZE_BYTES,
            op_count: INBOUND_CAP_OP_COUNT,
            batch_changes: INBOUND_CAP_BATCH_CHANGES,
            heads: INBOUND_CAP_HEADS,
            deps_per_change: INBOUND_CAP_DEPS_PER_CHANGE,
            traversal_budget: INBOUND_CAP_TRAVERSAL_BUDGET,
            connections: INBOUND_CAP_CONNECTIONS,
        }
    }
}

impl InboundCaps {
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a cap violation to the corresponding quarantine reason code.
    pub fn quarantine_reason_for_violation(violation: InboundCapViolation) -> ReasonCode {
        match violation {
            InboundCapViolation::RateExceeded => ReasonCode::RateExceeded,
            InboundCapViolation::Oversize => ReasonCode::Oversize,
            InboundCapViolation::OpCountExceeded => ReasonCode::OpCountExceeded,
            InboundCapViolation::BatchExceeded => ReasonCode::BatchExceeded,
            InboundCapViolation::HeadCountExceeded => ReasonCode::HeadCountExceeded,
            InboundCapViolation::DepCountExceeded => ReasonCode::DepCountExceeded,
            InboundCapViolation::TraversalBudgetExceeded => ReasonCode::TraversalBudgetExceeded,
            InboundCapViolation::ConnectionsExceeded => ReasonCode::ConnectionCapExceeded,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundCapViolation {
    RateExceeded,
    Oversize,
    OpCountExceeded,
    BatchExceeded,
    HeadCountExceeded,
    DepCountExceeded,
    TraversalBudgetExceeded,
    ConnectionsExceeded,
}

/// Per-sender token bucket enforcing `rate_ops_per_sec` / `rate_burst`.
///
/// Tokens are tracked in thousandths of an operation so a sub-second refill is
/// exact at microsecond resolution.  A sender's bucket is created full, so an
/// idle sender can always burst up to `rate_burst` operations.  A configured
/// rate or burst of zero fails closed (every delta is rejected).
#[derive(Debug, Default)]
pub(crate) struct InboundRateLimiter {
    buckets: std::collections::HashMap<String, TokenBucket>,
}

#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens_milli: u64,
    last_mono_us: u64,
}

const TOKEN_MILLI: u64 = 1000;

impl InboundRateLimiter {
    /// Consume `ops` tokens for `sender`, refilling from elapsed monotonic time.
    /// Returns `false` when the sender is over its configured rate/burst.
    pub(crate) fn check(
        &mut self,
        sender: &str,
        ops: u64,
        now_mono_us: u64,
        rate_ops_per_sec: u64,
        burst: u64,
    ) -> bool {
        if rate_ops_per_sec == 0 || burst == 0 {
            return false;
        }
        let capacity = burst.saturating_mul(TOKEN_MILLI);
        let bucket = self
            .buckets
            .entry(sender.to_string())
            .or_insert(TokenBucket {
                tokens_milli: capacity,
                last_mono_us: now_mono_us,
            });

        let elapsed_us = now_mono_us.saturating_sub(bucket.last_mono_us);
        if elapsed_us > 0 {
            let refill = elapsed_us
                .saturating_mul(rate_ops_per_sec)
                .saturating_mul(TOKEN_MILLI)
                / 1_000_000;
            bucket.tokens_milli = bucket.tokens_milli.saturating_add(refill).min(capacity);
            bucket.last_mono_us = now_mono_us;
        }

        let cost = ops.max(1).saturating_mul(TOKEN_MILLI);
        if bucket.tokens_milli >= cost {
            bucket.tokens_milli -= cost;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_caps_match_spec() {
        let c = InboundCaps::default();
        assert_eq!(c.rate_ops_per_sec, 100);
        assert_eq!(c.rate_burst, 500);
        assert_eq!(c.delta_size_bytes, 1024 * 1024);
        assert_eq!(c.op_count, 1000);
        assert_eq!(c.batch_changes, 50);
        assert_eq!(c.heads, 20);
        assert_eq!(c.deps_per_change, 50);
        assert_eq!(c.traversal_budget, 10_000);
        assert_eq!(c.connections, 10);
    }
}
