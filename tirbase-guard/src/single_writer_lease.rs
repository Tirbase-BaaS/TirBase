//! Single-writer lease (PV-5.8/5.8a, CLAIM-21.1–21.5).
//!
//! At most one issuer may hold a lease for a target at a time. Lease timing
//! uses monotonic time (`expires_mono`); `expires_est` is not used. Consecutive
//! renewals are capped and trigger a cooldown to prevent starvation (S21).

use tirbase_types::Did;

/// Production caller: gateway Stage 16 atomic commit (`SqliteStage16Store`) and
/// lease DB store in `tirbase-gateway/src/db/single_writer_leases.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleWriterLease {
    pub issuer_did: Did,
    pub target_id: String,
 /// Monotonic expiry (`CLOCK_BOOTTIME` domain seconds in gateway persistence).
    pub expires_mono_secs: i64,
    pub consecutive_renewals: u32,
 /// Monotonic cooldown deadline; while `Some(t)` and `now_mono < t` the same
 /// issuer cannot re-acquire (S21 / CLAIM-21.4).
    pub cooldown_until_mono_secs: Option<i64>,
}

impl SingleWriterLease {
    pub fn is_expired(&self, now_mono_secs: i64) -> bool {
        self.expires_mono_secs <= now_mono_secs
    }

    pub fn in_cooldown(&self, now_mono_secs: i64) -> bool {
        self.cooldown_until_mono_secs
            .is_some_and(|t| t > now_mono_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_and_cooldown() {
        let l = SingleWriterLease {
            issuer_did: Did::new("did:key:zissuer"),
            target_id: "t1".into(),
            expires_mono_secs: 10,
            consecutive_renewals: 0,
            cooldown_until_mono_secs: Some(12),
        };
        assert!(!l.is_expired(9));
        assert!(l.is_expired(10));
        assert!(l.in_cooldown(11));
        assert!(!l.in_cooldown(12));
    }
}
