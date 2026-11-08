//! Scenario S32 — Challenge-nonce flooding (task 16.4, CLAIM-16.4, PV-22.3, INV-9).
//!
//! Attack: flood challenge nonce issuance for a critical parameter while
//! `FreshnessState::Unverified`.
//! Expected: per-device issuance rate limiting rejects excess requests (default
//! 5/minute per device/target/param), preventing nonce-table/storage exhaustion
//! and preserving issuance for legitimate bounded use.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::traits::TimeSource;
use tirbase_guard::admit::AdmitPipelineState;
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::node_mode::NodeModeState;
use tirbase_guard::time::{FreshnessState, TimeRatchet, TimeRatchetConfig, TimeRatchetStore};
use tirbase_guard::{CommandGuard, GuardConfig, TargetAdmission};
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{DeviceSignature, FixedPointValue, TargetId, UNIT_PERCENT};

#[derive(Debug)]
struct T(u64, u64);
impl TimeSource for T {
    fn monotonic_now(&self) -> u64 { self.0 }
    fn wall_hint(&self) -> Option<i64> { Some((self.0 / 1_000_000) as i64) }
    fn boot_id(&self) -> u64 { self.1 }
}
#[derive(Debug, Default)]
struct MemRatchetStore(Mutex<Option<tirbase_guard::time::TimeRatchetRecord>>);
impl TimeRatchetStore for MemRatchetStore {
    fn load(&self) -> Result<Option<tirbase_guard::time::TimeRatchetRecord>, tirbase_guard::time::TimeRatchetError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save(&self, r: &tirbase_guard::time::TimeRatchetRecord) -> Result<(), tirbase_guard::time::TimeRatchetError> {
        *self.0.lock().unwrap() = Some(*r);
        Ok(())
    }
}

fn fpv(m: i64) -> FixedPointValue { FixedPointValue::new(m, -1, UNIT_PERCENT) }

pub fn s32_challenge_nonce_flood_is_rate_limited() {
    let target = TargetId::new("pump-1");
    let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    epochs.ensure_enrolled("dev1", 0).unwrap();
    let mut targets = BTreeMap::new();
    targets.insert(target.clone(), TargetAdmission { device_id: "dev1".into() });
    let profile = EnvelopeProfile {
        profile_id: [32u8; 16], version: 1, device_class: "pump".into(),
        parameters: vec![ParameterSpec {
            name: "speed".into(), unit_id: UNIT_PERCENT, canonical_exponent: -1,
            kind: ParameterKind::Range { min: fpv(0), max: fpv(1000) },
            max_rate_per_sec: fpv(10000), dwell_secs: 0, min_off_secs: 0,
            drift_window_secs: 60, max_delta_in_window: fpv(10000),
            safe_default: fpv(0), tightening_floor: fpv(0), critical: true,
        }],
        cross_constraints: vec![], policy_loosen_m: 2, policy_loosen_n: 2,
        policy_timelock_secs: 0, policy_cancel_window_secs: 0,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    };
    let mut pm = BTreeMap::new();
    pm.insert(target, Arc::new(ArcSwap::from_pointee(profile)));
    let ts = Arc::new(T(1_000_000_000, 1));
    let ratchet = Arc::new(Mutex::new(
        TimeRatchet::open(Arc::new(MemRatchetStore::default()), TimeRatchetConfig::default()).unwrap(),
    ));
    let reg = Arc::new(RwLock::new(RootCaRegistry::default()));
    let pipeline = Arc::new(AdmitPipelineState::new(
        Arc::new(pm.clone()),
        Arc::new(ArcSwap::from_pointee(None)),
        reg,
        ratchet,
        ts as Arc<dyn TimeSource>,
    ));
    pipeline.set_challenge_requests_per_minute(5);
    let _guard = CommandGuard::with_mode(epochs, GuardConfig { targets }, NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal))
        .with_pipeline(pipeline.clone(), Arc::new(pm), Arc::new(ArcSwap::from_pointee(None)));

    assert_eq!(pipeline.freshness_state(), FreshnessState::Unverified, "S32 precondition");

    let mut accepted = 0usize;
    let mut limited = 0usize;
    for n in 0..20 {
        let issuer = format!("did:key:flood-{n}");
        match pipeline.issue_challenge_nonce_for_device("dev1", &issuer, "pump-1", "speed") {
            Ok(nonce) => {
                accepted += 1;
                assert_eq!(nonce.nonce.len(), 32);
                assert_eq!(nonce.device_id, "dev1");
                assert_eq!(nonce.param, "speed");
            }
            Err(e) => {
                limited += 1;
                assert!(e.contains("rate") || e.contains("retry"), "unexpected error: {e}");
            }
        }
    }
    assert!(accepted <= 5, "S32: nonce flood accepted={accepted}; rate limit must bound issuance");
    assert!(limited >= 1, "S32: excess nonce requests must be rejected");

    // Wiring-mutation guard: disabling/removing the limit would allow all 20.
    // (This scenario fails if the rate limit is removed.)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn s32_challenge_nonce_flood() {
        s32_challenge_nonce_flood_is_rate_limited();
    }
}
