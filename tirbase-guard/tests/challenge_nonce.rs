//! Task 16 compatibility test IDs (CLAIM-16.4/S32, PV-22.3).
//! Production behavior is exercised via `tirbase-guard` pipeline issuance/rate
//! limiting and `tirbase-gateway`/`tirbase-sim` integration tests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::traits::TimeSource;
use tirbase_guard::admit::AdmitPipelineState;
use tirbase_guard::time::{TimeRatchet, TimeRatchetConfig, TimeRatchetStore};
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{DeviceSignature, FixedPointValue, TargetId, UNIT_PERCENT};

#[derive(Debug)]
struct T(u64);
impl TimeSource for T {
    fn monotonic_now(&self) -> u64 {
        self.0
    }
    fn wall_hint(&self) -> Option<i64> {
        Some((self.0 / 1_000_000) as i64)
    }
    fn boot_id(&self) -> u64 {
        1
    }
}
#[derive(Debug, Default)]
struct S(Mutex<Option<tirbase_guard::time::TimeRatchetRecord>>);
impl TimeRatchetStore for S {
    fn load(
        &self,
    ) -> Result<Option<tirbase_guard::time::TimeRatchetRecord>, tirbase_guard::time::TimeRatchetError>
    {
        Ok(*self.0.lock().unwrap())
    }
    fn save(
        &self,
        r: &tirbase_guard::time::TimeRatchetRecord,
    ) -> Result<(), tirbase_guard::time::TimeRatchetError> {
        *self.0.lock().unwrap() = Some(*r);
        Ok(())
    }
}
fn fpv(m: i64) -> FixedPointValue {
    FixedPointValue::new(m, -1, UNIT_PERCENT)
}

#[test]
fn test_nonce_flood_rate_limit() {
    let target = TargetId::new("pump-1");
    let mut pm = BTreeMap::new();
    pm.insert(
        target,
        Arc::new(ArcSwap::from_pointee(EnvelopeProfile {
            profile_id: [32; 16],
            version: 1,
            device_class: "pump".into(),
            parameters: vec![ParameterSpec {
                name: "speed".into(),
                unit_id: UNIT_PERCENT,
                canonical_exponent: -1,
                kind: ParameterKind::Range {
                    min: fpv(0),
                    max: fpv(1000),
                },
                max_rate_per_sec: fpv(10000),
                dwell_secs: 0,
                min_off_secs: 0,
                drift_window_secs: 60,
                max_delta_in_window: fpv(10000),
                safe_default: fpv(0),
                tightening_floor: fpv(0),
                critical: true,
            }],
            cross_constraints: vec![],
            policy_loosen_m: 2,
            policy_loosen_n: 2,
            policy_timelock_secs: 0,
            policy_cancel_window_secs: 0,
            signature: DeviceSignature::Ed25519([0; 64]),
        })),
    );
    let ts: Arc<dyn TimeSource> = Arc::new(T(1_000_000_000));
    let ratchet = Arc::new(Mutex::new(
        TimeRatchet::open(Arc::new(S::default()), TimeRatchetConfig::default()).unwrap(),
    ));
    let pipeline = Arc::new(AdmitPipelineState::new(
        Arc::new(pm),
        Arc::new(ArcSwap::from_pointee(None)),
        Arc::new(RwLock::new(RootCaRegistry::default())),
        ratchet,
        ts,
    ));
    pipeline.set_challenge_requests_per_minute(5);
    let mut accepted = 0usize;
    for n in 0..9 {
        if pipeline
            .issue_challenge_nonce_for_device("dev1", &format!("did:key:{n}"), "pump-1", "speed")
            .is_ok()
        {
            accepted += 1;
        }
    }
    assert!(accepted <= 5, "S32/CLAIM-16.4: flood accepted={accepted}");
}
