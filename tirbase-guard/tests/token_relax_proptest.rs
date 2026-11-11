//! CLAIM-15.8 / PV-4.6 / INV-7: token-cannot-relax property test.
//! For any token minted by any key, a command with a value outside the
//! EnvelopeProfile is always rejected regardless of token attenuations.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use proptest::prelude::*;
use std::io::Cursor;
use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_guard::admit::{AdmitContext, AdmitPipelineState, AdmitRejection};
use tirbase_guard::driver_proxy::{DriverProxy, IngressSource};
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::node_mode::NodeModeState;
use tirbase_guard::time::{TimeRatchet, TimeRatchetConfig, TimeRatchetStore};
use tirbase_guard::{sign_command, CommandGuard, GuardConfig, TargetAdmission};
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

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
struct S(std::sync::Mutex<Option<tirbase_guard::time::TimeRatchetRecord>>);
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn token_cannot_relax_envelope_bounds(out_of_bounds_mantissa in prop_oneof![-1000i64..-1i64, 1001i64..5000i64]) {
        let ca=InMemoryKeyProvider::generate().unwrap();
        let issuer=InMemoryKeyProvider::generate().unwrap();
        let target=TargetId::new("pump-1");
        let epochs=Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
        epochs.ensure_enrolled("dev1",1_000_000).unwrap();
        let mut targets=BTreeMap::new(); targets.insert(target.clone(), TargetAdmission{device_id:"dev1".into()});
        let profile=EnvelopeProfile{profile_id:[1;16],version:1,device_class:"t".into(),parameters:vec![ParameterSpec{name:"speed".into(),unit_id:UNIT_PERCENT,canonical_exponent:-1,kind:ParameterKind::Range{min:fpv(0),max:fpv(1000)},max_rate_per_sec:fpv(10000),dwell_secs:0,min_off_secs:0,drift_window_secs:0,max_delta_in_window:fpv(10000),safe_default:fpv(0),tightening_floor:fpv(0),critical:false}],cross_constraints:vec![],policy_loosen_m:2,policy_loosen_n:2,policy_timelock_secs:0,policy_cancel_window_secs:0,signature:DeviceSignature::Ed25519([0;64])};
        let mut pm=BTreeMap::new(); pm.insert(target.clone(), Arc::new(ArcSwap::from_pointee(profile)));
        let ts:Arc<dyn TimeSource>=Arc::new(T(1_000_000_000));
        let ratchet=Arc::new(std::sync::Mutex::new(TimeRatchet::open(Arc::new(S::default()),TimeRatchetConfig::default()).unwrap()));
        let reg=Arc::new(RwLock::new(RootCaRegistry::new(vec![ca.public_key_bytes().try_into().unwrap()])));
        let pipeline=Arc::new(AdmitPipelineState::new(Arc::new(pm.clone()),Arc::new(ArcSwap::from_pointee(None)),reg,ratchet,ts));
        pipeline.set_max_ttl_secs(10_000_000_000);
        let guard=CommandGuard::with_mode(epochs,GuardConfig{targets},NodeModeState::new(tirbase_guard::node_mode::NodeMode::Normal)).with_pipeline(pipeline,Arc::new(pm),Arc::new(ArcSwap::from_pointee(None)));
        // Token is validly minted (any key / standard attenuation) — must not relax envelope.
        let tok=create_command_token(issuer.did(),"CommandIssuer",3600,"pump-1","speed",&[],&ca.secret_seed()).unwrap();
        let mut cmd=CommandMessage{issuer_did:Did::new(issuer.did()),role:CommandRole::CommandIssuer,target_id:target,param:"speed".into(),desired_state:fpv(out_of_bounds_mantissa),sequence_number:1,idempotency_key:[3;16],expiry_est:9_999_999_999,policy_version:1,enrollment_epoch:0,challenge_nonce:None,co_signatures:vec![],signature:DeviceSignature::Ed25519([0;64])};
        sign_command(&mut cmd,&issuer).unwrap();
        let ctx=AdmitContext{ingress:IngressSource::LocalAdmin,source_key:"p",biscuit_token:Some(&tok),now_est_secs:Some(1_000),simulate:false};
        let mut out=Vec::new(); let mut proxy=DriverProxy::new(Cursor::new(&mut out));
        let e=guard.admit_with_context(&cmd,&ctx,&mut proxy,b"f").unwrap_err();
        prop_assert!(matches!(e, tirbase_guard::AdmitError::Pipeline{category:AdmitRejection::EnvelopeViolation,..} | tirbase_guard::AdmitError::Pipeline{category:AdmitRejection::ValueInvalid,..}), "out-of-envelope must be rejected, got {e:?}");
        prop_assert!(out.is_empty(), "no actuation frame on rejection");
    }
}
