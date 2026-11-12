//! Shared `CommandGuard` admit-pipeline fixture for scenarios that drive full
//! command admission (S16, S17).
//!
//! The fixture builds the same production objects the gateway wires: envelope
//! profiles, root CA registry, mutable time ratchet, epoch registry, and the
//! real `AdmitPipelineState`. Commands are signed with a real key provider and
//! carry a real Biscuit command token.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_guard::admit::{AdmitContext, AdmitPipelineState};
use tirbase_guard::driver_proxy::{DriverProxy, IngressSource};
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::time::{TimeRatchet, TimeRatchetConfig, TimeRatchetStore};
use tirbase_guard::AdmitError;
use tirbase_guard::{sign_command, CommandGuard, GuardConfig, TargetAdmission};
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

use super::common::{FixedTimeSource, MemoryRatchetStore};

fn fp(mantissa: i64) -> FixedPointValue {
    FixedPointValue::new(mantissa, -1, UNIT_PERCENT)
}

/// A fully wired, single-target guard fixture.
pub struct AdversaryFixture {
    pub guard: CommandGuard,
    pub pipeline: Arc<AdmitPipelineState>,
    pub target: TargetId,
    pub param: String,
    pub issuer: InMemoryKeyProvider,
    pub token: Vec<u8>,
    pub ca_secret: [u8; 32],
}

impl AdversaryFixture {
    pub fn new(target: &str, param: &str, critical: bool) -> Result<Self, String> {
        let ca = InMemoryKeyProvider::generate().map_err(|e| format!("harness CA: {e}"))?;
        let issuer = InMemoryKeyProvider::generate().map_err(|e| format!("harness issuer: {e}"))?;
        let target = TargetId::new(target);
        let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
        epochs
            .ensure_enrolled("dev1", 1_000)
            .map_err(|e| format!("{e:?}"))?;
        let mut targets = BTreeMap::new();
        targets.insert(
            target.clone(),
            TargetAdmission {
                device_id: "dev1".into(),
            },
        );
        let profile = EnvelopeProfile {
            profile_id: [16u8; 16],
            version: 1,
            device_class: "pump".into(),
            parameters: vec![ParameterSpec {
                name: param.to_string(),
                unit_id: UNIT_PERCENT,
                canonical_exponent: -1,
                kind: ParameterKind::Range {
                    min: fp(0),
                    max: fp(1000),
                },
                max_rate_per_sec: fp(10_000),
                dwell_secs: 0,
                min_off_secs: 0,
                drift_window_secs: 0,
                max_delta_in_window: fp(10_000),
                safe_default: fp(0),
                tightening_floor: fp(0),
                critical,
            }],
            cross_constraints: vec![],
            policy_loosen_m: 2,
            policy_loosen_n: 2,
            policy_timelock_secs: 0,
            policy_cancel_window_secs: 0,
            signature: DeviceSignature::Ed25519([0; 64]),
        };
        let mut profile_map = BTreeMap::new();
        profile_map.insert(target.clone(), Arc::new(ArcSwap::from_pointee(profile)));

        let time_source: Arc<dyn TimeSource> =
            Arc::new(FixedTimeSource::new(1, 1_700_000_000, 1_000));
        let ratchet = Arc::new(Mutex::new(
            TimeRatchet::open(
                Arc::new(MemoryRatchetStore::default()) as Arc<dyn TimeRatchetStore>,
                TimeRatchetConfig::default(),
            )
            .map_err(|e| format!("harness ratchet: {e}"))?,
        ));
        let registry = Arc::new(RwLock::new(RootCaRegistry::new(vec![ca
            .public_key_bytes()
            .try_into()
            .map_err(|_| "harness CA key width".to_string())?])));
        let pipeline = Arc::new(AdmitPipelineState::new(
            Arc::new(profile_map.clone()),
            Arc::new(ArcSwap::from_pointee(None)),
            registry,
            ratchet,
            time_source,
        ));
        pipeline.set_max_ttl_secs(10_000_000_000);
        let guard = CommandGuard::with_mode(
            epochs,
            GuardConfig { targets },
            tirbase_guard::node_mode::NodeModeState::new(
                tirbase_guard::node_mode::NodeMode::Normal,
            ),
        )
        .with_pipeline(
            pipeline.clone(),
            Arc::new(profile_map),
            Arc::new(ArcSwap::from_pointee(None)),
        );
        let token = create_command_token(
            issuer.did(),
            "CommandIssuer",
            3_600,
            target.as_str(),
            param,
            &[],
            &ca.secret_seed(),
        )
        .map_err(|e| format!("harness token: {e:?}"))?;
        Ok(Self {
            guard,
            pipeline,
            target,
            param: param.to_string(),
            issuer,
            token,
            ca_secret: ca.secret_seed(),
        })
    }

 /// Build (and sign) a command for this fixture's target/parameter.
    pub fn command(
        &self,
        value: i64,
        transaction: u8,
        sequence_number: u64,
    ) -> Result<CommandMessage, String> {
        let mut command = CommandMessage {
            issuer_did: Did::new(self.issuer.did()),
            role: CommandRole::CommandIssuer,
            target_id: self.target.clone(),
            param: self.param.clone(),
            desired_state: fp(value),
            sequence_number,
            idempotency_key: [transaction; 16],
            expiry_est: 9_999_999_999,
            policy_version: 1,
            enrollment_epoch: 0,
            challenge_nonce: None,
            co_signatures: vec![],
            signature: DeviceSignature::Ed25519([0; 64]),
        };
        sign_command(&mut command, &self.issuer).map_err(|e| format!("harness sign: {e}"))?;
        Ok(command)
    }

 /// Admit a command through the full production pipeline.
    pub fn admit(&self, command: &CommandMessage) -> Result<(), AdmitError> {
        self.admit_with_token(command, &self.token)
    }

 /// Admit a command carrying a specific Biscuit token.
    pub fn admit_with_token(
        &self,
        command: &CommandMessage,
        token: &[u8],
    ) -> Result<(), AdmitError> {
        let context = AdmitContext {
            ingress: IngressSource::LocalAdmin,
            source_key: "scenario-source",
            biscuit_token: Some(token),
            now_est_secs: Some(1_000),
            simulate: false,
        };
        let mut wire = Vec::new();
        let mut proxy = DriverProxy::new(Cursor::new(&mut wire));
        self.guard
            .admit_with_context(command, &context, &mut proxy, b"FRAME")
            .map(|_| ())
    }
}
