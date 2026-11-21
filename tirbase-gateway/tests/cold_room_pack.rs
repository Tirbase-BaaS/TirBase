// SPDX-License-Identifier: AGPL-3.0-only

//! Cold-room pack integration (CC-08, AGPL).
//!
//! Drives `tirbase-demo/cold-room` through the real guard pipeline:
//! 1. the committed `EnvelopeProfile` installs with its committed PA signature;
//! 2. every scenario in the pack is replayed against the pack's own profile,
//!    register maps, and expected output;
//! 3. the observed dispositions, defenses, and actuation counts match
//!    `expected/outcomes.toml` exactly.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;

use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_demo::{load_pack, AdversaryClass, Pack, StepDisposition};
use tirbase_gateway::guard::{open_drift_timing_store, SqliteStage16Store, Stage16Request};
use tirbase_guard::admit::{
    admit_stages_0_to_15, AdmitContext, AdmitDecision, AdmitRejection, PendingApprovalQuorum,
};
use tirbase_guard::driver_proxy::IngressSource;
use tirbase_guard::envelope::install_profile;
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::node_mode::{NodeMode, NodeModeState};
use tirbase_guard::time::{TimeRatchet, TimeRatchetConfig, TimeRatchetStore};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_guard::{DeviceModel, DeviceParameter, Stage16Store};
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::EnvelopeProfile;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId};

/// PolicyAuthority seed used for the committed cold-room fixture signature.
const FIXTURE_PA_SEED: [u8; 32] = [0x43; 32];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack() -> Pack {
    load_pack(workspace_root().join("tirbase-demo/cold-room")).expect("cold-room pack loads")
}

fn pack_profile() -> EnvelopeProfile {
    tirbase_gateway::profiles::load_profile_from_path(
        &workspace_root().join("tirbase-demo/cold-room/profiles/cold_room.toml"),
    )
    .expect("parse cold-room profile")
}

/// Device model matching `profiles/cold_room.toml`; used by install validation.
fn cold_room_device_model() -> DeviceModel {
    let deg_c = |min: i64, max: i64| {
        [
            FixedPointValue::new(min, -1, 1),
            FixedPointValue::new(max, -1, 1),
        ]
    };
    let boolean = || [FixedPointValue::new(0, 0, 7), FixedPointValue::new(1, 0, 7)];
    DeviceModel {
        device_class: "cold_room".to_string(),
        parameters: vec![
            DeviceParameter {
                name: "temperature_setpoint_c".to_string(),
                unit_id: 1,
                unit_label: "degC".to_string(),
                range: deg_c(-250, 80),
                writable: true,
            },
            DeviceParameter {
                name: "door_open".to_string(),
                unit_id: 7,
                unit_label: "boolean".to_string(),
                range: boolean(),
                writable: true,
            },
            DeviceParameter {
                name: "defrost_mode".to_string(),
                unit_id: 7,
                unit_label: "boolean".to_string(),
                range: boolean(),
                writable: true,
            },
            DeviceParameter {
                name: "defrost_termination_c".to_string(),
                unit_id: 1,
                unit_label: "degC".to_string(),
                range: deg_c(0, 80),
                writable: true,
            },
            DeviceParameter {
                name: "compressor_on".to_string(),
                unit_id: 7,
                unit_label: "boolean".to_string(),
                range: boolean(),
                writable: true,
            },
        ],
    }
}

fn pa_trust_root(pa_did: &str, pa_public_key: Vec<u8>) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: pa_did.to_string(),
                public_key: pa_public_key,
            }],
        ),
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![vec![1; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

#[test]
fn cold_room_profile_installs_with_the_committed_signature() {
    let profile = pack_profile();
    assert_eq!(profile.device_class, "cold_room");
    assert_eq!(profile.parameters.len(), 5);

    let pa = InMemoryKeyProvider::from_seed(FIXTURE_PA_SEED);
    let trust = pa_trust_root(pa.did(), pa.public_key_bytes());
    let signer = install_profile(&profile, &cold_room_device_model(), &trust)
        .expect("cold-room pack profile must install against its device model");
    assert_eq!(signer, pa.did());
}

#[test]
fn tampered_cold_room_profile_is_refused_at_install() {
    let mut profile = pack_profile();
    let setpoint = profile
        .parameters
        .iter_mut()
        .find(|parameter| parameter.name == "temperature_setpoint_c")
        .expect("setpoint parameter");
    // Widen the drift budget after signing: the committed signature must fail.
    setpoint.max_delta_in_window = FixedPointValue::new(60, -1, 1);

    let pa = InMemoryKeyProvider::from_seed(FIXTURE_PA_SEED);
    let trust = pa_trust_root(pa.did(), pa.public_key_bytes());
    let error = install_profile(&profile, &cold_room_device_model(), &trust)
        .expect_err("a body edit must invalidate the committed signature");
    assert!(
        format!("{error:?}").to_lowercase().contains("signature"),
        "unexpected install error: {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Scenario harness
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct MutableClock(AtomicU64);

impl MutableClock {
    fn set_secs(&self, secs: i64) {
        self.0.store((secs as u64) * 1_000_000, Ordering::SeqCst);
    }
}

impl TimeSource for MutableClock {
    fn monotonic_now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn wall_hint(&self) -> Option<i64> {
        Some((self.0.load(Ordering::SeqCst) / 1_000_000) as i64)
    }
    fn boot_id(&self) -> u64 {
        1
    }
}

/// Stands in for an operator-approved pending approval: the pack scenarios
/// exercise the envelope, drift, dwell, min-off and replay defenses, and assume
/// the out-of-band quorum for critical setpoints has already been granted.
#[derive(Debug, Default)]
struct ApprovedQuorum;

impl PendingApprovalQuorum for ApprovedQuorum {
    fn has_quorum(
        &self,
        _issuer_did: &str,
        _target_id: &str,
        _param: &str,
        _sequence_number: u64,
        _required_m: usize,
    ) -> Result<bool, String> {
        Ok(true)
    }
}

#[derive(Debug, Default)]
struct RatchetStore(Mutex<Option<tirbase_guard::time::TimeRatchetRecord>>);

impl TimeRatchetStore for RatchetStore {
    fn load(
        &self,
    ) -> Result<Option<tirbase_guard::time::TimeRatchetRecord>, tirbase_guard::time::TimeRatchetError>
    {
        Ok(*self.0.lock().unwrap())
    }
    fn save(
        &self,
        record: &tirbase_guard::time::TimeRatchetRecord,
    ) -> Result<(), tirbase_guard::time::TimeRatchetError> {
        *self.0.lock().unwrap() = Some(*record);
        Ok(())
    }
}

struct Harness {
    pipeline: tirbase_guard::admit::AdmitPipelineState,
    clock: Arc<MutableClock>,
    epoch_registry: EpochRegistry,
    node_mode: Arc<NodeModeState>,
    stage16: SqliteStage16Store,
    issuer: InMemoryKeyProvider,
    tokens: BTreeMap<String, Vec<u8>>,
    /// Parameters the profile marks `critical`; commands for them carry a
    /// single-use challenge nonce (Stage 9).
    critical_params: BTreeSet<String>,
    target: TargetId,
    entry_ids: AtomicU64,
    _directory: tempfile::TempDir,
}

fn harness() -> Harness {
    let directory = tempfile::tempdir().expect("temp dir");
    let db = directory.path().join("primary.db");

    let ca = InMemoryKeyProvider::generate().expect("ca key");
    let issuer = InMemoryKeyProvider::generate().expect("issuer key");
    let target = TargetId::new("cold-room-1");

    let epoch_registry = EpochRegistry::new(Arc::new(InMemoryEpochStore::default()));
    epoch_registry
        .ensure_enrolled("dev1", 1_000_000)
        .expect("enroll device");

    let profile = pack_profile();
    let mut profiles = BTreeMap::new();
    profiles.insert(
        target.clone(),
        Arc::new(ArcSwap::from_pointee(profile.clone())),
    );

    let clock = Arc::new(MutableClock(AtomicU64::new(1_000_000_000)));
    let ratchet = Arc::new(Mutex::new(
        TimeRatchet::open(
            Arc::new(RatchetStore::default()),
            TimeRatchetConfig::default(),
        )
        .expect("time ratchet"),
    ));
    let root_ca = Arc::new(RwLock::new(RootCaRegistry::new(vec![ca
        .public_key_bytes()
        .try_into()
        .expect("32-byte CA key")])));

    let pipeline = tirbase_guard::admit::AdmitPipelineState::new(
        Arc::new(profiles),
        Arc::new(ArcSwap::from_pointee(None)),
        root_ca,
        ratchet,
        clock.clone(),
    );
    pipeline.set_max_ttl_secs(10_000_000_000);
    pipeline.set_drift_store(open_drift_timing_store(&db).expect("drift store"));
    pipeline.set_quorum_provider(Arc::new(ApprovedQuorum));

    let critical_params: BTreeSet<String> = profile
        .parameters
        .iter()
        .filter(|parameter| parameter.critical)
        .map(|parameter| parameter.name.clone())
        .collect();

    let mut tokens = BTreeMap::new();
    for parameter in &profile.parameters {
        tokens.insert(
            parameter.name.clone(),
            create_command_token(
                issuer.did(),
                "CommandIssuer",
                3600,
                "cold-room-1",
                &parameter.name,
                &[],
                &ca.secret_seed(),
            )
            .expect("command token"),
        );
    }

    Harness {
        pipeline,
        clock,
        epoch_registry,
        node_mode: NodeModeState::new(NodeMode::Normal),
        stage16: SqliteStage16Store::open(&db).expect("stage16 store"),
        issuer,
        tokens,
        critical_params,
        target,
        entry_ids: AtomicU64::new(1),
        _directory: directory,
    }
}

/// Actual result of one scenario step.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StepResult {
    disposition: StepDisposition,
    mechanism: Option<&'static str>,
}

struct ScenarioRun {
    steps: Vec<StepResult>,
    actuations: usize,
}

fn command(
    issuer: &InMemoryKeyProvider,
    target: &TargetId,
    param: &str,
    desired_state: FixedPointValue,
    sequence: u64,
    challenge_nonce: Option<[u8; 32]>,
) -> CommandMessage {
    let mut cmd = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: target.clone(),
        param: param.to_string(),
        desired_state,
        sequence_number: sequence,
        idempotency_key: [sequence as u8; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce,
        co_signatures: vec![],
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    tirbase_guard::sign_command(&mut cmd, issuer).expect("sign command");
    cmd
}

fn mechanism_for(rejection: AdmitRejection) -> &'static str {
    match rejection {
        AdmitRejection::EnvelopeViolation => "envelope",
        AdmitRejection::DriftExceeded => "drift",
        AdmitRejection::DwellViolation => "dwell",
        AdmitRejection::MinOffViolation => "min_off",
        other => panic!("scenario rejected by an unexpected stage: {other:?}"),
    }
}

fn run_scenario(pack: &Pack, scenario_id: &str) -> ScenarioRun {
    let scenario = pack.scenario(scenario_id).expect("scenario");
    let expected = pack.expected_outcome(scenario_id).expect("expected output");
    let h = harness();
    let _ = &h.epoch_registry;
    let stage16 = &h.stage16;

    // Step 13 timing and Stage 16 summaries both read this clock.
    let mut results = Vec::new();
    let mut actuations = 0usize;

    for step in &scenario.steps {
        let clock_secs = step.at_secs;
        // Advance the pipeline clock; dwell/min-off and drift read it in Stage 13.
        h.clock.set_secs(clock_secs);

        let sequence = if step.replay_of.is_some() {
            step.replay_of.expect("replay sequence")
        } else {
            step.sequence
        };
        // Critical parameters need a single-use challenge nonce, issued against
        // the same clock the pipeline reads.
        let challenge = if h.critical_params.contains(&step.param) {
            Some(
                h.pipeline
                    .issue_challenge_nonce(h.issuer.did(), h.target.as_str(), &step.param),
            )
        } else {
            None
        };
        let cmd = command(
            &h.issuer,
            &h.target,
            &step.param,
            step.value,
            sequence,
            challenge,
        );
        let token = h.tokens.get(&step.param).expect("token for parameter");
        let now_est = 1_000 + (clock_secs - 1_000);
        let ctx = AdmitContext {
            ingress: IngressSource::LocalAdmin,
            source_key: "cold-room-pack-test",
            biscuit_token: Some(token.as_slice()),
            now_est_secs: Some(now_est),
            simulate: false,
        };
        let decision = admit_stages_0_to_15(
            &cmd,
            &ctx,
            &h.node_mode,
            &h.epoch_registry,
            &h.pipeline,
            Some("dev1"),
        );

        match decision {
            AdmitDecision::Accepted {
                idempotency_cache_hit,
                ..
            } => {
                if idempotency_cache_hit {
                    results.push(StepResult {
                        disposition: StepDisposition::Deduplicated,
                        mechanism: Some("idempotency"),
                    });
                    continue;
                }
                // Stage 16 commits the actuation and the drift/timing summary
                // that dwell and min-off read on later steps.
                let entry = h.entry_ids.fetch_add(1, Ordering::SeqCst);
                let mut entry_id = [0u8; 16];
                entry_id[..8].copy_from_slice(&entry.to_be_bytes());
                stage16
                    .commit_actuating(&Stage16Request {
                        cmd: &cmd,
                        entry_id,
                        actuating_ts: now_est,
                        now_est,
                        now_mono_secs: clock_secs,
                        lease_duration_secs: 30,
                        max_consecutive_renewals: 10,
                        original_result_json: "{\"status\":\"accepted\"}",
                        idempotency_retention_secs:
                            tirbase_guard::commit::DEFAULT_IDEMPOTENCY_RETENTION_SECS,
                    })
                    .unwrap_or_else(|error| {
                        panic!("scenario '{scenario_id}' stage16 commit failed: {error:?}")
                    });
                actuations += 1;
                results.push(StepResult {
                    disposition: StepDisposition::Accepted,
                    mechanism: None,
                });
            }
            AdmitDecision::Rejected {
                category, detail, ..
            } => {
                results.push(StepResult {
                    disposition: StepDisposition::Rejected,
                    mechanism: Some(mechanism_for(category)),
                });
                let _ = detail;
            }
            other => panic!("scenario '{scenario_id}' produced {other:?}"),
        }
    }

    assert_eq!(
        results.len(),
        expected.steps.len(),
        "scenario '{scenario_id}' step count"
    );
    ScenarioRun {
        steps: results,
        actuations,
    }
}

// ---------------------------------------------------------------------------
// Scenario defense
// ---------------------------------------------------------------------------

#[test]
fn every_cold_room_scenario_matches_its_expected_output() {
    let pack = pack();
    assert!(pack.scenarios.len() >= 6, "pack ships six scenarios");
    let classes: Vec<AdversaryClass> = pack.scenarios.iter().map(|s| s.class).collect();
    assert!(classes.contains(&AdversaryClass::S1));
    assert!(classes.contains(&AdversaryClass::S2));
    assert!(classes.contains(&AdversaryClass::S3));

    for scenario in &pack.scenarios {
        let expected = pack
            .expected_outcome(&scenario.id)
            .expect("expected output for scenario");
        let run = run_scenario(&pack, &scenario.id);

        let steps: Vec<StepDisposition> = run.steps.iter().map(|s| s.disposition).collect();
        assert_eq!(
            steps, expected.steps,
            "scenario '{}' dispositions differ from expected/outcomes.toml",
            scenario.id
        );
        assert_eq!(
            run.actuations, expected.actuations,
            "scenario '{}' actuation count differs from expected/outcomes.toml",
            scenario.id
        );

        for (index, (step, actual)) in scenario.steps.iter().zip(&run.steps).enumerate() {
            if let Some(mechanism) = &step.mechanism {
                assert_eq!(
                    actual.mechanism,
                    Some(mechanism.as_str()),
                    "scenario '{}' step {index} was defended by a different stage",
                    scenario.id
                );
            }
            if step.expect == StepDisposition::Rejected {
                assert!(
                    actual.mechanism.is_some(),
                    "scenario '{}' step {index} must name the rejecting stage",
                    scenario.id
                );
            }
        }
    }
}

#[test]
fn cold_room_replay_is_answered_from_the_cache() {
    let pack = pack();
    let scenario = pack.scenario("S3_replay").expect("replay scenario");
    let run = run_scenario(&pack, "S3_replay");
    assert_eq!(run.actuations, 1, "replay must not actuate twice");
    assert_eq!(run.steps[0].disposition, StepDisposition::Accepted);
    assert_eq!(run.steps[1].disposition, StepDisposition::Deduplicated);
    assert_eq!(scenario.steps.len(), 2);
}

#[test]
fn cold_room_slow_ramp_is_stopped_by_the_drift_window() {
    let run = run_scenario(&pack(), "S2_slow_ramp");
    let rejected: Vec<&StepResult> = run
        .steps
        .iter()
        .filter(|step| step.disposition == StepDisposition::Rejected)
        .collect();
    assert_eq!(
        rejected.len(),
        1,
        "only the sixth step exceeds the budget: {:?}",
        run.steps
    );
    assert_eq!(rejected[0].mechanism, Some("drift"));
    assert_eq!(run.actuations, 5);
}

/// The pack registers no executable code, so the gateway test also asserts the
/// only files it can see are data documents (defence in depth for the Python
/// purity gate in CI).
#[test]
fn cold_room_pack_is_data_only_from_the_gateway_side() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read pack dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(&workspace_root().join("tirbase-demo/cold-room"), &mut files);
    for file in files {
        let extension = file
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        assert!(
            extension == "toml" || extension == "md" || file.ends_with("run.sh"),
            "unexpected pack file {}",
            file.display()
        );
    }
}
