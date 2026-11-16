// SPDX-License-Identifier: AGPL-3.0-only

//! Pharma GDP pack integration (CC-10, AGPL).
//!
//! Drives `tirbase-demo/pharma-gdp` through the real guard pipeline:
//! 1. all three storage-class profiles install with their committed signatures;
//! 2. every command scenario matches the pack's own expected output;
//! 3. a transient excursion is held while cumulative drift is rejected;
//! 4. an expired calibration blocks release before any excursion assessment.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;

use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_demo::{
    classify_excursion, load_pack, AdversaryClass, ExcursionClass, Pack, ReleaseDisposition,
    ReleaseInputs, StepDisposition, RELEASE_CODE_CALIBRATION_EXPIRED, RELEASE_CODE_CLEAR,
    RELEASE_CODE_CUMULATIVE_DRIFT, RELEASE_CODE_TRANSIENT_EXCURSION,
};
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

/// PolicyAuthority seed used for the committed pharma-gdp fixture signatures.
const FIXTURE_PA_SEED: [u8; 32] = [0x47; 32];

const TARGET: &str = "pharma-2-8-1";
const COLD_PROFILE: &str = "profiles/gdp_2_8c.toml";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack_root() -> PathBuf {
    workspace_root().join("tirbase-demo/pharma-gdp")
}

fn pack() -> Pack {
    load_pack(pack_root()).expect("pharma-gdp pack loads")
}

fn pack_profile(relative: &str) -> EnvelopeProfile {
    tirbase_gateway::profiles::load_profile_from_path(&pack_root().join(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

/// Plant device model. Envelopes in the pack are the *command* limits, so the
/// device model is the wider plant capability the profiles must fit inside.
fn gdp_device_model() -> DeviceModel {
    let range =
        |name: &str, unit_id: u16, label: &str, min: i64, max: i64, exp: i8| DeviceParameter {
            name: name.to_string(),
            unit_id,
            unit_label: label.to_string(),
            range: [
                FixedPointValue::new(min, exp, unit_id),
                FixedPointValue::new(max, exp, unit_id),
            ],
            writable: true,
        };
    let boolean = |name: &str| DeviceParameter {
        name: name.to_string(),
        unit_id: 7,
        unit_label: "boolean".to_string(),
        range: [FixedPointValue::new(0, 0, 7), FixedPointValue::new(1, 0, 7)],
        writable: true,
    };
    DeviceModel {
        device_class: "gdp_room".to_string(),
        parameters: vec![
            range("temperature_setpoint_c", 1, "degC", -450, 500, -1),
            range("humidity_setpoint_rh", 6, "percent", 0, 100, 0),
            boolean("door_open"),
            boolean("defrost_mode"),
            boolean("compressor_on"),
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
fn every_storage_profile_installs_with_its_committed_signature() {
    let pa = InMemoryKeyProvider::from_seed(FIXTURE_PA_SEED);
    let trust = pa_trust_root(pa.did(), pa.public_key_bytes());

    for relative in [
        "profiles/gdp_2_8c.toml",
        "profiles/gdp_frozen.toml",
        "profiles/gdp_controlled_room.toml",
    ] {
        let profile = pack_profile(relative);
        assert_eq!(profile.device_class, "gdp_room");
        assert_eq!(profile.parameters.len(), 5, "{relative} parameters");
        let signer = install_profile(&profile, &gdp_device_model(), &trust)
            .unwrap_or_else(|error| panic!("{relative} must install: {error:?}"));
        assert_eq!(signer, pa.did());
    }
}

#[test]
fn tampered_storage_profile_is_refused_at_install() {
    let mut profile = pack_profile(COLD_PROFILE);
    let setpoint = profile
        .parameters
        .iter_mut()
        .find(|parameter| parameter.name == "temperature_setpoint_c")
        .expect("setpoint parameter");
    // Widen the drift budget after signing: the committed signature must fail.
    setpoint.max_delta_in_window = FixedPointValue::new(90, -1, 1);

    let pa = InMemoryKeyProvider::from_seed(FIXTURE_PA_SEED);
    let trust = pa_trust_root(pa.did(), pa.public_key_bytes());
    let error = install_profile(&profile, &gdp_device_model(), &trust)
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
/// exercise the envelope, drift, and dwell defenses, and assume the out-of-band
/// quorum for the critical storage setpoint has already been granted.
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
    let target = TargetId::new(TARGET);

    let epoch_registry = EpochRegistry::new(Arc::new(InMemoryEpochStore::default()));
    epoch_registry
        .ensure_enrolled("dev1", 1_000_000)
        .expect("enroll device");

    let profile = pack_profile(COLD_PROFILE);
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
                TARGET,
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

    let mut steps = Vec::new();
    let mut actuations = 0usize;

    for step in &scenario.steps {
        h.clock.set_secs(step.at_secs);
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
            step.sequence,
            challenge,
        );
        let token = h.tokens.get(&step.param).expect("token for parameter");
        let now_est = 1_000 + (step.at_secs - 1_000);
        let ctx = AdmitContext {
            ingress: IngressSource::LocalAdmin,
            source_key: "pharma-gdp-pack-test",
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
            AdmitDecision::Accepted { .. } => {
                let entry = h.entry_ids.fetch_add(1, Ordering::SeqCst);
                let mut entry_id = [0u8; 16];
                entry_id[..8].copy_from_slice(&entry.to_be_bytes());
                h.stage16
                    .commit_actuating(&Stage16Request {
                        cmd: &cmd,
                        entry_id,
                        actuating_ts: now_est,
                        now_est,
                        now_mono_secs: step.at_secs,
                        lease_duration_secs: 30,
                        max_consecutive_renewals: 10,
                        original_result_json: "{\"status\":\"accepted\"}",
                        idempotency_retention_secs:
                            tirbase_guard::commit::DEFAULT_IDEMPOTENCY_RETENTION_SECS,
                    })
                    .unwrap_or_else(|error| panic!("stage16 commit failed: {error:?}"));
                actuations += 1;
                steps.push(StepResult {
                    disposition: StepDisposition::Accepted,
                    mechanism: None,
                });
            }
            AdmitDecision::Rejected { category, .. } => steps.push(StepResult {
                disposition: StepDisposition::Rejected,
                mechanism: Some(mechanism_for(category)),
            }),
            other => panic!("scenario '{scenario_id}' produced {other:?}"),
        }
    }

    assert_eq!(
        steps.len(),
        expected.steps.len(),
        "scenario '{scenario_id}' step count"
    );
    ScenarioRun { steps, actuations }
}

// ---------------------------------------------------------------------------
// Scenario defense
// ---------------------------------------------------------------------------

#[test]
fn every_pharma_scenario_matches_its_expected_output() {
    let pack = pack();
    assert_eq!(pack.scenarios.len(), 3);

    for scenario in &pack.scenarios {
        assert_eq!(scenario.class, AdversaryClass::S2);
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
        }
    }
}

#[test]
fn transient_excursion_is_held_while_cumulative_drift_is_rejected() {
    let pack = pack();
    let storage = pack
        .storage_for_profile(COLD_PROFILE)
        .expect("2–8 °C storage class");

    // Transient: every command is dispatched, then classified from the accepted
    // timeline.
    let transient = run_scenario(&pack, "S2_transient_excursion");
    assert_eq!(transient.actuations, 3);
    assert!(transient
        .steps
        .iter()
        .all(|step| step.disposition == StepDisposition::Accepted));
    let transient_summary = classify_excursion(
        pack.scenario("S2_transient_excursion").expect("scenario"),
        storage,
    );
    assert_eq!(transient_summary.class, ExcursionClass::Transient);
    assert_eq!(transient_summary.out_of_band_secs, 300);
    let transient_decision = pack
        .evaluate_release(
            COLD_PROFILE,
            &ReleaseInputs {
                at_est: 1_770_000_000,
                excursion: Some("S2_transient_excursion"),
                ..Default::default()
            },
        )
        .expect("release decision");
    assert_eq!(transient_decision.disposition, ReleaseDisposition::Hold);
    assert_eq!(transient_decision.code, RELEASE_CODE_TRANSIENT_EXCURSION);
    assert!(!transient_decision.blocked);

    // Cumulative: the fifth command is refused, so the accepted timeline never
    // reaches that temperature and the lot is rejected.
    let cumulative = run_scenario(&pack, "S2_cumulative_drift");
    assert_eq!(cumulative.actuations, 4);
    let refusals: Vec<&StepResult> = cumulative
        .steps
        .iter()
        .filter(|step| step.disposition == StepDisposition::Rejected)
        .collect();
    assert_eq!(refusals.len(), 1, "only the last step is refused");
    assert_eq!(refusals[0].mechanism, Some("drift"));

    let cumulative_summary = classify_excursion(
        pack.scenario("S2_cumulative_drift").expect("scenario"),
        storage,
    );
    assert_eq!(cumulative_summary.class, ExcursionClass::Cumulative);
    assert_eq!(
        cumulative_summary.rejections,
        refusals.len(),
        "the classification counts the refusals the guard produced"
    );
    let cumulative_decision = pack
        .evaluate_release(
            COLD_PROFILE,
            &ReleaseInputs {
                at_est: 1_770_000_000,
                excursion: Some("S2_cumulative_drift"),
                ..Default::default()
            },
        )
        .expect("release decision");
    assert_eq!(cumulative_decision.disposition, ReleaseDisposition::Reject);
    assert_eq!(cumulative_decision.code, RELEASE_CODE_CUMULATIVE_DRIFT);
    assert!(cumulative_decision.blocked);
}

#[test]
fn calibration_expiry_blocks_release() {
    let pack = pack();
    let calibration = pack.calibration.as_ref().expect("calibration records");
    let expiry = calibration
        .sensor
        .iter()
        .map(|sensor| sensor.expires_at_est)
        .min()
        .expect("at least one sensor");

    // Valid record, clean excursion history: release.
    let clear = pack
        .evaluate_release(
            COLD_PROFILE,
            &ReleaseInputs {
                at_est: expiry - 86_400,
                ..Default::default()
            },
        )
        .expect("release decision");
    assert_eq!(clear.code, RELEASE_CODE_CLEAR);
    assert_eq!(clear.disposition, ReleaseDisposition::Release);
    assert!(!clear.blocked);

    // The record lapses: the same clean history can no longer release, and the
    // decision says which sensors are out of calibration.
    let blocked = pack
        .evaluate_release(
            COLD_PROFILE,
            &ReleaseInputs {
                at_est: expiry,
                mkt_c: Some(FixedPointValue::new(50, -1, 1)),
                ..Default::default()
            },
        )
        .expect("release decision");
    assert_eq!(blocked.code, RELEASE_CODE_CALIBRATION_EXPIRED);
    assert_eq!(blocked.disposition, ReleaseDisposition::Hold);
    assert!(blocked.blocked);
    for sensor in &calibration.sensor {
        if sensor.expires_at_est <= expiry {
            assert!(
                blocked
                    .reasons
                    .iter()
                    .any(|reason| reason.contains(&sensor.sensor_id)),
                "the decision must name '{}': {:?}",
                sensor.sensor_id,
                blocked.reasons
            );
        }
    }

    // Calibration outranks the excursion assessment, so a rejected excursion
    // cannot be confused with a calibration hold.
    let both = pack
        .evaluate_release(
            COLD_PROFILE,
            &ReleaseInputs {
                at_est: expiry,
                excursion: Some("S2_cumulative_drift"),
                ..Default::default()
            },
        )
        .expect("release decision");
    assert_eq!(both.code, RELEASE_CODE_CALIBRATION_EXPIRED);

    // The pack's own release rows agree with the derivation.
    for row in &pack.expected.release {
        let decision = pack
            .evaluate_release(
                &row.profile,
                &ReleaseInputs {
                    at_est: row.at_est,
                    excursion: row.excursion.as_deref(),
                    mkt_c: row.mkt_c,
                    lane_risk_level: row.lane_risk_level,
                    sensor_failures: row.sensor_failures,
                },
            )
            .expect("release decision");
        assert_eq!(decision.code, row.code, "release row '{}'", row.id);
    }
}

#[test]
fn pack_is_data_only_from_the_gateway_side() {
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
    walk(&pack_root(), &mut files);
    assert!(!files.is_empty());
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
