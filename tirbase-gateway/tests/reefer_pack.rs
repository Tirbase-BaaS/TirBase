// SPDX-License-Identifier: AGPL-3.0-only

//! Reefer/container pack integration (CC-09, AGPL).
//!
//! Drives `tirbase-demo/reefer` through the real guard pipeline:
//! 1. the committed `EnvelopeProfile` installs with its committed PA signature;
//! 2. every scenario in the pack is replayed against the pack's own profile,
//!    register maps, and expected output;
//! 3. the door-open-in-transit timeline is quarantined as the trip document
//!    requires, and that excursion record survives a simulated power loss.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use serde_json::json;

use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::auth::root_ca::RootCaRegistry;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::{KeyProvider, TimeSource};
use tirbase_demo::{load_pack, AdversaryClass, Pack, StepDisposition, TripDisposition};
use tirbase_gateway::db::target_state::SqliteTargetStateStore;
use tirbase_gateway::guard::{open_drift_timing_store, SqliteStage16Store, Stage16Request};
use tirbase_gateway::vertical_api::VerticalApi;
use tirbase_guard::admit::{
    admit_stages_0_to_15, AdmitContext, AdmitDecision, AdmitRejection, DriftHistoryStore,
    PendingApprovalQuorum,
};
use tirbase_guard::driver_proxy::IngressSource;
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::envelope::install_profile;
use tirbase_guard::node_mode::{NodeMode, NodeModeState};
use tirbase_guard::time::{TimeRatchet, TimeRatchetConfig, TimeRatchetStore};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_guard::{DeviceModel, DeviceParameter, Stage16Store};
use tirbase_types::command::CommandMessage;
use tirbase_types::envelope::EnvelopeProfile;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId};

/// PolicyAuthority seed used for the committed reefer fixture signature.
const FIXTURE_PA_SEED: [u8; 32] = [0x52; 32];

const TARGET: &str = "reefer-1";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack() -> Pack {
    load_pack(workspace_root().join("tirbase-demo/reefer")).expect("reefer pack loads")
}

fn pack_profile() -> EnvelopeProfile {
    tirbase_gateway::profiles::load_profile_from_path(
        &workspace_root().join("tirbase-demo/reefer/profiles/reefer.toml"),
    )
    .expect("parse reefer profile")
}

/// Device model matching `profiles/reefer.toml`; used by install validation.
fn reefer_device_model() -> DeviceModel {
    let deg_c = |min: i64, max: i64| {
        [
            FixedPointValue::new(min, -1, 1),
            FixedPointValue::new(max, -1, 1),
        ]
    };
    let boolean = || [FixedPointValue::new(0, 0, 7), FixedPointValue::new(1, 0, 7)];
    let range = |name: &str, min: i64, max: i64| DeviceParameter {
        name: name.to_string(),
        unit_id: 1,
        unit_label: "degC".to_string(),
        range: deg_c(min, max),
        writable: true,
    };
    let bit = |name: &str| DeviceParameter {
        name: name.to_string(),
        unit_id: 7,
        unit_label: "boolean".to_string(),
        range: boolean(),
        writable: true,
    };
    DeviceModel {
        device_class: "reefer".to_string(),
        parameters: vec![
            range("ambient_c", -450, 500),
            range("temperature_setpoint_c", -300, -180),
            bit("door_open"),
            bit("power_state"),
            bit("defrost_mode"),
            bit("compressor_on"),
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
fn reefer_profile_installs_with_the_committed_signature() {
    let profile = pack_profile();
    assert_eq!(profile.device_class, "reefer");
    assert_eq!(profile.parameters.len(), 6);

    let pa = InMemoryKeyProvider::from_seed(FIXTURE_PA_SEED);
    let trust = pa_trust_root(pa.did(), pa.public_key_bytes());
    let signer = install_profile(&profile, &reefer_device_model(), &trust)
        .expect("reefer pack profile must install against its device model");
    assert_eq!(signer, pa.did());
}

#[test]
fn tampered_reefer_profile_is_refused_at_install() {
    let mut profile = pack_profile();
    let ambient = profile
        .parameters
        .iter_mut()
        .find(|parameter| parameter.name == "ambient_c")
        .expect("ambient parameter");
    // Widen the ambient drift budget after signing: the committed signature fails.
    ambient.max_delta_in_window = FixedPointValue::new(300, -1, 1);

    let pa = InMemoryKeyProvider::from_seed(FIXTURE_PA_SEED);
    let trust = pa_trust_root(pa.did(), pa.public_key_bytes());
    let error = install_profile(&profile, &reefer_device_model(), &trust)
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
/// the out-of-band quorum for the critical cargo setpoint has been granted.
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
}

fn harness_at(db: &Path) -> Harness {
    let ca = InMemoryKeyProvider::generate().expect("ca key");
    let issuer = InMemoryKeyProvider::generate().expect("issuer key");
    let target = TargetId::new(TARGET);

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
        TimeRatchet::open(Arc::new(RatchetStore::default()), TimeRatchetConfig::default())
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
    pipeline.set_drift_store(open_drift_timing_store(db).expect("drift store"));
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
        stage16: SqliteStage16Store::open(db).expect("stage16 store"),
        issuer,
        tokens,
        critical_params,
        target,
        entry_ids: AtomicU64::new(1),
    }
}

/// Actual result of one scenario step.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StepResult {
    disposition: StepDisposition,
    mechanism: Option<&'static str>,
}

/// A command the guard actually dispatched, in defended order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptedStep {
    param: String,
    at_secs: i64,
    mantissa: i64,
}

struct ScenarioRun {
    steps: Vec<StepResult>,
    accepted: Vec<AcceptedStep>,
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

#[derive(Debug)]
enum StepDecision {
    Accepted,
    Rejected(AdmitRejection),
    Deduplicated,
}

/// Admit one step at `at_secs` against `h`, dispatching on acceptance.
fn admit_step(
    h: &Harness,
    param: &str,
    value: FixedPointValue,
    at_secs: i64,
    sequence: u64,
) -> StepDecision {
    h.clock.set_secs(at_secs);
    let challenge = if h.critical_params.contains(param) {
        Some(
            h.pipeline
                .issue_challenge_nonce(h.issuer.did(), h.target.as_str(), param),
        )
    } else {
        None
    };
    let cmd = command(&h.issuer, &h.target, param, value, sequence, challenge);
    let token = h.tokens.get(param).expect("token for parameter");
    let now_est = 1_000 + (at_secs - 1_000);
    let ctx = AdmitContext {
        ingress: IngressSource::LocalAdmin,
        source_key: "reefer-pack-test",
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
                return StepDecision::Deduplicated;
            }
            let entry = h.entry_ids.fetch_add(1, Ordering::SeqCst);
            let mut entry_id = [0u8; 16];
            entry_id[..8].copy_from_slice(&entry.to_be_bytes());
            h.stage16
                .commit_actuating(&Stage16Request {
                    cmd: &cmd,
                    entry_id,
                    actuating_ts: now_est,
                    now_est,
                    now_mono_secs: at_secs,
                    lease_duration_secs: 30,
                    max_consecutive_renewals: 10,
                    original_result_json: "{\"status\":\"accepted\"}",
                    idempotency_retention_secs:
                        tirbase_guard::commit::DEFAULT_IDEMPOTENCY_RETENTION_SECS,
                })
                .unwrap_or_else(|error| panic!("stage16 commit failed: {error:?}"));
            StepDecision::Accepted
        }
        AdmitDecision::Rejected { category, .. } => StepDecision::Rejected(category),
        other => panic!("step produced {other:?}"),
    }
}

fn run_scenario_at(pack: &Pack, scenario_id: &str, db: &Path) -> ScenarioRun {
    let scenario = pack.scenario(scenario_id).expect("scenario");
    let expected = pack.expected_outcome(scenario_id).expect("expected output");
    let h = harness_at(db);

    let mut steps = Vec::new();
    let mut accepted = Vec::new();
    let mut actuations = 0usize;

    for step in &scenario.steps {
        let sequence = step.replay_of.unwrap_or(step.sequence);
        match admit_step(&h, &step.param, step.value, step.at_secs, sequence) {
            StepDecision::Accepted => {
                actuations += 1;
                accepted.push(AcceptedStep {
                    param: step.param.clone(),
                    at_secs: step.at_secs,
                    mantissa: step.value.mantissa,
                });
                steps.push(StepResult {
                    disposition: StepDisposition::Accepted,
                    mechanism: None,
                });
            }
            StepDecision::Deduplicated => steps.push(StepResult {
                disposition: StepDisposition::Deduplicated,
                mechanism: Some("idempotency"),
            }),
            StepDecision::Rejected(category) => steps.push(StepResult {
                disposition: StepDisposition::Rejected,
                mechanism: Some(mechanism_for(category)),
            }),
        }
    }

    assert_eq!(
        steps.len(),
        expected.steps.len(),
        "scenario '{scenario_id}' step count"
    );
    ScenarioRun {
        steps,
        accepted,
        actuations,
    }
}

fn run_scenario(pack: &Pack, scenario_id: &str) -> ScenarioRun {
    let directory = tempfile::tempdir().expect("temp dir");
    run_scenario_at(pack, scenario_id, &directory.path().join("primary.db"))
}

/// Longest door-open interval, in seconds, among the accepted steps of `run`.
fn accepted_door_open_secs(run: &ScenarioRun) -> Option<i64> {
    let mut open_since: Option<i64> = None;
    let mut longest: Option<i64> = None;
    let mut last_secs = 0;
    for step in run.accepted.iter().filter(|step| step.param == "door_open") {
        last_secs = last_secs.max(step.at_secs);
        match step.mantissa {
            1 => open_since = open_since.or(Some(step.at_secs)),
            0 => {
                if let Some(start) = open_since.take() {
                    longest = Some(longest.unwrap_or(0).max(step.at_secs - start));
                }
            }
            _ => {}
        }
    }
    if let Some(start) = open_since {
        longest = Some(longest.unwrap_or(0).max(last_secs - start));
    }
    longest
}

// ---------------------------------------------------------------------------
// Scenario defense
// ---------------------------------------------------------------------------

#[test]
fn every_reefer_scenario_matches_its_expected_output() {
    let pack = pack();
    assert_eq!(pack.scenarios.len(), 5, "pack ships five scenarios");
    let classes: Vec<AdversaryClass> = pack.scenarios.iter().map(|s| s.class).collect();
    assert!(classes.contains(&AdversaryClass::S1));
    assert!(classes.contains(&AdversaryClass::S2));

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
fn door_open_in_transit_quarantines_the_trip() {
    let pack = pack();
    let run = run_scenario(&pack, "S2_door_open_in_transit");
    let trip = pack.trip.as_ref().expect("trip metadata");

    // The excursion is a consequence of the defended timeline: the attacker's
    // early close and quick reopen were refused, so the door really is open for
    // the full 300 s.
    assert_eq!(run.steps[1].mechanism, Some("dwell"));
    assert_eq!(run.steps[3].mechanism, Some("min_off"));
    assert_eq!(run.actuations, 2);

    let door_open_secs = accepted_door_open_secs(&run).expect("accepted door interval");
    assert_eq!(door_open_secs, 300);
    assert!(
        door_open_secs > i64::from(trip.max_door_open_secs),
        "300 s open must exceed the {}s excursion rule",
        trip.max_door_open_secs
    );

    // The pack's own derivation and the gateway's observation agree.
    assert_eq!(
        pack.door_open_secs("S2_door_open_in_transit"),
        Some(door_open_secs)
    );
    let expected_trip = pack.expected.trip.as_ref().expect("expected trip");
    assert_eq!(expected_trip.disposition, TripDisposition::Quarantined);
    assert_eq!(expected_trip.door_open_secs, door_open_secs);
    assert_eq!(
        pack.derived_trip_disposition("S2_door_open_in_transit"),
        Some(expected_trip.disposition)
    );
    assert_eq!(trip.trip_id, "TRIP-2026-1115-0042");
    assert_eq!(trip.container_id, "MSCU1234567");
}

// ---------------------------------------------------------------------------
// Power loss and recovery
// ---------------------------------------------------------------------------

#[test]
fn power_loss_and_recovery_keep_the_excursion_record() {
    let pack = pack();
    let trip = pack.trip.as_ref().expect("trip metadata");
    let directory = tempfile::tempdir().expect("temp dir");
    let db = directory.path().join("primary.db");

    // Trip in progress: the door excursion happens and is quarantined.
    let run = run_scenario_at(&pack, "S2_door_open_in_transit", &db);
    let door_open_secs = accepted_door_open_secs(&run).expect("accepted door interval");
    assert_eq!(door_open_secs, 300);
    assert_eq!(run.steps[2].disposition, StepDisposition::Accepted);

    // The excursion record is booked against the cold-chain vertical store, in
    // the same SQLite database the guard's ledger lives in.
    let record_id = "reefer-trip-excursion-1";
    {
        let api = VerticalApi::open(&db).expect("open vertical api");
        let (status, body) = api.dispatch(
            "POST",
            "/admin/cold-chain/sites",
            Some(
                &json!({
                    "id": "site-reefer-1",
                    "name": "Reefer MSCU1234567",
                    "tenant": "default",
                    "container_id": trip.container_id,
                    "trailer_id": trip.trailer_id,
                })
                .to_string(),
            ),
            1_300,
        );
        assert!(
            status == 200 || status == 201,
            "create site failed: {status} {body}"
        );

        let (status, body) = api.dispatch(
            "POST",
            "/admin/cold-chain/sites/site-reefer-1/readings",
            Some(
                &json!({
                    "id": record_id,
                    "tenant": "default",
                    "celsius_milli": -18_000,
                    "trip_id": trip.trip_id,
                    "container_id": trip.container_id,
                    "disposition": "quarantined",
                    "mechanism": "door_open_in_transit",
                    "door_open_secs": door_open_secs,
                    "max_door_open_secs": trip.max_door_open_secs,
                })
                .to_string(),
            ),
            1_300,
        );
        assert!(
            status == 200 || status == 201,
            "create excursion reading failed: {status} {body}"
        );
        // Dropping the API, the stage-16 store and every in-memory structure is
        // the power loss: nothing is flushed beyond what reached the database.
    }

    // Recovery: reopen the same database as a fresh process would.
    let api = VerticalApi::open(&db).expect("reopen vertical api");
    let (status, body) = api.dispatch(
        "GET",
        "/admin/cold-chain/sites/site-reefer-1/readings?tenant=default",
        None,
        1_400,
    );
    assert_eq!(status, 200, "list readings after restart: {body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("readings JSON");
    let record = listed["items"]
        .as_array()
        .expect("items array")
        .iter()
        .find(|item| item["id"] == record_id)
        .expect("the excursion record survived the power loss");
    assert_eq!(record["data"]["disposition"], "quarantined");
    assert_eq!(record["data"]["mechanism"], "door_open_in_transit");
    assert_eq!(record["data"]["door_open_secs"], door_open_secs);
    assert_eq!(record["data"]["trip_id"], trip.trip_id);

    // The guard's own durable state agrees: the door is recorded closed, and the
    // deactivation stamp is what dwell/min-off read after a restart.
    let state = SqliteTargetStateStore::open(&db)
        .expect("reopen target state")
        .load_all()
        .expect("load target state");
    assert_eq!(
        state.get(&(TARGET.to_string(), "door_open".to_string())),
        Some(&FixedPointValue::new(0, 0, 7)),
        "the door state must survive the power cut"
    );
    let timing = open_drift_timing_store(&db)
        .expect("reopen drift store")
        .timing_summary(TARGET, "door_open")
        .expect("timing summary")
        .expect("door_open timing summary");
    assert_eq!(
        timing.last_deactivation_mono,
        Some(1_300),
        "the saved deactivation time is the excursion record's anchor"
    );

    // Recovery keeps enforcing the interlock: a reopen at 1400 s is still inside
    // the 600 s min-off window.
    let h = harness_at(&db);
    match admit_step(&h, "door_open", FixedPointValue::new(1, 0, 7), 1_400, 4) {
        StepDecision::Rejected(AdmitRejection::MinOffViolation) => {}
        other => panic!("post-restart reopen must still hit min-off, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Data-only
// ---------------------------------------------------------------------------

/// The pack registers no executable code, so the gateway test also asserts the
/// only files it can see are data documents (defence in depth for the Python
/// purity gate in CI).
#[test]
fn reefer_pack_is_data_only_from_the_gateway_side() {
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
    walk(&workspace_root().join("tirbase-demo/reefer"), &mut files);
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
