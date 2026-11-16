// SPDX-License-Identifier: AGPL-3.0-only

//! Workflow-pack end-to-end integration (CC-13, AGPL).
//!
//! Proves the three committed workflow documents drive the real excursion
//! workflow: the pack's thresholds decide detection, its debounce rule decides
//! whether a quarantine is raised, its windows bound the assessment, its routes
//! are the channels that receive the alert, and its disposition code names the
//! decision. The same binary therefore behaves differently after a config edit —
//! no rebuild.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_demo::workflow::WorkflowConfig;
use tirbase_gateway::excursion::config::ExcursionPolicy;
use tirbase_gateway::excursion::mkt::MKT_UNIT_ID;
use tirbase_gateway::excursion::notifier::{
    ExcursionNotification, ExcursionNotifier, NotificationEvent, NotifierDispatcher,
};
use tirbase_gateway::excursion::{
    evaluate_detection, DetectionInputs, DispositionKind, DispositionPayload, DispositionRequest,
    EvidenceBundle, ExcursionReason, ExcursionState, ExcursionWorkflow, SignedResolution,
};
use tirbase_gateway::lot::{LotDraft, LotKind, LotRegistry};
use tirbase_types::{CommandRole, DeviceSignature, FixedPointValue};

use tirbase_gateway::excursion::config::LotDefaults;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack_dir(id: &str) -> PathBuf {
    workspace_root().join("tirbase-demo").join(id)
}

fn policy(id: &str) -> ExcursionPolicy {
    let dir = pack_dir(id);
    ExcursionPolicy::from_pack_dir(&dir).unwrap_or_else(|error| panic!("policy for {id}: {error}"))
}

fn deci_c(value: i64) -> FixedPointValue {
    FixedPointValue::new(value, -1, MKT_UNIT_ID)
}

fn lot_kind(name: &str) -> LotKind {
    LotKind::parse(name).unwrap_or_else(|| panic!("unknown lot kind {name}"))
}

#[derive(Debug)]
struct RecordingNotifier {
    channel: String,
    events: Mutex<Vec<NotificationEvent>>,
}

impl RecordingNotifier {
    fn new(channel: &str) -> Self {
        Self {
            channel: channel.to_string(),
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<NotificationEvent> {
        self.events.lock().expect("events").clone()
    }
}

impl ExcursionNotifier for RecordingNotifier {
    fn channel(&self) -> &str {
        &self.channel
    }

    fn deliver(&self, notification: &ExcursionNotification) -> Result<(), String> {
        self.events.lock().expect("events").push(notification.event);
        Ok(())
    }
}

/// In-band detection inputs for a policy: the middle of the labelled band.
fn inside_band(policy: &ExcursionPolicy) -> DetectionInputs {
    let thresholds = policy.thresholds();
    let middle = (thresholds.band_min_c.mantissa + thresholds.band_max_c.mantissa) / 2;
    DetectionInputs {
        temperature_c: Some(deci_c(middle)),
        previous_temperature_c: Some(deci_c(middle)),
        elapsed_secs: policy.sampling_interval_secs(),
        samples: vec![deci_c(middle); 3],
        ..Default::default()
    }
}

/// Out-of-band detection inputs: four degrees above the labelled band.
fn above_band(policy: &ExcursionPolicy) -> DetectionInputs {
    let hot = policy.thresholds().band_max_c.mantissa + 40;
    DetectionInputs {
        temperature_c: Some(deci_c(hot)),
        previous_temperature_c: Some(deci_c(hot)),
        elapsed_secs: policy.sampling_interval_secs(),
        samples: vec![deci_c(hot); 4],
        ..Default::default()
    }
}

fn dispatcher_for(policy: &ExcursionPolicy) -> (NotifierDispatcher, Vec<Arc<RecordingNotifier>>) {
    let mut dispatcher = NotifierDispatcher::new();
    let mut recorders = Vec::new();
    let mut registered: BTreeSet<String> = BTreeSet::new();
    for route in policy.enabled_routes() {
        if registered.insert(route.channel.clone()) {
            let recorder = Arc::new(RecordingNotifier::new(&route.channel));
            dispatcher = dispatcher.with(recorder.clone());
            recorders.push(recorder);
        }
    }
    (dispatcher, recorders)
}

fn sign_disposition(
    operator: &InMemoryKeyProvider,
    payload: &DispositionPayload,
) -> DeviceSignature {
    operator.sign(&payload.signing_bytes()).expect("sign")
}

/// Drive a complete nominal excursion for `lot_id` under `policy` and return the
/// closed record plus the policy values the run was checked against.
fn nominal_excursion(
    policy: &ExcursionPolicy,
    lot_id: &str,
    base_est: i64,
) -> tirbase_gateway::excursion::ExcursionRecord {
    let workflow = ExcursionWorkflow::open_in_memory().expect("workflow");

    // In-band samples do not trigger; the pack's band is what says so.
    let thresholds = policy.thresholds();
    let calm = evaluate_detection(&thresholds, &inside_band(policy), base_est);
    assert!(
        !calm.triggered(),
        "{lot_id}: in-band samples must not trigger ({:?})",
        calm.findings
    );

    // Out-of-band samples do.
    let detection = evaluate_detection(&thresholds, &above_band(policy), base_est + 60);
    assert!(detection.triggered(), "{lot_id}: hot samples must trigger");

    // The debounce rule decides whether the finding series becomes a quarantine.
    let gate = policy.debounce();
    let observations: Vec<i64> = (0..gate.min_findings())
        .map(|index| base_est + 60 + i64::from(index))
        .collect();
    assert!(gate.admits(&observations, None, base_est + 120));
    if gate.min_findings() > 1 {
        let fewer = &observations[..observations.len() - 1];
        assert!(
            !gate.admits(fewer, None, base_est + 120),
            "{lot_id}: fewer findings than the debounce minimum must not raise"
        );
    }
    assert!(
        !gate.admits(&observations, Some(base_est + 120), base_est + 121),
        "{lot_id}: the cooldown must suppress an immediate re-raise"
    );

    workflow
        .detect(
            "EXC-WORKFLOW",
            "tenant-workflow",
            "SITE-1",
            "dev-freezer-1",
            Some(lot_id),
            detection,
            base_est + 120,
        )
        .expect("detect");
    let quarantined = workflow
        .open_quarantine("EXC-WORKFLOW", base_est + 121)
        .expect("quarantine");
    assert_eq!(
        policy.assessment_deadline_est(quarantined.opened_est),
        quarantined.opened_est + i64::from(policy.assessment_secs())
    );
    assert!(!policy.quarantine_overdue(
        quarantined.opened_est,
        policy.assessment_deadline_est(quarantined.opened_est)
    ));

    let (dispatcher, recorders) = dispatcher_for(policy);
    let delivery = workflow
        .notify(
            "EXC-WORKFLOW",
            &dispatcher,
            NotificationEvent::QuarantineOpened,
            base_est + 122,
        )
        .expect("notify");
    assert!(!recorders.is_empty(), "{lot_id}: no enabled route");
    for recorder in &recorders {
        assert!(
            !recorder.events().is_empty(),
            "{lot_id}: channel {} received nothing",
            recorder.channel()
        );
    }
    assert_eq!(
        delivery.still_pending, 0,
        "{lot_id}: every configured channel accepted the alert"
    );

    // The disposition uses the pack's declared code for a rejection.
    let code = policy
        .disposition_code(DispositionKind::Reject)
        .unwrap_or_else(|| panic!("{lot_id}: no reject code"));
    assert!(!code.trim().is_empty());

    let operator = InMemoryKeyProvider::from_seed([0x37; 32]);
    let record = workflow.get("EXC-WORKFLOW").expect("record");
    let reason = ExcursionReason::TemperatureOutOfBand.as_str().to_string();
    let evidence = EvidenceBundle {
        temperature_samples: 4,
        mkt_c: record.detection.mkt_c,
        detection_digest: record.detection.digest(),
        quarantine_opened_est: record.opened_est,
        ledger_entry: Some(code.to_string()),
        notes: format!("{lot_id} rejected under {code}"),
    };
    let payload = DispositionPayload {
        record_id: "EXC-WORKFLOW".to_string(),
        disposition: DispositionKind::Reject,
        reason: reason.clone(),
        operator_did: operator.did().to_string(),
        operator_role: CommandRole::CommandIssuer,
        evidence_digest: evidence.digest(),
        note: "config-driven rejection".to_string(),
        decided_est: base_est + 200,
    };
    workflow
        .record_disposition(
            "EXC-WORKFLOW",
            DispositionRequest {
                disposition: DispositionKind::Reject,
                reason,
                operator_did: operator.did().to_string(),
                operator_role: CommandRole::CommandIssuer,
                evidence,
                note: "config-driven rejection".to_string(),
                signature: sign_disposition(&operator, &payload),
                decided_est: base_est + 200,
            },
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            base_est + 201,
        )
        .expect("disposition");

    let resolution = workflow
        .resolution_payload("EXC-WORKFLOW")
        .expect("resolution payload");
    let mut signed = SignedResolution::new(&resolution, base_est + 202, None).expect("resolution");
    signed
        .sign_with(&operator, CommandRole::CommandIssuer)
        .expect("sign resolution");
    workflow
        .sign_resolution(
            "EXC-WORKFLOW",
            &signed,
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            base_est + 203,
        )
        .expect("resolve");
    let closed = workflow
        .close("EXC-WORKFLOW", base_est + 204)
        .expect("close");
    assert_eq!(closed.state, ExcursionState::Closed);
    closed
}

// ---------------------------------------------------------------------------
// All three packs complete a nominal excursion
// ---------------------------------------------------------------------------

#[test]
fn all_three_packs_complete_a_nominal_excursion() {
    for id in ["cold-room", "reefer", "pharma-gdp"] {
        let policy = policy(id);
        let defaults = policy.lot_defaults();
        let lot_id = format!("{}-2026-1116-0001", defaults.label_prefix);
        let base_est = 1_780_000_000;

        let closed = nominal_excursion(&policy, &lot_id, base_est);
        assert_eq!(closed.lot_id.as_deref(), Some(lot_id.as_str()));
        assert!(closed.disposition.is_some());
        assert!(closed.resolution.is_some());

        // The decision is visible to lot traceability through the CC-11 bridge.
        let registry = LotRegistry::open_in_memory().expect("lot registry");
        registry
            .register(LotDraft::new(
                &lot_id,
                "tenant-workflow",
                lot_kind(defaults.lot_kind),
                "SITE-1",
                "COLD-1",
                100,
                defaults.uom,
                base_est,
            ))
            .expect("register lot");
        let link = registry
            .link_excursion(&closed, base_est + 205)
            .expect("bridge excursion");
        assert_eq!(link.record_id, "EXC-WORKFLOW");
        assert_eq!(link.disposition, DispositionKind::Reject.as_str());
        assert_eq!(link.reason, ExcursionReason::TemperatureOutOfBand.as_str());
        assert_eq!(
            registry.dispositions(&lot_id).expect("dispositions"),
            vec![link]
        );

        // Policy surfaces are wired to the document, not hard-coded.
        assert_eq!(policy.config().pack, id);
        assert_eq!(policy.mkt().max_samples, policy.config().mkt.max_samples);
        assert_eq!(
            policy.routes().len(),
            policy.config().notification.routes.len()
        );
        assert!(!policy.disposition_kinds().is_empty());
        assert_eq!(
            policy.sampling_interval_secs(),
            policy.config().windows.sampling_interval_secs
        );
        let lot_defaults: LotDefaults<'_> = policy.lot_defaults();
        assert_eq!(lot_defaults.uom, policy.config().lot.uom);
    }
}

// ---------------------------------------------------------------------------
// Editing the document changes behaviour without a rebuild
// ---------------------------------------------------------------------------

#[test]
fn widening_the_band_in_the_document_changes_detection() {
    let path = pack_dir("pharma-gdp").join("workflow.toml");
    let text = std::fs::read_to_string(&path).expect("read workflow");
    let hot = 200; // 20.0 °C, above the 2–8 °C band.

    let narrow = ExcursionPolicy::from_config(
        WorkflowConfig::parse(&text, "pharma-gdp/workflow.toml").expect("committed config"),
    );
    let inputs = DetectionInputs {
        temperature_c: Some(deci_c(hot)),
        previous_temperature_c: Some(deci_c(hot)),
        elapsed_secs: narrow.sampling_interval_secs(),
        ..Default::default()
    };
    let triggered = evaluate_detection(&narrow.thresholds(), &inputs, 1_780_000_000);
    assert!(
        triggered
            .reasons()
            .contains(&ExcursionReason::TemperatureOutOfBand),
        "the committed band must flag 20 °C"
    );

    // Same binary, different document: a 0–30 °C band accepts the same sample.
    let widened_text = text.replacen(
        "band_max_c = { mantissa = 80, exponent = -1, unit_id = 1 }",
        "band_max_c = { mantissa = 300, exponent = -1, unit_id = 1 }",
        1,
    );
    assert_ne!(widened_text, text);
    let widened = ExcursionPolicy::from_config(
        WorkflowConfig::parse(&widened_text, "edited-workflow.toml").expect("edited config"),
    );
    let accepted = evaluate_detection(&widened.thresholds(), &inputs, 1_780_000_000);
    assert!(
        !accepted.triggered(),
        "widened band must accept 20 °C: {:?}",
        accepted.findings
    );
    assert_ne!(narrow.thresholds(), widened.thresholds());
}

#[test]
fn policy_reports_the_field_of_an_invalid_document() {
    let path = pack_dir("cold-room").join("workflow.toml");
    let text = std::fs::read_to_string(&path).expect("read workflow");
    let broken = text.replacen("max_door_open_secs = 120", "max_door_open_secs = 0", 1);
    let error = ExcursionPolicy::from_toml(&broken, "broken-workflow.toml")
        .expect_err("zero door limit must be refused");
    let error = match error {
        tirbase_gateway::excursion::config::PolicyError::Config(error) => error,
        other => panic!("expected a config error, got {other}"),
    };
    assert_eq!(
        error.field().as_deref(),
        Some("thresholds.max_door_open_secs"),
        "was {error}"
    );
}
