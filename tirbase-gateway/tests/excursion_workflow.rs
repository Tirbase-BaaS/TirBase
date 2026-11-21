// SPDX-License-Identifier: AGPL-3.0-only

//! Excursion workflow integration tests (CC-11).
//!
//! Proves the detect → quarantine → notify → disposition → signed resolution →
//! closed path, crash recovery without duplicate notifications or lost
//! dispositions, quarantine visibility across reads and sync, and the MKT
//! reference vectors within the documented tolerance.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::excursion::mkt::{
    mean_kinetic_temperature_c, time_weighted_mkt_c, MktParameters, MktSample, MKT_EXPONENT,
    MKT_GOLDEN_VECTORS, MKT_TOLERANCE_C, MKT_UNIT_ID,
};
use tirbase_gateway::excursion::notifier::{
    DeduplicationFilter, ExcursionNotification, ExcursionNotifier, NotificationEvent,
    NotifierDispatcher,
};
use tirbase_gateway::excursion::{
    advance_state, evaluate_detection, DetectionInputs, DetectionOutcome, DetectionThresholds,
    DispositionKind, DispositionPayload, DispositionRequest, EvidenceBundle, ExcursionError,
    ExcursionReason, ExcursionState, ExcursionWorkflow, ResolutionPayload, SensorFault,
    SensorFaultKind, SignedResolution, SyncOutcome,
};
use tirbase_types::{CommandRole, DeviceSignature, FixedPointValue};

fn deci_c(value: i64) -> FixedPointValue {
    FixedPointValue::new(value, -1, MKT_UNIT_ID)
}

fn milli_c(value: i64) -> FixedPointValue {
    FixedPointValue::new(value, -3, MKT_UNIT_ID)
}

fn thresholds() -> DetectionThresholds {
    DetectionThresholds {
        band_min_c: deci_c(20),
        band_max_c: deci_c(80),
        max_rate_c_per_sec: deci_c(2),
        drift_budget_c: deci_c(50),
        max_door_open_secs: 120,
        max_defrost_secs: 900,
        compressor_max_runtime_secs: 21_600,
        max_telemetry_gap_secs: 300,
        mkt_limit_c: deci_c(80),
        mkt: MktParameters::default(),
    }
}

fn hot_detection(at: i64) -> DetectionOutcome {
    evaluate_detection(
        &thresholds(),
        &DetectionInputs {
            temperature_c: Some(deci_c(120)),
            previous_temperature_c: Some(deci_c(50)),
            elapsed_secs: 300,
            samples: vec![deci_c(50), deci_c(50), deci_c(120), deci_c(120)],
            ..Default::default()
        },
        at,
    )
}

fn sign_disposition(
    operator: &InMemoryKeyProvider,
    payload: &DispositionPayload,
) -> DeviceSignature {
    operator.sign(&payload.signing_bytes()).expect("sign")
}

// ---------------------------------------------------------------------------
// Notifier doubles
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RecordingNotifier {
    channel: &'static str,
    delivered: Mutex<Vec<String>>,
    fail_next: Mutex<BTreeSet<String>>,
}

impl RecordingNotifier {
    fn new(channel: &'static str) -> Self {
        Self {
            channel,
            delivered: Mutex::new(Vec::new()),
            fail_next: Mutex::new(BTreeSet::new()),
        }
    }

    fn fail_record(&self, record_id: &str) {
        self.fail_next
            .lock()
            .expect("fail set")
            .insert(record_id.to_string());
    }

    fn allow_record(&self, record_id: &str) {
        self.fail_next.lock().expect("fail set").remove(record_id);
    }

    fn delivered_ids(&self) -> Vec<String> {
        self.delivered.lock().expect("delivered").clone()
    }
}

impl ExcursionNotifier for RecordingNotifier {
    fn channel(&self) -> &str {
        self.channel
    }

    fn deliver(&self, notification: &ExcursionNotification) -> Result<(), String> {
        let should_fail = self
            .fail_next
            .lock()
            .expect("fail set")
            .contains(&notification.record_id);
        if should_fail {
            return Err("simulated transport failure".to_string());
        }
        self.delivered
            .lock()
            .expect("delivered")
            .push(notification.notification_id.clone());
        Ok(())
    }
}

#[derive(Debug)]
struct CountingNotifier {
    channel: &'static str,
    deliveries: AtomicUsize,
}

impl CountingNotifier {
    fn new(channel: &'static str) -> Self {
        Self {
            channel,
            deliveries: AtomicUsize::new(0),
        }
    }

    fn count(&self) -> usize {
        self.deliveries.load(Ordering::SeqCst)
    }
}

impl ExcursionNotifier for CountingNotifier {
    fn channel(&self) -> &str {
        self.channel
    }

    fn deliver(&self, _notification: &ExcursionNotification) -> Result<(), String> {
        self.deliveries.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MKT reference vectors and numeric behaviour
// ---------------------------------------------------------------------------

#[test]
fn mkt_matches_reference_vectors_within_documented_tolerance() {
    let parameters = MktParameters::default();
    for vector in MKT_GOLDEN_VECTORS {
        let samples: Vec<FixedPointValue> = vector
            .temperatures_deci_c
            .iter()
            .map(|deci| deci_c(*deci))
            .collect();
        let observed = mean_kinetic_temperature_c(&parameters, &samples)
            .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        let celsius = observed.mantissa as f64 / 1000.0;
        assert_eq!(
            observed.exponent, MKT_EXPONENT,
            "{} must be reported in milli-degrees",
            vector.name
        );
        assert_eq!(observed.unit_id, MKT_UNIT_ID);
        assert!(
            (celsius - vector.expected_c).abs() <= MKT_TOLERANCE_C,
            "{}: got {celsius} °C, expected {} °C, tolerance {MKT_TOLERANCE_C} °C",
            vector.name,
            vector.expected_c
        );
    }
}

#[test]
fn mkt_uses_configurable_activation_energy() {
    let haynes = MktParameters::default();
    let conservative = MktParameters::new(50_000, 8_314);
    let samples = [deci_c(50), deci_c(120), deci_c(120), deci_c(50)];
    let haynes_mkt = mean_kinetic_temperature_c(&haynes, &samples).expect("haynes");
    let conservative_mkt = mean_kinetic_temperature_c(&conservative, &samples).expect("alt");
    // Lower activation energy makes the warm interval weigh a little less, so the
    // single equivalent temperature is lower than the Haynes result.
    assert!(
        conservative_mkt.mantissa < haynes_mkt.mantissa,
        "MKT must respond to the configured activation energy"
    );
    assert!(conservative_mkt.mantissa > milli_c(5_000).mantissa);
}

#[test]
fn time_weighted_mkt_matches_documented_reference() {
    let parameters = MktParameters::default();
    let samples = [
        MktSample {
            temperature_c: milli_c(5_000),
            duration_secs: 8 * 3600,
        },
        MktSample {
            temperature_c: milli_c(15_000),
            duration_secs: 4 * 3600,
        },
    ];
    let mkt = time_weighted_mkt_c(&parameters, &samples).expect("weighted mkt");
    let celsius = mkt.mantissa as f64 / 1000.0;
    assert!(
        (celsius - 9.744131).abs() <= MKT_TOLERANCE_C,
        "weighted MKT {celsius} °C outside the documented tolerance"
    );
}

#[test]
fn mkt_rejects_bad_series() {
    let parameters = MktParameters::default();
    assert!(mean_kinetic_temperature_c(&parameters, &[]).is_err());
    assert!(mean_kinetic_temperature_c(&parameters, &[FixedPointValue::new(50, -1, 6)]).is_err());
}

// ---------------------------------------------------------------------------
// Detection inputs
// ---------------------------------------------------------------------------

#[test]
fn detection_covers_every_input_class() {
    let outcome = evaluate_detection(
        &thresholds(),
        &DetectionInputs {
            temperature_c: Some(deci_c(120)),
            previous_temperature_c: Some(deci_c(50)),
            elapsed_secs: 10,
            drift_c: Some(deci_c(60)),
            door_open_secs: 300,
            defrost_secs: 1_200,
            compressor_on_secs: 22_000,
            sensor_fault: Some(SensorFault {
                sensor_id: "PHARMA-2-8-A".to_string(),
                kind: SensorFaultKind::Disconnected,
            }),
            telemetry_gap_secs: Some(900),
            samples: vec![deci_c(50), deci_c(120), deci_c(120), deci_c(50)],
        },
        1_770_000_000,
    );

    let reasons: BTreeSet<_> = outcome.reasons().into_iter().collect();
    for reason in [
        ExcursionReason::TemperatureOutOfBand,
        ExcursionReason::RateExceeded,
        ExcursionReason::DriftExceeded,
        ExcursionReason::DoorOpenTooLong,
        ExcursionReason::DefrostTooLong,
        ExcursionReason::CompressorRuntimeExceeded,
        ExcursionReason::SensorFault,
        ExcursionReason::MissingTelemetry,
        ExcursionReason::MktExceeded,
    ] {
        assert!(
            reasons.contains(&reason),
            "detection must report {reason:?}; got {reasons:?}"
        );
    }
    assert!(outcome.mkt_c.is_some());
}

#[test]
fn missing_temperature_is_a_telemetry_finding() {
    let outcome = evaluate_detection(
        &thresholds(),
        &DetectionInputs {
            temperature_c: None,
            ..Default::default()
        },
        1_770_000_000,
    );
    assert_eq!(outcome.reasons(), vec![ExcursionReason::MissingTelemetry]);
}

// ---------------------------------------------------------------------------
// Full workflow
// ---------------------------------------------------------------------------

fn workflow(path: &std::path::Path) -> ExcursionWorkflow {
    ExcursionWorkflow::open(path).expect("open workflow")
}

fn detect_and_quarantine(
    wf: &ExcursionWorkflow,
    record_id: &str,
    dispatcher: &NotifierDispatcher,
    now_est: i64,
) -> String {
    let detection = hot_detection(now_est);
    let record = wf
        .detect(
            record_id,
            "tenant-a",
            "site-1",
            "dev-1",
            Some("LOT-2026-1115-0042"),
            detection,
            now_est,
        )
        .expect("detect");
    assert_eq!(record.state, ExcursionState::Detected);

    let quarantined = wf
        .open_quarantine(record_id, now_est + 1)
        .expect("quarantine");
    assert_eq!(quarantined.state, ExcursionState::Quarantined);

    let report = wf
        .notify(
            record_id,
            dispatcher,
            NotificationEvent::QuarantineOpened,
            now_est + 2,
        )
        .expect("notify");
    assert!(report.advanced_to_notified);
    record_id.to_string()
}

#[test]
fn detect_to_signed_resolution_completes_end_to_end() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("primary.db");
    let wf = workflow(&db);

    let operator = InMemoryKeyProvider::from_seed([0x21; 32]);
    let pager = Arc::new(CountingNotifier::new("pager"));
    let dispatcher = NotifierDispatcher::new().with(pager.clone());

    let record_id = detect_and_quarantine(&wf, "exc-1", &dispatcher, 1_770_000_000);
    assert_eq!(pager.count(), 1, "exactly one quarantine notification");

    let record = wf.get(&record_id).expect("load");
    assert_eq!(record.state, ExcursionState::Notified);
    let reasons = record.reasons();
    assert!(reasons.contains(&ExcursionReason::TemperatureOutOfBand));
    assert!(reasons.contains(&ExcursionReason::MktExceeded));

    // Quarantine is visible to reads.
    let view = wf.quarantine_view(&record_id).expect("view");
    assert_eq!(view.state, ExcursionState::Notified);
    assert_eq!(view.tenant, "tenant-a");
    assert_eq!(view.lot_id.as_deref(), Some("LOT-2026-1115-0042"));

    let evidence = EvidenceBundle {
        temperature_samples: record.detection.mkt_c.is_some() as u32 + 3,
        mkt_c: record.detection.mkt_c,
        detection_digest: record.detection.digest(),
        quarantine_opened_est: record.opened_est,
        ledger_entry: Some("ledger:exc-1:12".to_string()),
        notes: "Holding pending lab assessment.".to_string(),
    };
    let payload = DispositionPayload {
        record_id: record_id.clone(),
        disposition: DispositionKind::Hold,
        reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
        operator_did: operator.did().to_string(),
        operator_role: CommandRole::CommandIssuer,
        evidence_digest: evidence.digest(),
        note: "Holding pending lab assessment.".to_string(),
        decided_est: 1_770_000_100,
    };
    let disposition = wf
        .record_disposition(
            &record_id,
            DispositionRequest {
                disposition: DispositionKind::Hold,
                reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
                operator_did: operator.did().to_string(),
                operator_role: CommandRole::CommandIssuer,
                evidence: evidence.clone(),
                note: "Holding pending lab assessment.".to_string(),
                signature: sign_disposition(&operator, &payload),
                decided_est: 1_770_000_100,
            },
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            1_770_000_101,
        )
        .expect("disposition");
    assert_eq!(disposition.state, ExcursionState::Dispositioned);
    let stored = disposition.disposition.expect("disposition record");
    assert_eq!(stored.disposition, DispositionKind::Hold);
    assert_eq!(stored.operator_did, operator.did());
    assert_eq!(stored.evidence, evidence);

    let resolution_payload = wf.resolution_payload(&record_id).expect("payload");
    assert_eq!(
        resolution_payload,
        ResolutionPayload {
            record_id: record_id.clone(),
            disposition: DispositionKind::Hold,
            reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
            operator_did: operator.did().to_string(),
            evidence_digest: stored.evidence_digest.clone(),
            decided_est: 1_770_000_100,
            site_id: "site-1".to_string(),
            lot_id: Some("LOT-2026-1115-0042".to_string()),
        }
    );
    let mut signed =
        SignedResolution::new(&resolution_payload, 1_770_000_200, None).expect("build resolution");
    signed
        .sign_with(&operator, CommandRole::CommandIssuer)
        .expect("sign resolution");

    let resolved = wf
        .sign_resolution(
            &record_id,
            &signed,
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            1_770_000_201,
        )
        .expect("resolve");
    assert_eq!(resolved.state, ExcursionState::Resolved);
    assert!(resolved.resolution.is_some());

    let closed = wf.close(&record_id, 1_770_000_300).expect("close");
    assert_eq!(closed.state, ExcursionState::Closed);
    assert_eq!(closed.closed_est, Some(1_770_000_300));

    let history = wf.history(&record_id).expect("history");
    let events: Vec<&str> = history.iter().map(|entry| entry.event.as_str()).collect();
    assert_eq!(
        events,
        vec![
            "detected",
            "quarantined",
            "notified",
            "dispositioned",
            "resolved",
            "closed",
        ]
    );
}

#[test]
fn quarantine_survives_restart() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("primary.db");

    {
        let wf = workflow(&db);
        let pager = Arc::new(CountingNotifier::new("pager"));
        let dispatcher = NotifierDispatcher::new().with(pager);
        detect_and_quarantine(&wf, "exc-restart", &dispatcher, 1_770_000_000);
    }

    let wf = workflow(&db);
    let view = wf
        .quarantine_view("exc-restart")
        .expect("view after restart");
    assert_eq!(view.state, ExcursionState::Notified);
    assert!(view
        .reasons()
        .contains(&ExcursionReason::TemperatureOutOfBand));
    assert_eq!(view.lot_id.as_deref(), Some("LOT-2026-1115-0042"));
    assert_eq!(view.version, 3, "detected + quarantined + notified");

    // Reads and lists expose the same quarantined record.
    let listed = wf.list(Some("tenant-a"), None).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].record_id, "exc-restart");
}

#[test]
fn crash_recovery_retries_notifications_without_duplicates_and_keeps_disposition() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("primary.db");
    let operator = InMemoryKeyProvider::from_seed([0x33; 32]);

    // Open a quarantine, make the pager refuse, then "crash".
    let pager = Arc::new(RecordingNotifier::new("pager"));
    let dispatcher = NotifierDispatcher::new().with(pager.clone());
    {
        let wf = workflow(&db);
        let detection = hot_detection(1_770_000_000);
        wf.detect(
            "exc-crash",
            "tenant-a",
            "site-1",
            "dev-1",
            Some("LOT-1"),
            detection.clone(),
            1_770_000_000,
        )
        .expect("detect");
        wf.open_quarantine("exc-crash", 1_770_000_001)
            .expect("quarantine");
        pager.fail_record("exc-crash");
        let report = wf
            .notify(
                "exc-crash",
                &dispatcher,
                NotificationEvent::QuarantineOpened,
                1_770_000_002,
            )
            .expect("notify attempt");
        assert_eq!(report.still_pending, 1);
        assert_eq!(
            wf.get("exc-crash").expect("load").state,
            ExcursionState::Quarantined
        );

        // Recovery while the channel is still down: still quarantined, still pending.
        let down = wf
            .recover(&dispatcher, 1_770_000_003)
            .expect("recover while down");
        assert_eq!(down.awaiting_notification, 1);
        assert_eq!(down.undelivered_notifications, 1);
        assert_eq!(pager.delivered_ids().len(), 0);

        // The operator dispositions the quarantined lot before delivery succeeds.
        let evidence = EvidenceBundle {
            temperature_samples: 4,
            mkt_c: detection.mkt_c,
            detection_digest: detection.digest(),
            quarantine_opened_est: 1_770_000_000,
            ledger_entry: None,
            notes: "hold".to_string(),
        };
        let payload = DispositionPayload {
            record_id: "exc-crash".to_string(),
            disposition: DispositionKind::Hold,
            reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
            operator_did: operator.did().to_string(),
            operator_role: CommandRole::CommandIssuer,
            evidence_digest: evidence.digest(),
            note: "hold".to_string(),
            decided_est: 1_770_000_010,
        };
        wf.record_disposition(
            "exc-crash",
            DispositionRequest {
                disposition: DispositionKind::Hold,
                reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
                operator_did: operator.did().to_string(),
                operator_role: CommandRole::CommandIssuer,
                evidence,
                note: "hold".to_string(),
                signature: sign_disposition(&operator, &payload),
                decided_est: 1_770_000_010,
            },
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            1_770_000_011,
        )
        .expect("disposition while pending");
        // Drop everything: crash with one pending outbox row and one disposition.
    }

    // Restart: the disposition is still there and recovery must not lose it or
    // duplicate the pager delivery.
    pager.allow_record("exc-crash");
    let wf = workflow(&db);
    let report = wf.recover(&dispatcher, 1_770_000_100).expect("recover");

    let record = wf.get("exc-crash").expect("record after restart");
    assert_eq!(
        record.state,
        ExcursionState::Dispositioned,
        "recovery must never discard a recorded disposition"
    );
    assert!(record.disposition.is_some());
    assert_eq!(report.dispositioned, 1);

    // The pager sees the quarantine notification exactly once even though the
    // crash happened between "row written" and "transport accepted".
    assert_eq!(pager.delivered_ids().len(), 1);

    // A second recovery pass must not duplicate it again.
    let again = wf
        .recover(&dispatcher, 1_770_000_200)
        .expect("recover again");
    assert_eq!(again.pending_notifications, 0);
    assert_eq!(pager.delivered_ids().len(), 1);
}

#[test]
fn quarantine_is_visible_across_sync() {
    let local_dir = tempfile::tempdir().expect("temp dir");
    let remote_dir = tempfile::tempdir().expect("temp dir");
    let local = workflow(&local_dir.path().join("primary.db"));
    let remote = workflow(&remote_dir.path().join("primary.db"));
    let dispatcher = NotifierDispatcher::new().with(Arc::new(CountingNotifier::new("pager")));

    detect_and_quarantine(&local, "exc-sync", &dispatcher, 1_770_000_000);
    let view = local.quarantine_view("exc-sync").expect("view");

    // A peer that never ran detection sees the quarantine through the view.
    assert_eq!(
        remote
            .apply_remote_quarantine(&view, 1_770_000_050)
            .expect("sync"),
        SyncOutcome::Inserted
    );
    let peer = remote.get("exc-sync").expect("peer record");
    assert_eq!(peer.state, ExcursionState::Quarantined);
    assert!(peer
        .reasons()
        .contains(&ExcursionReason::TemperatureOutOfBand));
    assert_eq!(
        remote
            .quarantine_view("exc-sync")
            .expect("peer view")
            .version,
        view.version
    );

    // Stale and equal views are ignored.
    assert_eq!(
        remote
            .apply_remote_quarantine(&view, 1_770_000_051)
            .expect("replay"),
        SyncOutcome::IgnoredStale
    );

    // Once the local record is dispositioned a peer view must not release it.
    let operator = InMemoryKeyProvider::from_seed([0x44; 32]);
    let evidence = EvidenceBundle {
        temperature_samples: 4,
        mkt_c: local.get("exc-sync").unwrap().detection.mkt_c,
        detection_digest: local.get("exc-sync").unwrap().detection.digest(),
        quarantine_opened_est: local.get("exc-sync").unwrap().opened_est,
        ledger_entry: None,
        notes: "release".to_string(),
    };
    let payload = DispositionPayload {
        record_id: "exc-sync".to_string(),
        disposition: DispositionKind::Release,
        reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
        operator_did: operator.did().to_string(),
        operator_role: CommandRole::CommandIssuer,
        evidence_digest: evidence.digest(),
        note: "release".to_string(),
        decided_est: 1_770_000_060,
    };
    local
        .record_disposition(
            "exc-sync",
            DispositionRequest {
                disposition: DispositionKind::Release,
                reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
                operator_did: operator.did().to_string(),
                operator_role: CommandRole::CommandIssuer,
                evidence,
                note: "release".to_string(),
                signature: sign_disposition(&operator, &payload),
                decided_est: 1_770_000_060,
            },
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            1_770_000_061,
        )
        .expect("disposition");

    // A peer view that still reports "quarantined" must not lower the local
    // dispositioned record.
    let old_view = ExcursionWorkflow::open_in_memory()
        .and_then(|wf| {
            let d = NotifierDispatcher::new().with(Arc::new(CountingNotifier::new("pager")));
            detect_and_quarantine(&wf, "other", &d, 1_770_000_000);
            wf.quarantine_view("other")
        })
        .expect("scratch view");
    let mut stale_for_local = old_view;
    stale_for_local.record_id = "exc-sync".to_string();
    stale_for_local.version = 99;
    assert_eq!(
        local
            .apply_remote_quarantine(&stale_for_local, 1_770_000_070)
            .expect("peer cannot release"),
        SyncOutcome::RefusedDispositioned
    );
    assert_eq!(
        local.get("exc-sync").unwrap().state,
        ExcursionState::Dispositioned
    );
}

#[test]
fn receiver_deduplication_turns_retries_into_one_alert() {
    let dir = tempfile::tempdir().expect("temp dir");
    let wf = workflow(&dir.path().join("primary.db"));
    let pager = Arc::new(RecordingNotifier::new("pager"));
    let _dispatcher = NotifierDispatcher::new().with(pager.clone());

    let detection = hot_detection(1_770_000_000);
    wf.detect("exc-dup", "t", "s", "d", None, detection, 1_770_000_000)
        .expect("detect");
    wf.open_quarantine("exc-dup", 1_770_000_001)
        .expect("quarantine");

    // Simulate a crash between "accepted" and "outbox marked": the channel
    // records the delivery, but the workflow never marks it.
    let notification = ExcursionNotification {
        notification_id: ExcursionNotification::dedup_key(
            "exc-dup",
            "pager",
            NotificationEvent::QuarantineOpened,
        ),
        record_id: "exc-dup".to_string(),
        channel: "pager".to_string(),
        event: NotificationEvent::QuarantineOpened,
        tenant: "t".to_string(),
        site_id: "s".to_string(),
        reasons: vec!["temperature_out_of_band".to_string()],
        mkt_c: None,
        opened_est: 1_770_000_000,
        enqueued_est: 1_770_000_002,
    };
    // Transport accepted once; then retry delivers the same id again.
    pager.deliver(&notification).expect("first");
    pager.deliver(&notification).expect("retry");

    let mut dedup = DeduplicationFilter::new(64);
    let mut alerts = 0usize;
    for id in pager.delivered_ids() {
        if !dedup.is_duplicate(&id) {
            alerts += 1;
        }
    }
    assert_eq!(alerts, 1, "the receiver must alert exactly once");
}

#[test]
fn disposition_rejects_an_unreported_reason_and_a_wrong_signature() {
    let dir = tempfile::tempdir().expect("temp dir");
    let wf = workflow(&dir.path().join("primary.db"));
    let operator = InMemoryKeyProvider::from_seed([0x55; 32]);
    let other = InMemoryKeyProvider::from_seed([0x56; 32]);
    let dispatcher = NotifierDispatcher::new().with(Arc::new(CountingNotifier::new("pager")));
    detect_and_quarantine(&wf, "exc-bad", &dispatcher, 1_770_000_000);

    let record = wf.get("exc-bad").unwrap();
    let evidence = EvidenceBundle {
        temperature_samples: 4,
        mkt_c: record.detection.mkt_c,
        detection_digest: record.detection.digest(),
        quarantine_opened_est: record.opened_est,
        ledger_entry: None,
        notes: "no".to_string(),
    };

    // A reason the detection never reported.
    let bad_reason = DispositionRequest {
        disposition: DispositionKind::Reject,
        reason: "door_open_too_long".to_string(),
        operator_did: operator.did().to_string(),
        operator_role: CommandRole::CommandIssuer,
        evidence: evidence.clone(),
        note: "no".to_string(),
        signature: sign_disposition(
            &operator,
            &DispositionPayload {
                record_id: "exc-bad".to_string(),
                disposition: DispositionKind::Reject,
                reason: "door_open_too_long".to_string(),
                operator_did: operator.did().to_string(),
                operator_role: CommandRole::CommandIssuer,
                evidence_digest: evidence.digest(),
                note: "no".to_string(),
                decided_est: 1_770_000_010,
            },
        ),
        decided_est: 1_770_000_010,
    };
    assert!(matches!(
        wf.record_disposition(
            "exc-bad",
            bad_reason,
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            1_770_000_011
        ),
        Err(ExcursionError::InvalidRequest(_))
    ));

    // A signature by someone else.
    let forged = DispositionRequest {
        disposition: DispositionKind::Reject,
        reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
        operator_did: operator.did().to_string(),
        operator_role: CommandRole::CommandIssuer,
        evidence: evidence.clone(),
        note: "no".to_string(),
        signature: sign_disposition(
            &other,
            &DispositionPayload {
                record_id: "exc-bad".to_string(),
                disposition: DispositionKind::Reject,
                reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
                operator_did: operator.did().to_string(),
                operator_role: CommandRole::CommandIssuer,
                evidence_digest: evidence.digest(),
                note: "no".to_string(),
                decided_est: 1_770_000_010,
            },
        ),
        decided_est: 1_770_000_010,
    };
    assert!(matches!(
        wf.record_disposition(
            "exc-bad",
            forged,
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            1_770_000_011
        ),
        Err(ExcursionError::Signature(_))
    ));
}

// ---------------------------------------------------------------------------
// Property tests: transitions and illegal-transition rejection
// ---------------------------------------------------------------------------

fn state_strategy() -> impl Strategy<Value = ExcursionState> {
    prop_oneof![
        Just(ExcursionState::Detected),
        Just(ExcursionState::Quarantined),
        Just(ExcursionState::Notified),
        Just(ExcursionState::Dispositioned),
        Just(ExcursionState::Resolved),
        Just(ExcursionState::Closed),
    ]
}

fn legal_targets(from: ExcursionState) -> &'static [ExcursionState] {
    match from {
        ExcursionState::Detected => &[ExcursionState::Quarantined],
        ExcursionState::Quarantined => &[ExcursionState::Notified, ExcursionState::Dispositioned],
        ExcursionState::Notified => &[ExcursionState::Dispositioned],
        ExcursionState::Dispositioned => &[ExcursionState::Resolved],
        ExcursionState::Resolved => &[ExcursionState::Closed],
        ExcursionState::Closed => &[],
    }
}

proptest! {
    #[test]
    fn transitions_match_the_legal_graph(
        from in state_strategy(),
        to in state_strategy(),
    ) {
        let legal = legal_targets(from).contains(&to);
        prop_assert_eq!(from.can_transition_to(to), legal);
        match advance_state(from, to) {
            Ok(next) => prop_assert_eq!(next, to),
            Err(error) => {
                prop_assert_eq!(error.from, from);
                prop_assert_eq!(error.to, to);
                prop_assert!(!legal);
            }
        }
    }

    #[test]
    fn backward_and_self_transitions_are_always_rejected(
        from in state_strategy(),
        to in state_strategy(),
    ) {
        if to.rank() <= from.rank() {
            prop_assert!(!from.can_transition_to(to));
            prop_assert!(advance_state(from, to).is_err());
        }
    }

    #[test]
    fn illegal_jumps_are_rejected(
        from in state_strategy(),
        to in state_strategy(),
    ) {
        if !legal_targets(from).contains(&to) {
            prop_assert!(advance_state(from, to).is_err());
        }
    }

    #[test]
    fn closed_is_reachable_only_through_forward_legal_steps(
        steps in proptest::collection::vec(state_strategy(), 1..16)
    ) {
        let mut state = ExcursionState::Detected;
        let mut closed = false;
        for step in steps {
            if state.can_transition_to(step) {
                state = advance_state(state, step).expect("legal step");
                if state.is_terminal() {
                    closed = true;
                    break;
                }
            } else {
                prop_assert!(advance_state(state, step).is_err());
            }
        }
        if closed {
            prop_assert_eq!(state, ExcursionState::Closed);
        } else {
            prop_assert_ne!(state, ExcursionState::Closed);
        }
    }

    #[test]
    fn disposition_can_follow_quarantine_with_or_without_notification(
        notify_first in proptest::bool::ANY
    ) {
        let mut state = ExcursionState::Detected;
        state = advance_state(state, ExcursionState::Quarantined).unwrap();
        if notify_first {
            state = advance_state(state, ExcursionState::Notified).unwrap();
        }
        state = advance_state(state, ExcursionState::Dispositioned).unwrap();
        state = advance_state(state, ExcursionState::Resolved).unwrap();
        state = advance_state(state, ExcursionState::Closed).unwrap();
        prop_assert!(state.is_terminal());
    }
}
