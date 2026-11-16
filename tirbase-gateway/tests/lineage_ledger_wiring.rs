// SPDX-License-Identifier: AGPL-3.0-only

//! Lineage ledger wiring (CC-14).
//!
//! Drives real domain operations — a lot registration, split, repack and merge,
//! then an excursion detection, quarantine, signed disposition and signed
//! resolution — and reads the chain those writes produced. Proves:
//!
//! - every event lands in the ledger, in order, with the domain-derived entry id
//!   (`lot-registered:<lot>`, `lot-op:<operation_id>`,
//!   `excursion-disposition:<record>`, `excursion-resolution:<record>`);
//! - a replayed split, a re-registered lot, and retried disposition/resolution
//!   appends nothing (the chain length is unchanged);
//! - the chain verifies after a restart and survives a signed checkpoint;
//! - the exported bundle verifies offline from bytes alone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::excursion::mkt::{MktParameters, MKT_UNIT_ID};
use tirbase_gateway::excursion::notifier::{
    ExcursionNotification, ExcursionNotifier, NotificationEvent, NotifierDispatcher,
};
use tirbase_gateway::excursion::{
    evaluate_detection, DetectionInputs, DetectionOutcome, DetectionThresholds, DispositionKind,
    DispositionPayload, DispositionRequest, EvidenceBundle, ExcursionReason, ExcursionWorkflow,
    SignedResolution,
};
use tirbase_gateway::lineage_ledger::export::{export_bundle, trusted_key_entry, verify_bundle};
use tirbase_gateway::lineage_ledger::{
    AppendOutcome, LedgerSink, LineageLedger, EVENT_EXCURSION_DISPOSITIONED,
    EVENT_EXCURSION_RESOLVED, EVENT_LOT_MERGED, EVENT_LOT_REGISTERED, EVENT_LOT_REPACKED,
    EVENT_LOT_SPLIT,
};
use tirbase_gateway::lot::{
    ChildSpec, LotDraft, LotKind, LotRegistry, MergeRequest, OperationOutcome, RepackRequest,
    SplitRequest,
};
use tirbase_types::{CommandRole, FixedPointValue};

fn deci_c(value: i64) -> FixedPointValue {
    FixedPointValue::new(value, -1, MKT_UNIT_ID)
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

#[derive(Debug)]
struct RecordingNotifier {
    delivered: Mutex<Vec<String>>,
}

impl ExcursionNotifier for RecordingNotifier {
    fn channel(&self) -> &str {
        "pager"
    }

    fn deliver(&self, notification: &ExcursionNotification) -> Result<(), String> {
        self.delivered
            .lock()
            .expect("delivered")
            .push(notification.record_id.clone());
        Ok(())
    }
}

/// Open the three components on the gateway's `primary.db`, sharing one sink.
fn runtime(
    dir: &Path,
) -> (
    Arc<LedgerSink>,
    LotRegistry,
    ExcursionWorkflow,
    InMemoryKeyProvider,
) {
    let db = dir.join("primary.db");
    let operator = InMemoryKeyProvider::from_seed([0x51; 32]);
    let sink = Arc::new(
        LedgerSink::new(LineageLedger::open(&db).expect("ledger"), operator.did()).expect("sink"),
    );
    let lots = LotRegistry::open(&db)
        .expect("lots")
        .with_ledger(sink.clone());
    let excursions = ExcursionWorkflow::open(&db)
        .expect("excursions")
        .with_ledger(sink.clone());
    (sink, lots, excursions, operator)
}

#[test]
fn lot_and_excursion_operations_build_one_verifiable_chain() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (sink, lots, wf, operator) = runtime(dir.path());
    let resolver = |did: &str| (did == operator.did()).then(|| operator.public_key_bytes());

    // --- Lot registration and lineage -------------------------------------
    let parent = LotDraft::new(
        "LOT-A",
        "tenant-a",
        LotKind::Lot,
        "site-1",
        "dock-1",
        100,
        "kg",
        1_770_000_000,
    )
    .with_device("dev-1");
    lots.register(parent.clone()).expect("register");
    // An identical re-registration is a no-op for the store and for the chain.
    lots.register(parent.clone()).expect("re-register");
    assert_eq!(sink.ledger().len().expect("len"), 1);

    let split = SplitRequest {
        operation_id: "op-split-1".to_string(),
        parent_id: "LOT-A".to_string(),
        children: vec![ChildSpec::new("LOT-A1", 60), ChildSpec::new("LOT-A2", 40)],
        at_est: 1_770_000_010,
    };
    assert!(matches!(
        lots.split(split.clone()).expect("split"),
        OperationOutcome::Applied { .. }
    ));

    let repack = RepackRequest {
        operation_id: "op-repack-1".to_string(),
        parent_id: "LOT-A2".to_string(),
        child: ChildSpec::new("LOT-A2-R", 40),
        at_est: 1_770_000_011,
    };
    assert!(matches!(
        lots.repack(repack.clone()).expect("repack"),
        OperationOutcome::Applied { .. }
    ));

    let merge = MergeRequest {
        operation_id: "op-merge-1".to_string(),
        parent_ids: vec!["LOT-A1".to_string(), "LOT-A2-R".to_string()],
        child: ChildSpec::new("LOT-B", 100),
        at_est: 1_770_000_012,
    };
    assert!(matches!(
        lots.merge(merge.clone()).expect("merge"),
        OperationOutcome::Applied { .. }
    ));

    // --- Excursion: detect, quarantine, notify, disposition, resolve ------
    let record_id = "exc-1";
    wf.detect(
        record_id,
        "tenant-a",
        "site-1",
        "dev-1",
        Some("LOT-A1"),
        hot_detection(1_770_000_020),
        1_770_000_020,
    )
    .expect("detect");
    wf.open_quarantine(record_id, 1_770_000_021)
        .expect("quarantine");
    let dispatcher = NotifierDispatcher::new().with(Arc::new(RecordingNotifier {
        delivered: Mutex::new(Vec::new()),
    }));
    wf.notify(
        record_id,
        &dispatcher,
        NotificationEvent::QuarantineOpened,
        1_770_000_022,
    )
    .expect("notify");

    let record = wf.get(record_id).expect("record");
    let evidence = EvidenceBundle {
        temperature_samples: 4,
        mkt_c: record.detection.mkt_c,
        detection_digest: record.detection.digest(),
        quarantine_opened_est: record.opened_est,
        ledger_entry: None,
        notes: "Holding pending lab assessment.".to_string(),
    };
    let disposition_payload = DispositionPayload {
        record_id: record_id.to_string(),
        disposition: DispositionKind::Hold,
        reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
        operator_did: operator.did().to_string(),
        operator_role: CommandRole::CommandIssuer,
        evidence_digest: evidence.digest(),
        note: "Holding pending lab assessment.".to_string(),
        decided_est: 1_770_000_030,
    };
    let disposition_request = DispositionRequest {
        disposition: DispositionKind::Hold,
        reason: ExcursionReason::TemperatureOutOfBand.as_str().to_string(),
        operator_did: operator.did().to_string(),
        operator_role: CommandRole::CommandIssuer,
        evidence: evidence.clone(),
        note: "Holding pending lab assessment.".to_string(),
        signature: operator
            .sign(&disposition_payload.signing_bytes())
            .expect("sign disposition"),
        decided_est: 1_770_000_030,
    };
    wf.record_disposition(
        record_id,
        disposition_request.clone(),
        resolver,
        1_770_000_031,
    )
    .expect("disposition");

    let resolution_payload = wf
        .resolution_payload(record_id)
        .expect("resolution payload");
    let mut signed =
        SignedResolution::new(&resolution_payload, 1_770_000_040, None).expect("build resolution");
    signed
        .sign_with(&operator, CommandRole::CommandIssuer)
        .expect("sign resolution");
    wf.sign_resolution(record_id, &signed, resolver, 1_770_000_041)
        .expect("resolve");
    wf.close(record_id, 1_770_000_050).expect("close");

    // --- The chain those operations produced -----------------------------
    let entries = sink.ledger().entries().expect("entries");
    let events: Vec<&str> = entries
        .iter()
        .map(|entry| entry.event_type.as_str())
        .collect();
    assert_eq!(
        events,
        vec![
            EVENT_LOT_REGISTERED,
            EVENT_LOT_SPLIT,
            EVENT_LOT_REPACKED,
            EVENT_LOT_MERGED,
            EVENT_EXCURSION_DISPOSITIONED,
            EVENT_EXCURSION_RESOLVED,
        ],
        "one entry per domain event, in the order the operations ran"
    );
    let ids: Vec<&str> = entries
        .iter()
        .map(|entry| entry.entry_id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "lot-registered:LOT-A",
            "lot-op:op-split-1",
            "lot-op:op-repack-1",
            "lot-op:op-merge-1",
            "excursion-disposition:exc-1",
            "excursion-resolution:exc-1",
        ],
        "entry ids are derived from the domain object, so a retry is a duplicate"
    );
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
    for pair in entries.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].entry_hash);
    }

    assert_eq!(entries[0].lot_id.as_deref(), Some("LOT-A"));
    assert_eq!(entries[0].device_id.as_deref(), Some("dev-1"));
    assert_eq!(entries[0].actor_did, operator.did());
    assert_eq!(entries[0].payload["quantity"], 100);
    assert_eq!(entries[1].payload["operation_id"], "op-split-1");
    assert_eq!(entries[1].payload["inputs"], serde_json::json!(["LOT-A"]));
    assert_eq!(
        entries[1].payload["outputs"],
        serde_json::json!(["LOT-A1", "LOT-A2"])
    );
    assert_eq!(entries[3].payload["outputs"], serde_json::json!(["LOT-B"]));
    assert_eq!(entries[3].lot_id.as_deref(), Some("LOT-B"));
    assert_eq!(entries[4].actor_did, operator.did());
    assert_eq!(
        entries[4].payload["disposition"],
        DispositionKind::Hold.as_str()
    );
    assert_eq!(entries[4].payload["reason"], "temperature_out_of_band");
    assert_eq!(entries[4].lot_id.as_deref(), Some("LOT-A1"));
    assert_eq!(entries[4].device_id.as_deref(), Some("dev-1"));
    assert_eq!(
        entries[5].payload["signers"],
        serde_json::json!([operator.did()])
    );
    assert_eq!(entries[5].payload["record_id"], "exc-1");

    // --- Retries append nothing ------------------------------------------
    assert!(matches!(
        lots.split(split.clone()).expect("replayed split"),
        OperationOutcome::Replayed(_)
    ));
    assert!(matches!(
        lots.repack(repack.clone()).expect("replayed repack"),
        OperationOutcome::Replayed(_)
    ));
    assert!(matches!(
        lots.merge(merge.clone()).expect("replayed merge"),
        OperationOutcome::Replayed(_)
    ));
    wf.record_disposition(
        record_id,
        disposition_request.clone(),
        resolver,
        1_770_000_060,
    )
    .expect("replayed disposition");
    wf.sign_resolution(record_id, &signed, resolver, 1_770_000_061)
        .expect("replayed resolution");
    assert_eq!(
        sink.ledger().len().expect("len"),
        entries.len() as u64,
        "replays and retries must not add rows"
    );
    assert_eq!(lots.operations().expect("operations").len(), 3);

    // --- Checkpoint, restart and offline export --------------------------
    let checkpoint = sink
        .ledger()
        .checkpoint(&operator, 1_770_000_100)
        .expect("checkpoint");
    assert_eq!(checkpoint.seq, entries.len() as u64);

    let trusted = BTreeSet::from([operator.did().to_string()]);
    let keys = BTreeMap::from([trusted_key_entry(&operator)]);
    let resolve_key = |did: &str| keys.get(did).cloned();
    let report = sink
        .ledger()
        .verify(&trusted, &resolve_key)
        .expect("verify");
    assert!(report.ok, "{:?}", report.reasons());

    let reopened = LineageLedger::open(dir.path().join("primary.db")).expect("reopen ledger");
    let report = reopened.verify(&trusted, &resolve_key).expect("verify");
    assert!(
        report.ok,
        "chain intact after restart: {:?}",
        report.reasons()
    );
    assert_eq!(report.head_seq, entries.len() as u64);
    assert_eq!(report.checkpoints, 1);

    let bundle = export_bundle(
        &reopened,
        &operator,
        1,
        entries.len() as u64,
        &BTreeMap::new(),
        1_770_000_200,
    )
    .expect("export");
    let report = verify_bundle(&bundle.bundle, &bundle.signature, &keys, &BTreeMap::new());
    assert!(report.ok, "bundle verifies offline: {:?}", report.reasons());

    // A duplicate append through the sink reports the existing entry.
    let duplicate = sink
        .ledger()
        .append(tirbase_gateway::lineage_ledger::AppendRequest::new(
            "lot-registered:LOT-A",
            operator.did(),
            EVENT_LOT_REGISTERED,
            entries[0].payload.clone(),
            1_770_000_000,
        ))
        .expect("duplicate append");
    assert!(matches!(duplicate, AppendOutcome::Duplicate(_)));
    assert_eq!(duplicate.entry().entry_hash, entries[0].entry_hash);
}
