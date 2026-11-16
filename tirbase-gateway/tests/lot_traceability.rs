// SPDX-License-Identifier: AGPL-3.0-only

//! Lot and batch traceability integration tests (CC-12).
//!
//! Proves multi-level ancestry (split → repack → split → merge → aggregate),
//! cycle rejection, idempotent split/merge/repack replay, missing-link
//! reporting, the backward disposition query, and the query/export surfaces.

use std::collections::BTreeSet;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::excursion::mkt::{MktParameters, MKT_UNIT_ID};
use tirbase_gateway::excursion::notifier::{NotificationEvent, NotifierDispatcher};
use tirbase_gateway::excursion::{
    evaluate_detection, DetectionInputs, DetectionThresholds, DispositionKind, DispositionPayload,
    DispositionRequest, EvidenceBundle, ExcursionRecord, ExcursionState, ExcursionWorkflow,
    SignedResolution,
};
use tirbase_gateway::lot::{
    ChildSpec, DispositionLink, EdgeKind, LedgerKind, LedgerLink, LotDraft, LotError, LotKind,
    LotOperation, LotQuery, LotRegistry, LotTraceExport, MergeRequest, OpKind, OperationOutcome,
    RecallRequest, RepackRequest, SplitRequest, TimeWindow,
};
use tirbase_types::{CommandRole, FixedPointValue};

const TENANT: &str = "tenant-cold-chain";

fn lot_draft(lot_id: &str, site: &str, location: &str, quantity: u64) -> LotDraft {
    LotDraft::new(
        lot_id,
        TENANT,
        LotKind::Lot,
        site,
        location,
        quantity,
        "kg",
        1_700_000_000,
    )
}

/// Deci-degree reading for the detection thresholds.
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

fn hot_detection(at: i64) -> tirbase_gateway::excursion::DetectionOutcome {
    evaluate_detection(
        &thresholds(),
        &DetectionInputs {
            temperature_c: Some(deci_c(120)),
            previous_temperature_c: Some(deci_c(50)),
            elapsed_secs: 300,
            ..Default::default()
        },
        at,
    )
}

/// Drive a real CC-11 excursion all the way to a signed, closed disposition.
fn closed_excursion(
    workflow: &ExcursionWorkflow,
    record_id: &str,
    lot_id: Option<&str>,
    disposition: DispositionKind,
    base: i64,
) -> ExcursionRecord {
    let operator = InMemoryKeyProvider::from_seed([0x5a; 32]);
    workflow
        .detect(
            record_id,
            TENANT,
            "SITE-1",
            "dev-freezer-1",
            lot_id,
            hot_detection(base),
            base,
        )
        .expect("detect");
    workflow
        .open_quarantine(record_id, base + 1)
        .expect("quarantine");
    workflow
        .notify(
            record_id,
            &NotifierDispatcher::new(),
            NotificationEvent::QuarantineOpened,
            base + 2,
        )
        .expect("notify");

    let record = workflow.get(record_id).expect("load");
    let reason = "temperature_out_of_band".to_string();
    let evidence = EvidenceBundle {
        temperature_samples: 1,
        mkt_c: record.detection.mkt_c,
        detection_digest: record.detection.digest(),
        quarantine_opened_est: record.opened_est,
        ledger_entry: None,
        notes: "recall assessment".to_string(),
    };
    let payload = DispositionPayload {
        record_id: record_id.to_string(),
        disposition,
        reason: reason.clone(),
        operator_did: operator.did().to_string(),
        operator_role: CommandRole::CommandIssuer,
        evidence_digest: evidence.digest(),
        note: "recall assessment".to_string(),
        decided_est: base + 3,
    };
    workflow
        .record_disposition(
            record_id,
            DispositionRequest {
                disposition,
                reason,
                operator_did: operator.did().to_string(),
                operator_role: CommandRole::CommandIssuer,
                evidence,
                note: "recall assessment".to_string(),
                signature: operator.sign(&payload.signing_bytes()).expect("sign"),
                decided_est: base + 3,
            },
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            base + 4,
        )
        .expect("disposition");

    let resolution = workflow
        .resolution_payload(record_id)
        .expect("resolution payload");
    let mut signed = SignedResolution::new(&resolution, base + 5, None).expect("build resolution");
    signed
        .sign_with(&operator, CommandRole::CommandIssuer)
        .expect("sign resolution");
    workflow
        .sign_resolution(
            record_id,
            &signed,
            |did| (did == operator.did()).then(|| operator.public_key_bytes()),
            base + 6,
        )
        .expect("resolve");
    workflow.close(record_id, base + 7).expect("close")
}

/// Build the reference lineage used by several tests:
///
/// ```text
/// LOT-A --split--> B1 --repack--> C1 --split--> D1 --merge-->
///       \--> B2                                 D2 --merge--> LOT-E
///                                                   \--aggregate--> AGG-1
/// ```
struct Fixture {
    registry: LotRegistry,
}

impl Fixture {
    fn build() -> Self {
        let registry = LotRegistry::open_in_memory().expect("registry");
        registry
            .register(
                lot_draft("LOT-A", "SITE-1", "COLD-1", 100)
                    .with_label("Inbound lot A")
                    .with_device("dev-freezer-1")
                    .with_ledger("AE-100", LedgerKind::AppliedEffect),
            )
            .expect("register A");
        registry
            .register(lot_draft("B1", "SITE-1", "COLD-1", 60))
            .expect("register B1");
        registry
            .register(
                lot_draft("B2", "SITE-1", "COLD-2", 40)
                    .with_ledger("AE-101", LedgerKind::AppliedEffect),
            )
            .expect("register B2");
        registry
            .register(lot_draft("C1", "SITE-2", "PACK-1", 60))
            .expect("register C1");
        registry
            .register(lot_draft("D1", "SITE-3", "TRUCK-1", 30))
            .expect("register D1");
        registry
            .register(lot_draft("D2", "SITE-3", "TRUCK-2", 30))
            .expect("register D2");
        registry
            .register(lot_draft("LOT-E", "SITE-4", "DOCK-1", 60))
            .expect("register E");
        registry
            .register(lot_draft("AGG-1", "SITE-4", "DOCK-1", 60).with_label("Pallet, one"))
            .expect("register AGG-1");
        Self { registry }
    }

    fn link_reference_lineage(&self) {
        // B1 is the portion of LOT-A that gets repacked; C1..E follow from it.
        self.registry
            .add_edge("LOT-A", "B1", EdgeKind::Split, 10)
            .expect("A -> B1");
        self.registry
            .add_edge("LOT-A", "B2", EdgeKind::Split, 10)
            .expect("A -> B2");
        self.registry
            .add_edge("B1", "C1", EdgeKind::Repack, 20)
            .expect("B1 -> C1");
        self.registry
            .add_edge("C1", "D1", EdgeKind::Split, 30)
            .expect("C1 -> D1");
        self.registry
            .add_edge("C1", "D2", EdgeKind::Split, 30)
            .expect("C1 -> D2");
        self.registry
            .add_edge("D1", "LOT-E", EdgeKind::Merge, 40)
            .expect("D1 -> E");
        self.registry
            .add_edge("D2", "LOT-E", EdgeKind::Merge, 40)
            .expect("D2 -> E");
        // Aggregation is a containment edge: AGG-1 aggregates D1 and D2 but does
        // not consume their quantity.
        self.registry
            .add_edge("D1", "AGG-1", EdgeKind::Aggregate, 50)
            .expect("D1 -> AGG-1");
        self.registry
            .add_edge("D2", "AGG-1", EdgeKind::Aggregate, 50)
            .expect("D2 -> AGG-1");
    }
}

fn ids(nodes: &[tirbase_gateway::lot::TraceNode]) -> Vec<String> {
    nodes.iter().map(|node| node.lot_id.clone()).collect()
}

// ---------------------------------------------------------------------------
// Multi-level ancestry and recall
// ---------------------------------------------------------------------------

#[test]
fn multi_level_ancestry_preserves_paths_and_depths() {
    let fixture = Fixture::build();
    fixture.link_reference_lineage();

    let trace = fixture
        .registry
        .forward_trace("LOT-A")
        .expect("forward trace");
    let order = ids(&trace);
    assert_eq!(order, vec!["B1", "B2", "C1", "D1", "D2", "AGG-1", "LOT-E"]);

    let by_id = |id: &str| {
        trace
            .iter()
            .find(|node| node.lot_id == id)
            .unwrap_or_else(|| panic!("{id} missing from trace"))
            .clone()
    };
    assert_eq!(by_id("B1").depth, 1);
    assert_eq!(by_id("C1").depth, 2);
    assert_eq!(by_id("D1").depth, 3);
    assert_eq!(by_id("AGG-1").depth, 4);
    assert_eq!(by_id("LOT-E").depth, 4);
    assert_eq!(
        by_id("LOT-E").path,
        vec!["LOT-A", "B1", "C1", "D1", "LOT-E"]
    );
    assert_eq!(by_id("AGG-1").via, Some(EdgeKind::Aggregate));
    assert!(trace.iter().all(|node| !node.missing));
    // The graph is reachable from both directions exactly once per lot.
    assert_eq!(order.len(), order.iter().collect::<BTreeSet<_>>().len());

    let backward = fixture.registry.backward_trace("LOT-E").expect("backward");
    assert_eq!(ids(&backward), vec!["D1", "D2", "C1", "B1", "LOT-A"]);
}

#[test]
fn recall_returns_every_affected_lot_and_location() {
    let fixture = Fixture::build();
    fixture.link_reference_lineage();

    let report = fixture
        .registry
        .recall(&RecallRequest::new("LOT-A"), 100)
        .expect("recall");

    assert_eq!(report.origin_lot, "LOT-A");
    assert_eq!(
        report.lot_ids().into_iter().collect::<BTreeSet<_>>(),
        ["LOT-A", "B1", "B2", "C1", "D1", "D2", "LOT-E", "AGG-1"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>()
    );
    assert!(report.missing_links.is_empty());
    assert!(!report.truncated);
    assert_eq!(report.affected[0].lot_id, "LOT-A");
    assert_eq!(report.affected[0].depth, 0);

    let locations: Vec<(String, String, Vec<String>)> = report
        .locations
        .iter()
        .map(|location| {
            (
                location.site_id.clone(),
                location.location_id.clone(),
                location.lot_ids.clone(),
            )
        })
        .collect();
    assert_eq!(
        locations,
        vec![
            (
                "SITE-1".to_string(),
                "COLD-1".to_string(),
                vec!["B1".to_string(), "LOT-A".to_string()],
            ),
            (
                "SITE-1".to_string(),
                "COLD-2".to_string(),
                vec!["B2".to_string()],
            ),
            (
                "SITE-2".to_string(),
                "PACK-1".to_string(),
                vec!["C1".to_string()],
            ),
            (
                "SITE-3".to_string(),
                "TRUCK-1".to_string(),
                vec!["D1".to_string()],
            ),
            (
                "SITE-3".to_string(),
                "TRUCK-2".to_string(),
                vec!["D2".to_string()],
            ),
            (
                "SITE-4".to_string(),
                "DOCK-1".to_string(),
                vec!["AGG-1".to_string(), "LOT-E".to_string()],
            ),
        ]
    );

    // Ledger entries of every affected lot are carried into the report.
    assert_eq!(
        report.ledger_entries,
        vec!["AE-100".to_string(), "AE-101".to_string()]
    );

    // A leaf recall touches only itself.
    let leaf = fixture
        .registry
        .recall(&RecallRequest::new("LOT-E"), 100)
        .expect("leaf recall");
    assert_eq!(leaf.lot_ids(), vec!["LOT-E".to_string()]);
    assert_eq!(leaf.locations.len(), 1);
}

#[test]
fn recall_reports_an_affected_lot_with_its_disposition() {
    let fixture = Fixture::build();
    fixture.link_reference_lineage();
    fixture
        .registry
        .attach_disposition(
            "C1",
            DispositionLink {
                record_id: "EXC-7".to_string(),
                disposition: "reject".to_string(),
                reason: "temperature_out_of_band".to_string(),
                decided_est: 60,
            },
            61,
        )
        .expect("attach disposition");

    let report = fixture
        .registry
        .recall(&RecallRequest::new("LOT-A"), 100)
        .expect("recall");
    let affected = report
        .affected
        .iter()
        .find(|lot| lot.lot_id == "C1")
        .expect("C1 affected");
    let disposition = affected.disposition.as_ref().expect("disposition");
    assert_eq!(disposition.record_id, "EXC-7");
    assert_eq!(disposition.disposition, "reject");
    // The rest of the recall has no decision recorded.
    assert!(report
        .affected
        .iter()
        .filter(|lot| lot.lot_id != "C1")
        .all(|lot| lot.disposition.is_none()));
}

// ---------------------------------------------------------------------------
// Cycles
// ---------------------------------------------------------------------------

#[test]
fn cycle_is_rejected_and_nothing_is_written() {
    let registry = LotRegistry::open_in_memory().expect("registry");
    for id in ["A", "B", "C"] {
        registry
            .register(lot_draft(id, "SITE-1", "COLD-1", 10))
            .expect("register");
    }
    registry
        .add_edge("A", "B", EdgeKind::Split, 1)
        .expect("A->B");
    registry
        .add_edge("B", "C", EdgeKind::Split, 2)
        .expect("B->C");

    let error = registry
        .add_edge("C", "A", EdgeKind::Split, 3)
        .expect_err("cycle must be rejected");
    match error {
        LotError::CycleDetected {
            parent_id,
            child_id,
            path,
        } => {
            assert_eq!(parent_id, "C");
            assert_eq!(child_id, "A");
            assert_eq!(path, vec!["A", "B", "C", "A"]);
        }
        other => panic!("expected CycleDetected, got {other:?}"),
    }

    // The refused edge left no trace.
    assert_eq!(registry.edges().expect("edges").len(), 2);
    assert_eq!(
        ids(&registry.forward_trace("A").expect("trace")),
        vec!["B", "C"]
    );

    // Self-edges are the degenerate cycle.
    let error = registry
        .add_edge("A", "A", EdgeKind::Aggregate, 4)
        .expect_err("self edge must be rejected");
    assert!(matches!(error, LotError::CycleDetected { .. }));

    // A longer cycle is caught as well.
    registry
        .add_edge("C", "D", EdgeKind::Aggregate, 5)
        .expect("C->D");
    let error = registry
        .add_edge("D", "A", EdgeKind::Merge, 6)
        .expect_err("long cycle must be rejected");
    assert!(matches!(error, LotError::CycleDetected { .. }));

    registry.check_acyclic().expect("graph stays acyclic");
}

// ---------------------------------------------------------------------------
// Idempotent split / merge / repack
// ---------------------------------------------------------------------------

#[test]
fn replayed_split_merge_and_repack_are_idempotent() {
    let registry = LotRegistry::open_in_memory().expect("registry");
    registry
        .register(lot_draft("LOT-A", "SITE-1", "COLD-1", 100))
        .expect("register A");

    let split = SplitRequest {
        operation_id: "SPLIT-1".to_string(),
        parent_id: "LOT-A".to_string(),
        children: vec![
            ChildSpec::new("B1", 60).at("SITE-1", "COLD-1"),
            ChildSpec::new("B2", 40).at("SITE-1", "COLD-2"),
        ],
        at_est: 10,
    };
    let first = registry.split(split.clone()).expect("split");
    assert!(!first.replayed());
    assert_eq!(first.created(), ["B1".to_string(), "B2".to_string()]);
    let digest_after_first = registry.export_json(&LotQuery::all(), 11).expect("export");

    let second = registry.split(split.clone()).expect("replay split");
    assert!(second.replayed());
    assert!(second.created().is_empty());
    assert_eq!(second.operation().operation_id, "SPLIT-1");
    assert_eq!(
        registry.query(&LotQuery::all()).expect("lots").len(),
        3,
        "replay must not create lots"
    );
    assert_eq!(registry.edges().expect("edges").len(), 2);
    let digest_after_replay = registry.export_json(&LotQuery::all(), 12).expect("export");
    let first_export: LotTraceExport = serde_json::from_str(&digest_after_first).expect("parse");
    let replay_export: LotTraceExport = serde_json::from_str(&digest_after_replay).expect("parse");
    assert_eq!(
        replay_export.digest, first_export.digest,
        "replay must not change the trace"
    );

    // Repack a child, then replay it.
    let repack = RepackRequest {
        operation_id: "REPACK-1".to_string(),
        parent_id: "B1".to_string(),
        child: ChildSpec::new("C1", 60).at("SITE-2", "PACK-1"),
        at_est: 20,
    };
    let applied = registry.repack(repack.clone()).expect("repack");
    assert_eq!(applied.created(), ["C1".to_string()]);
    let replayed = registry.repack(repack).expect("replay repack");
    assert!(replayed.replayed());
    assert_eq!(registry.query(&LotQuery::all()).expect("lots").len(), 4);

    // Merge the repacked lot with the other half, then replay it.
    let merge = MergeRequest {
        operation_id: "MERGE-1".to_string(),
        parent_ids: vec!["C1".to_string(), "B2".to_string()],
        child: ChildSpec::new("LOT-E", 100).at("SITE-4", "DOCK-1"),
        at_est: 30,
    };
    let applied = registry.merge(merge.clone()).expect("merge");
    assert_eq!(applied.created(), ["LOT-E".to_string()]);
    let replayed = registry.merge(merge).expect("replay merge");
    assert!(replayed.replayed());
    assert_eq!(registry.query(&LotQuery::all()).expect("lots").len(), 5);
    assert_eq!(
        ids(&registry.forward_trace("LOT-A").expect("trace")),
        vec!["B1", "B2", "C1", "LOT-E"]
    );

    // Every operation is stored exactly once.
    let operations = registry.operations().expect("operations");
    assert_eq!(operations.len(), 3);
    assert_eq!(
        operations
            .iter()
            .map(|operation| operation.operation_id.as_str())
            .collect::<Vec<_>>(),
        vec!["SPLIT-1", "REPACK-1", "MERGE-1"]
    );
    assert!(operations
        .iter()
        .all(|operation: &LotOperation| operation.request_digest.len() == 64));
}

#[test]
fn reusing_an_operation_id_for_a_different_request_is_refused() {
    let registry = LotRegistry::open_in_memory().expect("registry");
    registry
        .register(lot_draft("LOT-A", "SITE-1", "COLD-1", 100))
        .expect("register");
    let request = SplitRequest {
        operation_id: "SPLIT-1".to_string(),
        parent_id: "LOT-A".to_string(),
        children: vec![ChildSpec::new("B1", 100)],
        at_est: 10,
    };
    registry.split(request).expect("split");

    let different = SplitRequest {
        operation_id: "SPLIT-1".to_string(),
        parent_id: "LOT-A".to_string(),
        children: vec![ChildSpec::new("B2", 100)],
        at_est: 10,
    };
    match registry.split(different).expect_err("conflict") {
        LotError::Conflict(detail) => assert!(detail.contains("SPLIT-1")),
        other => panic!("expected Conflict, got {other:?}"),
    }
    assert!(!registry.contains("B2").expect("contains"));
}

#[test]
fn operations_conserve_quantity_and_consume_the_parent_once() {
    let registry = LotRegistry::open_in_memory().expect("registry");
    registry
        .register(lot_draft("LOT-A", "SITE-1", "COLD-1", 100))
        .expect("register");

    // Children must sum to the parent.
    let short = SplitRequest {
        operation_id: "SPLIT-SHORT".to_string(),
        parent_id: "LOT-A".to_string(),
        children: vec![ChildSpec::new("B1", 60)],
        at_est: 10,
    };
    assert_eq!(
        registry.split(short).expect_err("quantity mismatch"),
        LotError::QuantityMismatch {
            expected: 100,
            actual: 60
        }
    );

    let split = SplitRequest {
        operation_id: "SPLIT-1".to_string(),
        parent_id: "LOT-A".to_string(),
        children: vec![ChildSpec::new("B1", 100)],
        at_est: 10,
    };
    registry.split(split).expect("split");
    assert_eq!(
        registry.get("LOT-A").expect("A").window,
        TimeWindow::closed(1_700_000_000, 10),
        "the parent's custody window closes when it is split"
    );

    // The parent is consumed: a second, differently-keyed split cannot mint
    // product out of it again.
    let again = SplitRequest {
        operation_id: "SPLIT-2".to_string(),
        parent_id: "LOT-A".to_string(),
        children: vec![ChildSpec::new("B2", 100)],
        at_est: 20,
    };
    match registry.split(again).expect_err("consumed") {
        LotError::InvalidRequest(detail) => assert!(detail.contains("already consumed")),
        other => panic!("expected InvalidRequest, got {other:?}"),
    }

    // A merge must match the sum of its parents exactly.
    let merge = MergeRequest {
        operation_id: "MERGE-1".to_string(),
        parent_ids: vec!["B1".to_string()],
        child: ChildSpec::new("LOT-E", 99),
        at_est: 30,
    };
    assert_eq!(
        registry.merge(merge).expect_err("merge mismatch"),
        LotError::QuantityMismatch {
            expected: 100,
            actual: 99
        }
    );
}

// ---------------------------------------------------------------------------
// Missing links
// ---------------------------------------------------------------------------

#[test]
fn missing_links_are_reported_and_do_not_break_queries() {
    let registry = LotRegistry::open_in_memory().expect("registry");
    registry
        .register(lot_draft("LOT-A", "SITE-1", "COLD-1", 50))
        .expect("register");
    // Edges may arrive before the identity records they name (a peer synced the
    // lineage first). They are not an error, they are a reported gap.
    registry
        .add_edge("LOT-A", "GHOST-DOWN", EdgeKind::Split, 10)
        .expect("downstream ghost");
    registry
        .add_edge("GHOST-UP", "LOT-A", EdgeKind::Merge, 20)
        .expect("upstream ghost");

    let trace = registry.forward_trace("LOT-A").expect("trace");
    assert_eq!(trace.len(), 1);
    assert!(trace[0].missing);
    assert_eq!(trace[0].site_id, None);

    let recall = registry
        .recall(&RecallRequest::new("LOT-A"), 30)
        .expect("recall");
    assert_eq!(
        recall.missing_links,
        vec!["GHOST-DOWN".to_string()],
        "a recall names the lots it cannot locate"
    );
    assert_eq!(recall.lot_ids(), vec!["LOT-A", "GHOST-DOWN"]);
    assert_eq!(recall.locations.len(), 1, "a ghost has no location");
    assert_eq!(recall.locations[0].lot_ids, vec!["LOT-A".to_string()]);

    let disposition = registry
        .disposition_report("LOT-A", 31)
        .expect("disposition");
    assert_eq!(
        disposition.missing_links,
        vec!["GHOST-UP".to_string()],
        "a disposition query names the sources it cannot resolve"
    );

    // Registering the ghost later closes the gap without a rewrite.
    registry
        .register(lot_draft("GHOST-DOWN", "SITE-9", "DOCK-9", 50))
        .expect("register ghost");
    let recall = registry
        .recall(&RecallRequest::new("LOT-A"), 32)
        .expect("recall");
    assert!(recall.missing_links.is_empty());
    assert_eq!(recall.locations.len(), 2);
}

// ---------------------------------------------------------------------------
// Backward query and dispositions
// ---------------------------------------------------------------------------

#[test]
fn disposition_query_walks_back_to_every_source() {
    let fixture = Fixture::build();
    fixture.link_reference_lineage();
    fixture
        .registry
        .attach_disposition(
            "LOT-A",
            DispositionLink {
                record_id: "EXC-1".to_string(),
                disposition: "reject".to_string(),
                reason: "temperature_out_of_band".to_string(),
                decided_est: 50,
            },
            51,
        )
        .expect("dispose A");
    fixture
        .registry
        .attach_disposition(
            "LOT-E",
            DispositionLink {
                record_id: "EXC-9".to_string(),
                disposition: "hold".to_string(),
                reason: "missing_telemetry".to_string(),
                decided_est: 70,
            },
            71,
        )
        .expect("dispose E");

    let report = fixture
        .registry
        .disposition_report("LOT-E", 80)
        .expect("disposition report");
    assert_eq!(
        ids(&report.source_lots),
        vec!["D1", "D2", "C1", "B1", "LOT-A"]
    );
    assert_eq!(
        report
            .dispositions
            .iter()
            .map(|link| link.record_id.as_str())
            .collect::<Vec<_>>(),
        vec!["EXC-9", "EXC-1"],
        "newest decision first"
    );
    // B2 is not upstream of LOT-E, so its ledger entry is not in the report.
    assert_eq!(report.ledger_entries, vec!["AE-100".to_string()]);
    assert_eq!(report.locations.len(), 5);
    assert!(report.missing_links.is_empty());
}

#[test]
fn attaching_a_disposition_is_idempotent() {
    let registry = LotRegistry::open_in_memory().expect("registry");
    registry
        .register(lot_draft("LOT-A", "SITE-1", "COLD-1", 10))
        .expect("register");
    let link = DispositionLink {
        record_id: "EXC-1".to_string(),
        disposition: "release".to_string(),
        reason: "excursion_within_allowance".to_string(),
        decided_est: 10,
    };
    registry
        .attach_disposition("LOT-A", link.clone(), 10)
        .expect("attach");
    registry
        .attach_disposition("LOT-A", link.clone(), 11)
        .expect("replay is a no-op");
    assert_eq!(
        registry.dispositions("LOT-A").expect("dispositions").len(),
        1
    );

    let mut changed = link;
    changed.disposition = "destroy".to_string();
    match registry
        .attach_disposition("LOT-A", changed, 12)
        .expect_err("conflict")
    {
        LotError::Conflict(detail) => assert!(detail.contains("EXC-1")),
        other => panic!("expected Conflict, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Identities, links, query and export
// ---------------------------------------------------------------------------

#[test]
fn identity_links_are_idempotent_and_a_reused_id_cannot_change_meaning() {
    let registry = LotRegistry::open_in_memory().expect("registry");
    let draft = lot_draft("LOT-A", "SITE-1", "COLD-1", 10).with_device("dev-1");
    let first = registry.register(draft.clone()).expect("register");
    let second = registry.register(draft).expect("re-register");
    assert_eq!(first, second);
    assert_eq!(registry.query(&LotQuery::all()).expect("lots").len(), 1);

    let conflicting = lot_draft("LOT-A", "SITE-1", "COLD-9", 10);
    assert_eq!(
        registry.register(conflicting).expect_err("conflict"),
        LotError::AlreadyExists("LOT-A".to_string())
    );

    let linked = registry
        .link_device("LOT-A", "dev-2", 1_700_000_100)
        .expect("link");
    assert_eq!(linked.device_ids, vec!["dev-1", "dev-2"]);
    let again = registry
        .link_device("LOT-A", "dev-2", 1_700_000_200)
        .expect("relink");
    assert_eq!(again.revision, linked.revision, "no-op must not bump");

    registry
        .link_ledger(
            "LOT-A",
            LedgerLink::new("EXC-4", LedgerKind::ExcursionRecord),
            1_700_000_300,
        )
        .expect("ledger");
    let lot = registry.get("LOT-A").expect("lot");
    assert_eq!(lot.ledger_entry_ids(), vec!["EXC-4".to_string()]);
    assert!(lot.window.contains(1_700_000_100));

    registry
        .relocate("LOT-A", "SITE-2", "PACK-2", 1_700_000_400)
        .expect("relocate");
    assert_eq!(registry.get("LOT-A").expect("lot").location_id, "PACK-2");
    let closed = registry
        .close_window("LOT-A", 1_700_000_500)
        .expect("close");
    assert_eq!(closed.window.end_est, Some(1_700_000_500));
    assert!(!closed.window.contains(1_700_000_500));
}

#[test]
fn query_filters_by_tenant_site_kind_device_ledger_and_window() {
    let fixture = Fixture::build();
    fixture.link_reference_lineage();

    assert_eq!(
        fixture.registry.query(&LotQuery::all()).expect("all").len(),
        8
    );
    assert_eq!(
        fixture
            .registry
            .query(&LotQuery::all().device("dev-freezer-1"))
            .expect("device")
            .iter()
            .map(|lot| lot.lot_id.as_str())
            .collect::<Vec<_>>(),
        vec!["LOT-A"]
    );
    assert_eq!(
        fixture
            .registry
            .query(&LotQuery::all().ledger_entry("AE-101"))
            .expect("ledger")
            .iter()
            .map(|lot| lot.lot_id.as_str())
            .collect::<Vec<_>>(),
        vec!["B2"]
    );
    assert_eq!(
        fixture
            .registry
            .query(&LotQuery::all().site("SITE-3"))
            .expect("site")
            .len(),
        2
    );
    assert_eq!(
        fixture
            .registry
            .query(&LotQuery::all().kind(LotKind::Repack))
            .expect("kind")
            .len(),
        0
    );
    assert_eq!(
        fixture
            .registry
            .query(&LotQuery::all().limit(2))
            .expect("limit")
            .len(),
        2
    );
    let mut windowed = LotQuery::all();
    windowed.start_after_est = Some(1_700_000_001);
    assert!(fixture
        .registry
        .query(&windowed)
        .expect("window")
        .is_empty());
}

#[test]
fn export_json_is_canonical_digested_and_round_trips() {
    let fixture = Fixture::build();
    fixture.link_reference_lineage();

    let first = fixture
        .registry
        .export_json(&LotQuery::all(), 100)
        .expect("export");
    let second = fixture
        .registry
        .export_json(&LotQuery::all(), 200)
        .expect("re-export");
    let a: LotTraceExport = serde_json::from_str(&first).expect("parse export");
    let b: LotTraceExport = serde_json::from_str(&second).expect("parse export");
    assert_eq!(a.digest, b.digest, "digest covers content, not the clock");
    assert!(a.digest_valid());
    assert_eq!(a.lots.len(), 8);
    assert_eq!(a.edges.len(), 9);
    assert_eq!(a.operations.len(), 0, "hand-added edges carry no operation");
    let lot_ids: Vec<&str> = a.lots.iter().map(|lot| lot.lot_id.as_str()).collect();
    assert_eq!(
        lot_ids,
        vec!["AGG-1", "B1", "B2", "C1", "D1", "D2", "LOT-A", "LOT-E"]
    );

    // Tampering with the content invalidates the digest.
    let mut tampered = a.clone();
    tampered.lots[0].location_id = "SOMEWHERE-ELSE".to_string();
    assert!(!tampered.digest_valid());

    // A filtered export only carries the matching lots and their edges.
    let filtered: LotTraceExport = serde_json::from_str(
        &fixture
            .registry
            .export_json(&LotQuery::all().site("SITE-3"), 100)
            .expect("filtered"),
    )
    .expect("parse");
    assert_eq!(filtered.lots.len(), 2);
    assert_eq!(filtered.edges.len(), 6);
}

#[test]
fn export_csv_publishes_one_row_per_lot_with_parents() {
    let fixture = Fixture::build();
    fixture.link_reference_lineage();
    fixture
        .registry
        .register(
            LotDraft::new(
                "LOT,QUOTED",
                TENANT,
                LotKind::Batch,
                "SITE-1",
                "COLD-3",
                5,
                "kg",
                10,
            )
            .with_label("Label, with \"quotes\""),
        )
        .expect("register quoted");
    // A fresh, unconsumed lot for the split-replay check below.
    fixture
        .registry
        .register(lot_draft("LOT-F", "SITE-5", "BAY-1", 100))
        .expect("register F");

    let csv = fixture.registry.export_csv(&LotQuery::all()).expect("csv");
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 11, "header plus ten lots");
    assert!(lines[0].starts_with("lot_id,kind,label,tenant,site_id,location_id,quantity,uom"));
    let e_row = lines
        .iter()
        .find(|line| line.starts_with("LOT-E,"))
        .expect("LOT-E row");
    assert!(e_row.contains("D1:merge;D2:merge"), "row was {e_row}");
    assert!(csv.contains("\"Label, with \"\"quotes\"\"\""));
    assert!(csv.contains("\"LOT,QUOTED\""));

    // A replay of a split writes no extra rows to the export.
    let before = fixture.registry.export_csv(&LotQuery::all()).expect("csv");
    let split = SplitRequest {
        operation_id: "SPLIT-CSV".to_string(),
        parent_id: "LOT-F".to_string(),
        children: vec![ChildSpec::new("B3", 100)],
        at_est: 90,
    };
    fixture.registry.split(split.clone()).expect("split F");
    fixture.registry.split(split).expect("replay split F");
    let after = fixture.registry.export_csv(&LotQuery::all()).expect("csv");
    assert_ne!(before, after);
    assert_eq!(
        after.lines().count(),
        before.lines().count() + 1,
        "the replayed split must not add a second row"
    );

    // Every created child carries the Split operation id on its edge.
    let edge = fixture
        .registry
        .edges()
        .expect("edges")
        .into_iter()
        .find(|edge| edge.child_id == "B3")
        .expect("B3 edge");
    assert_eq!(edge.operation_id.as_deref(), Some("SPLIT-CSV"));
    let operation = fixture.registry.operation("SPLIT-CSV").expect("operation");
    assert_eq!(operation.kind, OpKind::Split);
    assert_eq!(operation.outputs, vec!["B3".to_string()]);
    assert!(matches!(
        fixture.registry.split(SplitRequest {
            operation_id: "SPLIT-CSV".to_string(),
            parent_id: "LOT-F".to_string(),
            children: vec![ChildSpec::new("B3", 100)],
            at_est: 90,
        }),
        Ok(OperationOutcome::Replayed(_))
    ));
}

// ---------------------------------------------------------------------------
// CC-11 bridge: a closed excursion is the source of a lot disposition
// ---------------------------------------------------------------------------

#[test]
fn recall_reads_a_closed_excursion_decision() {
    let registry = LotRegistry::open_in_memory().expect("registry");
    registry
        .register(lot_draft("LOT-A", "SITE-1", "COLD-1", 100))
        .expect("register A");
    registry
        .register(lot_draft("B1", "SITE-1", "COLD-1", 100))
        .expect("register B1");
    registry
        .add_edge("LOT-A", "B1", EdgeKind::Split, 10)
        .expect("A -> B1");

    // A real excursion record: detected → quarantined → notified → reject →
    // signed resolution → closed.
    let workflow = ExcursionWorkflow::open_in_memory().expect("workflow");
    let closed = closed_excursion(
        &workflow,
        "EXC-B1",
        Some("B1"),
        DispositionKind::Reject,
        1_770_000_000,
    );
    assert_eq!(closed.state, ExcursionState::Closed);
    assert!(closed.resolution.is_some(), "the decision is signed");

    let link = registry
        .link_excursion(&closed, 1_770_000_100)
        .expect("bridge excursion");
    assert_eq!(link.record_id, "EXC-B1");
    assert_eq!(link.disposition, "reject");
    assert_eq!(link.reason, "temperature_out_of_band");
    assert_eq!(link.decided_est, 1_770_000_003);
    assert_eq!(
        registry.dispositions("B1").expect("dispositions"),
        vec![link.clone()]
    );

    // The recall query cites the decision the operator signed, not a link the
    // test assembled.
    let report = registry
        .recall(&RecallRequest::new("LOT-A"), 1_770_000_101)
        .expect("recall");
    let affected = report
        .affected
        .iter()
        .find(|lot| lot.lot_id == "B1")
        .expect("B1 affected");
    assert_eq!(affected.disposition.as_ref(), Some(&link));
    assert!(report
        .affected
        .iter()
        .filter(|lot| lot.lot_id != "B1")
        .all(|lot| lot.disposition.is_none()));

    // The backward disposition query reports the same decision.
    let backwards = registry
        .disposition_report("B1", 1_770_000_102)
        .expect("disposition report");
    assert_eq!(backwards.dispositions, vec![link.clone()]);

    // Bridging the same record again is a no-op.
    registry
        .link_excursion(&closed, 1_770_000_103)
        .expect("replay bridge");
    assert_eq!(registry.dispositions("B1").expect("dispositions").len(), 1);
}

#[test]
fn bridging_refuses_unfinished_or_unattributable_excursions() {
    let registry = LotRegistry::open_in_memory().expect("registry");
    registry
        .register(lot_draft("LOT-A", "SITE-1", "COLD-1", 10))
        .expect("register");
    let workflow = ExcursionWorkflow::open_in_memory().expect("workflow");

    // Still quarantined: there is no decision to cite yet.
    workflow
        .detect(
            "EXC-OPEN",
            TENANT,
            "SITE-1",
            "dev-freezer-1",
            Some("LOT-A"),
            hot_detection(2_000_000_000),
            2_000_000_000,
        )
        .expect("detect");
    workflow
        .open_quarantine("EXC-OPEN", 2_000_000_001)
        .expect("quarantine");
    let open = workflow.get("EXC-OPEN").expect("open record");
    assert_eq!(open.state, ExcursionState::Quarantined);
    match registry
        .link_excursion(&open, 2_000_000_002)
        .expect_err("open record must be refused")
    {
        LotError::InvalidRequest(detail) => {
            assert!(detail.contains("no final disposition"), "was {detail}")
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }

    // Closed, but it names no lot, so there is nothing to attribute it to.
    let unattributed = closed_excursion(
        &workflow,
        "EXC-NOLOT",
        None,
        DispositionKind::Hold,
        2_100_000_000,
    );
    match registry
        .link_excursion(&unattributed, 2_100_000_100)
        .expect_err("unattributed record must be refused")
    {
        LotError::InvalidRequest(detail) => {
            assert!(detail.contains("names no lot"), "was {detail}")
        }
        other => panic!("expected InvalidRequest, got {other:?}"),
    }

    // Closed and attributed, but the lot identity is not registered: refused
    // rather than inventing an identity.
    let ghost = closed_excursion(
        &workflow,
        "EXC-GHOST",
        Some("LOT-MISSING"),
        DispositionKind::Destroy,
        2_200_000_000,
    );
    assert_eq!(
        registry
            .link_excursion(&ghost, 2_200_000_100)
            .expect_err("unknown lot must be refused"),
        LotError::NotFound("LOT-MISSING".to_string())
    );

    // Nothing leaked into the registry.
    assert!(registry
        .dispositions("LOT-A")
        .expect("dispositions")
        .is_empty());
    assert!(registry
        .recall(&RecallRequest::new("LOT-A"), 2_200_000_200)
        .expect("recall")
        .affected
        .iter()
        .all(|lot| lot.disposition.is_none()));
}
