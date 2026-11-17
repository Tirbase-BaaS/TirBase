// SPDX-License-Identifier: AGPL-3.0-only

//! CC-21 reporting, ALCOA+, e-signature, audit and retention proofs.
//!
//! Rows are seeded with SQL into the tables the excursion, lot and asset stores
//! own, and the ledger is written through `LineageLedger::append`, so the
//! provenance a report carries is the provenance the production code writes.

use std::path::Path;

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use tirbase_gateway::lineage_ledger::{AppendRequest, LineageLedger};
use tirbase_gateway::reporting::{
    esign_payload, verify_payload_signature, CeremonyRequest, EsignCeremony, ExportFormat,
    ReauthMethod, ReauthProof, ReportError, ReportKind, ReportRequest, ReportService, ReportSigner,
    SignerEnrollment, SourceKind,
};

fn signer() -> ReportSigner {
    ReportSigner::from_seed(&[7u8; 32])
}

fn hex_digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

const SEED: &str = r#"
CREATE TABLE IF NOT EXISTS excursion_records (
    record_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, site_id TEXT NOT NULL,
    device_id TEXT NOT NULL, lot_id TEXT, state TEXT NOT NULL, state_rank INTEGER NOT NULL,
    opened_est INTEGER NOT NULL, updated_est INTEGER NOT NULL, revision INTEGER NOT NULL,
    detection_json TEXT NOT NULL, disposition_json TEXT, resolution_json TEXT, closed_est INTEGER
);
CREATE TABLE IF NOT EXISTS excursion_events (
    record_id TEXT NOT NULL, seq INTEGER NOT NULL, event TEXT NOT NULL,
    at_est INTEGER NOT NULL, detail_json TEXT NOT NULL, PRIMARY KEY (record_id, seq)
);
CREATE TABLE IF NOT EXISTS lot_records (
    lot_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL,
    site_id TEXT NOT NULL, location_id TEXT NOT NULL, device_ids_json TEXT NOT NULL,
    window_start_est INTEGER NOT NULL, window_end_est INTEGER, ledger_entries_json TEXT NOT NULL,
    quantity INTEGER NOT NULL, uom TEXT NOT NULL, created_est INTEGER NOT NULL,
    updated_est INTEGER NOT NULL, revision INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS lot_edges (
    parent_id TEXT NOT NULL, child_id TEXT NOT NULL, kind TEXT NOT NULL,
    operation_id TEXT, created_est INTEGER NOT NULL, PRIMARY KEY (parent_id, child_id, kind)
);
CREATE TABLE IF NOT EXISTS lot_operations (
    operation_id TEXT PRIMARY KEY, kind TEXT NOT NULL, inputs_json TEXT NOT NULL,
    outputs_json TEXT NOT NULL, request_digest TEXT NOT NULL, at_est INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS lot_dispositions (
    lot_id TEXT NOT NULL, record_id TEXT NOT NULL, disposition TEXT NOT NULL,
    reason TEXT NOT NULL, decided_est INTEGER NOT NULL, PRIMARY KEY (lot_id, record_id)
);
CREATE TABLE IF NOT EXISTS asset_revisions (
    asset_id TEXT NOT NULL, version INTEGER NOT NULL, tenant TEXT NOT NULL,
    serial TEXT NOT NULL, site_id TEXT NOT NULL, PRIMARY KEY (asset_id, version)
);
CREATE TABLE IF NOT EXISTS asset_calibrations (
    calibration_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, performed_est INTEGER NOT NULL,
    due_est INTEGER NOT NULL, method TEXT NOT NULL, laboratory_party_id TEXT NOT NULL,
    digest TEXT NOT NULL
);
"#;

fn seed(db: &Path) {
    let conn = Connection::open(db).expect("seed db");
    conn.execute_batch(SEED).expect("seed schema");

    conn.execute(
        "INSERT INTO excursion_records (record_id, tenant, site_id, device_id, lot_id, state, \
         state_rank, opened_est, updated_est, revision, detection_json) \
         VALUES ('e-1', 'acme', 's1', 'd1', 'L1', 'quarantined', 1, 1000, 2000, 1, ?1)",
        [r#"{"reasons":["temperature_high"],"max_c":125}"#],
    )
    .expect("excursion e-1");
    conn.execute(
        "INSERT INTO excursion_records (record_id, tenant, site_id, device_id, lot_id, state, \
         state_rank, opened_est, updated_est, revision, detection_json, disposition_json) \
         VALUES ('e-2', 'acme', 's1', 'd2', 'L2', 'dispositioned', 3, 1500, 3000, 2, ?1, ?2)",
        params![
            r#"{"reasons":["door_open"],"max_c":80}"#,
            r#"{"disposition":"reject","reason":"temperature excursion","operator_did":"did:op:1","decided_est":3000}"#
        ],
    )
    .expect("excursion e-2");
    conn.execute(
        "INSERT INTO excursion_events (record_id, seq, event, at_est, detail_json) \
         VALUES ('e-1', 1, 'detected', 1000, '{\"reasons\":[\"temperature_high\"]}')",
        [],
    )
    .expect("event 1");
    conn.execute(
        "INSERT INTO excursion_events (record_id, seq, event, at_est, detail_json) \
         VALUES ('e-1', 2, 'quarantined', 1100, '{}')",
        [],
    )
    .expect("event 2");

    conn.execute(
        "INSERT INTO lot_records (lot_id, tenant, kind, label, site_id, location_id, \
         device_ids_json, window_start_est, ledger_entries_json, quantity, uom, created_est, \
         updated_est, revision) \
         VALUES ('L1', 'acme', 'batch', 'LOT-1', 's1', 'loc-1', '[]', 900, '[]', 10, 'kg', 900, 2500, 1)",
        [],
    )
    .expect("lot L1");
    conn.execute(
        "INSERT INTO lot_records (lot_id, tenant, kind, label, site_id, location_id, \
         device_ids_json, window_start_est, ledger_entries_json, quantity, uom, created_est, \
         updated_est, revision) \
         VALUES ('L2', 'acme', 'batch', 'LOT-2', 's1', 'loc-1', '[]', 2000, '[]', 4, 'kg', 2000, 2600, 1)",
        [],
    )
    .expect("lot L2");
    conn.execute(
        "INSERT INTO lot_edges (parent_id, child_id, kind, operation_id, created_est) \
         VALUES ('L1', 'L2', 'split', 'op-1', 2000)",
        [],
    )
    .expect("edge");
    conn.execute(
        "INSERT INTO lot_operations (operation_id, kind, inputs_json, outputs_json, \
         request_digest, at_est) VALUES ('op-1', 'split', '[\"L1\"]', '[\"L2\"]', ?1, 2000)",
        [hex_digest("op-1")],
    )
    .expect("operation");
    conn.execute(
        "INSERT INTO lot_dispositions (lot_id, record_id, disposition, reason, decided_est) \
         VALUES ('L2', 'e-2', 'reject', 'temperature excursion', 3000)",
        [],
    )
    .expect("lot disposition");

    conn.execute(
        "INSERT INTO asset_revisions (asset_id, version, tenant, serial, site_id) \
         VALUES ('a-1', 1, 'acme', 'SN-1', 's1'), ('a-2', 1, 'acme', 'SN-2', 's1')",
        [],
    )
    .expect("assets");
    conn.execute(
        "INSERT INTO asset_calibrations (calibration_id, asset_id, performed_est, due_est, \
         method, laboratory_party_id, digest) VALUES ('c-1', 'a-1', 1000, 2000, 'comparison', \
         'lab-1', ?1)",
        [hex_digest("c-1")],
    )
    .expect("calibration c-1");
    conn.execute(
        "INSERT INTO asset_calibrations (calibration_id, asset_id, performed_est, due_est, \
         method, laboratory_party_id, digest) VALUES ('c-2', 'a-2', 5000, 1086400, 'comparison', \
         'lab-1', ?1)",
        [hex_digest("c-2")],
    )
    .expect("calibration c-2");
}

fn ledger_at(db: &Path) -> LineageLedger {
    let ledger = LineageLedger::open(db).expect("ledger");
    ledger
        .append(
            AppendRequest::new(
                "exc-ledger-1",
                "did:device:d1",
                "excursion_detected",
                serde_json::json!({ "record_id": "e-1", "reason": "temperature_high" }),
                1000,
            )
            .with_lot("L1")
            .with_device("d1"),
        )
        .expect("append detected");
    ledger
        .append(
            AppendRequest::new(
                "exc-ledger-2",
                "did:op:1",
                "excursion_dispositioned",
                serde_json::json!({ "record_id": "e-2", "disposition": "reject" }),
                3000,
            )
            .with_lot("L2"),
        )
        .expect("append disposition");
    ledger
}

fn fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    ReportService,
    LineageLedger,
) {
    let directory = tempfile::tempdir().expect("tempdir");
    let db = directory.path().join("primary.db");
    let service = ReportService::open(&db, signer()).expect("report service");
    seed(&db);
    let ledger = ledger_at(&db);
    (directory, db, service, ledger)
}

#[test]
fn report_traces_rows_to_source_events_and_ledger_entries() {
    let (_directory, _db, service, ledger) = fixture();
    let request = ReportRequest::new(ReportKind::ExcursionHistory, "acme", "did:op:1", 10_000);
    let report = service.generate(&request).expect("generate");

    assert_eq!(report.rows.len(), 2);
    assert_eq!(report.totals["records"], "2");
    let row = report
        .rows
        .iter()
        .find(|row| row.key == "e-1")
        .expect("e-1 row");
    assert!(row.cells["ledger_entries"].contains("exc-ledger-1"));
    assert_eq!(row.cells["reasons"], "temperature_high");
    assert!(row
        .sources
        .iter()
        .any(|source| source.kind == SourceKind::ExcursionEvent && source.id == "e-1:1"));

    let ledger_entry = ledger
        .load_by_entry_id("exc-ledger-1")
        .expect("ledger read")
        .expect("entry");
    assert!(report.cites(SourceKind::LedgerEntry, "exc-ledger-1"));
    assert_eq!(report.ledger_refs().len(), 2);
    let cited = report
        .sources
        .iter()
        .find(|source| source.kind == SourceKind::LedgerEntry && source.id == "exc-ledger-1")
        .expect("cited ledger entry");
    assert_eq!(cited.digest, ledger_entry.entry_hash);

    assert!(report.alcoa.satisfied(), "{:?}", report.alcoa);
    assert_eq!(
        service.load_report(&report.report_id).expect("reload"),
        report
    );

    let audit = service.audit_for_action("report_generated").expect("audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].subject, report.report_id);
    assert_eq!(audit[0].detail["content_sha256"], report.content_sha256);
    let chain = service.verify_audit_chain().expect("chain");
    assert!(chain.valid, "{:?}", chain.reasons);

    // Regenerating the same report is idempotent: same id, no new audit entry.
    let again = service.generate(&request).expect("regenerate");
    assert_eq!(again.report_id, report.report_id);
    assert_eq!(service.audit_entry_count().expect("audit count"), 1);
}

#[test]
fn aging_calibration_and_lot_reports_carry_their_provenance() {
    let (_directory, _db, service, _ledger) = fixture();

    let aging = service
        .generate(&ReportRequest::new(
            ReportKind::QuarantineAging,
            "acme",
            "did:op:1",
            1000 + 80 * 3600,
        ))
        .expect("aging");
    assert_eq!(aging.rows.len(), 1);
    assert_eq!(aging.rows[0].key, "e-1");
    assert_eq!(aging.rows[0].cells["age_bucket"], "critical");
    assert_eq!(aging.totals["aging"], "1");

    let calibration = service
        .generate(&ReportRequest::new(
            ReportKind::CalibrationDue,
            "acme",
            "did:op:1",
            10_000,
        ))
        .expect("calibration");
    assert_eq!(calibration.rows.len(), 2);
    assert_eq!(calibration.totals["overdue"], "1");
    assert_eq!(calibration.totals["due_soon"], "1");
    assert!(calibration.rows.iter().any(|row| {
        row.key == "c-1" && row.cells["status"] == "overdue" && row.cells["serial"] == "SN-1"
    }));

    let traceability = service
        .generate(
            &ReportRequest::new(ReportKind::LotTraceability, "acme", "did:op:1", 10_000)
                .with_subject("L1"),
        )
        .expect("traceability");
    assert_eq!(traceability.rows.len(), 1);
    assert!(traceability.rows[0].cells["children"].contains("L2 (split)"));
    assert!(traceability.rows.iter().any(|row| row
        .sources
        .iter()
        .any(|source| source.kind == SourceKind::LotEdge)));

    let disposition = service
        .generate(&ReportRequest::new(
            ReportKind::Disposition,
            "acme",
            "did:op:1",
            10_000,
        ))
        .expect("disposition");
    assert_eq!(disposition.rows.len(), 1);
    assert_eq!(disposition.rows[0].cells["disposition"], "reject");
    assert_eq!(disposition.rows[0].cells["lot_dispositions"], "L2:e-2");

    // Another tenant sees none of it.
    let other = service
        .generate(&ReportRequest::new(
            ReportKind::ExcursionHistory,
            "northwind",
            "did:op:1",
            10_000,
        ))
        .expect("other tenant");
    assert!(other.rows.is_empty());
    assert_eq!(other.totals["records"], "0");
    assert!(other.alcoa.satisfied());
}

#[test]
fn esignature_binds_the_record_is_single_use_and_needs_fresh_reauth() {
    let (_directory, db, service, _ledger) = fixture();
    let approved = service
        .generate(&ReportRequest::new(
            ReportKind::ExcursionHistory,
            "acme",
            "did:qa",
            10_000,
        ))
        .expect("report A");
    let other = service
        .generate(&ReportRequest::new(
            ReportKind::LotTraceability,
            "acme",
            "did:qa",
            10_000,
        ))
        .expect("report B");

    service
        .enroll_signer(
            &SignerEnrollment {
                signer_id: "did:qa".to_string(),
                credential_sha256: hex_digest("correct horse"),
                role: "quality".to_string(),
                enrolled_est: 1000,
            },
            "did:admin",
        )
        .expect("enroll");

    let proof = |at_est: i64, credential: &str| ReauthProof {
        method: ReauthMethod::Password,
        at_est,
        credential_sha256: hex_digest(credential),
    };

    // A wrong credential and a stale re-authentication are both refused and audited.
    let wrong = service.open_ceremony(&CeremonyRequest::new(
        "c-wrong",
        &approved.report_id,
        "did:qa",
        "Approving batch release",
        proof(9_900, "wrong"),
        10_000,
    ));
    assert!(matches!(wrong, Err(ReportError::ReauthFailed(_))));
    let stale = service.open_ceremony(&CeremonyRequest::new(
        "c-stale",
        &approved.report_id,
        "did:qa",
        "Approving batch release",
        proof(1_000, "correct horse"),
        10_000,
    ));
    assert!(matches!(stale, Err(ReportError::ReauthNotFresh { .. })));
    assert_eq!(
        service
            .audit_for_action("esign_reauth_failed")
            .expect("audit")
            .len(),
        2
    );

    let ceremony: EsignCeremony = service
        .open_ceremony(&CeremonyRequest::new(
            "c-1",
            &approved.report_id,
            "did:qa",
            "Approving batch release",
            proof(9_900, "correct horse"),
            10_000,
        ))
        .expect("ceremony");
    assert_eq!(ceremony.record_sha256, approved.content_sha256);
    assert_eq!(
        service
            .open_ceremony(&CeremonyRequest::new(
                "c-1",
                &approved.report_id,
                "did:qa",
                "Approving batch release",
                proof(9_900, "correct horse"),
                10_000,
            ))
            .expect("idempotent reopen")
            .nonce,
        ceremony.nonce
    );

    let signature = service.sign_ceremony("c-1", 10_050).expect("sign");
    let verified = service
        .verify_signature(&signature.signature_id)
        .expect("verify");
    assert!(verified.valid, "{:?}", verified.reasons);
    assert!(verified.record_matches);

    // Single use: the same ceremony cannot produce a second signature.
    assert_eq!(
        service.sign_ceremony("c-1", 10_060),
        Err(ReportError::CeremonyAlreadyUsed("c-1".to_string()))
    );

    // The signature cannot be replayed onto another record: the payload names the
    // report digest, so report B's payload does not verify under A's signature.
    let payload_for_other = esign_payload(
        &other.report_id,
        &other.content_sha256,
        &signature.signer_id,
        &signature.ceremony_id,
        &signature.nonce,
        &signature.reason,
        signature.signed_est,
    )
    .expect("payload");
    assert!(!verify_payload_signature(
        &signature.signer_public_key,
        &payload_for_other,
        &signature.signature
    ));

    // Tampering with the stored report breaks the binding too.
    let mut tampered = service
        .load_report(&approved.report_id)
        .expect("load")
        .clone();
    tampered
        .totals
        .insert("tampered".to_string(), "yes".to_string());
    let conn = Connection::open(&db).expect("db");
    conn.execute(
        "UPDATE report_generations SET content_json = ?2 WHERE report_id = ?1",
        params![
            approved.report_id,
            serde_json::to_string(&tampered).expect("json")
        ],
    )
    .expect("tamper");
    let broken = service
        .verify_signature(&signature.signature_id)
        .expect("verify tampered");
    assert!(!broken.valid);
    assert!(!broken.record_matches);

    let audit = service.audit_for_action("report_signed").expect("audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].detail["reason"], "Approving batch release");
    assert!(service.verify_audit_chain().expect("chain").valid);
}

#[test]
fn exports_are_signed_and_verifiable_then_survive_retention_and_restore() {
    let (directory, _db, service, _ledger) = fixture();
    let report = service
        .generate(&ReportRequest::new(
            ReportKind::ExcursionHistory,
            "acme",
            "did:qa",
            10_000,
        ))
        .expect("report");

    let csv = service
        .export(&report.report_id, ExportFormat::Csv, "did:qa", 10_100)
        .expect("csv");
    let json = service
        .export(&report.report_id, ExportFormat::Json, "did:qa", 10_100)
        .expect("json");
    let pdf = service
        .export(&report.report_id, ExportFormat::Pdf, "did:qa", 10_100)
        .expect("pdf");

    assert!(csv.body.starts_with(b"record_id,"));
    assert!(String::from_utf8_lossy(&csv.body).contains("e-1"));
    assert!(pdf.body.starts_with(b"%PDF-1.4"));
    assert_eq!(csv.manifest.signature_algorithm, "ed25519");
    assert_eq!(csv.manifest.body_bytes, csv.body.len());
    let decoded: serde_json::Value = serde_json::from_slice(&json.body).expect("json export");
    assert_eq!(decoded["report_id"], report.report_id);
    assert_eq!(decoded["content_sha256"], report.content_sha256);

    for export in [&csv, &json, &pdf] {
        let verification = service
            .verify_export(&export.manifest.export_id)
            .expect("verify export");
        assert!(verification.valid, "{:?}", verification.reasons);
        assert!(verification.signature_valid);
        assert_eq!(
            verification.recomputed_body_sha256.as_deref(),
            Some(export.manifest.body_sha256.as_str())
        );
    }
    assert_eq!(
        service
            .exports_for(&report.report_id)
            .expect("exports")
            .len(),
        3
    );

    // The export-verification report re-derives every verdict.
    let verification_report = service
        .generate(&ReportRequest::new(
            ReportKind::ExportVerification,
            "acme",
            "did:auditor",
            10_200,
        ))
        .expect("verification report");
    assert_eq!(verification_report.rows.len(), 3);
    assert_eq!(verification_report.totals["valid"], "3");
    assert!(verification_report
        .rows
        .iter()
        .all(|row| row.cells["verdict"] == "valid"));
    assert!(verification_report.alcoa.satisfied());

    // Snapshot before retention removes the bodies.
    let snapshot = directory.path().join("snapshot.db");
    service.snapshot_to(&snapshot).expect("snapshot");

    let pruned = service
        .prune_export_bodies(10_150, "did:admin", 10_300)
        .expect("prune");
    assert_eq!(pruned, 3);
    let after_prune = service
        .verify_export(&csv.manifest.export_id)
        .expect("verify pruned");
    assert!(!after_prune.valid);
    assert!(!after_prune.body_present);
    assert!(after_prune
        .reasons
        .iter()
        .any(|reason| reason.contains("pruned")));
    assert!(service
        .export_body(&csv.manifest.export_id)
        .expect("body")
        .is_none());

    // Retention pruned bodies only: generations, manifests and the audit chain
    // (including the pruning record) are intact and still verify.
    let chain_after = service.verify_audit_chain().expect("chain");
    assert!(chain_after.valid, "{:?}", chain_after.reasons);
    assert_eq!(
        service
            .audit_for_action("exports_pruned")
            .expect("audit")
            .len(),
        1
    );
    assert_eq!(
        service
            .audit_for_subject(&report.report_id)
            .expect("audit")
            .len(),
        1
    );
    assert_eq!(
        service
            .load_report(&report.report_id)
            .expect("report")
            .content_sha256,
        report.content_sha256
    );

    // Restore: open the snapshot as a fresh service. Audit, generations and the
    // pruned bodies all come back.
    let restored = ReportService::open(&snapshot, signer()).expect("restored");
    let restored_chain = restored.verify_audit_chain().expect("restored chain");
    assert!(restored_chain.valid, "{:?}", restored_chain.reasons);
    assert_eq!(restored_chain.entries, chain_after.entries - 1);
    assert!(restored
        .audit_for_action("exports_pruned")
        .expect("audit")
        .is_empty());
    assert_eq!(
        restored
            .load_report(&report.report_id)
            .expect("report")
            .content_sha256,
        report.content_sha256
    );
    let restored_export = restored
        .verify_export(&csv.manifest.export_id)
        .expect("verify restored");
    assert!(restored_export.valid);
    assert!(restored_export.body_present);
    assert_eq!(
        restored
            .export_body(&csv.manifest.export_id)
            .expect("body")
            .expect("present"),
        csv.body
    );
}
