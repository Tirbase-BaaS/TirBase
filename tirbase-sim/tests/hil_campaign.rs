// SPDX-License-Identifier: AGPL-3.0-only

//! CC-22 sensor/controller validation evidence.
//!
//! Runs the software bench campaign for every transport in the matrix, seals the
//! result with a digest, proves the campaign is byte-identical for the same seed,
//! and kills a real child process inside an open write transaction to prove a
//! power cut cannot corrupt calibration or ledger state.
//!
//! Reproduction (documented in `docs/evidence/hil/cc22-sensor-controller-validation/`):
//!
//! ```text
//! cargo test -p tirbase-sim --test hil_campaign -- --nocapture
//! ```
//!
//! Evidence is written to `target/hil-evidence/cc22/`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use rusqlite::Connection;

use tirbase_gateway::asset_registry::{
    AssetDraft, AssetIdentity, AssetKind, AssetRegistry, CalibrationDraft, CalibrationPoint,
    CertificateRef,
};
use tirbase_gateway::lineage_ledger::{AppendRequest, LineageLedger};
use tirbase_sim::hil::{run_campaign, verify_recovery, CaseKind, Transport};

/// Environment variable selecting the power-cut stage for the child process.
const CRASH_STAGE_ENV: &str = "HIL_CRASH_STAGE";
/// Database the child process opens.
const CRASH_DB_ENV: &str = "HIL_CRASH_DB";

fn evidence_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/hil-evidence/cc22")
}

fn certificate() -> CertificateRef {
    CertificateRef {
        certificate_id: "cert-reference".to_string(),
        sha256: "0".repeat(64),
        bytes: 512,
        media_type: "application/pdf".to_string(),
        issued_est: 900,
        expires_est: None,
        issuer: "reference-lab".to_string(),
    }
}

fn calibration_draft(calibration_id: &str) -> CalibrationDraft {
    calibration_draft_at(calibration_id, 2_000)
}

fn calibration_draft_at(calibration_id: &str, performed_est: i64) -> CalibrationDraft {
    CalibrationDraft::new(
        calibration_id,
        "asset-1",
        performed_est,
        31_536_000,
        "did:qa",
    )
    .with_laboratory("comparison-ice-point", "reference-lab")
    .with_uncertainty(tirbase_types::FixedPointValue::new(
        2,
        -1,
        tirbase_types::UNIT_DEG_C,
    ))
    .with_points(vec![
        CalibrationPoint::new(0, 1),
        CalibrationPoint::new(500, 499),
        CalibrationPoint::new(1_000, 1_001),
    ])
    .with_certificate(certificate())
}

fn seed_database(path: &Path) {
    let registry = AssetRegistry::open(path).expect("registry");
    let identity = AssetIdentity::new(AssetKind::Sensor, "acme", "PT100-class-A", "SN-0001")
        .with_manufacturer("reference-instruments")
        .with_firmware("1.0.0")
        .with_location("bench-site", "bench-rack-1")
        .with_installed_est(1_000);
    registry
        .put(AssetDraft::new("asset-1", identity, "did:qa"))
        .expect("asset");
    registry
        .register_calibration(calibration_draft("cal-base"))
        .expect("baseline calibration");

    let ledger = LineageLedger::open(path).expect("ledger");
    for index in 0..2u64 {
        ledger
            .append(AppendRequest::new(
                format!("seed-{index}"),
                "did:device:bench",
                "hil_bench_cycle",
                serde_json::json!({ "cycle": index }),
                10_000 + index as i64,
            ))
            .expect("seed append");
    }
}

fn run_child(stage: &str, db: &Path) {
    let status = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "crash_helper", "--nocapture"])
        .env(CRASH_STAGE_ENV, stage)
        .env(CRASH_DB_ENV, db)
        .status()
        .expect("spawn crash helper");
    assert!(
        !status.success(),
        "the crash helper must die at the write boundary for {stage}"
    );
}

#[test]
fn crash_helper() {
    let Ok(stage) = std::env::var(CRASH_STAGE_ENV) else {
        return;
    };
    let db = PathBuf::from(std::env::var(CRASH_DB_ENV).expect("crash db path"));
    match stage.as_str() {
        // Cut inside an open calibration transaction: the row must never appear.
        "calibration-uncommitted" => {
            let connection = Connection::open(&db).expect("open db");
            connection.execute_batch("BEGIN IMMEDIATE").expect("begin");
            connection
                .execute(
                    "INSERT INTO asset_calibrations (calibration_id, asset_id, performed_est, \
                     due_est, interval_secs, method, laboratory_party_id, uncertainty_mantissa, \
                     uncertainty_exponent, uncertainty_unit, points_json, certificate_id, \
                     certificate_sha256, certificate_bytes, certificate_media_type, \
                     certificate_issued_est, certificate_expires_est, certificate_issuer, \
                     actor_did, digest) VALUES ('cal-cut', 'asset-1', 3000, 4000, 1000, 'cut', \
                     'bench', 0, 0, 0, '[]', 'cert', '0000', 0, 'text/plain', 900, NULL, \
                     'bench', 'did:qa', 'cut')",
                    [],
                )
                .expect("insert calibration");
        }
        // Cut after the calibration committed but before the caller could record
        // anything else: the record must be durable and complete.
        "calibration-committed" => {
            let registry = AssetRegistry::open(&db).expect("registry");
            registry
                .register_calibration(calibration_draft_at("cal-cut", 3_000))
                .expect("committed calibration");
        }
        // Cut inside an open ledger transaction: no half entry, no chain break.
        "ledger-uncommitted" => {
            let connection = Connection::open(&db).expect("open db");
            connection.execute_batch("BEGIN IMMEDIATE").expect("begin");
            connection
                .execute(
                    "INSERT INTO lineage_ledger (seq, entry_id, prev_hash, entry_hash, \
                     recorded_est, actor_did, device_id, lot_id, event_type, payload_hash, \
                     payload_json) VALUES (99, 'cut-entry', 'prev', 'hash', 4000, \
                     'did:bench', NULL, NULL, 'hil_cut', 'payload', '{}')",
                    [],
                )
                .expect("insert ledger");
        }
        // Cut after the append committed: the entry is durable and linked.
        "ledger-committed" => {
            let ledger = LineageLedger::open(&db).expect("ledger");
            ledger
                .append(AppendRequest::new(
                    "cut-entry",
                    "did:device:bench",
                    "hil_bench_cycle",
                    serde_json::json!({ "cut": true }),
                    12_000,
                ))
                .expect("committed append");
        }
        other => panic!("unknown crash stage {other}"),
    }
    std::process::abort();
}

#[test]
fn campaign_covers_every_transport_and_is_reproducible() {
    let first = run_campaign(22);
    assert!(first.passed, "campaign failed: {}", first.to_json());

    for transport in [
        Transport::Ds18b20,
        Transport::CurrentLoop,
        Transport::Ble,
        Transport::Bacnet,
        Transport::ModbusRtu,
        Transport::ModbusTcp,
    ] {
        let bench = first
            .cases
            .iter()
            .any(|case| case.transport == transport && case.kind == CaseKind::Bench);
        let accuracy = first
            .cases
            .iter()
            .any(|case| case.transport == transport && case.kind == CaseKind::Accuracy);
        let recovery = first
            .cases
            .iter()
            .any(|case| case.transport == transport && case.kind == CaseKind::NetworkLoss);
        let environmental = first
            .cases
            .iter()
            .any(|case| case.transport == transport && case.kind == CaseKind::Environmental);
        assert!(bench, "{} has no bench case", transport.as_str());
        assert!(accuracy, "{} has no accuracy case", transport.as_str());
        assert!(recovery, "{} has no network-loss case", transport.as_str());
        assert!(
            environmental,
            "{} has no environmental case",
            transport.as_str()
        );
    }
    assert!(first
        .cases
        .iter()
        .any(|case| case.kind == CaseKind::Stability));

    let second = run_campaign(22);
    assert_eq!(
        first.digest, second.digest,
        "the campaign must be byte-identical for the same seed"
    );
    assert_eq!(first.to_json(), second.to_json());

    let directory = evidence_dir();
    std::fs::create_dir_all(&directory).expect("evidence dir");
    std::fs::write(directory.join("campaign.json"), first.to_json()).expect("campaign json");
    std::fs::write(directory.join("campaign.md"), first.to_markdown()).expect("campaign markdown");
}

#[test]
fn power_cut_during_write_leaves_calibration_and_ledger_consistent() {
    let cases = [
        ("calibration-uncommitted", false),
        ("calibration-committed", true),
        ("ledger-uncommitted", false),
        ("ledger-committed", true),
    ];
    let mut results = Vec::new();

    for (stage, committed) in cases {
        let directory = tempfile::tempdir().expect("tempdir");
        let db = directory.path().join("primary.db");
        seed_database(&db);
        let before = verify_recovery(&db).expect("baseline recovery check");
        assert!(before.integrity_ok && before.chain_ok, "{before:?}");
        assert_eq!(before.calibration_count, 1);
        assert_eq!(before.ledger_entries, 2);

        run_child(stage, &db);

        let after = verify_recovery(&db).expect("post-cut recovery check");
        assert!(
            after.integrity_ok,
            "sqlite integrity failed after {stage}: {after:?}"
        );
        assert!(
            after.chain_ok,
            "ledger chain broke after {stage}: {after:?}"
        );
        match stage {
            "calibration-uncommitted" | "ledger-uncommitted" => {
                // The in-flight row is rolled back atomically.
                assert_eq!(
                    after.calibration_count, before.calibration_count,
                    "{stage} left a partial calibration"
                );
                assert_eq!(
                    after.ledger_entries, before.ledger_entries,
                    "{stage} left a partial ledger entry"
                );
            }
            "calibration-committed" => {
                assert_eq!(
                    after.calibration_count, 2,
                    "{stage} lost a committed calibration"
                );
                assert_eq!(after.ledger_entries, 2);
            }
            "ledger-committed" => {
                assert_eq!(after.ledger_entries, 3, "{stage} lost a committed entry");
                assert_eq!(after.calibration_count, 1);
            }
            _ => unreachable!(),
        }
        results.push(serde_json::json!({
            "stage": stage,
            "expected_commit": committed,
            "before": before,
            "after": after,
        }));
    }

    // The interrupted rows must not exist anywhere.
    let directory = tempfile::tempdir().expect("tempdir");
    let db = directory.path().join("primary.db");
    seed_database(&db);
    run_child("calibration-uncommitted", &db);
    let connection = Connection::open(&db).expect("open db");
    let partial: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM asset_calibrations WHERE calibration_id = 'cal-cut'",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(partial, 0, "an interrupted calibration row survived");

    let directory_path = evidence_dir();
    std::fs::create_dir_all(&directory_path).expect("evidence dir");
    std::fs::write(
        directory_path.join("power-cut.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "tirbase.hil.cc22.power-cut.v1",
            "cases": results,
        }))
        .expect("power cut json"),
    )
    .expect("write power cut evidence");
}

/// The evidence pack must cite a digest that a fresh run can reproduce.
#[test]
fn committed_evidence_matches_a_fresh_run() {
    let committed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/evidence/hil/cc22-sensor-controller-validation/campaign.json");
    if !committed.exists() {
        // The pack is generated by the campaign test; this test only guards a
        // committed pack when one is present.
        return;
    }
    let text = std::fs::read_to_string(&committed).expect("committed campaign");
    let committed: serde_json::Value = serde_json::from_str(&text).expect("committed json");
    let fresh = run_campaign(
        committed["seed"]
            .as_u64()
            .expect("committed pack carries its seed"),
    );
    assert_eq!(
        committed["digest"], fresh.digest,
        "the committed evidence pack no longer matches the documented procedure"
    );
}

/// Keeps the ledger type imported for the recovery assertions above.
#[allow(dead_code)]
fn ledger_entries(path: &Path) -> usize {
    let ledger = LineageLedger::open(path).expect("ledger");
    ledger
        .verify(&BTreeSet::new(), &|_| None)
        .expect("verify")
        .checked
}
