// SPDX-License-Identifier: AGPL-3.0-only

//! Asset and calibration registry integration tests (CC-18).
//!
//! Proves the six deliverables end to end: asset identity is versioned with
//! model, serial, firmware, site and location; calibration points, interval,
//! uncertainty, certificate and due dates are stored and dated; drift is
//! detected against reference checks and against the original baseline; an
//! expired calibration blocks the affected CC-12 lot (and can raise a CC-11
//! excursion); a certificate is verifiable by hash and its bytes are never
//! stored; and the audit history and exports survive replacement and retirement.

use sha2::{Digest, Sha256};
use tirbase_gateway::asset_registry::{
    AssetDraft, AssetIdentity, AssetKind, AssetQuery, AssetRegistry, AssetStatus, CalibrationDraft,
    CalibrationPoint, CalibrationState, CertificateRef, ReferenceCheckDraft, ReleaseDecision,
    BLOCK_CALIBRATION_EXPIRED, BLOCK_REFERENCE_DRIFT,
};
use tirbase_gateway::excursion::{ExcursionReason, ExcursionWorkflow};
use tirbase_gateway::lot::{LotDraft, LotKind, LotRegistry};
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

const ACTOR: &str = "did:key:z6MkAssetRegistrar";
const OPERATOR: &str = "did:key:z6MkCalibrationOperator";

fn deci_c(value: i64) -> FixedPointValue {
    FixedPointValue::new(value, -1, UNIT_DEG_C)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sensor(serial: &str, installed_est: i64) -> AssetDraft {
    AssetDraft::new(
        format!("ASSET-{serial}"),
        AssetIdentity::new(AssetKind::Sensor, "tenant-a", "TS-100", serial)
            .with_manufacturer("ColdSense")
            .with_firmware("1.4.2")
            .with_location("site-1", "loc-1")
            .with_installed_est(installed_est)
            .with_calibration_required(86_400),
        ACTOR,
    )
    .with_reason("commissioned")
}

fn calibration_bytes() -> &'static [u8] {
    b"%PDF-1.7 certificate CERT-2026-04 for ASSET-SN-0001"
}

fn certificate() -> CertificateRef {
    CertificateRef::from_bytes(
        "CERT-2026-04",
        calibration_bytes(),
        "application/pdf",
        "Calibration Lab",
        900,
        None,
    )
}

fn calibration(id: &str, performed_est: i64, measured_offset: i64) -> CalibrationDraft {
    CalibrationDraft::new(id, "ASSET-SN-0001", performed_est, 3_600, ACTOR)
        .with_laboratory("comparison-ice-point", "lab-1")
        .with_uncertainty(deci_c(2))
        .with_points(vec![
            CalibrationPoint::new(20, 20 + measured_offset),
            CalibrationPoint::new(80, 80 + measured_offset),
        ])
        .with_certificate(certificate())
}

fn lot(device_id: &str) -> tirbase_gateway::lot::LotRecord {
    let lots = LotRegistry::open_in_memory().expect("lot registry");
    lots.register(
        LotDraft::new(
            "LOT-1",
            "tenant-a",
            LotKind::Lot,
            "site-1",
            "loc-1",
            100,
            "kg",
            1_000,
        )
        .with_device(device_id),
    )
    .expect("register lot")
}

// ---------------------------------------------------------------------------
// Identity, model, serial, firmware, site, location
// ---------------------------------------------------------------------------

#[test]
fn asset_identity_is_versioned_and_queried_as_of_an_instant() {
    let registry = AssetRegistry::open_in_memory().expect("registry");
    let first = registry.put(sensor("SN-0001", 1_000)).expect("register");

    assert_eq!(first.version, 1);
    assert_eq!(first.status, AssetStatus::Active);
    assert_eq!(first.identity.kind, AssetKind::Sensor);
    assert_eq!(first.identity.model, "TS-100");
    assert_eq!(first.identity.serial, "SN-0001");
    assert_eq!(first.identity.firmware, "1.4.2");
    assert_eq!(first.identity.site_id, "site-1");
    assert_eq!(first.identity.location_id, "loc-1");
    assert_eq!(first.identity.max_calibration_interval_secs, Some(86_400));
    assert!(first.is_effective_at(1_000));

    // Before the install there is no version in force.
    assert!(registry.get("ASSET-SN-0001", 999).is_err());

    // A firmware flash appends a version and closes the previous range.
    let mut identity = first.identity.clone();
    identity.firmware = "1.5.0".to_string();
    let second = registry
        .revise("ASSET-SN-0001", identity, 2_000, ACTOR, "firmware flash")
        .expect("revise");
    assert_eq!(second.version, 2);
    let versions = registry.versions("ASSET-SN-0001").expect("versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].effective_to_est, Some(2_000));
    assert_eq!(versions[0].identity.firmware, "1.4.2");
    assert_eq!(versions[1].identity.firmware, "1.5.0");
    assert_eq!(
        registry
            .get("ASSET-SN-0001", 1_500)
            .expect("historical")
            .identity
            .firmware,
        "1.4.2",
        "a firmware change must not rewrite what a historical event saw"
    );
    assert_eq!(
        registry
            .get("ASSET-SN-0001", 2_500)
            .expect("current")
            .identity
            .firmware,
        "1.5.0"
    );

    // History is append-only and names the actor and reason.
    let history = registry.history("ASSET-SN-0001").expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].action.as_str(), "registered");
    assert_eq!(history[1].action.as_str(), "revised");
    assert_eq!(history[1].reason, "firmware flash");
    assert_eq!(history[1].actor_did, ACTOR);

    // An in-service serial cannot be reused.
    let mut duplicate = sensor("SN-0001", 3_000);
    duplicate.asset_id = "ASSET-OTHER".to_string();
    duplicate.effective_from_est = 3_000;
    assert!(matches!(
        registry.put(duplicate),
        Err(tirbase_gateway::asset_registry::AssetError::SerialConflict { .. })
    ));

    // Identity validation fails closed on a missing location.
    let mut no_location = AssetDraft::new(
        "ASSET-BAD",
        AssetIdentity::new(AssetKind::Controller, "tenant-a", "CTRL-1", "SN-0002")
            .with_manufacturer("ColdSense")
            .with_firmware("2.0.0")
            .with_installed_est(1_000),
        ACTOR,
    );
    no_location.effective_from_est = 1_000;
    assert!(matches!(
        registry.put(no_location),
        Err(tirbase_gateway::asset_registry::AssetError::InvalidIdentifier { ref field, .. })
            if field == "site_id"
    ));

    // Query filters by kind, site, status and free text.
    let found = registry
        .query(
            &AssetQuery {
                kinds: vec![AssetKind::Sensor],
                site_id: Some("site-1".to_string()),
                status: Some(AssetStatus::Active),
                text: Some("ts-100".to_string()),
                limit: None,
            },
            2_500,
        )
        .expect("query");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].asset_id, "ASSET-SN-0001");
    assert!(registry
        .query(
            &AssetQuery {
                kinds: vec![AssetKind::Controller],
                ..AssetQuery::default()
            },
            2_500,
        )
        .expect("query controllers")
        .is_empty());
}

// ---------------------------------------------------------------------------
// Calibration points, intervals, certificates, uncertainty, due dates
// ---------------------------------------------------------------------------

#[test]
fn calibration_records_due_dates_and_certificate_hashes() {
    let registry = AssetRegistry::open_in_memory().expect("registry");
    registry.put(sensor("SN-0001", 1_000)).expect("register");

    let record = registry
        .register_calibration(calibration("CAL-1", 1_000, 1))
        .expect("calibration");
    assert_eq!(record.performed_est, 1_000);
    assert_eq!(record.due_est, 4_600);
    assert_eq!(record.interval_secs, 3_600);
    assert_eq!(record.uncertainty_c, deci_c(2));
    assert_eq!(record.points.len(), 2);
    assert_eq!(record.points[1].error_deci_c(), 1);
    assert_eq!(record.max_error_deci_c(), 1);

    // Due dates drive the state: valid, warning window, expired.
    assert_eq!(
        registry
            .calibration_state("ASSET-SN-0001", 1_000)
            .expect("state"),
        CalibrationState::Valid { due_est: 4_600 }
    );
    assert_eq!(
        registry
            .calibration_state("ASSET-SN-0001", 4_600 - 360)
            .expect("state"),
        CalibrationState::DueSoon { due_est: 4_600 }
    );
    assert_eq!(
        registry
            .calibration_state("ASSET-SN-0001", 4_600)
            .expect("state"),
        CalibrationState::Expired { due_est: 4_600 }
    );
    assert!(registry
        .calibration_state("ASSET-SN-0001", 4_600)
        .expect("state")
        .blocks_release());

    // The certificate is pinned by hash and verifies against the real bytes.
    assert_eq!(record.certificate.sha256, sha256_hex(calibration_bytes()));
    assert_eq!(record.certificate.bytes, calibration_bytes().len() as u64);
    registry
        .verify_certificate(&record.certificate, calibration_bytes())
        .expect("hash verifies");

    // Tampered bytes and a tampered digest both fail closed.
    let mut tampered = calibration_bytes().to_vec();
    tampered.push(b' ');
    assert!(matches!(
        registry.verify_certificate(&record.certificate, &tampered),
        Err(tirbase_gateway::asset_registry::AssetError::CertificateMismatch { .. })
    ));
    let mut forged = record.certificate.clone();
    forged.sha256 = format!("0{}", &forged.sha256[1..]);
    assert!(matches!(
        registry.verify_certificate(&forged, calibration_bytes()),
        Err(tirbase_gateway::asset_registry::AssetError::CertificateMismatch { .. })
    ));
    // A certificate that does not describe the calibration it is attached to is
    // refused by the digest, not by trusting the identifier.
    let mut wrong_id = record.certificate.clone();
    wrong_id.sha256 = sha256_hex(b"another certificate entirely");
    assert!(registry
        .verify_certificate(&wrong_id, calibration_bytes())
        .is_err());

    // Retrying the identical calibration is idempotent.
    let repeated = registry
        .register_calibration(calibration("CAL-1", 1_000, 1))
        .expect("idempotent");
    assert_eq!(repeated.digest, record.digest);
    assert_eq!(
        registry
            .calibrations("ASSET-SN-0001")
            .expect("records")
            .len(),
        1
    );

    // A second calibration must be performed later, and may not exceed policy.
    assert!(matches!(
        registry.register_calibration(calibration("CAL-0", 1_000, 1)),
        Err(tirbase_gateway::asset_registry::AssetError::EffectiveDate { .. })
    ));
    let later = registry
        .register_calibration(calibration("CAL-2", 4_700, 0))
        .expect("recalibration");
    assert_eq!(later.due_est, 8_300);
    assert_eq!(
        registry
            .calibration_state("ASSET-SN-0001", 8_000)
            .expect("state"),
        CalibrationState::DueSoon { due_est: 8_300 }
    );
    let mut too_long = calibration("CAL-3", 5_000, 0);
    too_long.interval_secs = 90_000;
    assert!(matches!(
        registry.register_calibration(too_long),
        Err(tirbase_gateway::asset_registry::AssetError::Invalid { ref field, .. })
            if field == "interval_secs"
    ));

    // Unordered reference points are refused.
    let mut unordered = calibration("CAL-4", 5_000, 0);
    unordered.points = vec![CalibrationPoint::new(80, 80), CalibrationPoint::new(20, 20)];
    assert!(matches!(
        registry.register_calibration(unordered),
        Err(tirbase_gateway::asset_registry::AssetError::Invalid { ref field, .. })
            if field.starts_with("points[1]")
    ));
}

// ---------------------------------------------------------------------------
// Drift detection against reference checks
// ---------------------------------------------------------------------------

#[test]
fn drift_is_detected_against_reference_and_baseline() {
    let registry = AssetRegistry::open_in_memory().expect("registry");
    // A controller without a calibration requirement isolates the drift gate.
    let mut draft = AssetDraft::new(
        "ASSET-CTRL-1",
        AssetIdentity::new(AssetKind::Controller, "tenant-a", "CTRL-9", "SN-CTRL-1")
            .with_manufacturer("ColdSense")
            .with_firmware("2.1.0")
            .with_location("site-1", "loc-1")
            .with_installed_est(1_000),
        ACTOR,
    );
    draft.effective_from_est = 1_000;
    registry.put(draft).expect("controller");

    // Baseline check: reading matches the ice point exactly.
    let (baseline, report) = registry
        .record_reference_check(ReferenceCheckDraft::new(
            "CHK-1",
            "ASSET-CTRL-1",
            1_000,
            0,
            0,
            3,
            OPERATOR,
        ))
        .expect("baseline check");
    assert!(!report.drifted);
    assert!(report.baseline_check_id.is_none());
    assert_eq!(registry.drift_report("CHK-1").expect("report"), report);

    // A check inside tolerance but 2 deci-C off baseline is not yet drift.
    let (_, report) = registry
        .record_reference_check(ReferenceCheckDraft::new(
            "CHK-2",
            "ASSET-CTRL-1",
            2_000,
            0,
            2,
            3,
            OPERATOR,
        ))
        .expect("second check");
    assert!(report.in_tolerance);
    assert_eq!(
        report.baseline_check_id.as_deref(),
        Some(baseline.check_id.as_str())
    );
    assert_eq!(report.baseline_delta_deci_c, Some(2));
    assert!(!report.drifted);

    // Still inside tolerance, but 4 deci-C away from the baseline: drifting.
    let (_, report) = registry
        .record_reference_check(ReferenceCheckDraft::new(
            "CHK-3",
            "ASSET-CTRL-1",
            3_000,
            0,
            4,
            3,
            OPERATOR,
        ))
        .expect("third check");
    assert!(!report.in_tolerance);
    assert_eq!(report.error_deci_c, 4);
    assert_eq!(report.baseline_delta_deci_c, Some(4));
    assert!(report.drifted);

    // The drifted check blocks the lot that the controller observed.
    let lot = lot("ASSET-CTRL-1");
    let decision = registry
        .evaluate_lot_release(&lot, &[], 3_100)
        .expect("release decision");
    let ReleaseDecision::Blocked { blocks, .. } = &decision else {
        panic!("expected a drift block, got {decision:?}");
    };
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].code, BLOCK_REFERENCE_DRIFT);
    assert!(blocks[0].detail.contains("CHK-3"));

    // An in-tolerance check clears the condition; the block is then resolvable.
    registry
        .record_reference_check(ReferenceCheckDraft::new(
            "CHK-4",
            "ASSET-CTRL-1",
            4_000,
            0,
            1,
            3,
            OPERATOR,
        ))
        .expect("in-tolerance check");
    let resolved = registry
        .resolve_block(&blocks[0].block_id, 4_100, OPERATOR, "probe reseated")
        .expect("resolve");
    assert_eq!(resolved.resolved_est, Some(4_100));
    assert!(!registry.is_lot_blocked("LOT-1").expect("blocked flag"));
    assert!(registry
        .evaluate_lot_release(&lot, &[], 4_200)
        .expect("decision")
        .is_allowed());
}

// ---------------------------------------------------------------------------
// Expired calibration blocks the affected lot
// ---------------------------------------------------------------------------

#[test]
fn an_expired_calibration_blocks_the_affected_lot() {
    let registry = AssetRegistry::open_in_memory().expect("registry");
    registry.put(sensor("SN-0001", 1_000)).expect("register");
    registry
        .register_calibration(calibration("CAL-1", 1_000, 0))
        .expect("calibration");
    let lot = lot("ASSET-SN-0001");

    // In calibration: the lot can be released.
    let allowed = registry
        .evaluate_lot_release(&lot, &[], 1_500)
        .expect("decision");
    assert!(allowed.is_allowed());
    assert_eq!(
        allowed,
        ReleaseDecision::Allowed {
            lot_id: "LOT-1".to_string(),
            checked_assets: vec!["ASSET-SN-0001".to_string()],
            checked_est: 1_500,
        }
    );
    assert!(!registry.is_lot_blocked("LOT-1").expect("blocked flag"));

    // Past the due date the lot is blocked, with the expiry on the record.
    let blocked = registry
        .evaluate_lot_release(&lot, &[], 5_000)
        .expect("decision");
    let ReleaseDecision::Blocked { blocks, .. } = &blocked else {
        panic!("expected a block, got {blocked:?}");
    };
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].code, BLOCK_CALIBRATION_EXPIRED);
    assert_eq!(blocks[0].lot_id, "LOT-1");
    assert_eq!(blocks[0].asset_id, "ASSET-SN-0001");
    assert!(blocks[0].detail.contains("expired at 4600"));
    assert!(registry.is_lot_blocked("LOT-1").expect("blocked flag"));

    // Re-evaluating is idempotent: one block, same deterministic id.
    let again = registry
        .evaluate_lot_release(&lot, &[], 5_100)
        .expect("decision");
    assert_eq!(again.blocks().len(), 1);
    assert_eq!(again.blocks()[0].block_id, blocks[0].block_id);

    // The block cannot be resolved while the calibration is still expired.
    assert!(matches!(
        registry.resolve_block(&blocks[0].block_id, 5_200, OPERATOR, "waiver"),
        Err(tirbase_gateway::asset_registry::AssetError::BlockStillApplies { .. })
    ));

    // Recalibration clears the condition, then the block resolves with evidence.
    registry
        .register_calibration(calibration("CAL-2", 5_200, 0))
        .expect("recalibration");
    let resolved = registry
        .resolve_block(&blocks[0].block_id, 5_300, OPERATOR, "recalibrated at 5200")
        .expect("resolve");
    assert_eq!(resolved.resolved_by.as_deref(), Some(OPERATOR));
    assert_eq!(
        resolved.resolution_reason.as_deref(),
        Some("recalibrated at 5200")
    );
    assert!(registry
        .evaluate_lot_release(&lot, &[], 5_400)
        .expect("decision")
        .is_allowed());
    assert!(!registry.is_lot_blocked("LOT-1").expect("blocked flag"));

    // The resolved block stays in the audit export.
    let export = registry.export_json(5_500).expect("export");
    let block = export
        .blocks
        .iter()
        .find(|block| block.block_id == blocks[0].block_id)
        .expect("block on record");
    assert_eq!(block.resolved_est, Some(5_300));
    // Both calibrations remain on record for the audit.
    assert!(export
        .calibrations
        .iter()
        .any(|record| record.calibration_id == "CAL-1"));
    assert!(export
        .calibrations
        .iter()
        .any(|record| record.calibration_id == "CAL-2"));
}

#[test]
fn a_missing_calibration_fails_closed() {
    let registry = AssetRegistry::open_in_memory().expect("registry");
    registry.put(sensor("SN-0001", 1_000)).expect("register");
    // The sensor requires calibration but none is recorded yet.
    assert_eq!(
        registry
            .calibration_state("ASSET-SN-0001", 1_500)
            .expect("state"),
        CalibrationState::Missing
    );
    let decision = registry
        .evaluate_lot_release(&lot("ASSET-SN-0001"), &[], 1_500)
        .expect("decision");
    assert!(!decision.is_allowed());
    assert_eq!(
        decision.blocks()[0].code,
        tirbase_gateway::asset_registry::BLOCK_CALIBRATION_MISSING
    );
}

#[test]
fn an_expired_calibration_raises_a_quarantine_excursion() {
    let registry = AssetRegistry::open_in_memory().expect("registry");
    registry.put(sensor("SN-0001", 1_000)).expect("register");
    registry
        .register_calibration(calibration("CAL-1", 1_000, 0))
        .expect("calibration");
    let workflow = ExcursionWorkflow::open_in_memory().expect("workflow");

    // Nothing to escalate while the calibration is valid.
    assert!(matches!(
        registry.raise_expiry_excursion(
            &workflow,
            "exc-1",
            "tenant-a",
            Some("LOT-1"),
            "ASSET-SN-0001",
            1_500,
        ),
        Err(tirbase_gateway::asset_registry::AssetError::NotExpired { .. })
    ));

    let record = registry
        .raise_expiry_excursion(
            &workflow,
            "exc-1",
            "tenant-a",
            Some("LOT-1"),
            "ASSET-SN-0001",
            6_000,
        )
        .expect("excursion");
    assert_eq!(record.lot_id.as_deref(), Some("LOT-1"));
    assert_eq!(record.site_id, "site-1");
    assert_eq!(record.device_id, "ASSET-SN-0001");
    assert_eq!(record.reasons(), vec![ExcursionReason::SensorFault]);
    assert_eq!(
        workflow.get("exc-1").expect("stored").state.as_str(),
        "detected"
    );
}

// ---------------------------------------------------------------------------
// History survives replacement and retirement
// ---------------------------------------------------------------------------

#[test]
fn asset_history_survives_replacement_and_retirement() {
    let registry = AssetRegistry::open_in_memory().expect("registry");
    let old = registry
        .put(sensor("SN-0001", 1_000))
        .expect("register old");
    registry
        .register_calibration(calibration("CAL-1", 1_000, 0))
        .expect("old calibration");

    // The old sensor is replaced by a new one at 2 000.
    let mut replacement = AssetDraft::new(
        "ASSET-SN-0002",
        AssetIdentity::new(AssetKind::Sensor, "tenant-a", "TS-200", "SN-0002")
            .with_manufacturer("ColdSense")
            .with_firmware("2.0.0")
            .with_location("site-1", "loc-1")
            .with_installed_est(2_000)
            .with_calibration_required(86_400),
        ACTOR,
    );
    replacement.effective_from_est = 2_000;
    let (closed, new) = registry
        .replace(
            "ASSET-SN-0001",
            replacement,
            2_000,
            ACTOR,
            "probe head failed",
        )
        .expect("replace");

    assert_eq!(closed.status, AssetStatus::Replaced);
    assert_eq!(
        closed.identity.replaced_by.as_deref(),
        Some("ASSET-SN-0002")
    );
    assert_eq!(new.status, AssetStatus::Active);
    assert_eq!(new.identity.replaces.as_deref(), Some("ASSET-SN-0001"));
    assert_eq!(
        old.status,
        AssetStatus::Active,
        "the earlier version is untouched"
    );

    // The old asset keeps its versions, history and calibration record.
    assert_eq!(
        registry.versions("ASSET-SN-0001").expect("versions").len(),
        2
    );
    let history = registry.history("ASSET-SN-0001").expect("history");
    assert_eq!(
        history
            .iter()
            .map(|entry| entry.action.as_str())
            .collect::<Vec<_>>(),
        vec!["registered", "replaced"]
    );
    assert_eq!(history[1].detail["replaced_by"], "ASSET-SN-0002");
    assert_eq!(
        registry
            .calibrations("ASSET-SN-0001")
            .expect("calibrations")
            .len(),
        1,
        "replacement must not delete the old asset's calibration"
    );

    // The new asset is retired at 3 000; its history also survives.
    let retired = registry
        .retire("ASSET-SN-0002", 3_000, ACTOR, "site closed")
        .expect("retire");
    assert_eq!(retired.status, AssetStatus::Retired);
    assert_eq!(
        registry.versions("ASSET-SN-0002").expect("versions").len(),
        2
    );
    assert_eq!(
        registry.history("ASSET-SN-0002").expect("history")[1]
            .action
            .as_str(),
        "retired"
    );
    assert_eq!(
        registry
            .get("ASSET-SN-0002", 2_500)
            .expect("before retirement")
            .status,
        AssetStatus::Active
    );

    // Retired is terminal: retrying the retirement is idempotent (same version,
    // same history), and a retired asset cannot be replaced.
    let repeated = registry
        .retire("ASSET-SN-0002", 3_100, ACTOR, "again")
        .expect("idempotent retirement");
    assert_eq!(repeated.version, retired.version);
    assert_eq!(registry.history("ASSET-SN-0002").expect("history").len(), 2);
    let mut third = AssetDraft::new(
        "ASSET-SN-0003",
        AssetIdentity::new(AssetKind::Sensor, "tenant-a", "TS-300", "SN-0003")
            .with_manufacturer("ColdSense")
            .with_firmware("3.0.0")
            .with_location("site-1", "loc-1")
            .with_installed_est(3_200)
            .with_calibration_required(86_400),
        ACTOR,
    );
    third.effective_from_est = 3_200;
    assert!(matches!(
        registry.replace("ASSET-SN-0002", third, 3_100, ACTOR, "next"),
        Err(tirbase_gateway::asset_registry::AssetError::IllegalStatusTransition { .. })
    ));

    // The audit export still carries both assets and the old calibration.
    let export = registry.export_json(4_000).expect("export");
    assert_eq!(export.schema, "TirBase/v1/AssetRegistryExport");
    assert_eq!(export.assets.len(), 2);
    let statuses: Vec<AssetStatus> = export.assets.iter().map(|asset| asset.status).collect();
    assert!(statuses.contains(&AssetStatus::Replaced));
    assert!(statuses.contains(&AssetStatus::Retired));
    assert!(export
        .calibrations
        .iter()
        .any(|record| record.calibration_id == "CAL-1"));

    // The export is digested and byte-stable for the same instant.
    let again = registry.export_json(4_000).expect("export");
    assert_eq!(export.digest, again.digest);
    let json = export.to_json().expect("json");
    assert!(json.contains("\"schema\":\"TirBase/v1/AssetRegistryExport\""));
    assert!(json.contains("\"sha256\":"));
    // Certificate bytes are never in the export: only the digest and metadata.
    assert!(!json.contains("PDF-1.7"));

    // The flat reporting export has one row per asset version in force.
    let csv = registry.export_csv(4_000).expect("csv");
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(
        lines[0],
        "asset_id,version,kind,status,model,serial,manufacturer,firmware,site_id,location_id,\
         installed_est,calibration_required,effective_from_est,effective_to_est,digest"
    );
    assert_eq!(lines.len(), 3, "header plus two assets: {csv}");
    assert!(lines.iter().any(|line| line.starts_with(
        "ASSET-SN-0001,2,sensor,replaced,TS-100,SN-0001,ColdSense,1.4.2,site-1,loc-1,"
    )));
    assert!(lines
        .iter()
        .any(|line| line.starts_with("ASSET-SN-0002,2,sensor,retired,TS-200,SN-0002")));
}
