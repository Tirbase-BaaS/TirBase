// SPDX-License-Identifier: AGPL-3.0-only

//! F-06 wiring: audit records and exports carry signed time-confidence
//! evidence, and the export bundle exposes it as a standalone artefact.

use std::sync::Arc;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::timesync::{DriftBound, SignedTimeEvidence, TimeConfidence, TimeEvidence};
use tirbase_core::traits::{time_source, KeyProvider};
use tirbase_gateway::security_log::{AuditTimeEvidenceSource, SecurityEventLog};
use tirbase_gateway::security_log_export::{export_evidence_bundle, export_log, ExportedLog};

#[derive(Debug)]
struct OfflineEvidenceSource;

impl AuditTimeEvidenceSource for OfflineEvidenceSource {
    fn evidence(&self) -> TimeEvidence {
        let ts = time_source();
        TimeEvidence::offline(
            ts.wall_hint().map(|us| us / 1_000_000).unwrap_or(0),
            ts.monotonic_now() / 1_000_000,
            ts.boot_id(),
            1_700_000_000,
            3_600,
            DriftBound::default(),
        )
    }
}

fn test_key() -> InMemoryKeyProvider {
    InMemoryKeyProvider::from_seed([9u8; 32])
}

fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "tirbase-f06-{tag}-{}-{}",
        std::process::id(),
        time_source().monotonic_now()
    ));
    std::fs::create_dir_all(&dir).expect("tempdir");
    dir
}

fn append_one(log: &SecurityEventLog) {
    log.append_payload(
        tirbase_core::events::SecurityEvent::new(
            tirbase_core::events::SecurityEventCategory::Startup,
            tirbase_core::events::Severity::Low,
            tirbase_core::events::ReasonCode::CommandAccepted,
        )
        .with_target("f06-audit"),
    );
}

#[test]
fn f06_audit_records_and_export_carry_verifiable_time_evidence() {
    let dir = unique_temp_dir("audit");
    let db_path = dir.join("primary.db");
    let log = SecurityEventLog::new_persistent(&db_path, Some(Arc::new(test_key())), false);
    log.set_time_evidence_source(Arc::new(OfflineEvidenceSource));

    let record = log.append_payload(
        tirbase_core::events::SecurityEvent::new(
            tirbase_core::events::SecurityEventCategory::CommandDecision,
            tirbase_core::events::Severity::Low,
            tirbase_core::events::ReasonCode::CommandAccepted,
        )
        .with_target("f06-audit"),
    );

    let audit_evidence = record
        .time_evidence
        .as_ref()
        .expect("audit record carries time evidence");
    assert_eq!(audit_evidence.confidence().marker(), "offline");
    audit_evidence
        .verify(&test_key().public_key_bytes())
        .expect("audit evidence verifies under the device key");

    // A second record ensures the marker survives persistence and export.
    append_one(&log);

    let export_key = test_key();
    let json = export_log(&db_path, &export_key, "json", false, &[]).expect("export");
    let exported: ExportedLog = serde_json::from_slice(&json).expect("parse export");

    assert_eq!(exported.events.len(), 2);
    let first = exported.events[0]
        .time_evidence
        .as_ref()
        .expect("exported event keeps its marker");
    assert_eq!(first.confidence().marker(), "offline");
    first
        .verify(&export_key.public_key_bytes())
        .expect("exported per-event evidence verifies");

    // The export operation itself carries a signed projection of the log's
    // last evidence, so a verifier can bound the export time too.
    assert_eq!(exported.time_evidence.confidence().marker(), "offline");
    match exported.time_evidence.confidence() {
        TimeConfidence::Offline {
            elapsed_since_anchor_secs,
            drift_bound_ms,
        } => {
            assert!(*elapsed_since_anchor_secs >= 3_600);
            assert!(*drift_bound_ms >= 430);
        }
        other => panic!("expected offline export evidence, got {other:?}"),
    }
    exported
        .time_evidence
        .verify(&export_key.public_key_bytes())
        .expect("export time evidence verifies");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f06_export_bundle_exposes_standalone_time_evidence() {
    let dir = unique_temp_dir("bundle");
    let db_path = dir.join("primary.db");
    let log = SecurityEventLog::new_persistent(&db_path, Some(Arc::new(test_key())), false);
    log.set_time_evidence_source(Arc::new(OfflineEvidenceSource));
    append_one(&log);

    let out = dir.join("evidence.bundle");
    export_evidence_bundle(&db_path, &test_key(), &out).expect("bundle");
    let bytes = std::fs::read(&out).expect("read bundle");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("time_evidence.json"),
        "bundle must list and contain time_evidence.json"
    );

    // The standalone artefact deserialises and verifies. Walk the bundle's
    // `u32 name-len | name | u64 data-len | data` entries rather than
    // searching for the name (manifest.json also mentions it).
    let marker = b"time_evidence.json";
    let mut pos = 0usize;
    let mut evidence = None;
    while pos + 4 <= bytes.len() {
        let name_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + name_len + 8 > bytes.len() {
            break;
        }
        let name = &bytes[pos..pos + name_len];
        pos += name_len;
        let data_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        if name == marker {
            evidence = Some(
                serde_json::from_slice::<SignedTimeEvidence>(&bytes[pos..pos + data_len])
                    .expect("parse evidence"),
            );
            break;
        }
        pos += data_len;
    }
    evidence
        .expect("bundle contains time evidence")
        .verify(&test_key().public_key_bytes())
        .expect("bundle time evidence verifies");

    let _ = std::fs::remove_dir_all(&dir);
}
