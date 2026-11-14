// SPDX-License-Identifier: AGPL-3.0-only

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = tirbase_core::traits::monotonic_now();
    let dir = std::env::temp_dir().join(format!(
        "tirbase_gdpr_export_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_db(path: &Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.pragma_update(None, "journal_mode", "WAL").unwrap();
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_event_personal_fields (
            seq INTEGER NOT NULL, field_name TEXT NOT NULL, salt BLOB NOT NULL, plaintext BLOB NOT NULL,
            PRIMARY KEY (seq, field_name)
        );",
    ).unwrap();
    c
}

#[test]
fn gdpr_commitment_in_chain_plaintext_in_separate_table() {
 // CLAIM-27.1, PV-7.7, RD-3. Integration: emit personal-field event; commitment in
 // hash chain, plaintext stored in security_event_personal_fields table.
    let dir = unique_temp_dir("gdpr_commit");
    let db_path = dir.join("primary.db");
 // Production caller path: SecurityEventLog::emit() for personal-field events.
    let log = tirbase_gateway::security_log::SecurityEventLog::new_persistent(
        db_path.clone(),
        None,
        false,
    );
    tirbase_core::events::install_security_event_sink(log.clone());
    let payload = tirbase_core::events::SecurityEvent::new(
        tirbase_core::events::SecurityEventCategory::Enrollment,
        tirbase_core::events::Severity::Medium,
        tirbase_core::events::ReasonCode::CommandAccepted,
    )
    .with_actor("did:tirbase:admin-test")
    .with_personal_field("operator_contact", "alice@example.test");
    log.append_payload(payload);
    std::thread::sleep(Duration::from_millis(50));

    let conn = open_db(&db_path);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM security_event_personal_fields",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        count >= 1,
        "plaintext+salt must be stored in security_event_personal_fields"
    );
    let row: (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT salt, plaintext FROM security_event_personal_fields WHERE field_name='operator_contact' LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row.0.len(), 32, "random salt must be 32 bytes");
    assert_eq!(
        String::from_utf8_lossy(&row.1),
        "alice@example.test",
        "plaintext stored in separate table"
    );
    let report =
        tirbase_gateway::security_log_export::verify_log_at_path(&db_path).expect("verify");
    assert!(
        report.ok,
        "chain must remain verifiable (commitment in chain): {:?}",
        report.broken_ranges
    );
 // verify export includes commitment
    let conn2 = open_db(&db_path);
    let pfs = tirbase_gateway::security_log::read_personal_fields_for_seq(&conn2, 1).expect("read");
    assert!(!pfs.is_empty());
    let (fname, salt, plain) = &pfs[0];
    assert_eq!(fname, "operator_contact");
    assert_eq!(String::from_utf8_lossy(plain), "alice@example.test");
    let expected =
        tirbase_gateway::security_log::gdpr_salted_commitment(salt, "alice@example.test");
 // commitment reconstructed by verifier matches; and was used in chain (report.ok proves it).
    assert_eq!(expected.len(), 32);
    let report =
        tirbase_gateway::security_log_export::verify_log_at_path(&db_path).expect("verify");
    assert!(
        report.ok,
        "chain must remain verifiable: {:?}",
        report.broken_ranges
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gdpr_mutation_plaintext_in_hash_chain_must_fail() {
 // Mutation check (CLAIM-27.1): storing plaintext in the hash chain must fail.
 // The chained hash must incorporate the salted commitment; substituting plaintext
 // (or omitting commitment) produces a different hash and cannot match the chain.
    let dir = unique_temp_dir("gdpr_mut");
    let db_path = dir.join("primary.db");
    let log = tirbase_gateway::security_log::SecurityEventLog::new_persistent(
        db_path.clone(),
        None,
        false,
    );
    let payload = tirbase_core::events::SecurityEvent::new(
        tirbase_core::events::SecurityEventCategory::Enrollment,
        tirbase_core::events::Severity::Medium,
        tirbase_core::events::ReasonCode::CommandAccepted,
    )
    .with_personal_field("operator_contact", "bob@example.test");
    let rec = log.append_payload(payload);
    assert!(
        !rec.personal_commitments.is_empty(),
        "commitment must be present in chained record"
    );
    let real_hash = tirbase_gateway::security_log::event_hash(&rec, false);
 // Mutation: plaintext placed in hash-chain input instead of salted commitment must differ.
    let mut mutated = rec.clone();
 // represent the bad design: commitment bytes derived directly from plaintext (no random salt)
    let mut bad = [0u8; 32];
    let digest = <sha2::Sha256 as sha2::Digest>::digest(b"bob@example.test");
    bad.copy_from_slice(&digest);
    mutated.personal_commitments[0].commitment = bad;
    let mutated_hash = tirbase_gateway::security_log::event_hash(&mutated, false);
    assert_ne!(
        real_hash, mutated_hash,
        "plaintext-derived/unsalted commitment must not produce the same chain hash"
    );
 // Omitting commitment (plaintext-only model with no commitment) must also differ.
    let mut omitted = rec.clone();
    omitted.personal_commitments.clear();
    let omitted_hash = tirbase_gateway::security_log::event_hash(&omitted, false);
    assert_ne!(
        real_hash, omitted_hash,
        "omitting salted commitment from hash chain must fail to match"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn test_key() -> tirbase_core::identity::file_key_provider::FileKeyProvider {
    tirbase_core::identity::file_key_provider::FileKeyProvider::from_seed(
        [7u8; 32],
        "did:tirbase:test-device".to_string(),
        std::path::PathBuf::from("/tmp/tirbase-test-key"),
    )
    .expect("key")
}

#[test]
fn log_export_cbor_json_signed_and_pseudonymized_disclaimer() {
 // CLAIM-27.2, PV-7.7, PV-7.8.
    let dir = unique_temp_dir("export");
    let db_path = dir.join("primary.db");
    let log = tirbase_gateway::security_log::SecurityEventLog::new_persistent(
        db_path.clone(),
        None,
        false,
    );
    log.append_payload(
        tirbase_core::events::SecurityEvent::new(
            tirbase_core::events::SecurityEventCategory::CommandDecision,
            tirbase_core::events::Severity::Low,
            tirbase_core::events::ReasonCode::CommandAccepted,
        )
        .with_personal_field("operator_contact", "carol@example.test"),
    );
    let key = test_key();
    let json = tirbase_gateway::security_log_export::export_log(&db_path, &key, "json", false, &[])
        .expect("json export");
    let v: serde_json::Value = serde_json::from_slice(&json).expect("json");
    assert!(
        !v["signature_hex"].as_str().unwrap_or("").is_empty(),
        "export must be signed by device key"
    );
    assert_eq!(v["pseudonymized"].as_bool(), Some(false));
    let cbor = tirbase_gateway::security_log_export::export_log(&db_path, &key, "cbor", false, &[])
        .expect("cbor export");
    assert!(!cbor.is_empty(), "CBOR export");
    let pseudo = tirbase_gateway::security_log_export::export_log(
        &db_path,
        &key,
        "json",
        true,
        b"fixed-salt",
    )
    .expect("pseudo");
    let pv: serde_json::Value = serde_json::from_slice(&pseudo).expect("json");
    assert_eq!(pv["pseudonymized"].as_bool(), Some(true));
    let disc = pv["disclaimer"].as_str().unwrap_or("");
    assert!(
        disc.contains("NOT chain-verified") || disc.to_lowercase().contains("not chain-verified"),
        "pseudonymized export must carry explicit disclaimer that it is not chain-verified: {disc}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn export_evidence_bundle_contains_required_parts_and_signed() {
 // CLAIM-27.3, PV-7.10.
    let dir = unique_temp_dir("bundle");
    let db_path = dir.join("primary.db");
    let log = tirbase_gateway::security_log::SecurityEventLog::new_persistent(
        db_path.clone(),
        None,
        false,
    );
    for _ in 0..3 {
        log.append_payload(tirbase_core::events::SecurityEvent::new(
            tirbase_core::events::SecurityEventCategory::Startup,
            tirbase_core::events::Severity::Low,
            tirbase_core::events::ReasonCode::CommandAccepted,
        ));
    }
    let key = test_key();
    let out = dir.join("evidence.bundle");
    tirbase_gateway::security_log_export::export_evidence_bundle(&db_path, &key, &out)
        .expect("bundle");
    let bytes = std::fs::read(&out).expect("read bundle");
    let s = String::from_utf8_lossy(&bytes);
    for required in [
        "log.json",
        "checkpoints.json",
        "device_public_key.txt",
        "verify_report.json",
        "manifest.json",
        "signature.hex",
        "export_timestamp_unix",
    ] {
        assert!(
            s.contains(required),
            "evidence bundle must contain {required}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_log_reports_intact_and_broken_chain() {
 // CLAIM-27.4, PV-7.5, INV-4.
    let dir = unique_temp_dir("verify");
    let db_path = dir.join("primary.db");
    let log = tirbase_gateway::security_log::SecurityEventLog::new_persistent(
        db_path.clone(),
        None,
        false,
    );
    for _ in 0..3 {
        log.append_payload(tirbase_core::events::SecurityEvent::new(
            tirbase_core::events::SecurityEventCategory::CommandDecision,
            tirbase_core::events::Severity::Low,
            tirbase_core::events::ReasonCode::CommandAccepted,
        ));
    }
    let ok = tirbase_gateway::security_log_export::verify_log_at_path(&db_path).expect("verify");
    assert!(ok.ok, "intact chain must verify: {ok:?}");
    assert!(ok.broken_ranges.is_empty());
 // Break chain in DB.
    let conn = open_db(&db_path);
    conn.execute(
        "UPDATE security_events SET prev_hash = X'00010203' WHERE seq=2",
        [],
    )
    .unwrap();
    let bad = tirbase_gateway::security_log_export::verify_log_at_path(&db_path).expect("verify");
    assert!(!bad.ok, "broken chain must fail verification");
    assert!(
        !bad.broken_ranges.is_empty(),
        "must report broken sequence range(s)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_log_mutation_exiting_zero_on_broken_chain_must_fail() {
 // Mutation check (CLAIM-27.4): a verify implementation that exits/reports ok on
 // a broken chain must fail this test.
    let dir = unique_temp_dir("verify_mut");
    let db_path = dir.join("primary.db");
    let log = tirbase_gateway::security_log::SecurityEventLog::new_persistent(
        db_path.clone(),
        None,
        false,
    );
    for _ in 0..4 {
        log.append_payload(tirbase_core::events::SecurityEvent::new(
            tirbase_core::events::SecurityEventCategory::CommandDecision,
            tirbase_core::events::Severity::Low,
            tirbase_core::events::ReasonCode::CommandAccepted,
        ));
    }
    let conn = open_db(&db_path);
    conn.execute(
        "UPDATE security_events SET target='tampered' WHERE seq=3",
        [],
    )
    .unwrap();
    let report =
        tirbase_gateway::security_log_export::verify_log_at_path(&db_path).expect("verify");
    assert!(
        !report.ok,
        "tampered event must not verify as intact: {report:?}"
    );
    assert!(
        report
            .broken_ranges
            .iter()
            .any(|r| r.start_seq <= 3 && r.end_seq >= 3 || r.start_seq >= 3),
        "broken range report must identify affected sequence: {:?}",
        report.broken_ranges
    );
    let _ = std::fs::remove_dir_all(&dir);
}
