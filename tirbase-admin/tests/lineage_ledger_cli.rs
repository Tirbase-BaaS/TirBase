// SPDX-License-Identifier: AGPL-3.0-only

//! Offline bundle verification through the admin CLI (CC-14).
//!
//! The command reads only the bundle file, the detached signature and (when the
//! manifest names them) attachment files. These tests write a real bundle from
//! the ledger, then verify it — and a tampered copy — without any database,
//! gateway or network access.

use std::collections::BTreeMap;
use std::path::Path;

use tirbase_admin::cmd::ledger::{parse_trusted_keys, run, LedgerVerifyArgs};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::lineage_ledger::export::{export_bundle, BundleViolationKind};
use tirbase_gateway::lineage_ledger::{AppendRequest, LineageLedger, EVENT_LOT_REGISTERED};

fn key(seed: u8) -> InMemoryKeyProvider {
    InMemoryKeyProvider::from_seed([seed; 32])
}

fn trusted_arg(key: &InMemoryKeyProvider) -> String {
    format!("{}={}", key.did(), hex::encode(key.public_key_bytes()))
}

/// Build a two-entry bundle with one attachment and write it to `dir`.
fn write_bundle(dir: &Path) -> InMemoryKeyProvider {
    let ledger = LineageLedger::open_in_memory().expect("ledger");
    for index in 1..=2 {
        ledger
            .append(AppendRequest::new(
                format!("evt-{index}"),
                key(1).did(),
                EVENT_LOT_REGISTERED,
                serde_json::json!({"lot": "LOT-CLI", "note": format!("evt-{index}")}),
                100 + index,
            ))
            .expect("append");
    }
    let signer = key(11);
    ledger.checkpoint(&signer, 200).expect("checkpoint");
    let attachments =
        BTreeMap::from([("evidence.txt".to_string(), b"supporting evidence".to_vec())]);
    let signed = export_bundle(&ledger, &signer, 1, 2, &attachments, 300).expect("export");
    signed
        .write_to_dir(dir, &attachments)
        .expect("write bundle");
    signer
}

fn args(dir: &Path, trusted: Vec<String>) -> LedgerVerifyArgs {
    LedgerVerifyArgs {
        bundle: dir.join("bundle.json"),
        signature: dir.join("bundle.sig"),
        trusted_keys: trusted,
        attachments_dir: Some(dir.join("attachments")),
        json: false,
    }
}

#[test]
fn offline_cli_verifies_a_bundle_and_reports_tampering() {
    let dir = tempfile::tempdir().expect("temp dir");
    let signer = write_bundle(dir.path());

    let report = run(&args(dir.path(), vec![trusted_arg(&signer)])).expect("verify");
    assert!(report.ok, "{:?}", report.reasons());
    assert!(report.signature_ok && report.chain_ok && report.root_hash_ok);
    assert_eq!(report.range, Some((1, 2)));
    assert_eq!(report.signer_did.as_deref(), Some(signer.did()));

    // An untrusted signer is refused by name.
    let report = run(&args(dir.path(), vec![trusted_arg(&key(12))])).expect("verify");
    assert!(!report.ok);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.kind == BundleViolationKind::UntrustedSigner));
    assert!(report.reasons()[0].contains("untrusted_signer"));

    // Editing an entry in the on-disk bundle fails offline verification.
    let bundle_path = dir.path().join("bundle.json");
    let text = std::fs::read_to_string(&bundle_path).expect("read bundle");
    let tampered = text.replace("\"note\":\"evt-2\"", "\"note\":\"EVIL\"");
    assert_ne!(tampered, text);
    std::fs::write(&bundle_path, tampered).expect("write tampered bundle");
    let report = run(&args(dir.path(), vec![trusted_arg(&signer)])).expect("verify");
    assert!(!report.ok);
    let kinds: Vec<BundleViolationKind> = report
        .violations
        .iter()
        .map(|violation| violation.kind)
        .collect();
    assert!(
        kinds.contains(&BundleViolationKind::SignatureInvalid)
            || kinds.contains(&BundleViolationKind::PayloadHashMismatch),
        "{kinds:?}"
    );

    // A missing signature file is an I/O error, not a silent pass.
    assert!(run(&LedgerVerifyArgs {
        bundle: dir.path().join("bundle.json"),
        signature: dir.path().join("does-not-exist.sig"),
        trusted_keys: vec![trusted_arg(&signer)],
        attachments_dir: Some(dir.path().join("attachments")),
        json: false,
    })
    .is_err());
}

#[test]
fn trusted_key_parsing_rejects_missing_and_malformed_entries() {
    assert!(parse_trusted_keys(&[]).is_err());
    assert!(parse_trusted_keys(&["did:key:z6MkNoKey".to_string()]).is_err());
    assert!(parse_trusted_keys(&["did:key:z6Mk=zzzz".to_string()]).is_err());
    assert!(parse_trusted_keys(&["did:key:z6Mk=abcd".to_string()]).is_err());

    let signer = key(13);
    let parsed = parse_trusted_keys(&[trusted_arg(&signer)]).expect("parse");
    assert_eq!(
        parsed.get(signer.did()).map(Vec::as_slice),
        Some(signer.public_key_bytes().as_slice())
    );
}
