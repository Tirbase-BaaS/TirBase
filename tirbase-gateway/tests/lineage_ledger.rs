// SPDX-License-Identifier: AGPL-3.0-only

//! Lineage ledger and signed export integration tests (CC-14).
//!
//! Proves the append-only chain (sequence, previous hash, domain-separated hash,
//! actor/device/lot, event type, payload hash), idempotent appends across a
//! restart, signed checkpoints, tamper detection (truncation, reorder, duplicate,
//! wrong signer), and the signed export bundle's offline verification,
//! attachment hashing and import round-trip.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use serde_json::json;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::lineage_ledger::export::{
    attachment_digest, export_bundle, trusted_key_entry, verify_bundle, verify_bundle_hex,
    BundleViolationKind, SignedBundle,
};
use tirbase_gateway::lineage_ledger::{
    entry_hash, payload_hash, AppendOutcome, AppendRequest, LedgerError, LineageLedger,
    ViolationKind, EVENT_EXCURSION_DISPOSITIONED, EVENT_LOT_REGISTERED, EVENT_LOT_SPLIT, ZERO_HASH,
};

fn key(seed: u8) -> InMemoryKeyProvider {
    InMemoryKeyProvider::from_seed([seed; 32])
}

fn trusted(keys: &[&InMemoryKeyProvider]) -> BTreeMap<String, Vec<u8>> {
    keys.iter().map(|key| trusted_key_entry(*key)).collect()
}

fn signer_set(keys: &[&InMemoryKeyProvider]) -> BTreeSet<String> {
    keys.iter().map(|key| key.did().to_string()).collect()
}

fn append(
    ledger: &LineageLedger,
    entry_id: &str,
    lot: &str,
    event: &str,
    at_est: i64,
) -> AppendOutcome {
    ledger
        .append(
            AppendRequest::new(
                entry_id,
                key(1).did(),
                event,
                json!({"lot": lot, "note": entry_id}),
                at_est,
            )
            .with_lot(lot)
            .with_device("dev-freezer-1"),
        )
        .expect("append")
}

fn seed_ledger() -> LineageLedger {
    let ledger = LineageLedger::open_in_memory().expect("ledger");
    for (index, event) in [
        EVENT_LOT_REGISTERED,
        EVENT_LOT_SPLIT,
        EVENT_EXCURSION_DISPOSITIONED,
    ]
    .into_iter()
    .enumerate()
    {
        append(
            &ledger,
            &format!("evt-{}", index + 1),
            "LOT-A",
            event,
            100 + index as i64,
        );
    }
    ledger
}

fn verify(ledger: &LineageLedger, keys: &[&InMemoryKeyProvider]) -> bool {
    let trusted_keys = trusted(keys);
    let resolve = |did: &str| trusted_keys.get(did).cloned();
    let report = ledger
        .verify(&signer_set(keys), &resolve)
        .expect("verify ledger");
    assert_eq!(report.ok, report.violations.is_empty());
    report.ok
}

fn kinds(ledger: &LineageLedger, keys: &[&InMemoryKeyProvider]) -> Vec<ViolationKind> {
    let trusted_keys = trusted(keys);
    let resolve = |did: &str| trusted_keys.get(did).cloned();
    ledger
        .verify(&signer_set(keys), &resolve)
        .expect("verify")
        .violations
        .into_iter()
        .map(|violation| violation.kind)
        .collect()
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn append_builds_a_contiguous_domain_separated_chain() {
    let ledger = seed_ledger();
    let entries = ledger.entries().expect("entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].seq, 1);
    assert_eq!(entries[0].prev_hash, ZERO_HASH);
    assert_eq!(entries[0].event_type, EVENT_LOT_REGISTERED);
    assert_eq!(entries[0].lot_id.as_deref(), Some("LOT-A"));
    assert_eq!(entries[0].device_id.as_deref(), Some("dev-freezer-1"));

    for pair in entries.windows(2) {
        assert_eq!(
            pair[1].prev_hash, pair[0].entry_hash,
            "each entry links to its predecessor"
        );
    }
    for entry in &entries {
        assert_eq!(
            entry.payload_hash,
            payload_hash(&entry.payload).expect("payload hash")
        );
        let recomputed = entry_hash(
            entry.seq,
            &entry.prev_hash,
            entry.recorded_est,
            &entry.actor_did,
            entry.device_id.as_deref(),
            entry.lot_id.as_deref(),
            &entry.event_type,
            &entry.payload_hash,
        )
        .expect("entry hash");
        assert_eq!(recomputed, entry.entry_hash);
    }

    let anchor = key(2);
    let checkpoint = ledger.checkpoint(&anchor, 200).expect("checkpoint");
    assert_eq!(checkpoint.seq, 3);
    assert_eq!(checkpoint.count, 3);
    assert_eq!(checkpoint.head_hash, entries[2].entry_hash);
    assert_eq!(checkpoint.signer_did, anchor.did());
    // Checkpointing an unchanged head is idempotent for the same signer.
    let again = ledger.checkpoint(&anchor, 201).expect("re-checkpoint");
    assert_eq!(again, checkpoint);
    // A different signer at the same head is refused.
    assert!(matches!(
        ledger.checkpoint(&key(3), 202),
        Err(LedgerError::CheckpointConflict(_))
    ));

    let trusted_keys = trusted(&[&anchor]);
    let resolve = |did: &str| trusted_keys.get(did).cloned();
    let report = ledger
        .verify(&signer_set(&[&anchor]), &resolve)
        .expect("verify");
    assert!(report.ok, "{:?}", report.reasons());
    assert_eq!(report.head_seq, 3);
    assert_eq!(report.checkpoints, 1);
    assert_eq!(
        ledger.entries_for_lot("LOT-A").expect("lot entries").len(),
        3
    );
    assert_eq!(ledger.range(2, 3).expect("range").len(), 2);
}

// ---------------------------------------------------------------------------
// Idempotent appends across a restart
// ---------------------------------------------------------------------------

#[test]
fn a_retried_append_does_not_duplicate_and_survives_a_restart() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("primary.db");
    let anchor = key(4);
    let request = AppendRequest::new(
        "evt-idempotent",
        anchor.did(),
        EVENT_LOT_REGISTERED,
        json!({"lot": "LOT-A"}),
        10,
    )
    .with_lot("LOT-A");

    {
        let ledger = LineageLedger::open(&path).expect("ledger");
        let first = ledger.append(request.clone()).expect("append");
        assert!(first.appended());
        assert_eq!(first.entry().seq, 1);
        let retry = ledger.append(request.clone()).expect("retry");
        assert!(matches!(retry, AppendOutcome::Duplicate(_)));
        assert_eq!(retry.entry(), first.entry());
        assert_eq!(ledger.len().expect("len"), 1);

        let different = AppendRequest {
            payload: json!({"lot": "LOT-B"}),
            ..request.clone()
        };
        assert!(matches!(
            ledger.append(different).expect_err("conflict"),
            LedgerError::Conflict(_)
        ));
        ledger.checkpoint(&anchor, 11).expect("checkpoint");
    }

    // Reopen: the chain survives, the retry is still a no-op, and the next
    // append continues at the correct link.
    let ledger = LineageLedger::open(&path).expect("reopen");
    assert_eq!(ledger.len().expect("len"), 1);
    assert!(matches!(
        ledger.append(request).expect("retry after restart"),
        AppendOutcome::Duplicate(_)
    ));
    let next = ledger
        .append(AppendRequest::new(
            "evt-2",
            anchor.did(),
            EVENT_LOT_SPLIT,
            json!({"lot": "LOT-A", "children": ["B1"]}),
            12,
        ))
        .expect("append next");
    assert!(next.appended());
    assert_eq!(next.entry().seq, 2);
    assert_eq!(
        next.entry().prev_hash,
        ledger.get(1).expect("get").expect("entry").entry_hash
    );
    assert!(verify(&ledger, &[&anchor]), "chain intact after restart");
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

#[test]
fn tampered_payloads_and_actors_are_detected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("primary.db");
    let ledger = LineageLedger::open(&path).expect("ledger");
    seed_ledger_into(&ledger);
    assert!(verify(&ledger, &[]));

    let original_payload: String = Connection::open(&path)
        .expect("open")
        .query_row(
            "SELECT payload_json FROM lineage_ledger WHERE seq=2",
            [],
            |row| row.get(0),
        )
        .expect("payload");

    // Rewrite a stored payload: it no longer matches what the entry committed
    // to. The entry hash still matches, because it commits to the payload *hash*
    // — that separation keeps the commitment cheap to recompute.
    tamper(
        &path,
        "UPDATE lineage_ledger SET payload_json='{\"lot\":\"EVIL\"}' WHERE seq=2",
    );
    let reported = kinds(&ledger, &[]);
    assert!(
        reported.contains(&ViolationKind::PayloadHashMismatch),
        "{reported:?}"
    );
    assert!(
        !reported.contains(&ViolationKind::EntryHashMismatch),
        "entry hash commits to the payload hash, not the payload: {reported:?}"
    );

    // Restore the payload, then rewrite the actor: the entry hash breaks.
    let conn = Connection::open(&path).expect("open");
    conn.execute(
        "UPDATE lineage_ledger SET payload_json=?1 WHERE seq=2",
        rusqlite::params![original_payload],
    )
    .expect("restore payload");
    conn.execute(
        "UPDATE lineage_ledger SET actor_did='did:key:z6MkImposter' WHERE seq=2",
        [],
    )
    .expect("tamper actor");
    let reported = kinds(&ledger, &[]);
    assert!(
        reported.contains(&ViolationKind::EntryHashMismatch),
        "{reported:?}"
    );
    assert!(
        !reported.contains(&ViolationKind::PayloadHashMismatch),
        "{reported:?}"
    );
}

#[test]
fn truncation_and_reordering_are_detected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("primary.db");
    let ledger = LineageLedger::open(&path).expect("ledger");
    let anchor = key(5);
    seed_ledger_into(&ledger);
    ledger.checkpoint(&anchor, 300).expect("checkpoint");
    assert!(verify(&ledger, &[&anchor]));

    // Cut the tail under a signed checkpoint.
    tamper(&path, "DELETE FROM lineage_ledger WHERE seq=3");
    let report = ledger
        .verify(&signer_set(&[&anchor]), &|did: &str| {
            trusted(&[&anchor]).get(did).cloned()
        })
        .expect("verify");
    assert!(!report.ok);
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation.kind == ViolationKind::Truncation),
        "{:?}",
        report.reasons()
    );

    // Reorder two contiguous entries (swap their sequence numbers).
    tamper(&path, "UPDATE lineage_ledger SET seq=1000 WHERE seq=1");
    tamper(&path, "UPDATE lineage_ledger SET seq=1 WHERE seq=2");
    tamper(&path, "UPDATE lineage_ledger SET seq=2 WHERE seq=1000");
    let reported = kinds(&ledger, &[&anchor]);
    assert!(
        reported.contains(&ViolationKind::PreviousHashMismatch)
            || reported.contains(&ViolationKind::SequenceGap),
        "{reported:?}"
    );
}

#[test]
fn wrong_signer_is_rejected() {
    let ledger = seed_ledger();
    let trusted_signer = key(6);
    let attacker = key(7);
    ledger.checkpoint(&attacker, 400).expect("checkpoint");

    // The attacker's key is not in the trusted set.
    let reported = kinds(&ledger, &[&trusted_signer]);
    assert!(
        reported.contains(&ViolationKind::WrongSigner),
        "{reported:?}"
    );

    // Trusting the DID but resolving it to the wrong public key fails the
    // signature itself.
    let report = ledger
        .verify(
            &BTreeSet::from([attacker.did().to_string()]),
            &|_did: &str| Some(trusted_signer.public_key_bytes()),
        )
        .expect("verify");
    assert!(!report.ok);
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation.kind == ViolationKind::CheckpointSignature),
        "{:?}",
        report.reasons()
    );

    // And the right key verifies.
    assert!(verify(&ledger, &[&attacker]));
}

// ---------------------------------------------------------------------------
// Bundle round trip
// ---------------------------------------------------------------------------

fn seed_five(ledger: &LineageLedger) {
    for index in 1..=5 {
        append(
            ledger,
            &format!("evt-{index}"),
            "LOT-A",
            if index == 5 {
                EVENT_EXCURSION_DISPOSITIONED
            } else {
                EVENT_LOT_REGISTERED
            },
            500 + index as i64,
        );
    }
}

fn bundle_bytes() -> (
    LineageLedger,
    InMemoryKeyProvider,
    BTreeMap<String, Vec<u8>>,
) {
    let ledger = LineageLedger::open_in_memory().expect("ledger");
    seed_five(&ledger);
    let anchor = key(8);
    ledger.checkpoint(&anchor, 600).expect("checkpoint");
    let attachments = BTreeMap::from([(
        "lab-report.txt".to_string(),
        b"analytical certificate: pass".to_vec(),
    )]);
    (ledger, anchor, attachments)
}

#[test]
fn signed_bundle_round_trips_and_reimports_idempotently() {
    let (ledger, anchor, attachments) = bundle_bytes();
    let signed = export_bundle(&ledger, &anchor, 1, 5, &attachments, 700).expect("export");
    assert_eq!(signed.bundle.manifest.entry_count, 5);
    assert_eq!(signed.bundle.manifest.range_start, 1);
    assert_eq!(signed.bundle.manifest.range_end, 5);
    assert_eq!(
        signed.bundle.manifest.root_hash,
        ledger.head().unwrap().unwrap().entry_hash
    );
    assert_eq!(signed.bundle.manifest.checkpoints.len(), 1);
    assert_eq!(signed.bundle.manifest.attachments.len(), 1);
    assert_eq!(
        signed.bundle.manifest.attachments[0].sha256_hex,
        attachment_digest(&attachments["lab-report.txt"])
    );

    let report = verify_bundle(
        &signed.bundle,
        &signed.signature,
        &trusted(&[&anchor]),
        &attachments,
    );
    assert!(report.ok, "{:?}", report.reasons());
    assert!(report.signature_ok && report.chain_ok && report.root_hash_ok);
    assert_eq!(report.signer_did.as_deref(), Some(anchor.did()));

    // Files: write, read back, verify with no ledger in the loop.
    let dir = tempfile::tempdir().expect("temp dir");
    signed
        .write_to_dir(dir.path(), &attachments)
        .expect("write");
    let read = SignedBundle::read_from_dir(dir.path()).expect("read");
    let read_attachments = read.read_attachments(dir.path());
    let naive = std::fs::read_to_string(dir.path().join("bundle.json")).expect("bundle.json");
    assert_eq!(naive, signed.to_json().expect("json"));
    let report = verify_bundle_hex(
        &read.bundle,
        &read.signature_hex(),
        &trusted(&[&anchor]),
        &read_attachments,
    );
    assert!(report.ok, "{:?}", report.reasons());

    // Import into a fresh ledger: identical head, and the chain continues.
    let mirror = LineageLedger::open_in_memory().expect("mirror");
    let import = mirror.import_bundle(&read.bundle).expect("import");
    assert_eq!(import.imported, 5);
    assert_eq!(import.skipped, 0);
    assert_eq!(
        mirror.head().unwrap().unwrap().entry_hash,
        ledger.head().unwrap().unwrap().entry_hash
    );
    assert!(verify(&mirror, &[&anchor]));
    let continued = append(&mirror, "evt-6", "LOT-A", EVENT_LOT_SPLIT, 800);
    assert_eq!(continued.entry().seq, 6);
    assert_eq!(
        continued.entry().prev_hash,
        mirror.get(5).unwrap().unwrap().entry_hash
    );

    // Re-importing the same bundle writes nothing.
    let again = mirror.import_bundle(&read.bundle).expect("re-import");
    assert_eq!(again.imported, 0);
    assert_eq!(again.skipped, 5);
    assert_eq!(mirror.len().expect("len"), 6);
}

// ---------------------------------------------------------------------------
// Tampered bundles
// ---------------------------------------------------------------------------

#[test]
fn tampered_bundles_fail_verification() {
    let (ledger, anchor, attachments) = bundle_bytes();
    let trusted_keys = trusted(&[&anchor]);
    let signed = export_bundle(&ledger, &anchor, 1, 5, &attachments, 700).expect("export");

    // 1. Edit one entry's payload without re-signing.
    let mut edited = signed.bundle.clone();
    edited.entries[2].payload = json!({"lot": "LOT-EVIL"});
    let report = verify_bundle(&edited, &signed.signature, &trusted_keys, &attachments);
    assert!(!report.ok);
    let reported: Vec<BundleViolationKind> = report.violations.iter().map(|v| v.kind).collect();
    assert!(
        reported.contains(&BundleViolationKind::SignatureInvalid),
        "{reported:?}"
    );
    assert!(
        reported.contains(&BundleViolationKind::PayloadHashMismatch),
        "{reported:?}"
    );

    // 2. Re-sign the edited bundle with the real key: the signature is now valid
    // but the content still does not match its committed hashes.
    let resigned = SignedBundle::sign(edited, &anchor).expect("re-sign");
    let report = verify_bundle(
        &resigned.bundle,
        &resigned.signature,
        &trusted_keys,
        &attachments,
    );
    assert!(!report.ok);
    assert!(!report.chain_ok);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.kind == BundleViolationKind::PayloadHashMismatch),
        "{:?}",
        report.reasons()
    );

    // 3. A duplicate entry, re-signed and with the manifest adjusted.
    let mut duplicated = signed.bundle.clone();
    duplicated.entries.insert(2, duplicated.entries[1].clone());
    duplicated.manifest.entry_count += 1;
    let resigned = SignedBundle::sign(duplicated, &anchor).expect("re-sign");
    let report = verify_bundle(
        &resigned.bundle,
        &resigned.signature,
        &trusted_keys,
        &attachments,
    );
    assert!(!report.ok);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.kind == BundleViolationKind::Duplicate
                || v.kind == BundleViolationKind::RangeMismatch),
        "{:?}",
        report.reasons()
    );

    // 4. Truncation hidden from the manifest but caught by the checkpoint.
    let mut shortened = signed.bundle.clone();
    shortened.entries.pop();
    shortened.manifest.entry_count = 4;
    shortened.manifest.range_end = 4;
    shortened.manifest.root_hash = shortened.entries.last().unwrap().entry_hash.clone();
    let resigned = SignedBundle::sign(shortened, &anchor).expect("re-sign");
    let report = verify_bundle(
        &resigned.bundle,
        &resigned.signature,
        &trusted_keys,
        &attachments,
    );
    assert!(!report.ok);
    assert!(
        report
            .violations
            .iter()
            .any(|v| v.kind == BundleViolationKind::Truncation),
        "{:?}",
        report.reasons()
    );

    // 5. Root hash and count are cross-checked against the entries.
    let mut wrong_root = signed.bundle.clone();
    wrong_root.manifest.root_hash = ZERO_HASH.to_string();
    let resigned = SignedBundle::sign(wrong_root, &anchor).expect("re-sign");
    let report = verify_bundle(
        &resigned.bundle,
        &resigned.signature,
        &trusted_keys,
        &attachments,
    );
    assert!(report
        .violations
        .iter()
        .any(|v| v.kind == BundleViolationKind::RootHashMismatch));

    let mut wrong_count = signed.bundle.clone();
    wrong_count.manifest.entry_count = 4;
    let resigned = SignedBundle::sign(wrong_count, &anchor).expect("re-sign");
    let report = verify_bundle(
        &resigned.bundle,
        &resigned.signature,
        &trusted_keys,
        &attachments,
    );
    assert!(report
        .violations
        .iter()
        .any(|v| v.kind == BundleViolationKind::CountMismatch));

    // 6. Wrong signer: a trusted key set without the bundle's signer.
    let report = verify_bundle(
        &signed.bundle,
        &signed.signature,
        &trusted(&[&key(9)]),
        &attachments,
    );
    assert!(!report.ok);
    assert!(report
        .violations
        .iter()
        .any(|v| v.kind == BundleViolationKind::UntrustedSigner));

    // 7. Attachments: missing and altered.
    let report = verify_bundle(
        &signed.bundle,
        &signed.signature,
        &trusted_keys,
        &BTreeMap::new(),
    );
    assert!(report
        .violations
        .iter()
        .any(|v| v.kind == BundleViolationKind::AttachmentMissing));
    let altered = BTreeMap::from([(
        "lab-report.txt".to_string(),
        b"analytical certificate: FAIL".to_vec(),
    )]);
    let report = verify_bundle(&signed.bundle, &signed.signature, &trusted_keys, &altered);
    assert!(!report.attachments_ok);
    assert!(report
        .violations
        .iter()
        .any(|v| v.kind == BundleViolationKind::AttachmentHashMismatch));

    // 8. A signature that does not parse is a signature failure, not a panic.
    let report = verify_bundle_hex(&signed.bundle, "not-hex", &trusted_keys, &attachments);
    assert!(!report.signature_ok);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn seed_ledger_into(ledger: &LineageLedger) {
    for (index, event) in [
        EVENT_LOT_REGISTERED,
        EVENT_LOT_SPLIT,
        EVENT_EXCURSION_DISPOSITIONED,
    ]
    .into_iter()
    .enumerate()
    {
        append(
            ledger,
            &format!("evt-{}", index + 1),
            "LOT-A",
            event,
            100 + index as i64,
        );
    }
}

fn tamper(path: &std::path::Path, sql: &str) {
    let conn = Connection::open(path).expect("open for tamper");
    conn.execute(sql, []).expect("tamper");
}
