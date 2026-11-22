// SPDX-License-Identifier: AGPL-3.0-only

//! ST-13 acceptance tests: field register, enforced CCTV retention, legal holds,
//! subject access/deletion and the recorded pilot sign-off.

use std::fs;
use std::path::PathBuf;

use tirbase_venue_privacy::{
    privacy_register, CctvActor, CctvError, CctvEvent, CctvEventKind, CctvHoldScope, CctvLegalHold,
    CctvRole, CctvStore, PersonalData, CCTV_SAFETY_SECS, CCTV_SECURITY_SECS, RETENTION_CODES,
};

const T0: i64 = 1_000_000;

fn actor(role: CctvRole) -> CctvActor {
    CctvActor::new("actor-1", role, "venue-1").expect("actor")
}

fn event(id: &str, kind: CctvEventKind, subject: Option<&str>) -> CctvEvent {
    let event = CctvEvent::new(id, "venue-1", "cam-n1", "zone-north", kind, T0).expect("event");
    match subject {
        Some(subject) => event.with_subject(subject).expect("subject"),
        None => event,
    }
}

#[test]
fn every_personal_data_field_has_purpose_retention_and_access() {
    let fields = privacy_register().expect("register");
    assert!(fields.len() >= 25, "register must cover the venue fields");
    for domain in ["ticket", "credential", "cctv", "access"] {
        assert!(
            fields.iter().any(|field| field.domain == domain),
            "missing {domain} fields"
        );
    }
    for field in &fields {
        assert!(
            !field.purpose.trim().is_empty(),
            "{} purpose",
            field.field_id
        );
        assert!(
            !field.retention_detail.trim().is_empty(),
            "{} retention",
            field.field_id
        );
        assert!(
            !field.access_rule.trim().is_empty(),
            "{} access",
            field.field_id
        );
        assert!(
            !field.deletion_method.trim().is_empty(),
            "{} deletion",
            field.field_id
        );
        assert!(
            RETENTION_CODES.contains(&field.retention_code.as_str()),
            "{} retention code",
            field.field_id
        );
        if field.personal_data == PersonalData::Yes {
            assert!(
                !field.lawful_basis.trim().is_empty(),
                "{} basis",
                field.field_id
            );
        }
    }
    assert!(fields
        .iter()
        .any(|field| field.retention_code == "LEGAL_HOLD"));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let schedule = fs::read_to_string(root.join("data/venue-retention-schedule.csv"))
        .expect("retention schedule");
    for code in [
        "CCTV_SECURITY_30D",
        "CCTV_SAFETY_90D",
        "CCTV_OPERATIONAL_7D",
        "LEGAL_HOLD",
    ] {
        assert!(schedule.contains(code), "schedule missing {code}");
    }
}

#[test]
fn cctv_retention_is_enforced_at_read_and_purge() {
    let mut store = CctvStore::new();
    let officer = actor(CctvRole::PrivacyOfficer);
    store
        .insert(
            &officer,
            event("cctv-retention", CctvEventKind::Security, None),
        )
        .expect("insert");

    let safety = event("cctv-safety-class", CctvEventKind::Safety, None);
    assert_eq!(safety.retention_deadline(), T0 + CCTV_SAFETY_SECS);
    let operational = event("cctv-operational-class", CctvEventKind::Operational, None);
    assert_eq!(operational.retention_deadline(), T0 + 7 * 86_400);
    let deadline = T0 + CCTV_SECURITY_SECS;
    assert!(store.read(&officer, "cctv-retention", deadline).is_ok());
    let expired = store
        .read(&officer, "cctv-retention", deadline + 1)
        .expect_err("expired metadata must not be readable");
    assert!(matches!(expired, CctvError::Expired(_)));

    let report = store.purge_expired(&officer, deadline + 1).expect("purge");
    assert_eq!(report.purged, vec!["cctv-retention".to_string()]);
    assert!(store
        .read(&officer, "cctv-retention", deadline + 1)
        .is_err());
    assert!(store.is_empty());
    assert!(store
        .access_log()
        .iter()
        .any(|record| record.action == "read" && !record.allowed));
    assert!(store
        .access_log()
        .iter()
        .any(|record| record.action == "purge" && record.allowed));
}

#[test]
fn cctv_legal_hold_blocks_deletion_and_extends_retention() {
    let mut store = CctvStore::new();
    let officer = actor(CctvRole::PrivacyOfficer);
    let held = event("cctv-held", CctvEventKind::Security, Some("subject-held"));
    store.insert(&officer, held).expect("insert");
    let hold = CctvLegalHold::new(
        "hold-1",
        "venue-1",
        CctvHoldScope::Subject("subject-held".to_string()),
        "civil claim; preserve CCTV metadata",
        T0 + 10,
    )
    .expect("hold");
    store
        .add_legal_hold(&officer, hold, T0 + 10)
        .expect("add hold");

    let after_expiry = T0 + CCTV_SECURITY_SECS + 1;
    assert!(
        store.read(&officer, "cctv-held", after_expiry).is_ok(),
        "a legal hold must keep held metadata readable"
    );
    let report = store.purge_expired(&officer, after_expiry).expect("purge");
    assert!(report.purged.is_empty());
    assert_eq!(report.retained_under_hold, vec!["cctv-held".to_string()]);

    let deletion = store
        .delete_subject(&officer, "subject-held", "dsar-1", after_expiry)
        .expect("delete");
    assert!(deletion.deleted.is_empty());
    assert_eq!(deletion.retained_under_hold, vec!["cctv-held".to_string()]);
    assert_eq!(deletion.legal_holds.len(), 1);
    assert!(deletion.legal_holds[0].is_active());

    store
        .release_legal_hold(&officer, "hold-1", after_expiry + 1)
        .expect("release");
    let report = store
        .purge_expired(&officer, after_expiry + 1)
        .expect("purge after release");
    assert_eq!(report.purged, vec!["cctv-held".to_string()]);
}

#[test]
fn cctv_access_is_role_scoped_and_audited() {
    let mut store = CctvStore::new();
    let officer = actor(CctvRole::PrivacyOfficer);
    store
        .insert(
            &officer,
            event("cctv-security", CctvEventKind::Security, None),
        )
        .expect("insert security");
    store
        .insert(&officer, event("cctv-safety", CctvEventKind::Safety, None))
        .expect("insert safety");

    let security = actor(CctvRole::SecurityOperator);
    let other_venue =
        CctvActor::new("actor-2", CctvRole::PrivacyOfficer, "venue-2").expect("other actor");
    assert!(matches!(
        store.read(&other_venue, "cctv-security", T0 + 1),
        Err(CctvError::VenueMismatch)
    ));
    assert!(store.read(&security, "cctv-security", T0 + 1).is_ok());
    assert!(matches!(
        store.read(&security, "cctv-safety", T0 + 1),
        Err(CctvError::Forbidden(_))
    ));
    let auditor = actor(CctvRole::Auditor);
    assert!(store.read(&auditor, "cctv-safety", T0 + 1).is_ok());
    assert!(matches!(
        store.add_legal_hold(
            &auditor,
            CctvLegalHold::new(
                "auditor-hold",
                "venue-1",
                CctvHoldScope::Venue("venue-1".to_string()),
                "not allowed",
                T0
            )
            .expect("hold"),
            T0
        ),
        Err(CctvError::Forbidden(_))
    ));
    assert!(store
        .access_log()
        .iter()
        .any(|record| record.actor_id == "actor-1" && record.action == "read" && !record.allowed));
}

#[test]
fn subject_access_and_deletion_are_scoped_and_respect_holds() {
    let mut store = CctvStore::new();
    let officer = actor(CctvRole::PrivacyOfficer);
    store
        .insert(
            &officer,
            event("cctv-a", CctvEventKind::Security, Some("subject-a")),
        )
        .expect("insert a");
    store
        .insert(
            &officer,
            event("cctv-b", CctvEventKind::Operational, Some("subject-b")),
        )
        .expect("insert b");
    let hold = CctvLegalHold::new(
        "hold-b",
        "venue-1",
        CctvHoldScope::Subject("subject-b".to_string()),
        "regulator request",
        T0 + 1,
    )
    .expect("hold");
    store.add_legal_hold(&officer, hold, T0 + 1).expect("hold");

    let export = store
        .subject_export(&officer, "subject-a", T0 + 2)
        .expect("export a");
    assert_eq!(export.events.len(), 1);
    assert_eq!(export.events[0].event_id(), "cctv-a");
    assert!(export.legal_holds.is_empty());

    let deletion = store
        .delete_subject(&officer, "subject-a", "dsar-a", T0 + 3)
        .expect("delete a");
    assert_eq!(deletion.deleted, vec!["cctv-a".to_string()]);
    assert!(store.read(&officer, "cctv-a", T0 + 4).is_err());
    assert!(store.read(&officer, "cctv-b", T0 + 4).is_ok());

    let held_export = store
        .subject_export(&officer, "subject-b", T0 + 5)
        .expect("export b");
    assert!(held_export.includes_held_events);
    assert_eq!(held_export.legal_holds.len(), 1);
}

#[test]
fn raw_video_and_biometrics_are_refused() {
    let safe = CctvEvent::new(
        "cctv-safe",
        "venue-1",
        "cam-1",
        "zone-1",
        CctvEventKind::Security,
        T0,
    )
    .expect("safe");
    assert!(safe
        .clone()
        .with_note("data:image/jpeg;base64,AAAA")
        .is_err());
    assert!(safe.with_note("face_embedding uploaded").is_err());
    assert!(CctvEvent::new(
        "data:video/mp4;base64,AAAA",
        "venue-1",
        "cam-1",
        "zone-1",
        CctvEventKind::Security,
        T0
    )
    .is_err());

    let json = serde_json::json!({
        "event_id": "cctv-json",
        "venue_id": "venue-1",
        "camera_id": "cam-1",
        "zone_id": "zone-1",
        "kind": "security",
        "occurred_est": T0,
        "media": "base64,AAAA"
    });
    assert!(serde_json::from_value::<CctvEvent>(json).is_err());
}

#[test]
fn cctv_store_persists_metadata_access_log_and_holds() {
    let mut store = CctvStore::new();
    let officer = actor(CctvRole::PrivacyOfficer);
    store
        .insert(
            &officer,
            event("cctv-json", CctvEventKind::Safety, Some("subject-c")),
        )
        .expect("insert");
    store
        .add_legal_hold(
            &officer,
            CctvLegalHold::new(
                "hold-json",
                "venue-1",
                CctvHoldScope::Event("cctv-json".to_string()),
                "preserve for review",
                T0,
            )
            .expect("hold"),
            T0,
        )
        .expect("add hold");
    let json = store.to_json().expect("serialize");
    let mut restored = CctvStore::from_json(&json).expect("restore");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored.access_log().len(), store.access_log().len());
    assert_eq!(restored.holds().len(), 1);
    assert_eq!(
        restored
            .read(&officer, "cctv-json", T0 + 1)
            .expect("restored read")
            .kind(),
        CctvEventKind::Safety
    );
    assert_eq!(CCTV_SAFETY_SECS, 90 * 86_400);
}

#[test]
fn pilot_privacy_signoff_and_dpia_pack_are_recorded() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    for relative in [
        "docs/compliance/venue-dpia/README.md",
        "docs/compliance/venue-dpia/ticket.md",
        "docs/compliance/venue-dpia/credential.md",
        "docs/compliance/venue-dpia/cctv.md",
        "docs/compliance/venue-dpia/access.md",
        "docs/compliance/venue-data-flow-retention.md",
        "docs/compliance/venue-cctv-retention.md",
        "docs/compliance/venue-subject-access-deletion.md",
        "docs/compliance/venue-local-authority-reporting.md",
        "docs/compliance/venue-pilot-privacy-signoff.md",
    ] {
        let text = fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("missing {relative}: {error}"));
        assert!(!text.trim().is_empty(), "{relative} is empty");
    }
    let signoff = fs::read_to_string(root.join("docs/compliance/venue-pilot-privacy-signoff.md"))
        .expect("sign-off");
    for needle in [
        "Pilot",
        "DPIA owner",
        "Privacy reviewer",
        "Status: Approved",
        "2026-11-22",
    ] {
        assert!(signoff.contains(needle), "sign-off missing {needle:?}");
    }
}
