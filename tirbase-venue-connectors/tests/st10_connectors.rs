// SPDX-License-Identifier: Apache-2.0

//! ST-10 venue connector framework tests.

use std::collections::BTreeMap;
use std::sync::Arc;

use tirbase_venue_connectors::{
    announcement_idempotency_key, certify, scan_idempotency_key, AccessDecision, AccessOutcome,
    AlarmKind, AlarmSeverity, Announcement, AnnouncementSeverity, BmsPointWrite, BmsValue,
    CameraContext, ConnectorProfile, HolderDisclosure, InboundVenueEvents, MockVenueApi,
    MockVenueConfig, PrivacyPolicy, RetryPolicy, ScanDirection, TicketScan, VenueAlarm,
    VenueDispatcher, VenueDomain, VenueEvent, VenueSubmit, VenueWebhookVerifier, WebhookError,
};

fn scan(id: &str) -> TicketScan {
    TicketScan::new(
        id,
        "venue-1",
        "gate-n1",
        "ticket-1",
        "scanner-holder-1",
        ScanDirection::Entry,
        1_000,
    )
    .expect("scan")
}

fn announcement(id: &str) -> Announcement {
    Announcement::new(
        id,
        "venue-1",
        vec!["zone-north".to_string()],
        AnnouncementSeverity::Info,
        "Gates open in ten minutes.",
        1_000,
    )
    .expect("announcement")
}

fn policy() -> PrivacyPolicy {
    PrivacyPolicy::standard("test-deployment-salt")
}

#[test]
fn event_schemas_are_strict_and_round_trip() {
    let event = VenueEvent::ticket_scan(scan("scan-1"));
    let json = serde_json::to_value(&event).expect("json");
    assert_eq!(json["kind"], "ticket_scan");
    assert_eq!(json["scan"]["scan_id"], "scan-1");
    let restored: VenueEvent = serde_json::from_value(json.clone()).expect("restore");
    assert_eq!(restored, event);
    assert_eq!(restored.event_id(), event.event_id());

    let mut extended = json;
    extended["scan"]["face_template"] = serde_json::json!("AAAA");
    assert!(serde_json::from_value::<VenueEvent>(extended).is_err());

    assert!(TicketScan::new(
        "scan 2",
        "venue-1",
        "gate-n1",
        "ticket-1",
        "holder",
        ScanDirection::Entry,
        1_000
    )
    .is_err());
    assert!(Announcement::new(
        "ann-1",
        "venue-1",
        vec!["zone-north".into()],
        AnnouncementSeverity::Info,
        "text",
        1_000
    )
    .expect("announcement")
    .until(1_000)
    .is_err());
    assert!(CameraContext::new("venue-1", "cam-1", "zone-north", "trigger-1", 1_000).is_ok());
    assert!(CameraContext::new(
        "venue-1",
        "cam-1",
        "zone-north",
        "data:image/jpeg;base64,AAAA",
        1_000
    )
    .is_err());
    assert!(BmsPointWrite::new("venue-1", "point-1", BmsValue::Number(f64::NAN), 1_000).is_err());
}

#[test]
fn profile_parses_and_maps_redacted_events() {
    let profile = ConnectorProfile::from_toml(
        r#"
schema_version = 1
connector = "vendor-ticketing"
domain = "ticketing"
venue = "venue-1"
endpoint = "https://vendor.example/venue/events"
webhook_secret_ref = "env:VENUE_WEBHOOK_SECRET"

[privacy]
holder = "pseudonymise"
pseudonym_salt_ref = "env:VENUE_PRIVACY_SALT"
max_retention_secs = 86400

[retry]
max_attempts = 4
base_delay_secs = 2
factor = 2
max_delay_secs = 60

[mapping]
schema_version = 1

[[mapping.field]]
target = "scan.id"
source = "event.event_id"
required = true

[[mapping.field]]
target = "scan.ticket"
source = "payload.ticket_id"
required = true
"#,
    )
    .expect("profile");

    assert_eq!(profile.profile().domain, VenueDomain::Ticketing);
    assert_eq!(profile.retry_policy().max_attempts, 4);
    let event = VenueEvent::ticket_scan(
        scan("scan-map").with_holder_details(Some("Alice Example"), Some("alice@example.com")),
    );
    let mapped = profile
        .apply_to_event(&event, &profile.privacy("deployment-salt"))
        .expect("mapping");
    assert_eq!(mapped["scan"]["id"], event.event_id());
    assert_eq!(mapped["scan"]["ticket"], "ticket-1");
    let serialised = mapped.to_string();
    assert!(!serialised.contains("Alice Example"));
    assert!(!serialised.contains("alice@example.com"));

    let insecure = ConnectorProfile::from_toml(
        r#"
schema_version = 1
connector = "vendor"
domain = "pa"
venue = "venue-1"
endpoint = "http://vendor.example/events"
[privacy]
holder = "omit"
pseudonym_salt_ref = "env:SALT"
max_retention_secs = 60
[mapping]
schema_version = 1
[[mapping.field]]
target = "id"
source = "event.event_id"
"#,
    );
    assert!(insecure.is_err());

    let raw_secret = ConnectorProfile::from_toml(
        r#"
schema_version = 1
connector = "vendor"
domain = "pa"
venue = "venue-1"
endpoint = "https://vendor.example/events"
[privacy]
holder = "omit"
pseudonym_salt_ref = "super-secret-value"
max_retention_secs = 60
[mapping]
schema_version = 1
[[mapping.field]]
target = "id"
source = "event.event_id"
"#,
    );
    assert!(raw_secret.is_err());
}

#[test]
fn replays_do_not_duplicate_scans_or_announcements() {
    let mock = Arc::new(MockVenueApi::new(
        "venue-all",
        "venue-1",
        vec![VenueDomain::Ticketing, VenueDomain::Pa],
    ));
    let mut dispatcher =
        VenueDispatcher::new(Box::new(Arc::clone(&mock)), policy(), Default::default());

    let scan_event = VenueEvent::ticket_scan(scan("scan-replay"));
    let announcement_event = VenueEvent::announcement(announcement("ann-replay"));

    assert_eq!(
        dispatcher.submit(&scan_event, 1_000).expect("scan"),
        VenueSubmit::Queued(1)
    );
    assert_eq!(
        dispatcher
            .submit(&announcement_event, 1_000)
            .expect("announcement"),
        VenueSubmit::Queued(2)
    );
    let report = dispatcher.flush(1_000);
    assert_eq!(report.delivered, 2);
    assert_eq!(mock.record_count(), 2);
    assert_eq!(mock.delivered_events().len(), 2);

    assert!(matches!(
        dispatcher.submit(&scan_event, 1_100).expect("replay scan"),
        VenueSubmit::AlreadyDelivered(_)
    ));
    assert!(matches!(
        dispatcher
            .submit(&announcement_event, 1_100)
            .expect("replay announcement"),
        VenueSubmit::AlreadyDelivered(_)
    ));
    assert_eq!(dispatcher.flush(1_100).attempted, 0);
    assert_eq!(mock.record_count(), 2);
    assert_eq!(mock.delivered_events().len(), 2);

    assert_eq!(
        scan_idempotency_key("venue-all", "venue-1", "scan-replay"),
        scan_idempotency_key("venue-all", "venue-1", "scan-replay")
    );
    assert_ne!(
        announcement_idempotency_key("venue-all", "venue-1", "ann-replay"),
        scan_idempotency_key("venue-all", "venue-1", "scan-replay")
    );
}

#[test]
fn retries_back_off_and_dead_letters_then_replay_once() {
    let mock = Arc::new(MockVenueApi::with_config(
        "flaky",
        "venue-1",
        vec![VenueDomain::Ticketing],
        MockVenueConfig::default().with_fail_first(2),
    ));
    let mut dispatcher = VenueDispatcher::new(
        Box::new(Arc::clone(&mock)),
        policy(),
        RetryPolicy::new(3, 1, 2, 10),
    );
    let event = VenueEvent::ticket_scan(scan("scan-retry"));
    dispatcher.submit(&event, 1_000).expect("submit");

    let first = dispatcher.flush(1_000);
    assert_eq!(first.attempted, 1);
    assert_eq!(first.retried, 1);
    let second = dispatcher.flush(1_001);
    assert_eq!(second.attempted, 1);
    assert_eq!(second.retried, 1);
    let third = dispatcher.flush(1_004);
    assert_eq!(third.delivered, 1);
    assert_eq!(mock.calls(), 3);
    assert_eq!(mock.record_count(), 1);

    let mock = Arc::new(MockVenueApi::with_config(
        "dead-letter",
        "venue-1",
        vec![VenueDomain::Ticketing],
        MockVenueConfig::default().with_fail_first(1),
    ));
    let mut dispatcher = VenueDispatcher::new(
        Box::new(Arc::clone(&mock)),
        policy(),
        RetryPolicy::new(1, 1, 1, 1),
    );
    let event = VenueEvent::ticket_scan(scan("scan-dlq"));
    dispatcher.submit(&event, 2_000).expect("submit");
    let report = dispatcher.flush(2_000);
    assert_eq!(report.dead_lettered, 1);
    let dlq_id = dispatcher.engine().outbox().dead_letters()[0]
        .dlq_id
        .clone();

    mock.clear_failures();
    dispatcher.replay(&dlq_id, 2_100).expect("replay");
    assert_eq!(dispatcher.flush(2_100).delivered, 1);
    assert_eq!(mock.record_count(), 1);
    assert!(matches!(
        dispatcher.submit(&event, 2_200).expect("settled"),
        VenueSubmit::AlreadyDelivered(_)
    ));
    assert!(dispatcher.replay(&dlq_id, 2_300).is_err());
}

#[test]
fn unsigned_webhooks_are_refused_and_replays_are_suppressed() {
    let verifier = VenueWebhookVerifier::new("webhook-secret");
    let event = VenueEvent::announcement(announcement("ann-webhook"));
    let body = serde_json::to_vec(&event).expect("body");

    assert_eq!(
        verifier.verify(&BTreeMap::new(), &body, 1_000),
        Err(WebhookError::MissingSignature)
    );

    let headers = verifier.signed_headers(1_000, &body);
    let verified = verifier.verify(&headers, &body, 1_000).expect("signed");
    assert_eq!(verified.event(&body).expect("event"), event);

    let stale = verifier.verify(&headers, &body, 2_000);
    assert!(matches!(stale, Err(WebhookError::StaleTimestamp { .. })));

    let mut tampered = body.clone();
    tampered.push(b' ');
    assert_eq!(
        verifier.verify(&headers, &tampered, 1_000),
        Err(WebhookError::SignatureMismatch)
    );

    let rotating = verifier.clone().with_secret("next-secret");
    let next_signature = rotating.sign_with(1, 1_000, &body).expect("rotated");
    let mut rotated_headers = headers.clone();
    rotated_headers.insert(rotating.signature_header().to_string(), next_signature);
    assert!(rotating.verify(&rotated_headers, &body, 1_000).is_ok());

    let mut inbound = InboundVenueEvents::new(verifier.clone());
    let first = inbound.accept(&headers, &body, 1_000).expect("first");
    assert!(!first.replay);
    let replay = inbound.accept(&headers, &body, 1_000).expect("replay");
    assert!(replay.replay);
    assert_eq!(inbound.accepted(), 1);

    let changed = VenueEvent::announcement(
        Announcement::new(
            "ann-webhook",
            "venue-1",
            vec!["zone-north".to_string()],
            AnnouncementSeverity::Warning,
            "Different text under the same id.",
            1_000,
        )
        .expect("changed"),
    );
    let changed_body = serde_json::to_vec(&changed).expect("changed body");
    let changed_headers = verifier.signed_headers(1_000, &changed_body);
    assert_eq!(
        inbound.accept(&changed_headers, &changed_body, 1_000),
        Err(WebhookError::PayloadConflict)
    );
}

#[test]
fn privacy_removes_direct_identifiers_and_refuses_media_and_biometrics() {
    let policy = policy();
    let private =
        scan("scan-private").with_holder_details(Some("Alice Example"), Some("alice@example.com"));
    let prepared = policy
        .prepare(&VenueEvent::ticket_scan(private))
        .expect("prepared");
    let serialised = prepared.payload.to_string();
    assert!(!serialised.contains("Alice Example"));
    assert!(!serialised.contains("alice@example.com"));
    assert!(!serialised.contains("scanner-holder-1"));
    assert!(serialised.contains("vh-"));

    let token = policy.pseudonym("scanner-holder-1");
    assert_eq!(token, policy.pseudonym("scanner-holder-1"));
    assert_ne!(token, policy.pseudonym("scanner-holder-2"));

    let omitted = PrivacyPolicy::new(HolderDisclosure::Omit, "salt");
    let omitted_event = omitted
        .redact_event(&VenueEvent::ticket_scan(scan("scan-omit")))
        .expect("omitted");
    let json = serde_json::to_value(omitted_event).expect("json");
    assert_eq!(json["scan"]["holder_ref"], "redacted");

    let announcement = Announcement::new(
        "ann-private",
        "venue-1",
        vec!["zone-north".into()],
        AnnouncementSeverity::Info,
        "Call +44 20 7946 0958 or email alice@example.com for help.",
        1_000,
    )
    .expect("announcement");
    let redacted = policy
        .redact_event(&VenueEvent::announcement(announcement))
        .expect("redacted");
    let text = match redacted {
        VenueEvent::Announcement { announcement } => announcement.text,
        other => panic!("unexpected {other:?}"),
    };
    assert!(text.contains("[redacted-number]"));
    assert!(text.contains("[redacted-email]"));
    assert!(!text.contains("alice@example.com"));

    let media_alarm = VenueAlarm::new(
        "alarm-media",
        "venue-1",
        "zone-north",
        AlarmKind::Intrusion,
        AlarmSeverity::Critical,
        1_000,
    )
    .expect("alarm")
    .with_detail("data:image/jpeg;base64,AAAA");
    assert!(policy
        .redact_event(&VenueEvent::alarm(media_alarm))
        .is_err());

    let biometric = Announcement::new(
        "ann-bio",
        "venue-1",
        vec!["zone-north".into()],
        AnnouncementSeverity::Info,
        "Biometric face_embedding upload complete.",
        1_000,
    )
    .expect("announcement");
    assert!(policy
        .redact_event(&VenueEvent::announcement(biometric))
        .is_err());
    assert!(policy.may_retain(
        &VenueEvent::ticket_scan(scan("scan-retain")),
        1_000 + 86_400
    ));
}

#[test]
fn conformance_certifies_a_correct_connector_and_catches_double_delivery() {
    let mock = MockVenueApi::new(
        "venue-integration",
        "venue-1",
        vec![VenueDomain::Ticketing, VenueDomain::Pa, VenueDomain::Bms],
    );
    let report = certify(
        &mock,
        &policy(),
        &VenueWebhookVerifier::new("webhook-secret"),
        5_000,
    );
    assert!(report.certified, "{:?}", report.failures());
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "unsigned-webhook" && check.passed));
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "replay-ticketing" && check.passed));
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "replay-pa" && check.passed));
    assert_eq!(report.to_json()["certified"], true);

    let broken = MockVenueApi::with_config(
        "broken-vendor",
        "venue-1",
        vec![VenueDomain::Ticketing],
        MockVenueConfig::default().with_dedupe(false),
    );
    let broken = certify(
        &broken,
        &policy(),
        &VenueWebhookVerifier::new("webhook-secret"),
        6_000,
    );
    assert!(!broken.certified);
    assert!(broken
        .failures()
        .iter()
        .any(|check| check.name == "replay-ticketing"));
}

#[test]
fn access_decisions_and_alarms_validate() {
    let decision = AccessDecision::new(
        "decision-1",
        "scan-1",
        "venue-1",
        "gate-n1",
        AccessOutcome::Denied {
            reason: tirbase_venue_connectors::DenyReason::Replay,
        },
        1_000,
    )
    .expect("decision");
    assert!(matches!(
        decision.outcome,
        AccessOutcome::Denied {
            reason: tirbase_venue_connectors::DenyReason::Replay
        }
    ));
    let alarm = VenueAlarm::new(
        "alarm-1",
        "venue-1",
        "zone-north",
        AlarmKind::GateFault,
        AlarmSeverity::Warning,
        1_000,
    )
    .expect("alarm")
    .with_source("gate-controller");
    assert_eq!(alarm.kind.as_str(), "gate_fault");
}
