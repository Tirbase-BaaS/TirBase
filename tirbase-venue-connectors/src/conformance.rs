// SPDX-License-Identifier: Apache-2.0

//! Venue conformance suite.
//!
//! The suite is the certification gate for a closed connector. It points the
//! connector at a vendor fixture and proves the contract the venue runtime
//! relies on:
//!
//! * **identity and health** — a bounded name, a bound venue and at least one
//!   declared domain;
//! * **delivery per domain** — a sample scan, decision, alarm or announcement is
//!   accepted;
//! * **replay per domain** — the same event presented again is a duplicate, not
//!   a second scan or announcement;
//! * **signed webhooks** — an unsigned callback is rejected, a signed callback
//!   is accepted, and a tampered body fails;
//! * **privacy** — a prepared scan carries no holder name or email and no raw
//!   holder reference.
//!
//! A connector that delivers a replayed scan twice, or accepts an unsigned
//! webhook, is not certified.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tirbase_integrations::{DeliveryOutcome, DeliveryResult};

use crate::domain::{VenueConnector, VenueDomain};
use crate::event::{
    AccessDecision, AccessOutcome, AlarmKind, AlarmSeverity, Announcement, AnnouncementSeverity,
    ScanDirection, TicketScan, VenueAlarm, VenueEvent,
};
use crate::privacy::PrivacyPolicy;
use crate::webhook::VenueWebhookVerifier;

/// One check in a certification run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VenueCheck {
    /// Check name.
    pub name: String,
    /// Whether it passed.
    pub passed: bool,
    /// Secret-free, payload-free evidence.
    pub detail: String,
}

/// The result of certifying one venue connector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VenueCertificationReport {
    /// Connector name.
    pub connector: String,
    /// Venue.
    pub venue: String,
    /// Declared domains.
    pub domains: Vec<VenueDomain>,
    /// Individual checks, in order.
    pub checks: Vec<VenueCheck>,
    /// Whether every check passed.
    pub certified: bool,
    /// When certification ran.
    pub checked_est: i64,
}

impl VenueCertificationReport {
    /// Failed checks.
    pub fn failures(&self) -> Vec<&VenueCheck> {
        self.checks.iter().filter(|check| !check.passed).collect()
    }

    /// Structured JSON form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "connector": self.connector,
            "venue": self.venue,
            "domains": self.domains,
            "certified": self.certified,
            "checked_est": self.checked_est,
            "checks": self.checks,
        })
    }

    /// Compact human summary.
    pub fn summary(&self) -> String {
        let passed = self.checks.iter().filter(|check| check.passed).count();
        if self.certified {
            format!("{} certified ({} checks)", self.connector, passed)
        } else {
            let failed: Vec<&str> = self
                .failures()
                .iter()
                .map(|check| check.name.as_str())
                .collect();
            format!(
                "{} not certified: {}/{} checks passed, failed: {}",
                self.connector,
                passed,
                self.checks.len(),
                failed.join(", ")
            )
        }
    }
}

fn check(name: &str, passed: bool, detail: impl Into<String>) -> VenueCheck {
    VenueCheck {
        name: name.to_string(),
        passed,
        detail: detail.into(),
    }
}

fn accepted(result: &DeliveryResult) -> bool {
    matches!(
        result.outcome,
        DeliveryOutcome::Delivered | DeliveryOutcome::Duplicate
    )
}

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
    .expect("sample scan")
}

fn announcement(id: &str) -> Announcement {
    Announcement::new(
        id,
        "venue-1",
        vec!["zone-north".to_string()],
        AnnouncementSeverity::Info,
        "The north concourse is open.",
        1_000,
    )
    .expect("sample announcement")
}

fn decision(id: &str) -> AccessDecision {
    AccessDecision::new(
        id,
        "scan-1",
        "venue-1",
        "gate-n1",
        AccessOutcome::Granted,
        1_000,
    )
    .expect("sample decision")
}

fn alarm(id: &str) -> VenueAlarm {
    VenueAlarm::new(
        id,
        "venue-1",
        "zone-north",
        AlarmKind::CrowdDensity,
        AlarmSeverity::Warning,
        1_000,
    )
    .expect("sample alarm")
}

fn sample(domain: VenueDomain, id: &str) -> VenueEvent {
    match domain {
        VenueDomain::Ticketing => VenueEvent::ticket_scan(scan(id)),
        VenueDomain::Access => VenueEvent::access_decision(decision(id)),
        VenueDomain::Bms | VenueDomain::Cctv => VenueEvent::alarm(alarm(id)),
        VenueDomain::Pa => VenueEvent::announcement(announcement(id)),
    }
}

/// Certify a connector against a vendor fixture.
///
/// `connector` must be wired to an idempotent fixture (for example
/// [`crate::mock::MockVenueApi`]) or vendor sandbox. `privacy` is the live
/// policy the deployment will use; `webhook` is the verifier the venue will
/// expose for inbound vendor callbacks. The run is deterministic for a given
/// `checked_est`.
pub fn certify(
    connector: &dyn VenueConnector,
    privacy: &PrivacyPolicy,
    webhook: &VenueWebhookVerifier,
    checked_est: i64,
) -> VenueCertificationReport {
    let name = connector.name().to_string();
    let venue = connector.venue().to_string();
    let domains = connector.domains().to_vec();
    let mut checks = Vec::new();

    checks.push(check(
        "identity",
        !name.trim().is_empty()
            && name.len() <= 64
            && !venue.trim().is_empty()
            && !domains.is_empty(),
        format!(
            "connector {name:?} bound to {venue:?} with {} domain(s)",
            domains.len()
        ),
    ));

    let health = connector.health();
    checks.push(check(
        "health",
        !health.detail.trim().is_empty(),
        health.detail.clone(),
    ));

    let capabilities = connector.capabilities();
    checks.push(check(
        "idempotent-capability",
        capabilities.idempotent,
        format!(
            "declares idempotent={} transport={}",
            capabilities.idempotent,
            capabilities.transport.as_str()
        ),
    ));

    for (index, domain) in domains.iter().enumerate() {
        let id = format!("conformance-{}-{index}-{checked_est}", domain.as_str());
        let raw = sample(*domain, &id);
        let event = match privacy.redact_event(&raw) {
            Ok(event) => event,
            Err(error) => {
                checks.push(check(
                    &format!("delivery-{}", domain.as_str()),
                    false,
                    format!("sample could not be redacted: {error}"),
                ));
                continue;
            }
        };
        let first = connector.deliver(&event);
        checks.push(check(
            &format!("delivery-{}", domain.as_str()),
            first.outcome == DeliveryOutcome::Delivered,
            format!("first delivery: {}", first.outcome.as_str()),
        ));
        let replay = connector.deliver(&event);
        checks.push(check(
            &format!("replay-{}", domain.as_str()),
            accepted(&replay) && replay.outcome == DeliveryOutcome::Duplicate,
            format!("replayed delivery: {}", replay.outcome.as_str()),
        ));
    }

    let body = serde_json::to_vec(&VenueEvent::ticket_scan(scan(&format!(
        "conformance-webhook-{checked_est}"
    ))))
    .unwrap_or_default();
    let unsigned = BTreeMap::new();
    checks.push(check(
        "unsigned-webhook",
        webhook.verify(&unsigned, &body, checked_est).is_err(),
        "an unsigned callback is refused",
    ));
    let headers = webhook.signed_headers(checked_est, &body);
    checks.push(check(
        "signed-webhook",
        webhook.verify(&headers, &body, checked_est).is_ok(),
        "a signed callback is accepted",
    ));
    let mut tampered = body.clone();
    tampered.push(b' ');
    checks.push(check(
        "tampered-webhook",
        webhook.verify(&headers, &tampered, checked_est).is_err(),
        "a changed body fails verification",
    ));

    let private = scan(&format!("conformance-privacy-{checked_est}"))
        .with_holder_details(Some("Alice Example"), Some("alice@example.com"));
    let prepared = privacy.prepare(&VenueEvent::ticket_scan(private));
    let privacy_ok = prepared
        .as_ref()
        .map(|event| {
            let serialised = event.payload.to_string();
            !serialised.contains("Alice Example")
                && !serialised.contains("alice@example.com")
                && !serialised.contains("scanner-holder-1")
        })
        .unwrap_or(false);
    checks.push(check(
        "privacy-holder",
        privacy_ok,
        "prepared scan carries no holder name, email or raw holder reference",
    ));

    let certified = checks.iter().all(|check| check.passed);
    VenueCertificationReport {
        connector: name,
        venue,
        domains,
        checks,
        certified,
        checked_est,
    }
}
