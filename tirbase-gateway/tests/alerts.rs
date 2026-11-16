// SPDX-License-Identifier: AGPL-3.0-only

//! CC-17 acceptance tests: repeated events must not page twice, a failed
//! delivery must be retried and visible, and an unacknowledged critical alert
//! must escalate.
//!
//! The transports here are fakes that implement the Apache-2.0 connector
//! interface (`tirbase_notify::NotifyTransport`), which is exactly how a vendor
//! plugin is wired in: the AGPL engine only ever sees that trait.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tirbase_gateway::alerts::config::AlertsConfig;
use tirbase_gateway::alerts::routing::{ChannelConfig, RouteRule, RoutingTable};
use tirbase_gateway::alerts::{
    AckOutcome, Alert, AlertNotifier, AlertRouter, AlertStore, RaiseOutcome,
};
use tirbase_gateway::excursion::notifier::{ExcursionNotification, NotificationEvent};
use tirbase_notify::backoff::RetryPolicy;
use tirbase_notify::oncall::{OnCallSchedule, Rotation};
use tirbase_notify::webhook::{HttpPoster, WebhookRequest, WebhookTransport};
use tirbase_notify::{
    AlertMessage, ConnectorKind, DeliveryFailure, DeliveryReceipt, DeliveryTarget,
    MemorySecretStore, NotifyTransport, Severity,
};

// ─── Fakes ──────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Recorder {
    attempts: Mutex<Vec<(String, String, AlertMessage)>>,
}

impl Recorder {
    fn attempts(&self) -> Vec<(String, String, AlertMessage)> {
        self.attempts.lock().unwrap().clone()
    }

    fn attempt_count(&self) -> usize {
        self.attempts.lock().unwrap().len()
    }
}

/// Per-channel failure script, so a test can fail exactly one channel.
#[derive(Debug, Default)]
struct Script {
    failures: Mutex<VecDeque<DeliveryFailure>>,
    fail_always: Mutex<Option<DeliveryFailure>>,
}

impl Script {
    fn fail_next(failure: DeliveryFailure) -> Arc<Self> {
        let script = Self::default();
        script.failures.lock().unwrap().push_back(failure);
        Arc::new(script)
    }

    fn fail_always(failure: DeliveryFailure) -> Arc<Self> {
        let script = Self::default();
        *script.fail_always.lock().unwrap() = Some(failure);
        Arc::new(script)
    }

    fn next_failure(&self) -> Option<DeliveryFailure> {
        if let Some(failure) = self.fail_always.lock().unwrap().clone() {
            return Some(failure);
        }
        self.failures.lock().unwrap().pop_front()
    }
}

#[derive(Debug)]
struct FakeTransport {
    channel: String,
    recorder: Arc<Recorder>,
    script: Arc<Script>,
}

impl NotifyTransport for FakeTransport {
    fn channel(&self) -> &str {
        &self.channel
    }

    fn deliver(
        &self,
        message: &AlertMessage,
        target: &DeliveryTarget,
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        self.recorder.attempts.lock().unwrap().push((
            self.channel.clone(),
            target.address.clone(),
            message.clone(),
        ));
        if let Some(failure) = self.script.next_failure() {
            return Err(failure);
        }
        Ok(DeliveryReceipt {
            provider_id: Some("fake-1".to_string()),
        })
    }
}

#[derive(Debug, Default)]
struct RecordingPoster {
    requests: Mutex<Vec<WebhookRequest>>,
}

impl HttpPoster for RecordingPoster {
    fn post(&self, request: &WebhookRequest) -> Result<u16, String> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(204)
    }
}

// ─── Fixtures ───────────────────────────────────────────────────────────────

fn schedule(max_level: u32) -> OnCallSchedule {
    let mut rotations = vec![Rotation {
        role: "cold-chain".to_string(),
        level: 1,
        start_est: 0,
        period_secs: 86_400,
        members: vec!["ana@example.com".to_string(), "bo@example.com".to_string()],
    }];
    if max_level >= 2 {
        rotations.push(Rotation {
            role: "cold-chain".to_string(),
            level: 2,
            start_est: 0,
            period_secs: 86_400,
            members: vec!["lead@example.com".to_string()],
        });
    }
    OnCallSchedule::new(rotations).expect("schedule")
}

fn channels() -> Vec<ChannelConfig> {
    vec![
        ChannelConfig {
            name: "email".to_string(),
            kind: ConnectorKind::Email,
            endpoint: "alerts@tirbase.local".to_string(),
            secret_ref: None,
        },
        ChannelConfig {
            name: "console".to_string(),
            kind: ConnectorKind::Console,
            endpoint: "-".to_string(),
            secret_ref: None,
        },
    ]
}

fn rule() -> RouteRule {
    RouteRule::new("excursion", Severity::Warning, "cold-chain", "email")
        .with_channels(vec!["email".to_string(), "console".to_string()])
        .escalating(300, 2)
}

fn table(max_level: u32) -> RoutingTable {
    let rule = if max_level >= 2 {
        rule()
    } else {
        RouteRule::new("excursion", Severity::Warning, "cold-chain", "email")
            .with_channels(vec!["email".to_string(), "console".to_string()])
    };
    RoutingTable::new(vec![rule], channels(), schedule(max_level)).expect("routing")
}

fn build_router(
    store: AlertStore,
    table: RoutingTable,
    recorder: &Arc<Recorder>,
    retry: RetryPolicy,
) -> AlertRouter {
    build_router_with(
        store,
        table,
        recorder,
        retry,
        Arc::new(Script::default()),
        Arc::new(Script::default()),
    )
}

fn build_router_with(
    store: AlertStore,
    table: RoutingTable,
    recorder: &Arc<Recorder>,
    retry: RetryPolicy,
    email: Arc<Script>,
    console: Arc<Script>,
) -> AlertRouter {
    AlertRouter::new(
        store,
        table,
        vec![
            Box::new(FakeTransport {
                channel: "email".to_string(),
                recorder: recorder.clone(),
                script: email,
            }),
            Box::new(FakeTransport {
                channel: "console".to_string(),
                recorder: recorder.clone(),
                script: console,
            }),
        ],
        retry,
    )
    .expect("router")
}

fn alert(at_est: i64) -> Alert {
    Alert::critical(
        "alert-1",
        "excursion",
        "tenant-a",
        "site-1",
        "cold room too warm",
    )
    .with_dedup_key("excursion:rec-1:quarantine_opened")
    .with_body("temperature out of band for 12 min")
    .observed_at(at_est)
}

// ─── Done when: a repeated event does not produce duplicate pages ───────────

#[test]
fn raising_the_same_event_twice_pages_once() {
    let recorder = Arc::new(Recorder::default());
    let router = build_router(
        AlertStore::open_in_memory().expect("store"),
        table(1),
        &recorder,
        RetryPolicy::default(),
    );

    let first = router.raise_alert(&alert(1_000)).expect("raise");
    assert_eq!(
        first,
        RaiseOutcome::Raised {
            alert_id: "alert-1".to_string(),
            deliveries: 2,
        }
    );
    assert_eq!(
        recorder.attempt_count(),
        2,
        "one email and one console page"
    );

    let second = router.raise_alert(&alert(1_000)).expect("raise again");
    assert_eq!(
        second,
        RaiseOutcome::Duplicate {
            alert_id: "alert-1".to_string(),
            deliveries: 2,
        }
    );
    assert_eq!(
        recorder.attempt_count(),
        2,
        "the repeat must not page again"
    );
    assert_eq!(router.deliveries("alert-1").expect("deliveries").len(), 2);

    // A different alert id with the same deduplication key is still the same
    // event: the receiver must not get two pages for one excursion.
    let restated = Alert::critical("alert-2", "excursion", "tenant-a", "site-1", "warm again")
        .with_dedup_key("excursion:rec-1:quarantine_opened")
        .observed_at(1_010);
    assert!(matches!(
        router.raise_alert(&restated).expect("raise"),
        RaiseOutcome::Duplicate { .. }
    ));
    assert_eq!(recorder.attempt_count(), 2);

    // Re-running delivery does not re-page a delivery that was accepted.
    let report = router.run_due(10_000).expect("run");
    assert_eq!(report.delivered, 0);
    assert_eq!(recorder.attempt_count(), 2);
}

// ─── Done when: a failed delivery is retried and visible ────────────────────

#[test]
fn a_failed_delivery_is_retried_with_backoff_and_stays_visible() {
    let recorder = Arc::new(Recorder::default());
    let retry = RetryPolicy::new(3, 10, 120).expect("policy");
    let router = build_router_with(
        AlertStore::open_in_memory().expect("store"),
        table(1),
        &recorder,
        retry,
        Script::fail_next(DeliveryFailure::retriable("smtp connect: timeout")),
        Arc::new(Script::default()),
    );

    router.raise_alert(&alert(1_000)).expect("raise");
    // The email channel failed; the console channel was accepted.
    let deliveries = router.deliveries("alert-1").expect("deliveries");
    let email = deliveries
        .iter()
        .find(|delivery| delivery.channel == "email")
        .expect("email delivery");
    assert_eq!(email.state, "pending");
    assert_eq!(email.attempts, 1);
    assert_eq!(email.last_error.as_deref(), Some("smtp connect: timeout"));
    assert!(
        email.next_attempt_est > 1_000,
        "retry must be scheduled ahead"
    );
    assert!(email.delivered_est.is_none());

    let audit = router.audit("alert-1").expect("audit");
    assert!(
        audit
            .iter()
            .any(|entry| entry.kind == "retry" && entry.detail.contains("smtp connect")),
        "the failed attempt must be visible in the audit: {audit:?}"
    );

    // Before the deadline nothing is attempted; after it, the retry happens.
    let attempts_before = recorder.attempt_count();
    let report = router.run_due(1_000).expect("run");
    assert_eq!(report.retried, 0);
    assert_eq!(recorder.attempt_count(), attempts_before);

    let report = router.run_due(email.next_attempt_est).expect("run");
    assert_eq!(report.delivered, 1);
    let deliveries = router.deliveries("alert-1").expect("deliveries");
    let email = deliveries
        .iter()
        .find(|delivery| delivery.channel == "email")
        .expect("email delivery");
    assert_eq!(email.state, "delivered");
    assert_eq!(email.attempts, 2);
    assert_eq!(email.delivered_est, Some(email.next_attempt_est));
}

#[test]
fn an_exhausted_or_permanent_failure_becomes_a_visible_dead_letter() {
    let recorder = Arc::new(Recorder::default());
    let router = build_router_with(
        AlertStore::open_in_memory().expect("store"),
        table(1),
        &recorder,
        RetryPolicy::new(2, 5, 5).expect("policy"),
        Script::fail_always(DeliveryFailure::retriable("relay unavailable")),
        Script::fail_always(DeliveryFailure::retriable("console sink unavailable")),
    );

    router.raise_alert(&alert(1_000)).expect("raise");
    assert!(router.dead_letters().expect("dead letters").is_empty());

    // First failure is retriable and scheduled; the second exhausts the policy.
    let pending = router.deliveries("alert-1").expect("deliveries");
    let deadline = pending
        .iter()
        .map(|delivery| delivery.next_attempt_est)
        .max()
        .expect("deadline");
    router.run_due(deadline).expect("run");

    let dead = router.dead_letters().expect("dead letters");
    assert_eq!(
        dead.len(),
        2,
        "both channels exhausted their budget: {dead:?}"
    );
    assert!(dead.iter().all(|letter| letter.attempts == 2));
    assert!(dead
        .iter()
        .any(|letter| letter.last_error.contains("console sink unavailable")));
    assert!(dead
        .iter()
        .any(|letter| letter.last_error.contains("relay unavailable")));
    assert!(router
        .deliveries("alert-1")
        .expect("deliveries")
        .iter()
        .all(|delivery| delivery.state == "dead_letter"));
    assert!(router
        .audit("alert-1")
        .expect("audit")
        .iter()
        .any(|entry| entry.kind == "dead_letter"));

    // A permanent failure is not retried at all.
    let recorder = Arc::new(Recorder::default());
    let router = build_router_with(
        AlertStore::open_in_memory().expect("store"),
        table(1),
        &recorder,
        RetryPolicy::new(5, 5, 5).expect("policy"),
        Script::fail_always(DeliveryFailure::permanent("malformed address")),
        Script::fail_always(DeliveryFailure::permanent("malformed address")),
    );
    router.raise_alert(&alert(1_000)).expect("raise");
    let dead = router.dead_letters().expect("dead letters");
    assert_eq!(dead.len(), 2);
    assert!(dead.iter().all(|letter| letter.attempts == 1));
}

// ─── Done when: an unacknowledged critical alert escalates ──────────────────

#[test]
fn an_unacknowledged_critical_alert_escalates_after_its_deadline() {
    let recorder = Arc::new(Recorder::default());
    let router = build_router(
        AlertStore::open_in_memory().expect("store"),
        table(2),
        &recorder,
        RetryPolicy::default(),
    );

    router.raise_alert(&alert(1_000)).expect("raise");
    let level_one = router.deliveries("alert-1").expect("deliveries");
    assert_eq!(level_one.len(), 2);
    assert!(level_one.iter().all(|delivery| delivery.level == 1));
    let to_ana = recorder
        .attempts()
        .iter()
        .any(|(channel, address, _)| channel == "email" && address == "ana@example.com");
    assert!(to_ana, "the level-1 on-call member must be the one paged");

    // One second before the deadline nothing escalates.
    let report = router.run_due(1_299).expect("run");
    assert_eq!(report.escalated, 0);
    assert_eq!(router.deliveries("alert-1").expect("deliveries").len(), 2);

    let report = router.run_due(1_300).expect("run");
    assert_eq!(report.escalated, 1);
    let deliveries = router.deliveries("alert-1").expect("deliveries");
    assert_eq!(deliveries.len(), 4, "level 2 adds one page per channel");
    let level_two: Vec<_> = deliveries
        .iter()
        .filter(|delivery| delivery.level == 2)
        .collect();
    assert_eq!(level_two.len(), 2);
    assert!(level_two
        .iter()
        .all(|delivery| delivery.state == "delivered"));
    let record = router.record("alert-1").expect("record");
    assert_eq!(record.escalation_level, 2);
    assert!(record.is_open());
    assert!(!record.is_acknowledged());
    assert!(recorder
        .attempts()
        .iter()
        .any(|(channel, address, message)| channel == "email"
            && address == "lead@example.com"
            && message.escalation_level == 2));
    assert!(router
        .audit("alert-1")
        .expect("audit")
        .iter()
        .any(|entry| entry.kind == "escalated" && entry.detail.contains("level=2")));

    // The highest level has been reached: it does not escalate again.
    let report = router.run_due(100_000).expect("run");
    assert_eq!(report.escalated, 0);
    assert_eq!(router.deliveries("alert-1").expect("deliveries").len(), 4);
    assert_eq!(router.open_alerts("tenant-a").expect("open").len(), 1);
}

#[test]
fn acknowledging_stops_the_escalation_and_is_idempotent() {
    let recorder = Arc::new(Recorder::default());
    let router = build_router(
        AlertStore::open_in_memory().expect("store"),
        table(2),
        &recorder,
        RetryPolicy::default(),
    );
    router.raise_alert(&alert(1_000)).expect("raise");

    assert_eq!(
        router.acknowledge("alert-1", "ana", 1_100).expect("ack"),
        AckOutcome::Acknowledged {
            alert_id: "alert-1".to_string()
        }
    );
    assert_eq!(
        router
            .acknowledge("alert-1", "bo", 1_200)
            .expect("ack again"),
        AckOutcome::AlreadyAcknowledged {
            alert_id: "alert-1".to_string(),
            by: "ana".to_string(),
            at_est: 1_100,
        }
    );
    let record = router.record("alert-1").expect("record");
    assert!(record.is_acknowledged());
    assert!(!record.is_open());
    assert_eq!(record.acknowledged_by.as_deref(), Some("ana"));
    assert!(router.open_alerts("tenant-a").expect("open").is_empty());

    let report = router.run_due(1_400).expect("run");
    assert_eq!(report.escalated, 0);
    assert_eq!(router.deliveries("alert-1").expect("deliveries").len(), 2);
    assert!(router
        .audit("alert-1")
        .expect("audit")
        .iter()
        .any(|entry| entry.kind == "acknowledged" && entry.detail.contains("ana")));

    assert!(router.acknowledge("missing", "ana", 1_500).is_err());
}

// ─── At-least-once across a restart ─────────────────────────────────────────

#[test]
fn a_pending_delivery_survives_a_restart_and_is_delivered_once() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("primary.db");

    let failing = Arc::new(Recorder::default());
    {
        let router = build_router_with(
            AlertStore::open(&path).expect("store"),
            table(1),
            &failing,
            RetryPolicy::new(5, 60, 600).expect("policy"),
            Script::fail_always(DeliveryFailure::retriable("relay down")),
            Script::fail_always(DeliveryFailure::retriable("relay down")),
        );
        router.raise_alert(&alert(1_000)).expect("raise");
        assert!(router
            .deliveries("alert-1")
            .expect("deliveries")
            .iter()
            .all(|delivery| delivery.state == "pending"));
    }

    // New process: the queue is on disk, and the retry uses the stored attempt
    // count and deadline.
    let healthy = Arc::new(Recorder::default());
    let router = build_router(
        AlertStore::open(&path).expect("reopen"),
        table(1),
        &healthy,
        RetryPolicy::new(5, 60, 600).expect("policy"),
    );
    let report = router.run_due(10_000).expect("run");
    assert_eq!(report.delivered, 2);
    assert_eq!(healthy.attempt_count(), 2);
    let resent = &healthy.attempts()[0].2;
    assert_eq!(resent.alert_id, "alert-1");
    assert_eq!(resent.dedup_key, "excursion:rec-1:quarantine_opened");
    assert_eq!(
        resent.alert_id,
        router.deliveries("alert-1").expect("deliveries")[0].alert_id,
        "a re-sent delivery keeps the identity a receiver deduplicates on"
    );
    // Nothing is re-sent after the queue drains.
    assert_eq!(router.run_due(20_000).expect("run").delivered, 0);
    assert_eq!(healthy.attempt_count(), 2);
}

// ─── Secrets by reference, end to end through the engine ────────────────────

#[test]
fn a_channel_secret_is_resolved_by_reference_and_never_stored() {
    let poster = Arc::new(RecordingPoster::default());
    let secrets = MemorySecretStore::new().with("webhook/alerting", "hook-secret-value");
    let transport = WebhookTransport::new(
        "webhook",
        Box::new(PosterHandle(poster.clone())),
        Box::new(secrets),
    );
    let routing = RoutingTable::new(
        vec![RouteRule::new(
            "excursion",
            Severity::Warning,
            "cold-chain",
            "webhook",
        )],
        vec![ChannelConfig {
            name: "webhook".to_string(),
            kind: ConnectorKind::Webhook,
            endpoint: "https://hooks.example.com/tirbase".to_string(),
            secret_ref: Some(tirbase_notify::SecretRef::new("webhook/alerting").expect("ref")),
        }],
        schedule(1),
    )
    .expect("routing");
    let router = AlertRouter::with_default_retry(
        AlertStore::open_in_memory().expect("store"),
        routing,
        vec![Box::new(transport)],
    )
    .expect("router");

    router.raise_alert(&alert(1_000)).expect("raise");
    let requests = poster.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers.contains_key("X-TirBase-Signature"));
    assert!(!requests[0].body.contains("hook-secret-value"));
    assert_eq!(
        requests[0].headers["Idempotency-Key"],
        "excursion:rec-1:quarantine_opened"
    );

    // The database stores the reference, never the value.
    let stored = &router.deliveries("alert-1").expect("deliveries")[0];
    assert_eq!(
        stored
            .secret_ref
            .as_ref()
            .map(|reference| reference.as_str()),
        Some("webhook/alerting")
    );
    for entry in router.audit("alert-1").expect("audit") {
        assert!(!entry.detail.contains("hook-secret-value"), "{entry:?}");
    }

    // A missing secret fails permanently, naming only the reference, and is
    // visible as a dead letter rather than a lost page.
    let routing = RoutingTable::new(
        vec![RouteRule::new(
            "excursion",
            Severity::Warning,
            "cold-chain",
            "webhook",
        )],
        vec![ChannelConfig {
            name: "webhook".to_string(),
            kind: ConnectorKind::Webhook,
            endpoint: "https://hooks.example.com/tirbase".to_string(),
            secret_ref: Some(tirbase_notify::SecretRef::new("webhook/missing").expect("ref")),
        }],
        schedule(1),
    )
    .expect("routing");
    let router = AlertRouter::with_default_retry(
        AlertStore::open_in_memory().expect("store"),
        routing,
        vec![Box::new(WebhookTransport::new(
            "webhook",
            Box::new(PosterHandle(poster)),
            Box::new(MemorySecretStore::new()),
        ))],
    )
    .expect("router");
    router.raise_alert(&alert(1_000)).expect("raise");
    let dead = router.dead_letters().expect("dead letters");
    assert_eq!(dead.len(), 1);
    assert!(dead[0].last_error.contains("webhook/missing"), "{dead:?}");
    assert!(!dead[0].last_error.contains("hook-secret-value"));
}

/// `Arc<RecordingPoster>` is not `Box<dyn HttpPoster>` on its own; this wrapper
/// keeps the poster inspectable from the test after the transport took it.
#[derive(Debug)]
struct PosterHandle(Arc<RecordingPoster>);

impl HttpPoster for PosterHandle {
    fn post(&self, request: &WebhookRequest) -> Result<u16, String> {
        self.0.post(request)
    }
}

// ─── Routing by severity, site, role and on-call schedule ───────────────────

#[test]
fn routing_honours_severity_site_and_the_on_call_rotation() {
    let recorder = Arc::new(Recorder::default());
    let on_call = OnCallSchedule::new(vec![
        Rotation {
            role: "cold-chain".to_string(),
            level: 1,
            start_est: 0,
            period_secs: 3_600,
            members: vec!["ana@example.com".to_string()],
        },
        Rotation {
            role: "cold-chain".to_string(),
            level: 1,
            start_est: 0,
            period_secs: 3_600,
            members: vec!["ana@example.com".to_string()],
        },
    ]);
    assert!(on_call.is_err(), "duplicate rotations are ambiguous");

    let on_call = OnCallSchedule::new(vec![Rotation {
        role: "cold-chain".to_string(),
        level: 1,
        start_est: 0,
        period_secs: 3_600,
        members: vec!["ana@example.com".to_string(), "bo@example.com".to_string()],
    }])
    .expect("schedule");
    let routing = RoutingTable::new(
        vec![
            RouteRule::new("console-all", Severity::Warning, "cold-chain", "console"),
            RouteRule::new("email-site-1", Severity::Warning, "cold-chain", "email")
                .for_site("site-1"),
        ],
        channels(),
        on_call,
    )
    .expect("routing");
    let router = AlertRouter::with_default_retry(
        AlertStore::open_in_memory().expect("store"),
        routing,
        vec![
            Box::new(FakeTransport {
                channel: "email".to_string(),
                recorder: recorder.clone(),
                script: Arc::new(Script::default()),
            }),
            Box::new(FakeTransport {
                channel: "console".to_string(),
                recorder: recorder.clone(),
                script: Arc::new(Script::default()),
            }),
        ],
    )
    .expect("router");

    // site-1 uses the site rule only: email to whoever is on call at 4_000.
    router.raise_alert(&alert(4_000)).expect("raise");
    let pages = recorder.attempts();
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].0, "email");
    assert_eq!(pages[0].1, "bo@example.com", "rotation slot at t=4000");

    // Another site falls back to the global console rule.
    let elsewhere = Alert::critical("alert-2", "excursion", "tenant-a", "site-2", "warm")
        .with_dedup_key("dedup-2")
        .observed_at(4_100);
    router.raise_alert(&elsewhere).expect("raise");
    let pages = recorder.attempts();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[1].0, "console");
    assert_eq!(pages[1].1, "-");

    // Below the rule's minimum severity nothing is paged, but the alert is still
    // recorded and visible.
    let informational = Alert::new(
        "alert-3",
        "excursion",
        Severity::Info,
        "tenant-a",
        "site-1",
        "fyi",
    )
    .with_dedup_key("dedup-3")
    .observed_at(4_200);
    let outcome = router.raise_alert(&informational).expect("raise");
    assert!(
        matches!(outcome, RaiseOutcome::Unrouted { .. }),
        "{outcome:?}"
    );
    assert_eq!(recorder.attempt_count(), 2);
    let audit = router.audit("alert-3").expect("audit");
    assert!(audit.iter().any(|entry| entry.kind == "unrouted"));
    assert!(router
        .open_alerts("tenant-a")
        .expect("open")
        .iter()
        .any(|record| record.alert_id == "alert-3"));
}

// ─── The console connector, and the CC-11 bridge ────────────────────────────

#[derive(Debug, Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedBuffer {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_console_connector_receives_a_page_raised_from_a_cc11_notification() {
    let buffer = SharedBuffer::default();
    let sink = tirbase_notify::console::ConsoleSink::new("console", buffer.clone());
    let routing = RoutingTable::new(
        vec![RouteRule::new(
            "excursion",
            Severity::Warning,
            "cold-chain",
            "console",
        )],
        vec![ChannelConfig {
            name: "console".to_string(),
            kind: ConnectorKind::Console,
            endpoint: "-".to_string(),
            secret_ref: None,
        }],
        schedule(1),
    )
    .expect("routing");
    let router = AlertRouter::with_default_retry(
        AlertStore::open_in_memory().expect("store"),
        routing,
        vec![Box::new(sink)],
    )
    .expect("router");

    let notification = ExcursionNotification {
        notification_id: "notif-1".to_string(),
        record_id: "rec-1".to_string(),
        channel: "pager".to_string(),
        event: NotificationEvent::QuarantineOpened,
        tenant: "tenant-a".to_string(),
        site_id: "site-1".to_string(),
        reasons: vec!["temperature_out_of_band".to_string()],
        mkt_c: None,
        opened_est: 1_000,
        enqueued_est: 1_010,
    };
    let alert = Alert::from_excursion(&notification, Severity::Critical);
    router.raise_alert(&alert).expect("raise");
    router.raise_alert(&alert).expect("raise again");

    let written = String::from_utf8(buffer.0.lock().unwrap().clone()).expect("utf8");
    assert_eq!(written.lines().count(), 1, "one page, not two: {written:?}");
    assert!(written.contains("CRITICAL"), "{written}");
    assert!(written.contains("site-1"), "{written}");
    assert!(written.contains("notif-1"), "{written}");
    assert!(
        written.contains("cold room") || written.contains("excursion"),
        "{written}"
    );
}

// ─── Configuration ─────────────────────────────────────────────────────────

#[test]
fn the_documented_configuration_builds_a_router_and_refuses_inline_secrets() {
    let document = r#"
[alerts]
secrets_dir = "/etc/tirbase/secrets"

[[alerts.channels]]
name = "console"
kind = "console"
endpoint = "-"

[[alerts.routes]]
rule_id = "excursion"
min_severity = "warning"
roles = ["cold-chain"]
channels = ["console"]
ack_required = true
escalate_after_secs = 600
max_level = 2

[[alerts.on_call]]
role = "cold-chain"
level = 1
start_est = 0
period_secs = 86400
members = ["ana@example.com"]

[[alerts.on_call]]
role = "cold-chain"
level = 2
start_est = 0
period_secs = 86400
members = ["lead@example.com"]
"#;
    let config = AlertsConfig::from_toml(document).expect("config");
    let routing = config.routing().expect("routing");
    let recorder = Arc::new(Recorder::default());
    let router = AlertRouter::new(
        AlertStore::open_in_memory().expect("store"),
        routing,
        vec![Box::new(FakeTransport {
            channel: "console".to_string(),
            recorder: recorder.clone(),
            script: Arc::new(Script::default()),
        })],
        config.retry_policy().expect("retry"),
    )
    .expect("router");
    router.raise_alert(&alert(1_000)).expect("raise");
    assert_eq!(recorder.attempt_count(), 1);
    assert_eq!(router.run_due(1_600).expect("run").escalated, 1);

    let inline = document.replace(
        "kind = \"console\"",
        "kind = \"console\"\nsecret = \"hunter2\"",
    );
    let error = AlertsConfig::from_toml(&inline).expect_err("inline secret");
    assert!(error.to_string().contains("unknown field"), "{error}");
}
