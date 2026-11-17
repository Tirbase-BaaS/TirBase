// SPDX-License-Identifier: Apache-2.0

//! End-to-end behaviour of the integration framework against the mock vendor.
//!
//! These tests exercise the three "done when" conditions directly:
//!
//! - a connector is built, certified and delivered through this crate alone (no
//!   AGPL dependency, proved separately in `agpl_free.rs`);
//! - replaying an event never creates a second downstream record;
//! - the mock harness certifies a good connector and refuses a careless one.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tirbase_integrations::auth::{ApiKey, Auth, HmacWebhook, MutualTls, OAuth2Client};
use tirbase_integrations::conformance::certify;
use tirbase_integrations::connector::{
    Connector, ConnectorCapabilities, ConnectorHealth, ConnectorKind, DeliveryOutcome,
    DeliveryRequest, DeliveryResult, IntegrationEvent,
};
use tirbase_integrations::connectors::{CsvConnector, HttpConnector, HttpConnectorConfig};
use tirbase_integrations::connectors::{
    MqttConnector, MqttPublish, MqttTransport, MqttTransportError, SftpConnector, SftpPut,
    SftpSession, SftpTransportError, WebhookConnector, WebhookConnectorConfig,
};
use tirbase_integrations::engine::{DeliveryEngine, EngineError, FlushReport};
use tirbase_integrations::mapping::Mapping;
use tirbase_integrations::mock::{MockVendorConfig, MockVendorServer};
use tirbase_integrations::observability::HealthStatus;
use tirbase_integrations::outbox::SubmitOutcome;
use tirbase_integrations::retry::RetryPolicy;

fn event(id: &str, payload: serde_json::Value) -> IntegrationEvent {
    IntegrationEvent::new(id, "reading.recorded", "acme", 1_000, payload)
}

const MAPPING: &str = r#"
schema_version = 1

[[field]]
target = "device.serial"
source = "payload.serial"
required = true
transform = "trim"

[[field]]
target = "value_c"
source = "payload.temperature_c"
"#;

#[test]
fn http_connector_delivers_maps_and_never_duplicates_on_replay() {
    let mock =
        MockVendorServer::start(MockVendorConfig::default().with_api_key("x-api-key", "k-1"))
            .expect("mock vendor");

    let config = HttpConnectorConfig::new("vendor-http", mock.events_url())
        .with_auth(Auth::ApiKey(ApiKey::new("x-api-key", "k-1").expect("key")));
    let connector = HttpConnector::with_default_client(
        config,
        Some(Mapping::from_toml(MAPPING).expect("mapping")),
    )
    .expect("connector");
    let mut engine =
        DeliveryEngine::new(Box::new(connector)).with_retry_policy(RetryPolicy::new(3, 1, 2, 10));

    let first = event(
        "e-1",
        serde_json::json!({ "serial": " SN-9 ", "temperature_c": 21.5 }),
    );
    assert_eq!(
        engine.submit(&first, 100).expect("submit"),
        SubmitOutcome::Queued(1)
    );
    assert_eq!(
        engine.flush(100),
        FlushReport {
            attempted: 1,
            delivered: 1,
            duplicates: 0,
            retried: 0,
            dead_lettered: 0,
        }
    );

    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/api/events");
    assert_eq!(requests[0].header("x-api-key"), Some("k-1"));
    assert_eq!(
        requests[0].header("idempotency-key"),
        Some(first.idempotency_key("vendor-http").as_str())
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&requests[0].body).expect("json body"),
        serde_json::json!({ "device": { "serial": "SN-9" }, "value_c": 21.5 })
    );
    assert_eq!(mock.record_count(), 1);

    // Submitting the same event again is a no-op, not a second delivery.
    assert_eq!(
        engine.submit(&first, 110).expect("submit"),
        SubmitOutcome::AlreadyDelivered(1)
    );
    assert_eq!(engine.flush(110).attempted, 0);
    assert_eq!(mock.record_count(), 1);
    assert_eq!(mock.requests().len(), 1);

    // A fresh event is delivered normally.
    let second = event(
        "e-2",
        serde_json::json!({ "serial": "SN-10", "temperature_c": 22 }),
    );
    engine.submit(&second, 120).expect("submit");
    assert_eq!(engine.flush(120).delivered, 1);
    assert_eq!(mock.record_count(), 2);
    assert_eq!(engine.health().status, HealthStatus::Ok);
    assert_eq!(engine.health_response().status_code, 200);
}

#[test]
fn retries_back_off_then_deliver_once() {
    let mock = MockVendorServer::start(MockVendorConfig::default().with_fail_first(2))
        .expect("mock vendor");
    let connector = HttpConnector::with_default_client(
        HttpConnectorConfig::new("retry-http", mock.events_url()),
        None,
    )
    .expect("connector");
    let mut engine =
        DeliveryEngine::new(Box::new(connector)).with_retry_policy(RetryPolicy::new(3, 10, 2, 60));

    let event = event("e-retry", serde_json::json!({ "value": 1 }));
    engine.submit(&event, 100).expect("submit");

    let first = engine.flush(100);
    assert_eq!((first.attempted, first.retried, first.delivered), (1, 1, 0));
    // Nothing is due before the backoff elapses.
    assert_eq!(engine.flush(109).attempted, 0);
    let second = engine.flush(110);
    assert_eq!(
        (second.attempted, second.retried, second.delivered),
        (1, 1, 0)
    );
    let third = engine.flush(130);
    assert_eq!(
        (third.attempted, third.delivered, third.dead_lettered),
        (1, 1, 0)
    );

    let metrics = engine.metrics();
    assert_eq!(metrics.attempts, 3);
    assert_eq!(metrics.retries, 2);
    assert_eq!(metrics.delivered, 1);
    assert_eq!(metrics.dead_letters, 0);
    assert_eq!(mock.record_count(), 1);
    assert_eq!(mock.requests().len(), 3);
    let record = engine.outbox().record(1).expect("record");
    assert_eq!(record.attempts, 3);
}

#[test]
fn dead_letter_replay_delivers_once_and_is_then_refused() {
    let mock = MockVendorServer::start(MockVendorConfig::default().with_fail_first(10))
        .expect("mock vendor");
    let connector = HttpConnector::with_default_client(
        HttpConnectorConfig::new("dlq-http", mock.events_url()),
        None,
    )
    .expect("connector");
    let mut engine =
        DeliveryEngine::new(Box::new(connector)).with_retry_policy(RetryPolicy::new(2, 5, 2, 30));

    let event = event("e-dlq", serde_json::json!({ "value": 7 }));
    let key = event.idempotency_key("dlq-http");
    engine.submit(&event, 100).expect("submit");
    engine.flush(100);
    let exhausted = engine.flush(110);
    assert_eq!(exhausted.dead_lettered, 1);
    assert_eq!(engine.outbox().dead_letters().len(), 1);
    assert_eq!(engine.health().status, HealthStatus::Unhealthy);
    assert_eq!(engine.health_response().status_code, 503);
    assert_eq!(mock.record_count(), 0);

    let dlq_id = engine.outbox().dead_letters()[0].dlq_id.clone();
    mock.clear_failures();
    let seq = engine.replay(&dlq_id, 200).expect("replay");
    assert_eq!(engine.flush(200).delivered, 1);
    assert_eq!(mock.record_count(), 1);
    assert!(mock.has_record(&key));

    // The event is settled; replaying again must not create a second record.
    assert!(matches!(
        engine.replay(&dlq_id, 210),
        Err(EngineError::AlreadyDelivered(_))
    ));
    assert_eq!(engine.flush(210).attempted, 0);
    assert_eq!(mock.record_count(), 1);
    assert_eq!(engine.metrics().replays, 1);
    assert_eq!(
        engine
            .outbox()
            .dead_letter(&dlq_id)
            .expect("letter")
            .replay_count,
        1
    );
    assert_eq!(engine.health().status, HealthStatus::Ok);
    let _ = seq;
}

#[test]
fn replay_of_a_live_record_is_deduplicated_by_the_outbox() {
    let mock = MockVendorServer::start(MockVendorConfig::default()).expect("mock vendor");
    let connector = HttpConnector::with_default_client(
        HttpConnectorConfig::new("dedupe-http", mock.events_url()),
        None,
    )
    .expect("connector");
    let mut engine = DeliveryEngine::new(Box::new(connector));
    let event = event("e-live", serde_json::json!({ "value": 1 }));
    engine.submit(&event, 100).expect("submit");
    assert_eq!(engine.flush(100).delivered, 1);
    assert_eq!(
        engine.submit(&event, 101).expect("submit"),
        SubmitOutcome::AlreadyDelivered(1)
    );
    assert_eq!(engine.outbox().records().len(), 1);
    assert_eq!(mock.record_count(), 1);
}

#[test]
fn webhook_signature_is_accepted_and_a_tampered_one_is_permanent() {
    let mock = MockVendorServer::start(MockVendorConfig::default().with_hmac_secret("whsec"))
        .expect("mock vendor");
    let signing = HmacWebhook::new("whsec");
    let connector = WebhookConnector::with_default_client(
        WebhookConnectorConfig::new("vendor-hook", mock.webhook_url()),
        signing,
        None,
    )
    .expect("connector");
    let mut engine = DeliveryEngine::new(Box::new(connector));

    let reading = event("e-hook", serde_json::json!({ "value": 3 }));
    engine.submit(&reading, 100).expect("submit");
    assert_eq!(engine.flush(100).delivered, 1);
    assert_eq!(mock.record_count(), 1);
    let request = &mock.requests()[0];
    assert!(request
        .header("x-tirbase-signature")
        .expect("signature header")
        .starts_with("sha256="));
    assert_eq!(request.header("x-tirbase-timestamp"), Some("100"));

    // Same key again: the vendor recognises the duplicate.
    let duplicate = DeliveryRequest::new(&reading, "vendor-hook", 2, 101);
    assert_eq!(
        engine.connector().deliver(&duplicate).outcome,
        DeliveryOutcome::Duplicate
    );
    assert_eq!(mock.record_count(), 1);

    // A connector signing with the wrong secret is rejected outright.
    let forged = WebhookConnector::with_default_client(
        WebhookConnectorConfig::new("vendor-hook", mock.webhook_url()),
        HmacWebhook::new("wrong-secret"),
        None,
    )
    .expect("connector");
    let result = forged.deliver(&DeliveryRequest::new(
        &event("e-forged", serde_json::json!({ "value": 4 })),
        "vendor-hook",
        1,
        102,
    ));
    assert_eq!(result.outcome, DeliveryOutcome::Permanent);
    assert_eq!(mock.record_count(), 1);
}

#[test]
fn oauth2_client_credentials_are_cached_and_wrong_secrets_fail_closed() {
    let mock =
        MockVendorServer::start(MockVendorConfig::default().with_oauth_client("cid", "csecret"))
            .expect("mock vendor");
    let token_url = format!("{}/oauth/token", mock.base_url());
    let token = OAuth2Client::with_default_client(
        token_url.clone(),
        "cid",
        "csecret",
        Some("events write".to_string()),
    )
    .expect("oauth client");
    let config = HttpConnectorConfig::new("vendor-oauth", mock.events_url())
        .with_auth(Auth::OAuth2(Arc::new(token)));
    let connector = HttpConnector::with_default_client(config, None).expect("connector");
    let mut engine = DeliveryEngine::new(Box::new(connector));

    engine
        .submit(&event("e-o1", serde_json::json!({ "v": 1 })), 100)
        .expect("submit");
    engine
        .submit(&event("e-o2", serde_json::json!({ "v": 2 })), 200)
        .expect("submit");
    assert_eq!(engine.flush(200).delivered, 2);
    assert_eq!(mock.record_count(), 2);
    assert_eq!(mock.requests_for("/oauth/token").len(), 1);
    assert_eq!(
        mock.requests_for("/api/events")[0].header("authorization"),
        Some("Bearer mock-token-cid")
    );

    let bad_token =
        OAuth2Client::with_default_client(token_url, "cid", "wrong", None).expect("oauth client");
    let bad = HttpConnector::with_default_client(
        HttpConnectorConfig::new("vendor-oauth-bad", mock.events_url())
            .with_auth(Auth::OAuth2(Arc::new(bad_token))),
        None,
    )
    .expect("connector");
    let result = bad.deliver(&DeliveryRequest::new(
        &event("e-o3", serde_json::json!({ "v": 3 })),
        "vendor-oauth-bad",
        1,
        300,
    ));
    assert_eq!(result.outcome, DeliveryOutcome::Permanent);
    assert!(result.detail.contains("401"), "{}", result.detail);
    assert_eq!(mock.record_count(), 2);
}

#[test]
fn api_key_mismatch_and_bad_mtls_material_fail_closed() {
    let mock =
        MockVendorServer::start(MockVendorConfig::default().with_api_key("x-api-key", "right"))
            .expect("mock vendor");
    let connector = HttpConnector::with_default_client(
        HttpConnectorConfig::new("vendor-key", mock.events_url()).with_auth(Auth::ApiKey(
            ApiKey::new("x-api-key", "wrong").expect("key"),
        )),
        None,
    )
    .expect("connector");
    let result = connector.deliver(&DeliveryRequest::new(
        &event("e-key", serde_json::json!({})),
        "vendor-key",
        1,
        100,
    ));
    assert_eq!(result.outcome, DeliveryOutcome::Permanent);
    assert_eq!(mock.record_count(), 0);
    assert_eq!(mock.requests().len(), 1);

    let bad_material = MutualTls::new(
        b"not a certificate".to_vec(),
        b"not a cert".to_vec(),
        b"not a key".to_vec(),
    );
    assert!(bad_material
        .client_builder(std::time::Duration::from_secs(5))
        .is_err());
    assert!(!format!("{bad_material:?}").contains("not a key"));
}

#[test]
fn csv_connector_writes_one_row_per_event_and_is_idempotent() {
    let directory = tempfile::tempdir().expect("tempdir");
    let drop_dir = directory.path().join("drop");
    let connector = CsvConnector::new(
        "csv-drop",
        drop_dir.clone(),
        vec![
            "event_id".to_string(),
            "value".to_string(),
            "note".to_string(),
        ],
    )
    .expect("connector");
    let mut engine = DeliveryEngine::new(Box::new(connector));

    let first = event(
        "e-csv-1",
        serde_json::json!({ "value": 3.5, "note": "a,b" }),
    );
    engine.submit(&first, 100).expect("submit");
    assert_eq!(engine.flush(100).delivered, 1);

    let key = first.idempotency_key("csv-drop");
    let path = drop_dir.join(format!("{key}.csv"));
    let contents = std::fs::read_to_string(&path).expect("row file");
    assert_eq!(contents, "event_id,value,note\ne-csv-1,3.5,\"a,b\"\n");

    let duplicate = DeliveryRequest::new(&first, "csv-drop", 2, 101);
    assert_eq!(
        engine.connector().deliver(&duplicate).outcome,
        DeliveryOutcome::Duplicate
    );
    assert_eq!(std::fs::read_to_string(&path).expect("row file"), contents);

    engine
        .submit(&event("e-csv-2", serde_json::json!({ "value": 4 })), 102)
        .expect("submit");
    assert_eq!(engine.flush(102).delivered, 1);
    assert_eq!(std::fs::read_dir(&drop_dir).expect("dir").count(), 2);
    assert!(engine.health().status == HealthStatus::Ok);
}

#[derive(Default)]
struct RecordingBroker {
    seen: Arc<Mutex<BTreeMap<String, usize>>>,
}

impl MqttTransport for RecordingBroker {
    fn publish(
        &self,
        topic: &str,
        payload: &[u8],
        qos: u8,
        _retain: bool,
    ) -> Result<MqttPublish, MqttTransportError> {
        if topic != "plant/acme/readings" {
            return Err(MqttTransportError::permanent(format!(
                "unexpected topic {topic}"
            )));
        }
        if qos != 1 {
            return Err(MqttTransportError::permanent("expected QoS 1"));
        }
        let message: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|error| MqttTransportError::permanent(error.to_string()))?;
        let key = message["idempotency_key"]
            .as_str()
            .ok_or_else(|| MqttTransportError::permanent("missing idempotency key"))?
            .to_string();
        let mut seen = self.seen.lock().expect("broker lock");
        let count = seen.entry(key).or_insert(0);
        *count += 1;
        Ok(MqttPublish {
            duplicate: *count > 1,
            packet_id: 9,
        })
    }
}

#[test]
fn mqtt_connector_publishes_an_envelope_and_detects_duplicates() {
    let broker = RecordingBroker::default();
    let seen = Arc::clone(&broker.seen);
    let connector = MqttConnector::new("mqtt-plant", "plant/acme/readings", 1, broker)
        .expect("connector")
        .with_retain(true);
    let mut engine = DeliveryEngine::new(Box::new(connector));

    let event = event("e-mqtt", serde_json::json!({ "value": 9 }));
    engine.submit(&event, 100).expect("submit");
    assert_eq!(engine.flush(100).delivered, 1);
    let duplicate = DeliveryRequest::new(&event, "mqtt-plant", 2, 101);
    assert_eq!(
        engine.connector().deliver(&duplicate).outcome,
        DeliveryOutcome::Duplicate
    );
    assert_eq!(seen.lock().expect("seen").values().sum::<usize>(), 2);
    let key = seen
        .lock()
        .expect("seen")
        .keys()
        .next()
        .expect("key")
        .clone();
    assert!(key.starts_with("tbi-"), "{key}");
    assert_eq!(key.len(), 36);
}

struct MemorySftp {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl SftpSession for MemorySftp {
    fn put_if_absent(&self, path: &str, bytes: &[u8]) -> Result<SftpPut, SftpTransportError> {
        let mut files = self.files.lock().expect("files");
        if files.contains_key(path) {
            return Ok(SftpPut::AlreadyPresent);
        }
        files.insert(path.to_string(), bytes.to_vec());
        Ok(SftpPut::Created)
    }
}

#[test]
fn sftp_connector_puts_a_file_once_per_event() {
    let files = Arc::new(Mutex::new(BTreeMap::new()));
    let connector = SftpConnector::new(
        "sftp-drop",
        "/inbound/tirbase",
        MemorySftp {
            files: Arc::clone(&files),
        },
    )
    .expect("connector");
    let mut engine = DeliveryEngine::new(Box::new(connector));
    let event = event("e-sftp", serde_json::json!({ "value": 1 }));
    let key = event.idempotency_key("sftp-drop");
    engine.submit(&event, 100).expect("submit");
    assert_eq!(engine.flush(100).delivered, 1);

    let files = files.lock().expect("files");
    assert_eq!(files.len(), 1);
    let (path, bytes) = files.iter().next().expect("file");
    assert_eq!(path, &format!("/inbound/tirbase/{key}.json"));
    let document: serde_json::Value = serde_json::from_slice(bytes).expect("json");
    assert_eq!(document["event_id"], "e-sftp");
    drop(files);

    let duplicate = DeliveryRequest::new(&event, "sftp-drop", 2, 101);
    assert_eq!(
        engine.connector().deliver(&duplicate).outcome,
        DeliveryOutcome::Duplicate
    );

    let traversal = SftpConnector::new(
        "sftp-bad",
        "/inbound/../etc",
        MemorySftp {
            files: Arc::new(Mutex::new(BTreeMap::new())),
        },
    );
    assert!(traversal.is_err());
}

/// A connector that reports success for everything: the harness must reject it.
struct CarelessConnector;

impl Connector for CarelessConnector {
    fn name(&self) -> &str {
        "careless"
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Http
    }

    fn capabilities(&self) -> ConnectorCapabilities {
        ConnectorCapabilities::default()
    }

    fn deliver(&self, _request: &DeliveryRequest) -> DeliveryResult {
        DeliveryResult::delivered("trust me")
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy("claims to be healthy")
    }
}

#[test]
fn mock_harness_certifies_a_real_connector_and_rejects_a_careless_one() {
    let mock = MockVendorServer::start(MockVendorConfig::default()).expect("mock vendor");
    let connector = HttpConnector::with_default_client(
        HttpConnectorConfig::new("certified-http", mock.events_url()),
        None,
    )
    .expect("connector");
    let report = certify(&connector, 1_000);
    assert!(report.certified, "{}", report.summary());
    assert!(report.checks.len() >= 8);
    assert!(report
        .checks
        .iter()
        .any(|check| check.name == "duplicate" && check.passed));
    assert_eq!(report.to_json()["certified"], true);
    // The suite's duplicate probe hit the same downstream record, not a new one.
    assert_eq!(mock.record_count(), 2);

    let rejected = certify(&CarelessConnector, 1_000);
    assert!(!rejected.certified);
    assert!(rejected.summary().contains("not certified"));
    let failed: Vec<&str> = rejected
        .failures()
        .iter()
        .map(|check| check.name.as_str())
        .collect();
    assert!(failed.contains(&"duplicate"), "{failed:?}");
    assert!(failed.contains(&"oversized-payload"), "{failed:?}");
}

#[test]
fn logs_are_redacted_and_health_tracks_pending_and_dead_letters() {
    let secret = "super-secret-api-key";
    let mock =
        MockVendorServer::start(MockVendorConfig::default().with_api_key("x-api-key", secret))
            .expect("mock vendor");
    let connector = HttpConnector::with_default_client(
        HttpConnectorConfig::new("observed-http", mock.events_url())
            .with_auth(Auth::ApiKey(ApiKey::new("x-api-key", secret).expect("key"))),
        None,
    )
    .expect("connector");
    let mut engine =
        DeliveryEngine::new(Box::new(connector)).with_retry_policy(RetryPolicy::new(1, 1, 1, 1));

    engine
        .submit(&event("e-obs-1", serde_json::json!({ "value": 1 })), 100)
        .expect("submit");
    assert_eq!(engine.flush(100).delivered, 1);
    assert_eq!(engine.logs().len(), 1);
    assert_eq!(engine.logs()[0].outcome, DeliveryOutcome::Delivered);
    let rendered = format!("{:?}", engine.logs());
    assert!(!rendered.contains(secret), "log leaked the API key");
    assert!(engine.logs()[0].detail.contains("201"));
    assert_eq!(engine.health().status, HealthStatus::Ok);

    // Inject a failure: the record is retried, then dead-lettered, and health
    // degrades then fails.
    mock.set_failures(100);
    engine
        .submit(&event("e-obs-2", serde_json::json!({ "value": 2 })), 200)
        .expect("submit");
    assert_eq!(engine.flush(200).dead_lettered, 1);
    let health = engine.health();
    assert_eq!(health.status, HealthStatus::Unhealthy);
    assert_eq!(health.dead_letters, 1);
    assert_eq!(engine.health_response().status_code, 503);
    assert!(engine.metrics().dead_letters >= 1);
    assert!(!format!("{:?}", engine.metrics()).contains(secret));
}
