// SPDX-License-Identifier: Apache-2.0

//! Redacted structured logs, metrics and the health document.
//!
//! Logs are records, not format strings: the engine emits one per delivery
//! attempt with the connector, event id, attempt and outcome, and the detail is
//! truncated and stripped of credential-shaped text. Payloads are never logged.
//! [`redact_value`] masks secret-named keys in any structured field.

use serde::{Deserialize, Serialize};

use crate::connector::{ConnectorKind, DeliveryOutcome};

/// Replacement text for a redacted value.
pub const REDACTED: &str = "***";

/// Most log records the engine retains for inspection.
pub const MAX_RETAINED_LOGS: usize = 512;

/// Longest detail kept on one log record.
pub const MAX_DETAIL_LEN: usize = 240;

/// Health states a connector can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Delivering, nothing outstanding.
    Ok,
    /// Ready, but with pending or retrying work.
    Degraded,
    /// Not delivering; dead letters or an unhealthy connector.
    Unhealthy,
}

impl HealthStatus {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            HealthStatus::Ok => "ok",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        }
    }

    /// HTTP status a health endpoint answers with.
    pub fn status_code(self) -> u16 {
        match self {
            HealthStatus::Ok | HealthStatus::Degraded => 200,
            HealthStatus::Unhealthy => 503,
        }
    }
}

/// Whether a field name denotes a credential-shaped value.
pub fn sensitive_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    const MARKERS: [&str; 12] = [
        "secret",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "credential",
        "private_key",
        "client_secret",
        "signature",
        "hmac",
    ];
    MARKERS.iter().any(|marker| lowered.contains(marker))
}

/// Recursively mask secret-named keys in a JSON value.
pub fn redact_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(object) => {
            let mut redacted = serde_json::Map::new();
            for (key, nested) in object {
                if sensitive_key(key) {
                    redacted.insert(key.clone(), serde_json::Value::String(REDACTED.to_string()));
                } else {
                    redacted.insert(key.clone(), redact_value(nested));
                }
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(redact_value).collect())
        }
        other => other.clone(),
    }
}

/// Strip credential-shaped text and truncate to [`MAX_DETAIL_LEN`].
///
/// Whitespace is normalised, which is fine for a log detail. `Bearer <token>`
/// drops the token, and any `key=value` field whose key looks secret has its
/// value replaced with `***`, including the value that follows a sensitive key
/// ending in `=Bearer`.
pub fn sanitize_detail(detail: &str) -> String {
    let mut sanitized = String::with_capacity(detail.len());
    let mut mask_next = false;
    for (index, token) in detail.split_whitespace().enumerate() {
        if index > 0 {
            sanitized.push(' ');
        }
        if mask_next {
            sanitized.push_str(REDACTED);
            mask_next = false;
            continue;
        }
        if token.eq_ignore_ascii_case("bearer") {
            sanitized.push_str(token);
            mask_next = true;
            continue;
        }
        for (position, part) in token.split(['&', ';']).enumerate() {
            if position > 0 {
                sanitized.push('&');
            }
            match part.split_once('=') {
                Some((key, value)) if sensitive_key(key) => {
                    sanitized.push_str(key);
                    sanitized.push('=');
                    sanitized.push_str(REDACTED);
                    if value.eq_ignore_ascii_case("bearer") {
                        mask_next = true;
                    }
                }
                _ => sanitized.push_str(part),
            }
        }
    }
    if sanitized.len() <= MAX_DETAIL_LEN {
        return sanitized;
    }
    let mut end = MAX_DETAIL_LEN;
    while !sanitized.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &sanitized[..end])
}

/// One structured log record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// When the attempt happened.
    pub at_est: i64,
    /// Connector name.
    pub connector: String,
    /// Event id.
    pub event_id: String,
    /// 1-based attempt number.
    pub attempt: u32,
    /// Outcome of the attempt.
    pub outcome: DeliveryOutcome,
    /// Redacted detail.
    pub detail: String,
}

impl LogRecord {
    /// Build a record, sanitising the detail.
    pub fn new(
        at_est: i64,
        connector: impl Into<String>,
        event_id: impl Into<String>,
        attempt: u32,
        outcome: DeliveryOutcome,
        detail: impl AsRef<str>,
    ) -> Self {
        Self {
            at_est,
            connector: connector.into(),
            event_id: event_id.into(),
            attempt,
            outcome,
            detail: sanitize_detail(detail.as_ref()),
        }
    }

    /// Structured JSON form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "at_est": self.at_est,
            "connector": self.connector,
            "event_id": self.event_id,
            "attempt": self.attempt,
            "outcome": self.outcome.as_str(),
            "detail": self.detail,
        })
    }
}

/// A sink a host can plug in (journald, tracing, a file).
pub trait LogSink {
    /// Receive one record.
    fn record(&mut self, record: &LogRecord);
}

/// Counters for one connector.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Delivery attempts made.
    pub attempts: u64,
    /// Events the downstream accepted.
    pub delivered: u64,
    /// Attempts the downstream recognised as duplicates.
    pub duplicates: u64,
    /// Attempts classified retryable.
    pub retries: u64,
    /// Records moved to the dead-letter queue.
    pub dead_letters: u64,
    /// Dead letters re-enqueued for replay.
    pub replays: u64,
}

/// Metric counters.
#[derive(Debug, Default)]
pub struct Metrics {
    snapshot: MetricsSnapshot,
}

impl Metrics {
    /// Record one attempt outcome.
    pub fn record_attempt(&mut self, outcome: DeliveryOutcome) {
        self.snapshot.attempts = self.snapshot.attempts.saturating_add(1);
        match outcome {
            DeliveryOutcome::Delivered => {
                self.snapshot.delivered = self.snapshot.delivered.saturating_add(1);
            }
            DeliveryOutcome::Duplicate => {
                self.snapshot.duplicates = self.snapshot.duplicates.saturating_add(1);
            }
            DeliveryOutcome::Retryable => {
                self.snapshot.retries = self.snapshot.retries.saturating_add(1);
            }
            DeliveryOutcome::Permanent => {}
        }
    }

    /// Record a dead-letter move.
    pub fn record_dead_letter(&mut self) {
        self.snapshot.dead_letters = self.snapshot.dead_letters.saturating_add(1);
    }

    /// Record a replay enqueue.
    pub fn record_replay(&mut self) {
        self.snapshot.replays = self.snapshot.replays.saturating_add(1);
    }

    /// Current counters.
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.snapshot
    }
}

/// Health of one delivery engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSnapshot {
    /// Overall status.
    pub status: HealthStatus,
    /// Connector name.
    pub connector: String,
    /// Connector family.
    pub kind: ConnectorKind,
    /// Connector readiness detail.
    pub detail: String,
    /// Records awaiting delivery.
    pub pending: usize,
    /// Dead letters that have not been replayed successfully.
    pub dead_letters: usize,
    /// When the last event was accepted, if ever.
    pub last_delivery_est: Option<i64>,
    /// Counters.
    pub metrics: MetricsSnapshot,
}

impl HealthSnapshot {
    /// Structured JSON form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status.as_str(),
            "connector": self.connector,
            "kind": self.kind.as_str(),
            "detail": self.detail,
            "pending": self.pending,
            "dead_letters": self.dead_letters,
            "last_delivery_est": self.last_delivery_est,
            "metrics": self.metrics,
        })
    }
}

/// A health endpoint answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Status code the endpoint should return.
    pub status_code: u16,
    /// JSON body.
    pub body: String,
}

impl HealthSnapshot {
    /// Render the HTTP health endpoint answer.
    pub fn response(&self) -> HealthResponse {
        HealthResponse {
            status_code: self.status.status_code(),
            body: self.to_json().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_masks_secret_named_keys_recursively() {
        let value = serde_json::json!({
            "endpoint": "https://vendor.example/api",
            "auth": {
                "api_key": "k-123",
                "password": "hunter2",
                "token": "tok",
                "client_secret": "cs",
                "timeout": 30
            },
            "items": [{ "signature": "abc", "name": "ok" }]
        });
        let redacted = redact_value(&value);
        let text = redacted.to_string();
        for secret in ["k-123", "hunter2", "\"tok\"", "cs", "abc"] {
            assert!(!text.contains(secret), "{secret} leaked in {text}");
        }
        assert!(text.contains("https://vendor.example/api"));
        assert!(text.contains("\"timeout\":30"));
        assert!(text.contains("\"name\":\"ok\""));
    }

    #[test]
    fn log_details_are_sanitised_and_truncated() {
        let record = LogRecord::new(
            10,
            "http-vendor",
            "e-1",
            2,
            DeliveryOutcome::Retryable,
            "POST failed: Authorization=Bearer abc123&client_secret=shh",
        );
        assert!(!record.detail.contains("abc123"), "{}", record.detail);
        assert!(!record.detail.contains("shh"), "{}", record.detail);
        let long = LogRecord::new(
            10,
            "http-vendor",
            "e-1",
            1,
            DeliveryOutcome::Delivered,
            "x".repeat(1_000),
        );
        assert!(long.detail.len() <= MAX_DETAIL_LEN + 4);
        assert_eq!(record.to_json()["outcome"], "retryable");
    }

    #[test]
    fn health_status_maps_to_codes() {
        assert_eq!(HealthStatus::Ok.status_code(), 200);
        assert_eq!(HealthStatus::Degraded.status_code(), 200);
        assert_eq!(HealthStatus::Unhealthy.status_code(), 503);
        let snapshot = HealthSnapshot {
            status: HealthStatus::Unhealthy,
            connector: "http-vendor".to_string(),
            kind: ConnectorKind::Http,
            detail: "dead letters present".to_string(),
            pending: 1,
            dead_letters: 1,
            last_delivery_est: None,
            metrics: MetricsSnapshot::default(),
        };
        let response = snapshot.response();
        assert_eq!(response.status_code, 503);
        assert!(response.body.contains("\"status\":\"unhealthy\""));
    }
}
