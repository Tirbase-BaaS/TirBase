// SPDX-License-Identifier: Apache-2.0

//! The connector surface.
//!
//! A vendor connector implements [`Connector`] against this crate only; it never
//! links the AGPL runtime. The engine (`crate::engine`) owns retries, dead
//! letters, replay and metrics so a connector only has to answer one question:
//! what happened when I tried to deliver this event?

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation context for derived idempotency keys.
pub const CONTEXT_IDEMPOTENCY: &str = "TirBase/v1/IntegrationIdempotency";

/// Default payload ceiling a connector must accept (1 MiB).
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Transport family a connector speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    /// HTTP/REST endpoint.
    Http,
    /// Signed webhook endpoint.
    Webhook,
    /// MQTT broker publish.
    Mqtt,
    /// CSV file or batch drop.
    Csv,
    /// SFTP upload.
    Sftp,
}

impl ConnectorKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectorKind::Http => "http",
            ConnectorKind::Webhook => "webhook",
            ConnectorKind::Mqtt => "mqtt",
            ConnectorKind::Csv => "csv",
            ConnectorKind::Sftp => "sftp",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "http" => Some(ConnectorKind::Http),
            "webhook" => Some(ConnectorKind::Webhook),
            "mqtt" => Some(ConnectorKind::Mqtt),
            "csv" => Some(ConnectorKind::Csv),
            "sftp" => Some(ConnectorKind::Sftp),
            _ => None,
        }
    }
}

/// Authentication a connector can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    /// No authentication.
    None,
    /// Static API key header.
    ApiKey,
    /// OAuth2 client-credentials bearer token.
    OAuth2ClientCredentials,
    /// Mutual TLS client certificate.
    MutualTls,
    /// HMAC-SHA256 request signature.
    HmacSignature,
}

impl AuthKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthKind::None => "none",
            AuthKind::ApiKey => "api_key",
            AuthKind::OAuth2ClientCredentials => "oauth2_client_credentials",
            AuthKind::MutualTls => "mutual_tls",
            AuthKind::HmacSignature => "hmac_signature",
        }
    }
}

/// What a connector promises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorCapabilities {
    /// Whether delivering the same idempotency key twice is a duplicate, not a
    /// second downstream record.
    pub idempotent: bool,
    /// Authentication mechanisms the connector can be configured with.
    pub auth: Vec<AuthKind>,
    /// Largest payload the connector accepts, in bytes.
    pub max_payload_bytes: usize,
}

impl Default for ConnectorCapabilities {
    fn default() -> Self {
        Self {
            idempotent: true,
            auth: vec![AuthKind::None],
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }
}

/// One event to deliver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntegrationEvent {
    /// Stable event identifier supplied by the producer.
    pub event_id: String,
    /// Event type (`reading.recorded`, `excursion.opened`, …).
    pub event_type: String,
    /// Tenant the event belongs to.
    pub tenant: String,
    /// When the event happened, in caller-supplied seconds.
    pub occurred_est: i64,
    /// Event body.
    pub payload: serde_json::Value,
}

impl IntegrationEvent {
    /// Build an event.
    pub fn new(
        event_id: impl Into<String>,
        event_type: impl Into<String>,
        tenant: impl Into<String>,
        occurred_est: i64,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            event_type: event_type.into(),
            tenant: tenant.into(),
            occurred_est,
            payload,
        }
    }

    /// Deterministic idempotency key for this event on `connector`.
    ///
    /// Derived from the connector name and the event id, so a retry, a process
    /// restart or a dead-letter replay all present the same key and the
    /// downstream system can recognise the duplicate.
    pub fn idempotency_key(&self, connector: &str) -> String {
        idempotency_key(connector, &self.event_id)
    }

    /// Context a mapping document is applied against: `{event, payload}`.
    pub fn mapping_context(&self) -> serde_json::Value {
        serde_json::json!({
            "event": {
                "event_id": self.event_id,
                "event_type": self.event_type,
                "tenant": self.tenant,
                "occurred_est": self.occurred_est,
            },
            "payload": self.payload,
        })
    }
}

/// Derive the idempotency key for `event_id` on `connector`.
pub fn idempotency_key(connector: &str, event_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_IDEMPOTENCY.as_bytes());
    hasher.update(b"\0");
    hasher.update(connector.as_bytes());
    hasher.update(b"\0");
    hasher.update(event_id.as_bytes());
    let digest: String = hasher
        .finalize()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("tbi-{digest}")
}

/// One delivery attempt handed to a connector.
#[derive(Debug, Clone, PartialEq)]
pub struct DeliveryRequest {
    /// Event identifier.
    pub event_id: String,
    /// Event type.
    pub event_type: String,
    /// Tenant the event belongs to.
    pub tenant: String,
    /// Idempotency key the downstream must dedupe on.
    pub idempotency_key: String,
    /// 1-based attempt number.
    pub attempt: u32,
    /// When the attempt is being made.
    pub now_est: i64,
    /// Event body.
    pub payload: serde_json::Value,
}

impl DeliveryRequest {
    /// Build a request for one event and attempt.
    pub fn new(event: &IntegrationEvent, connector: &str, attempt: u32, now_est: i64) -> Self {
        Self {
            event_id: event.event_id.clone(),
            event_type: event.event_type.clone(),
            tenant: event.tenant.clone(),
            idempotency_key: event.idempotency_key(connector),
            attempt,
            now_est,
            payload: event.payload.clone(),
        }
    }

    /// Mapping context for this request.
    pub fn mapping_context(&self) -> serde_json::Value {
        serde_json::json!({
            "event": {
                "event_id": self.event_id,
                "event_type": self.event_type,
                "tenant": self.tenant,
                "attempt": self.attempt,
                "attempted_est": self.now_est,
            },
            "payload": self.payload,
        })
    }
}

/// What a delivery attempt concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
    /// The downstream accepted the event.
    Delivered,
    /// The downstream already had this idempotency key.
    Duplicate,
    /// A transient failure; retry later.
    Retryable,
    /// A permanent failure; retry would not help.
    Permanent,
}

impl DeliveryOutcome {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryOutcome::Delivered => "delivered",
            DeliveryOutcome::Duplicate => "duplicate",
            DeliveryOutcome::Retryable => "retryable",
            DeliveryOutcome::Permanent => "permanent",
        }
    }

    /// Whether the event is now settled downstream.
    pub fn is_accepted(self) -> bool {
        matches!(
            self,
            DeliveryOutcome::Delivered | DeliveryOutcome::Duplicate
        )
    }
}

/// Result of one delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryResult {
    /// Outcome classification.
    pub outcome: DeliveryOutcome,
    /// Short evidence, safe to log (no secrets, no full payload).
    pub detail: String,
    /// Downstream `Retry-After`, when it supplied one.
    pub retry_after_secs: Option<u64>,
}

impl DeliveryResult {
    /// The downstream accepted the event.
    pub fn delivered(detail: impl Into<String>) -> Self {
        Self {
            outcome: DeliveryOutcome::Delivered,
            detail: detail.into(),
            retry_after_secs: None,
        }
    }

    /// The downstream already had this idempotency key.
    pub fn duplicate(detail: impl Into<String>) -> Self {
        Self {
            outcome: DeliveryOutcome::Duplicate,
            detail: detail.into(),
            retry_after_secs: None,
        }
    }

    /// A transient failure.
    pub fn retryable(detail: impl Into<String>, retry_after_secs: Option<u64>) -> Self {
        Self {
            outcome: DeliveryOutcome::Retryable,
            detail: detail.into(),
            retry_after_secs,
        }
    }

    /// A permanent failure.
    pub fn permanent(detail: impl Into<String>) -> Self {
        Self {
            outcome: DeliveryOutcome::Permanent,
            detail: detail.into(),
            retry_after_secs: None,
        }
    }
}

/// Connector health as the connector sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorHealth {
    /// Whether the connector is ready to attempt deliveries.
    pub healthy: bool,
    /// Short, secret-free explanation.
    pub detail: String,
}

impl ConnectorHealth {
    /// Healthy with a detail.
    pub fn healthy(detail: impl Into<String>) -> Self {
        Self {
            healthy: true,
            detail: detail.into(),
        }
    }

    /// Unhealthy with a reason.
    pub fn unhealthy(detail: impl Into<String>) -> Self {
        Self {
            healthy: false,
            detail: detail.into(),
        }
    }
}

/// The connector contract.
///
/// Implementations must be safe to call from the delivery engine's thread and
/// must classify failures honestly: claiming [`DeliveryOutcome::Retryable`] for a
/// permanent error burns the retry budget, and claiming
/// [`DeliveryOutcome::Delivered`] when the downstream rejected the event loses
/// it.
pub trait Connector: Send + Sync {
    /// Stable connector name (used in idempotency keys, metrics and logs).
    fn name(&self) -> &str;

    /// Transport family.
    fn kind(&self) -> ConnectorKind;

    /// What the connector promises.
    fn capabilities(&self) -> ConnectorCapabilities;

    /// Attempt one delivery.
    fn deliver(&self, request: &DeliveryRequest) -> DeliveryResult;

    /// Current readiness.
    fn health(&self) -> ConnectorHealth;
}

/// A connector plus how to build it, for vendor registry wiring.
pub type BoxedConnector = Box<dyn Connector>;

/// Why a connector could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorBuildError {
    /// Offending configuration field.
    pub field: String,
    /// Why the value is unusable.
    pub detail: String,
}

impl ConnectorBuildError {
    /// Build an error naming the field.
    pub fn new(field: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ConnectorBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid connector {}: {}", self.field, self.detail)
    }
}

impl std::error::Error for ConnectorBuildError {}

/// Validate a connector name and payload ceiling, shared by the connectors.
pub(crate) fn validate_connector_common(
    name: &str,
    max_payload_bytes: usize,
) -> Result<(), ConnectorBuildError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(ConnectorBuildError::new(
            "name",
            "must be 1..=64 characters",
        ));
    }
    if !trimmed
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(ConnectorBuildError::new(
            "name",
            "may contain only letters, digits, '-', '_' and '.'",
        ));
    }
    if max_payload_bytes == 0 {
        return Err(ConnectorBuildError::new(
            "max_payload_bytes",
            "must be greater than zero",
        ));
    }
    Ok(())
}

/// Whether a payload fits the connector's ceiling.
pub(crate) fn payload_size(payload: &serde_json::Value) -> Result<usize, ConnectorBuildError> {
    serde_json::to_vec(payload)
        .map(|bytes| bytes.len())
        .map_err(|error| {
            ConnectorBuildError::new("payload", format!("cannot encode payload: {error}"))
        })
}
