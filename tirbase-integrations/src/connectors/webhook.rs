// SPDX-License-Identifier: Apache-2.0

//! Signed webhook connector: HMAC-SHA256 over `"<timestamp>.<body>"`.

use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::blocking::Client;

use crate::auth::HmacWebhook;
use crate::connector::{
    payload_size, validate_connector_common, AuthKind, Connector, ConnectorBuildError,
    ConnectorCapabilities, ConnectorHealth, ConnectorKind, DeliveryRequest, DeliveryResult,
    DEFAULT_MAX_PAYLOAD_BYTES,
};
use crate::connectors::http::{classify_response, classify_transport_error};
use crate::mapping::Mapping;

/// Webhook connector configuration.
#[derive(Debug, Clone)]
pub struct WebhookConnectorConfig {
    /// Connector name.
    pub name: String,
    /// Endpoint URL.
    pub url: String,
    /// Extra request headers.
    pub headers: BTreeMap<String, String>,
    /// Request timeout.
    pub timeout_secs: u64,
    /// Largest payload accepted.
    pub max_payload_bytes: usize,
}

impl WebhookConnectorConfig {
    /// Configuration for `url` with defaults.
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            headers: BTreeMap::new(),
            timeout_secs: 15,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
}

/// A webhook connector that signs every request.
pub struct WebhookConnector {
    config: WebhookConnectorConfig,
    client: Client,
    signing: HmacWebhook,
    mapping: Option<Mapping>,
}

impl WebhookConnector {
    /// Build with an explicit client and signer.
    pub fn new(
        config: WebhookConnectorConfig,
        signing: HmacWebhook,
        mapping: Option<Mapping>,
        client: Client,
    ) -> Result<Self, ConnectorBuildError> {
        validate_connector_common(&config.name, config.max_payload_bytes)?;
        if !config.url.starts_with("http://") && !config.url.starts_with("https://") {
            return Err(ConnectorBuildError::new("url", "must be an http(s) URL"));
        }
        if config.timeout_secs == 0 {
            return Err(ConnectorBuildError::new(
                "timeout_secs",
                "must be greater than zero",
            ));
        }
        Ok(Self {
            config,
            client,
            signing,
            mapping,
        })
    }

    /// Build with a default client honouring `timeout_secs`.
    pub fn with_default_client(
        config: WebhookConnectorConfig,
        signing: HmacWebhook,
        mapping: Option<Mapping>,
    ) -> Result<Self, ConnectorBuildError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|error| ConnectorBuildError::new("client", error.to_string()))?;
        Self::new(config, signing, mapping, client)
    }

    /// The configured URL without query or fragment.
    pub fn display_url(&self) -> &str {
        self.config
            .url
            .split(['?', '#'])
            .next()
            .unwrap_or(&self.config.url)
    }

    /// The signed body for one delivery.
    fn body(&self, request: &DeliveryRequest) -> Result<Vec<u8>, ConnectorBuildError> {
        let value = match self.mapping.as_ref() {
            Some(mapping) => mapping
                .apply(&request.mapping_context())
                .map_err(|error| ConnectorBuildError::new("mapping", error.to_string()))?,
            None => serde_json::json!({
                "event_id": request.event_id,
                "event_type": request.event_type,
                "tenant": request.tenant,
                "idempotency_key": request.idempotency_key,
                "data": request.payload,
            }),
        };
        let bytes = serde_json::to_vec(&value)
            .map_err(|error| ConnectorBuildError::new("payload", error.to_string()))?;
        let size = payload_size(&value)?;
        if size > self.config.max_payload_bytes {
            return Err(ConnectorBuildError::new(
                "payload",
                format!(
                    "{size} bytes exceeds the {}-byte ceiling",
                    self.config.max_payload_bytes
                ),
            ));
        }
        Ok(bytes)
    }
}

impl Connector for WebhookConnector {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Webhook
    }

    fn capabilities(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            idempotent: true,
            auth: vec![AuthKind::HmacSignature],
            max_payload_bytes: self.config.max_payload_bytes,
        }
    }

    fn deliver(&self, request: &DeliveryRequest) -> DeliveryResult {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(error) => return DeliveryResult::permanent(error.to_string()),
        };
        let timestamp = request.now_est;
        let signature = self.signing.sign(timestamp, &body);
        let mut builder = self
            .client
            .post(&self.config.url)
            .header("idempotency-key", &request.idempotency_key)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .header(self.signing.timestamp_header(), timestamp.to_string())
            .header(self.signing.signature_header(), signature);
        for (name, value) in &self.config.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        match builder.body(body).send() {
            Ok(response) => classify_response(request.attempt, response),
            Err(error) => classify_transport_error(&error),
        }
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy(format!(
            "webhook {} configured with HMAC-SHA256",
            self.display_url()
        ))
    }
}
