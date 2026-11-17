// SPDX-License-Identifier: Apache-2.0

//! HTTP/REST connector.

use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::Method;

use crate::auth::Auth;
use crate::connector::{
    validate_connector_common, AuthKind, Connector, ConnectorBuildError, ConnectorCapabilities,
    ConnectorHealth, ConnectorKind, DeliveryRequest, DeliveryResult, DEFAULT_MAX_PAYLOAD_BYTES,
};
use crate::mapping::Mapping;

/// HTTP connector configuration.
#[derive(Debug, Clone)]
pub struct HttpConnectorConfig {
    /// Connector name.
    pub name: String,
    /// Endpoint URL.
    pub url: String,
    /// HTTP method (`POST`, `PUT` or `PATCH`).
    pub method: String,
    /// Extra request headers.
    pub headers: BTreeMap<String, String>,
    /// Request timeout.
    pub timeout_secs: u64,
    /// Authentication.
    pub auth: Option<Auth>,
    /// Largest payload accepted.
    pub max_payload_bytes: usize,
}

impl HttpConnectorConfig {
    /// Configuration for `POST url` with no authentication.
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            method: "POST".to_string(),
            headers: BTreeMap::new(),
            timeout_secs: 15,
            auth: None,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        }
    }

    /// Add a header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Set the authentication.
    pub fn with_auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }
}

/// A generic HTTP/REST connector.
pub struct HttpConnector {
    config: HttpConnectorConfig,
    client: Client,
    mapping: Option<Mapping>,
}

impl HttpConnector {
    /// Build with an explicit client.
    pub fn new(
        config: HttpConnectorConfig,
        mapping: Option<Mapping>,
        client: Client,
    ) -> Result<Self, ConnectorBuildError> {
        validate_connector_common(&config.name, config.max_payload_bytes)?;
        if !config.url.starts_with("http://") && !config.url.starts_with("https://") {
            return Err(ConnectorBuildError::new("url", "must be an http(s) URL"));
        }
        if !matches!(config.method.as_str(), "POST" | "PUT" | "PATCH") {
            return Err(ConnectorBuildError::new(
                "method",
                "must be POST, PUT or PATCH",
            ));
        }
        if config.timeout_secs == 0 {
            return Err(ConnectorBuildError::new(
                "timeout_secs",
                "must be greater than zero",
            ));
        }
        let method = Method::from_bytes(config.method.as_bytes())
            .map_err(|error| ConnectorBuildError::new("method", error.to_string()))?;
        let _ = method;
        for header in config.headers.keys() {
            if reqwest::header::HeaderName::from_bytes(header.as_bytes()).is_err() {
                return Err(ConnectorBuildError::new(
                    "headers",
                    format!("invalid header name {header:?}"),
                ));
            }
        }
        Ok(Self {
            config,
            client,
            mapping,
        })
    }

    /// Build with a default client honouring `timeout_secs`.
    pub fn with_default_client(
        config: HttpConnectorConfig,
        mapping: Option<Mapping>,
    ) -> Result<Self, ConnectorBuildError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|error| ConnectorBuildError::new("client", error.to_string()))?;
        Self::new(config, mapping, client)
    }

    /// The configured URL, with any query string dropped so credentials in it
    /// never reach a log.
    pub fn display_url(&self) -> &str {
        self.config
            .url
            .split(['?', '#'])
            .next()
            .unwrap_or(&self.config.url)
    }

    /// The request body for one delivery.
    fn body(&self, request: &DeliveryRequest) -> Result<Vec<u8>, ConnectorBuildError> {
        let value = match self.mapping.as_ref() {
            Some(mapping) => mapping
                .apply(&request.mapping_context())
                .map_err(|error| ConnectorBuildError::new("mapping", error.to_string()))?,
            None => request.payload.clone(),
        };
        let bytes = serde_json::to_vec(&value)
            .map_err(|error| ConnectorBuildError::new("payload", error.to_string()))?;
        if bytes.len() > self.config.max_payload_bytes {
            return Err(ConnectorBuildError::new(
                "payload",
                format!(
                    "{} bytes exceeds the {}-byte ceiling",
                    bytes.len(),
                    self.config.max_payload_bytes
                ),
            ));
        }
        Ok(bytes)
    }
}

impl Connector for HttpConnector {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Http
    }

    fn capabilities(&self) -> ConnectorCapabilities {
        let mut auth = vec![AuthKind::None];
        match self.config.auth.as_ref().map(|auth| match auth {
            Auth::None => AuthKind::None,
            Auth::ApiKey(_) => AuthKind::ApiKey,
            Auth::Bearer(_) => AuthKind::OAuth2ClientCredentials,
            Auth::OAuth2(_) => AuthKind::OAuth2ClientCredentials,
        }) {
            Some(kind) if !auth.contains(&kind) => auth.push(kind),
            _ => {}
        }
        if self.config.url.starts_with("https://") {
            auth.push(AuthKind::MutualTls);
        }
        ConnectorCapabilities {
            idempotent: true,
            auth,
            max_payload_bytes: self.config.max_payload_bytes,
        }
    }

    fn deliver(&self, request: &DeliveryRequest) -> DeliveryResult {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(error) => return DeliveryResult::permanent(error.to_string()),
        };
        let method = Method::from_bytes(self.config.method.as_bytes()).unwrap_or(Method::POST);
        let mut builder = self
            .client
            .request(method, &self.config.url)
            .header("idempotency-key", &request.idempotency_key)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json");
        for (name, value) in &self.config.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if let Some(auth) = self.config.auth.as_ref() {
            builder = match auth.apply(builder, request.now_est) {
                Ok(builder) => builder,
                Err(error) => return DeliveryResult::permanent(format!("authentication: {error}")),
            };
        }
        match builder.body(body).send() {
            Ok(response) => classify_response(request.attempt, response),
            Err(error) => classify_transport_error(&error),
        }
    }

    fn health(&self) -> ConnectorHealth {
        ConnectorHealth::healthy(format!(
            "{} {} configured",
            self.config.method,
            self.display_url()
        ))
    }
}

/// Map a successful transport to an outcome.
pub(crate) fn classify_response(_attempt: u32, response: Response) -> DeliveryResult {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    let body = response.text().unwrap_or_default();
    classify_status(status, &body, retry_after)
}

/// Classify an HTTP status and body.
pub fn classify_status(status: u16, body: &str, retry_after: Option<u64>) -> DeliveryResult {
    let excerpt = truncate(body, 200);
    let duplicate_marker = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("duplicate").and_then(|flag| flag.as_bool()))
        .unwrap_or(false);
    match status {
        200..=299 if duplicate_marker => {
            DeliveryResult::duplicate(format!("downstream reported duplicate ({status})"))
        }
        200..=299 => DeliveryResult::delivered(format!("accepted ({status})")),
        409 => DeliveryResult::duplicate("downstream reported conflict (409)"),
        408 | 425 | 429 => {
            DeliveryResult::retryable(format!("transient status {status}: {excerpt}"), retry_after)
        }
        500..=599 => {
            DeliveryResult::retryable(format!("upstream status {status}: {excerpt}"), retry_after)
        }
        400 | 401 | 403 | 404 | 405 | 410 | 413 | 415 | 422 => {
            DeliveryResult::permanent(format!("rejected ({status}): {excerpt}"))
        }
        _ => DeliveryResult::permanent(format!("unexpected status {status}: {excerpt}")),
    }
}

/// Classify a transport failure.
pub(crate) fn classify_transport_error(error: &reqwest::Error) -> DeliveryResult {
    let detail = truncate(&error.to_string(), 200);
    if error.is_timeout() || error.is_connect() {
        return DeliveryResult::retryable(format!("transport: {detail}"), None);
    }
    if error.is_request() || error.is_body() || error.is_decode() {
        return DeliveryResult::retryable(format!("request: {detail}"), None);
    }
    DeliveryResult::permanent(format!("transport: {detail}"))
}

pub(crate) fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}
