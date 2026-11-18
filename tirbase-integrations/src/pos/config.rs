// SPDX-License-Identifier: Apache-2.0

//! Connector configuration schema.
//!
//! A POS connector is configured by one TOML document: which families it serves,
//! where it points, how it authenticates (by reference, never by inline secret),
//! how requests are shaped (the shared mapping DSL), how failures are retried and
//! how often reconciliation runs. Validation is total: a document that parses but
//! cannot be used is rejected with the offending field named, and a document that
//! carries card data or a raw secret is refused rather than stored.
//!
//! ```toml
//! schema_version = 1
//! connector = "acme-payments"
//! families = ["payment", "tax"]
//! endpoint = "https://payments.acme.example/v1"
//! timeout_ms = 5000
//!
//! [retry]
//! max_attempts = 5
//! base_delay_secs = 5
//! factor = 2
//! max_delay_secs = 300
//!
//! [reconciliation]
//! enabled = true
//! interval_secs = 3600
//! tolerance_minor = 0
//!
//! [[secret]]
//! name = "api_key"
//! from = "env:ACME_POS_API_KEY"
//! ```

use serde::{Deserialize, Serialize};

use crate::mapping::{Mapping, MappingDocument, MappingError};
use crate::retry::RetryPolicy;

use super::pci::{assert_no_card_data, is_card_field};
use super::reconcile::ReconciliationPolicy;
use super::{PosError, PosFamily};

/// Configuration document schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Longest endpoint accepted.
pub const MAX_ENDPOINT_LEN: usize = 512;

/// Shortest and longest request timeout accepted, in milliseconds.
pub const MIN_TIMEOUT_MS: u64 = 100;

/// Longest request timeout accepted, in milliseconds.
pub const MAX_TIMEOUT_MS: u64 = 120_000;

fn default_timeout_ms() -> u64 {
    5_000
}

/// Retry section of a connector configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    /// Attempts allowed before a dead letter.
    pub max_attempts: u32,
    /// Delay after the first failure, in seconds.
    pub base_delay_secs: u64,
    /// Multiplier per further failure.
    pub factor: u32,
    /// Ceiling on any single delay, in seconds.
    pub max_delay_secs: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay_secs: 5,
            factor: 2,
            max_delay_secs: 300,
        }
    }
}

impl RetryConfig {
    /// The retry policy this section describes.
    pub fn to_policy(&self) -> RetryPolicy {
        RetryPolicy::new(
            self.max_attempts,
            self.base_delay_secs,
            self.factor,
            self.max_delay_secs,
        )
    }
}

/// A secret the connector needs, resolved by the host.
///
/// The document names the secret and where the host loads it from; it never
/// carries the value, so a configuration file can be committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// Logical name the connector uses.
    pub name: String,
    /// `env:NAME` or `file:/path/to/secret`.
    pub from: String,
}

impl SecretRef {
    /// The environment variable this reference names, when it names one.
    pub fn env_var(&self) -> Option<&str> {
        self.from.strip_prefix("env:")
    }

    /// The file path this reference names, when it names one.
    pub fn file_path(&self) -> Option<&str> {
        self.from.strip_prefix("file:")
    }
}

/// A validated connector configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    /// Schema version; must be [`CONFIG_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Connector name (letters, digits, `-`, `_`, `.`).
    pub connector: String,
    /// Families the connector serves.
    pub families: Vec<PosFamily>,
    /// Base endpoint of the vendor API.
    pub endpoint: String,
    /// Whether plain HTTP is allowed for a loopback endpoint (development only).
    #[serde(default)]
    pub allow_insecure_loopback: bool,
    /// Request timeout, in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Secrets the connector needs.
    #[serde(default)]
    pub secret: Vec<SecretRef>,
    /// Optional mapping document applied to request payloads.
    #[serde(default)]
    pub mapping: Option<MappingDocument>,
    /// Retry policy.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Reconciliation policy.
    #[serde(default)]
    pub reconciliation: ReconciliationPolicy,
}

impl ConnectorConfig {
    /// Parse and validate a TOML document.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: ConnectorConfig = toml::from_str(text).map_err(|error| {
            ConfigError::new(
                "document",
                format!("cannot parse connector config: {error}"),
            )
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate every field, including the embedded mapping document.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::new(
                "schema_version",
                format!(
                    "unsupported version {} (supported {CONFIG_SCHEMA_VERSION})",
                    self.schema_version
                ),
            ));
        }
        crate::connector::validate_connector_common(&self.connector, 1)
            .map_err(|error| ConfigError::new("connector", error.detail))?;
        if self.families.is_empty() {
            return Err(ConfigError::new(
                "families",
                "a connector must serve at least one family",
            ));
        }
        for (index, family) in self.families.iter().enumerate() {
            if self.families[..index].contains(family) {
                return Err(ConfigError::new(
                    "families",
                    format!("duplicate family {:?}", family.as_str()),
                ));
            }
        }
        check_endpoint(&self.endpoint, self.allow_insecure_loopback)?;
        if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&self.timeout_ms) {
            return Err(ConfigError::new(
                "timeout_ms",
                format!("must be {MIN_TIMEOUT_MS}..={MAX_TIMEOUT_MS}"),
            ));
        }
        if self.retry.max_attempts == 0 {
            return Err(ConfigError::new("retry.max_attempts", "must be at least 1"));
        }
        self.reconciliation.validate()?;
        for secret in &self.secret {
            validate_secret(secret)?;
        }
        if let Some(document) = &self.mapping {
            Mapping::from_document(document.clone())
                .map_err(|error| ConfigError::new("mapping", mapping_detail(&error)))?;
        }
        Ok(())
    }

    /// Compile the embedded mapping document, if any.
    pub fn compiled_mapping(&self) -> Result<Option<Mapping>, ConfigError> {
        match &self.mapping {
            Some(document) => Mapping::from_document(document.clone())
                .map(Some)
                .map_err(|error| ConfigError::new("mapping", mapping_detail(&error))),
            None => Ok(None),
        }
    }

    /// Shape a vendor payload from `{event, payload}`, if a mapping is configured.
    pub fn apply_mapping(
        &self,
        context: &serde_json::Value,
    ) -> Result<Option<serde_json::Value>, ConfigError> {
        match self.compiled_mapping()? {
            Some(mapping) => mapping
                .apply(context)
                .map(Some)
                .map_err(|error| ConfigError::new("mapping", mapping_detail(&error))),
            None => Ok(None),
        }
    }

    /// The retry policy this configuration asks for.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry.to_policy()
    }

    /// Whether the configuration serves `family`.
    pub fn serves(&self, family: PosFamily) -> bool {
        self.families.contains(&family)
    }

    /// Resolve a configured secret name to its environment variable.
    pub fn secret_env(&self, name: &str) -> Option<&str> {
        self.secret
            .iter()
            .find(|secret| secret.name == name)
            .and_then(SecretRef::env_var)
    }
}

fn mapping_detail(error: &MappingError) -> String {
    error.to_string()
}

fn check_endpoint(endpoint: &str, allow_insecure_loopback: bool) -> Result<(), ConfigError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(ConfigError::new("endpoint", "must not be empty"));
    }
    if endpoint.len() > MAX_ENDPOINT_LEN {
        return Err(ConfigError::new(
            "endpoint",
            format!("must be at most {MAX_ENDPOINT_LEN} bytes"),
        ));
    }
    if endpoint.contains('@') {
        return Err(ConfigError::new(
            "endpoint",
            "must not carry credentials; use a secret reference",
        ));
    }
    if endpoint.chars().any(char::is_whitespace) {
        return Err(ConfigError::new("endpoint", "must not contain whitespace"));
    }
    let host = endpoint
        .split_once("://")
        .map(|(scheme, rest)| (scheme, rest.split('/').next().unwrap_or_default()))
        .ok_or_else(|| ConfigError::new("endpoint", "must carry a scheme"))?;
    let (scheme, host) = host;
    if scheme.eq_ignore_ascii_case("https") {
        if host.is_empty() {
            return Err(ConfigError::new("endpoint", "must carry a host"));
        }
        return Ok(());
    }
    if scheme.eq_ignore_ascii_case("http") {
        let hostname = host.split(':').next().unwrap_or_default();
        let loopback = matches!(hostname, "127.0.0.1" | "localhost" | "[::1]" | "::1");
        if allow_insecure_loopback && loopback {
            return Ok(());
        }
        return Err(ConfigError::new(
            "endpoint",
            "plain HTTP is only allowed for a loopback host with allow_insecure_loopback",
        ));
    }
    Err(ConfigError::new(
        "endpoint",
        format!("unsupported scheme {scheme:?}; use https"),
    ))
}

fn validate_secret(secret: &SecretRef) -> Result<(), ConfigError> {
    if secret.name.trim().is_empty() || secret.name.len() > 64 {
        return Err(ConfigError::new("secret.name", "must be 1..=64 characters"));
    }
    if !secret
        .name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(ConfigError::new(
            "secret.name",
            "may contain only letters, digits, '-', '_' and '.'",
        ));
    }
    if is_card_field(&secret.name) {
        return Err(ConfigError::new(
            "secret.name",
            "a connector may not hold card data; keep an opaque token instead",
        ));
    }
    let location = secret.from.trim();
    let valid_location = secret
        .env_var()
        .map(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
        })
        .unwrap_or(false);
    let valid_file = secret
        .file_path()
        .map(|value| !value.is_empty() && value.len() <= 256)
        .unwrap_or(false);
    if !valid_location && !valid_file {
        return Err(ConfigError::new(
            "secret.from",
            "must be 'env:NAME' or 'file:/path/to/secret'",
        ));
    }
    if location.len() > 256 {
        return Err(ConfigError::new("secret.from", "must be at most 256 bytes"));
    }
    assert_no_card_data("secret.from", location)
        .map_err(|error| ConfigError::new("secret.from", error.to_string()))?;
    Ok(())
}

/// Why a configuration document is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Offending field.
    pub field: String,
    /// Why the value is unusable.
    pub detail: String,
}

impl ConfigError {
    /// Build an error naming the field.
    pub fn new(field: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            detail: detail.into(),
        }
    }

    /// The equivalent [`PosError`].
    pub fn to_pos_error(&self) -> PosError {
        PosError::Configuration {
            field: self.field.clone(),
            detail: self.detail.clone(),
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid connector configuration {}: {}",
            self.field, self.detail
        )
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
schema_version = 1
connector = "acme-payments"
families = ["payment", "tax"]
endpoint = "https://payments.acme.example/v1"
timeout_ms = 5000

[retry]
max_attempts = 3
base_delay_secs = 2
factor = 2
max_delay_secs = 30

[reconciliation]
enabled = true
interval_secs = 3600
tolerance_minor = 0

[[secret]]
name = "api_key"
from = "env:ACME_POS_API_KEY"

[mapping]
schema_version = 1

[[mapping.field]]
target = "charge.amount_minor"
source = "payload.amount_minor"
"#;

    #[test]
    fn a_complete_document_parses_and_validates() {
        let config = ConnectorConfig::from_toml(VALID).expect("valid config");
        assert_eq!(config.families, vec![PosFamily::Payment, PosFamily::Tax]);
        assert!(config.serves(PosFamily::Payment));
        assert_eq!(config.secret_env("api_key"), Some("ACME_POS_API_KEY"));
        assert_eq!(config.retry_policy().max_attempts, 3);
        let mapped = config
            .apply_mapping(&serde_json::json!({
                "event": {},
                "payload": { "amount_minor": 2500 }
            }))
            .expect("mapping")
            .expect("document");
        assert_eq!(mapped["charge"]["amount_minor"], 2500);
    }

    #[test]
    fn unsafe_or_unusable_documents_are_refused() {
        let http = VALID.replace("https://", "http://");
        assert!(ConnectorConfig::from_toml(&http).is_err());

        let inline_secret = VALID.replace("env:ACME_POS_API_KEY", "hunter2");
        assert!(ConnectorConfig::from_toml(&inline_secret).is_err());

        let card_secret = VALID.replace("name = \"api_key\"", "name = \"card_number\"");
        assert!(ConnectorConfig::from_toml(&card_secret).is_err());

        let duplicate = VALID.replace("[\"payment\", \"tax\"]", "[\"payment\", \"payment\"]");
        assert!(ConnectorConfig::from_toml(&duplicate).is_err());

        let version = VALID.replace(
            "schema_version = 1\nconnector",
            "schema_version = 9\nconnector",
        );
        assert!(ConnectorConfig::from_toml(&version).is_err());
    }

    #[test]
    fn loopback_http_needs_the_explicit_opt_in() {
        let loopback = VALID.replace("https://payments.acme.example/v1", "http://127.0.0.1:8080");
        assert!(ConnectorConfig::from_toml(&loopback).is_err());
        let opted_in = loopback.replace(
            "timeout_ms = 5000",
            "timeout_ms = 5000\nallow_insecure_loopback = true",
        );
        assert!(ConnectorConfig::from_toml(&opted_in).is_ok());
    }
}
