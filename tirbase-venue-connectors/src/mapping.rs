// SPDX-License-Identifier: Apache-2.0

//! Connector profile and mapping config.
//!
//! A closed connector ships one TOML profile. It names the vendor, domain, venue
//! and endpoint, references secrets by `env:`/`file:` *reference* (never a
//! value), carries the privacy and retry policy, and embeds the CC-20 mapping
//! document that shapes the vendor JSON. The profile is validated once at
//! startup; the compiled mapping is then applied to every redacted event.
//!
//! ```toml
//! schema_version = 1
//! connector = "vendor-ticketing"
//! domain = "ticketing"
//! venue = "venue-1"
//! endpoint = "https://vendor.example/venue/events"
//! webhook_secret_ref = "env:VENUE_WEBHOOK_SECRET"
//!
//! [privacy]
//! holder = "pseudonymise"
//! pseudonym_salt_ref = "env:VENUE_PRIVACY_SALT"
//! max_retention_secs = 86400
//!
//! [retry]
//! max_attempts = 4
//! base_delay_secs = 2
//! factor = 2
//! max_delay_secs = 60
//!
//! [mapping]
//! schema_version = 1
//!
//! [[mapping.field]]
//! target = "scan.id"
//! source = "event.event_id"
//! required = true
//!
//! [[mapping.field]]
//! target = "scan.ticket"
//! source = "payload.ticket_id"
//! required = true
//! ```

use serde::{Deserialize, Serialize};
use tirbase_integrations::mapping::MappingDocument;
use tirbase_integrations::{Mapping, RetryPolicy};

use crate::domain::VenueDomain;
use crate::event::VenueEvent;
use crate::privacy::{HolderDisclosure, PrivacyError, PrivacyPolicy};

/// Supported profile schema version.
pub const PROFILE_SCHEMA_VERSION: u32 = 1;

/// Privacy section of a connector profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyConfig {
    /// Holder-reference handling.
    pub holder: HolderDisclosure,
    /// Secret reference for the pseudonymisation salt.
    pub pseudonym_salt_ref: String,
    /// Retention ceiling in seconds.
    pub max_retention_secs: i64,
}

/// Retry section of a connector profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    /// Attempts before a dead letter.
    pub max_attempts: u32,
    /// Delay after the first failure.
    pub base_delay_secs: u64,
    /// Multiplier per further failure.
    pub factor: u32,
    /// Ceiling on one delay.
    pub max_delay_secs: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        let policy = RetryPolicy::default();
        Self {
            max_attempts: policy.max_attempts,
            base_delay_secs: policy.base_delay_secs,
            factor: policy.factor,
            max_delay_secs: policy.max_delay_secs,
        }
    }
}

/// A validated connector profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorProfile {
    /// Profile schema version.
    pub schema_version: u32,
    /// Connector name.
    pub connector: String,
    /// Venue domain.
    pub domain: VenueDomain,
    /// Venue bound to this connector.
    pub venue: String,
    /// Vendor endpoint.
    pub endpoint: String,
    /// Allow plain HTTP only for a loopback fixture.
    #[serde(default)]
    pub allow_insecure_loopback: bool,
    /// Secret reference for inbound webhook verification.
    #[serde(default)]
    pub webhook_secret_ref: Option<String>,
    /// Privacy rules.
    pub privacy: PrivacyConfig,
    /// Retry policy.
    #[serde(default)]
    pub retry: RetryConfig,
    /// CC-20 field mapping.
    pub mapping: MappingDocument,
}

/// A profile with its mapping compiled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledProfile {
    profile: ConnectorProfile,
    mapping: Mapping,
}

impl CompiledProfile {
    /// The validated profile.
    pub fn profile(&self) -> &ConnectorProfile {
        &self.profile
    }

    /// The compiled mapping.
    pub fn mapping(&self) -> &Mapping {
        &self.mapping
    }

    /// Retry policy the dispatcher should use.
    pub fn retry_policy(&self) -> RetryPolicy {
        RetryPolicy::new(
            self.profile.retry.max_attempts,
            self.profile.retry.base_delay_secs,
            self.profile.retry.factor,
            self.profile.retry.max_delay_secs,
        )
    }

    /// Build the live privacy policy, resolving the salt in the host.
    pub fn privacy(&self, salt: impl Into<String>) -> PrivacyPolicy {
        PrivacyPolicy::new(self.profile.privacy.holder, salt)
            .with_retention(self.profile.privacy.max_retention_secs)
    }

    /// Apply the vendor mapping to one redacted event.
    pub fn apply_to_event(
        &self,
        event: &VenueEvent,
        privacy: &PrivacyPolicy,
    ) -> Result<serde_json::Value, ProfileError> {
        let prepared = privacy.prepare(event)?;
        self.mapping
            .apply(&prepared.mapping_context())
            .map_err(|error| ProfileError::Mapping(error.to_string()))
    }
}

impl ConnectorProfile {
    /// Parse and validate a TOML profile.
    pub fn from_toml(text: &str) -> Result<CompiledProfile, ProfileError> {
        let profile: ConnectorProfile =
            toml::from_str(text).map_err(|error| ProfileError::Toml(error.to_string()))?;
        profile.validate()?;
        let mapping = Mapping::from_document(profile.mapping.clone())
            .map_err(|error| ProfileError::Mapping(error.to_string()))?;
        Ok(CompiledProfile { profile, mapping })
    }

    /// Validate every field.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != PROFILE_SCHEMA_VERSION {
            return Err(ProfileError::Invalid {
                field: "schema_version".to_string(),
                detail: format!("must be {PROFILE_SCHEMA_VERSION}"),
            });
        }
        validate_name("connector", &self.connector)?;
        validate_name("venue", &self.venue)?;
        validate_endpoint(&self.endpoint, self.allow_insecure_loopback)?;
        if let Some(secret) = &self.webhook_secret_ref {
            validate_secret_ref("webhook_secret_ref", secret)?;
        }
        validate_secret_ref(
            "privacy.pseudonym_salt_ref",
            &self.privacy.pseudonym_salt_ref,
        )?;
        if self.privacy.max_retention_secs <= 0 {
            return Err(ProfileError::Invalid {
                field: "privacy.max_retention_secs".to_string(),
                detail: "must be positive".to_string(),
            });
        }
        if self.retry.max_attempts == 0 {
            return Err(ProfileError::Invalid {
                field: "retry.max_attempts".to_string(),
                detail: "must be at least 1".to_string(),
            });
        }
        if self.retry.base_delay_secs == 0
            || self.retry.factor == 0
            || self.retry.max_delay_secs == 0
        {
            return Err(ProfileError::Invalid {
                field: "retry".to_string(),
                detail: "delays and factor must be positive".to_string(),
            });
        }
        if self.retry.max_delay_secs < self.retry.base_delay_secs {
            return Err(ProfileError::Invalid {
                field: "retry.max_delay_secs".to_string(),
                detail: "must not be below base_delay_secs".to_string(),
            });
        }
        Ok(())
    }
}

fn validate_name(field: &str, value: &str) -> Result<(), ProfileError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(ProfileError::Invalid {
            field: field.to_string(),
            detail: "must be 1..=64 characters".to_string(),
        });
    }
    if !trimmed
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(ProfileError::Invalid {
            field: field.to_string(),
            detail: "may contain only letters, digits, '-', '_' and '.'".to_string(),
        });
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str, allow_insecure_loopback: bool) -> Result<(), ProfileError> {
    if endpoint.starts_with("https://") && endpoint.len() > "https://".len() {
        return Ok(());
    }
    let loopback = endpoint.starts_with("http://127.0.0.1:")
        || endpoint.starts_with("http://localhost:")
        || endpoint.starts_with("http://[::1]:");
    if allow_insecure_loopback && loopback {
        return Ok(());
    }
    Err(ProfileError::Invalid {
        field: "endpoint".to_string(),
        detail: "must be an https URL; plain HTTP only for a loopback fixture with allow_insecure_loopback".to_string(),
    })
}

fn validate_secret_ref(field: &str, value: &str) -> Result<(), ProfileError> {
    let Some((scheme, name)) = value.split_once(':') else {
        return Err(ProfileError::Invalid {
            field: field.to_string(),
            detail: "must be an env: or file: secret reference, not a value".to_string(),
        });
    };
    if !matches!(scheme, "env" | "file") || name.trim().is_empty() {
        return Err(ProfileError::Invalid {
            field: field.to_string(),
            detail: "must be an env: or file: secret reference, not a value".to_string(),
        });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ProfileError::Invalid {
            field: field.to_string(),
            detail: "secret reference must not contain whitespace".to_string(),
        });
    }
    Ok(())
}

/// Why a profile was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// The document is not valid TOML or does not match the schema.
    Toml(String),
    /// A field is invalid.
    Invalid {
        /// Offending field.
        field: String,
        /// Why it is invalid.
        detail: String,
    },
    /// The mapping document was refused.
    Mapping(String),
    /// The privacy policy refused a preview.
    Privacy(String),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Toml(detail) => write!(f, "profile TOML: {detail}"),
            ProfileError::Invalid { field, detail } => write!(f, "invalid {field}: {detail}"),
            ProfileError::Mapping(detail) => write!(f, "mapping: {detail}"),
            ProfileError::Privacy(detail) => write!(f, "privacy: {detail}"),
        }
    }
}

impl std::error::Error for ProfileError {}

impl From<PrivacyError> for ProfileError {
    fn from(error: PrivacyError) -> Self {
        ProfileError::Privacy(error.to_string())
    }
}
