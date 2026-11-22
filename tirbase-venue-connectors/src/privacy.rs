// SPDX-License-Identifier: Apache-2.0

//! Redaction and privacy rules.
//!
//! Venue data crosses a trust boundary when it reaches a ticketing, access, BMS,
//! CCTV or PA vendor. The policy here is deliberately narrow:
//!
//! * a holder reference is either omitted or replaced by a deterministic,
//!   deployment-salted token, so the vendor can correlate scans without ever
//!   seeing the scanner's reference;
//! * holder names and emails are removed, never transformed or truncated;
//! * announcement text and free-text alarm detail are scrubbed of email
//!   addresses and long phone-like numbers;
//! * biometric markers are refused outright;
//! * camera media cannot be represented by the API at all
//!   ([`crate::domain::CameraContext`] is metadata-only).
//!
//! The raw event stays with the venue runtime; only the result of
//! [`PrivacyPolicy::prepare`] is queued for delivery.

use serde::{Deserialize, Serialize};
use tirbase_integrations::auth::{hex_lower, hmac_sha256};
use tirbase_integrations::{IntegrationEvent, SecretString};

use crate::event::VenueEvent;

/// Domain-separation context for holder pseudonyms.
pub const CONTEXT_HOLDER_TOKEN: &str = "TirBase/v1/VenueHolderToken";

/// What to do with the scanner's holder reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderDisclosure {
    /// Replace the reference with a salted pseudonym.
    Pseudonymise,
    /// Replace the reference with `redacted`.
    Omit,
}

/// Why an event could not be prepared for delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivacyError {
    /// The event is structurally invalid.
    InvalidEvent(String),
    /// The event carries a biometric marker.
    BiometricData(String),
    /// The event carries camera media.
    CameraMedia(String),
    /// The event carries special-category data this framework never forwards.
    SpecialCategory(String),
}

impl std::fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivacyError::InvalidEvent(detail) => write!(f, "invalid venue event: {detail}"),
            PrivacyError::BiometricData(field) => {
                write!(
                    f,
                    "{field} carries biometric data, which is never delivered"
                )
            }
            PrivacyError::CameraMedia(field) => {
                write!(f, "{field} carries camera media, which is never delivered")
            }
            PrivacyError::SpecialCategory(field) => {
                write!(
                    f,
                    "{field} carries special-category data, which is never delivered"
                )
            }
        }
    }
}

impl std::error::Error for PrivacyError {}

impl From<crate::event::SchemaError> for PrivacyError {
    fn from(error: crate::event::SchemaError) -> Self {
        PrivacyError::InvalidEvent(error.to_string())
    }
}

const BIOMETRIC_MARKERS: [&str; 4] = [
    "biometric",
    "face_embedding",
    "face_image",
    "fingerprint_template",
];

/// Venue privacy policy.
#[derive(Clone)]
pub struct PrivacyPolicy {
    holder: HolderDisclosure,
    salt: SecretString,
    max_retention_secs: i64,
}

impl std::fmt::Debug for PrivacyPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivacyPolicy")
            .field("holder", &self.holder)
            .field("salt", &"***")
            .field("max_retention_secs", &self.max_retention_secs)
            .finish()
    }
}

impl PrivacyPolicy {
    /// Deployment policy with a pseudonymisation salt.
    pub fn new(holder: HolderDisclosure, salt: impl Into<String>) -> Self {
        Self {
            holder,
            salt: SecretString::new(salt),
            max_retention_secs: 86_400,
        }
    }

    /// The standard policy: pseudonymise the holder and keep payloads for a day.
    pub fn standard(salt: impl Into<String>) -> Self {
        Self::new(HolderDisclosure::Pseudonymise, salt)
    }

    /// Bound how long the venue may retain the event, in seconds.
    pub fn with_retention(mut self, max_retention_secs: i64) -> Self {
        self.max_retention_secs = max_retention_secs.max(1);
        self
    }

    /// How holder references are disclosed.
    pub fn holder(&self) -> HolderDisclosure {
        self.holder
    }

    /// Retention ceiling in seconds.
    pub fn max_retention_secs(&self) -> i64 {
        self.max_retention_secs
    }

    /// When a retained event must be deleted.
    pub fn retention_deadline(&self, event: &VenueEvent) -> i64 {
        event.occurred_est().saturating_add(self.max_retention_secs)
    }

    /// Whether the event may still be retained at `now_est`.
    pub fn may_retain(&self, event: &VenueEvent, now_est: i64) -> bool {
        now_est <= self.retention_deadline(event)
    }

    /// Deterministic pseudonym for a holder reference.
    ///
    /// Salted HMAC-SHA256 truncated to 16 bytes. Stable for a deployment, so
    /// repeat scans of the same holder correlate, and useless without the salt.
    pub fn pseudonym(&self, holder_ref: &str) -> String {
        let mut message = Vec::with_capacity(CONTEXT_HOLDER_TOKEN.len() + holder_ref.len() + 1);
        message.extend_from_slice(CONTEXT_HOLDER_TOKEN.as_bytes());
        message.push(0);
        message.extend_from_slice(holder_ref.as_bytes());
        let digest = hmac_sha256(self.salt.expose().as_bytes(), &message);
        format!("vh-{}", hex_lower(&digest[..16]))
    }

    /// Remove direct identifiers from an event.
    ///
    /// The returned event is safe to hand to a connector and to serialise for the
    /// vendor. It still validates against the event schema.
    pub fn redact_event(&self, event: &VenueEvent) -> Result<VenueEvent, PrivacyError> {
        event.validate()?;
        let redacted = match event {
            VenueEvent::TicketScan { scan } => {
                let mut scan = scan.clone();
                scan.holder_name = None;
                scan.holder_email = None;
                scan.holder_ref = match self.holder {
                    HolderDisclosure::Pseudonymise => self.pseudonym(&scan.holder_ref),
                    HolderDisclosure::Omit => "redacted".to_string(),
                };
                VenueEvent::ticket_scan(scan)
            }
            VenueEvent::AccessDecision { decision } => {
                VenueEvent::access_decision(decision.clone())
            }
            VenueEvent::Alarm { alarm } => {
                let mut alarm = alarm.clone();
                if let Some(detail) = &alarm.detail {
                    if looks_like_media(detail) {
                        return Err(PrivacyError::CameraMedia("alarm detail".to_string()));
                    }
                    alarm.detail = Some(scrub_text(detail));
                }
                VenueEvent::alarm(alarm)
            }
            VenueEvent::Announcement { announcement } => {
                let mut announcement = announcement.clone();
                announcement.text = scrub_text(&announcement.text);
                VenueEvent::announcement(announcement)
            }
        };
        let serialised = serde_json::to_string(&redacted)
            .map_err(|error| PrivacyError::InvalidEvent(error.to_string()))?;
        let lower = serialised.to_ascii_lowercase();
        for marker in BIOMETRIC_MARKERS {
            if lower.contains(marker) {
                return Err(PrivacyError::BiometricData(marker.to_string()));
            }
        }
        Ok(redacted)
    }

    /// Build the redacted [`IntegrationEvent`] the dispatcher queues.
    ///
    /// The connector-specific idempotency key is derived by the delivery engine
    /// from this event id and the connector name, so the same scan or
    /// announcement always presents the same key to the same vendor.
    pub fn prepare(&self, event: &VenueEvent) -> Result<IntegrationEvent, PrivacyError> {
        event.validate()?;
        let redacted = self.redact_event(event)?;
        let payload = redacted.payload()?;
        Ok(IntegrationEvent::new(
            event.event_id(),
            event.kind().as_str(),
            event.venue_id(),
            event.occurred_est(),
            payload,
        ))
    }
}

/// Mask email addresses and phone-like sequences in free text.
pub fn scrub_text(text: &str) -> String {
    let email_masked = text
        .split_whitespace()
        .map(|word| {
            let core = word.trim_matches(|character: char| {
                matches!(
                    character,
                    ',' | '.' | ';' | ':' | '!' | '?' | '(' | ')' | '"' | '\''
                )
            });
            if looks_like_email(core) {
                "[redacted-email]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    mask_phone_sequences(&email_masked)
}

fn looks_like_email(word: &str) -> bool {
    let Some((local, domain)) = word.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

fn mask_phone_sequences(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if !(character.is_ascii_digit() || character == '+') {
            out.push(character);
            index += 1;
            continue;
        }
        let start = index;
        let mut digits = 0usize;
        let mut end = index;
        while end < chars.len() {
            let current = chars[end];
            if current.is_ascii_digit() {
                digits += 1;
                end += 1;
            } else if matches!(current, '+' | '-' | '(' | ')' | '.')
                || (current == ' ' && end + 1 < chars.len() && chars[end + 1].is_ascii_digit())
            {
                end += 1;
            } else {
                break;
            }
        }
        if digits >= 7 {
            out.push_str("[redacted-number]");
        } else {
            out.extend(&chars[start..end]);
        }
        index = end;
    }
    out
}

fn looks_like_media(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("data:image")
        || lower.contains("base64,")
        || lower.contains("face_embedding")
        || lower.contains("biometric")
}
