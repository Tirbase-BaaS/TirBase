// SPDX-License-Identifier: Apache-2.0

//! Inbound webhook verification.
//!
//! Vendors call the venue with scan acknowledgements, announcement receipts and
//! alarm updates. Every callback must carry a timestamp and an HMAC-SHA256
//! signature over `"<timestamp>.<body>"`; an unsigned body is refused before it
//! is parsed. Multiple `v1=` signatures and multiple configured secrets are
//! accepted during rotation.
//!
//! Verification is deliberately separated from routing: [`InboundVenueEvents`]
//! verifies, validates the event schema, and suppresses a replayed callback
//! (same event id, same body) so an acknowledgement cannot be counted twice.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use tirbase_integrations::auth::{constant_time_eq, hex_lower, hmac_sha256};
use tirbase_integrations::SecretString;

use crate::event::VenueEvent;

/// Context mixed into every signature.
pub const CONTEXT_WEBHOOK: &str = "TirBase/v1/VenueWebhook";
/// Default timestamp header.
pub const DEFAULT_TIMESTAMP_HEADER: &str = "x-venue-timestamp";
/// Default signature header.
pub const DEFAULT_SIGNATURE_HEADER: &str = "x-venue-signature";
/// Default tolerated clock skew, in seconds.
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;

/// Why a webhook was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookError {
    /// The timestamp header is absent.
    MissingTimestamp,
    /// The timestamp header is not an integer.
    MalformedTimestamp,
    /// The signature header is absent or empty. Unsigned bodies never pass.
    MissingSignature,
    /// The signature header contains no usable `v1=` value.
    MalformedSignature,
    /// The timestamp is outside the tolerated window.
    StaleTimestamp {
        /// Timestamp presented by the vendor.
        timestamp_est: i64,
        /// Venue time at verification.
        now_est: i64,
        /// Tolerated skew.
        tolerance_secs: i64,
    },
    /// No configured secret produced the presented signature.
    SignatureMismatch,
    /// The signed body is not a valid venue event.
    InvalidPayload(String),
    /// A replay presented the same event id with a different body.
    PayloadConflict,
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookError::MissingTimestamp => write!(f, "webhook timestamp is missing"),
            WebhookError::MalformedTimestamp => write!(f, "webhook timestamp is malformed"),
            WebhookError::MissingSignature => write!(f, "webhook is unsigned"),
            WebhookError::MalformedSignature => write!(f, "webhook signature is malformed"),
            WebhookError::StaleTimestamp {
                timestamp_est,
                now_est,
                tolerance_secs,
            } => write!(
                f,
                "webhook timestamp {timestamp_est} outside ±{tolerance_secs}s of {now_est}"
            ),
            WebhookError::SignatureMismatch => write!(f, "webhook signature mismatch"),
            WebhookError::InvalidPayload(detail) => write!(f, "webhook payload: {detail}"),
            WebhookError::PayloadConflict => {
                write!(f, "webhook replay changed the body for the same event id")
            }
        }
    }
}

impl std::error::Error for WebhookError {}

/// A verified webhook body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedWebhook {
    /// Signed timestamp.
    pub timestamp_est: i64,
    /// SHA-256 of the body, for audit without retaining the body.
    pub body_sha256: String,
}

impl VerifiedWebhook {
    /// Parse and validate the signed body as a venue event.
    pub fn event(&self, body: &[u8]) -> Result<VenueEvent, WebhookError> {
        let event: VenueEvent = serde_json::from_slice(body)
            .map_err(|error| WebhookError::InvalidPayload(error.to_string()))?;
        event
            .validate()
            .map_err(|error| WebhookError::InvalidPayload(error.to_string()))?;
        Ok(event)
    }
}

/// HMAC-SHA256 webhook verifier with rotation support.
#[derive(Clone)]
pub struct VenueWebhookVerifier {
    secrets: Vec<SecretString>,
    timestamp_header: String,
    signature_header: String,
    tolerance_secs: i64,
}

impl std::fmt::Debug for VenueWebhookVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VenueWebhookVerifier")
            .field("secrets", &format!("{} secret(s)", self.secrets.len()))
            .field("timestamp_header", &self.timestamp_header)
            .field("signature_header", &self.signature_header)
            .field("tolerance_secs", &self.tolerance_secs)
            .finish()
    }
}

impl VenueWebhookVerifier {
    /// Build a verifier with one secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secrets: vec![SecretString::new(secret)],
            timestamp_header: DEFAULT_TIMESTAMP_HEADER.to_string(),
            signature_header: DEFAULT_SIGNATURE_HEADER.to_string(),
            tolerance_secs: DEFAULT_TOLERANCE_SECS,
        }
    }

    /// Accept an additional secret during rotation.
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secrets.push(SecretString::new(secret));
        self
    }

    /// Override the header names.
    pub fn with_headers(
        mut self,
        timestamp_header: impl Into<String>,
        signature_header: impl Into<String>,
    ) -> Self {
        self.timestamp_header = timestamp_header.into().to_ascii_lowercase();
        self.signature_header = signature_header.into().to_ascii_lowercase();
        self
    }

    /// Override the tolerated skew.
    pub fn with_tolerance(mut self, tolerance_secs: i64) -> Self {
        self.tolerance_secs = tolerance_secs.max(0);
        self
    }

    /// The timestamp header name.
    pub fn timestamp_header(&self) -> &str {
        &self.timestamp_header
    }

    /// The signature header name.
    pub fn signature_header(&self) -> &str {
        &self.signature_header
    }

    /// Sign with the first (current) secret: `v1=<hex>`.
    pub fn sign(&self, timestamp_est: i64, body: &[u8]) -> String {
        self.sign_with(0, timestamp_est, body)
            .expect("a verifier always has at least one secret")
    }

    /// Sign with the secret at `index`, for rotation drills.
    pub fn sign_with(&self, index: usize, timestamp_est: i64, body: &[u8]) -> Option<String> {
        let secret = self.secrets.get(index)?;
        let digest = signature(secret.expose(), timestamp_est, body);
        Some(format!("v1={}", hex_lower(&digest)))
    }

    /// Headers for a signed fixture request.
    pub fn signed_headers(&self, timestamp_est: i64, body: &[u8]) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert(self.timestamp_header.clone(), timestamp_est.to_string());
        headers.insert(
            self.signature_header.clone(),
            self.sign(timestamp_est, body),
        );
        headers
    }

    /// Verify a callback.
    pub fn verify(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        now_est: i64,
    ) -> Result<VerifiedWebhook, WebhookError> {
        let presented = headers
            .get(&self.signature_header)
            .map(String::as_str)
            .unwrap_or_default()
            .trim();
        if presented.is_empty() {
            return Err(WebhookError::MissingSignature);
        }
        let timestamp = headers
            .get(&self.timestamp_header)
            .ok_or(WebhookError::MissingTimestamp)?
            .trim()
            .parse::<i64>()
            .map_err(|_| WebhookError::MalformedTimestamp)?;
        if now_est.saturating_sub(timestamp).abs() > self.tolerance_secs {
            return Err(WebhookError::StaleTimestamp {
                timestamp_est: timestamp,
                now_est,
                tolerance_secs: self.tolerance_secs,
            });
        }
        let candidates = parse_signatures(presented)?;
        for secret in &self.secrets {
            let expected = signature(secret.expose(), timestamp, body);
            if candidates
                .iter()
                .any(|candidate| constant_time_eq(candidate, &expected))
            {
                return Ok(VerifiedWebhook {
                    timestamp_est: timestamp,
                    body_sha256: hex_lower(&Sha256::digest(body)),
                });
            }
        }
        Err(WebhookError::SignatureMismatch)
    }

    /// Verify, then parse and validate the venue event.
    pub fn verify_event(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        now_est: i64,
    ) -> Result<VenueEvent, WebhookError> {
        let verified = self.verify(headers, body, now_est)?;
        verified.event(body)
    }
}

fn signature(secret: &str, timestamp_est: i64, body: &[u8]) -> [u8; 32] {
    let mut message = Vec::with_capacity(CONTEXT_WEBHOOK.len() + body.len() + 32);
    message.extend_from_slice(CONTEXT_WEBHOOK.as_bytes());
    message.push(0);
    message.extend_from_slice(timestamp_est.to_string().as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    hmac_sha256(secret.as_bytes(), &message)
}

fn parse_signatures(value: &str) -> Result<Vec<[u8; 32]>, WebhookError> {
    let mut signatures = Vec::new();
    for entry in value.split([',', ';']) {
        let entry = entry.trim();
        let Some(encoded) = entry.strip_prefix("v1=") else {
            continue;
        };
        let bytes = hex::decode(encoded).map_err(|_| WebhookError::MalformedSignature)?;
        if bytes.len() != 32 {
            return Err(WebhookError::MalformedSignature);
        }
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&bytes);
        signatures.push(signature);
    }
    if signatures.is_empty() {
        return Err(WebhookError::MalformedSignature);
    }
    Ok(signatures)
}

/// Result of accepting an inbound event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundOutcome {
    /// The verified event.
    pub event: VenueEvent,
    /// Whether this exact event id was already accepted.
    pub replay: bool,
}

/// Verified inbound event sink with replay suppression.
pub struct InboundVenueEvents {
    verifier: VenueWebhookVerifier,
    seen: BTreeMap<String, VenueEvent>,
}

impl InboundVenueEvents {
    /// Build a sink.
    pub fn new(verifier: VenueWebhookVerifier) -> Self {
        Self {
            verifier,
            seen: BTreeMap::new(),
        }
    }

    /// The verifier.
    pub fn verifier(&self) -> &VenueWebhookVerifier {
        &self.verifier
    }

    /// Verify and accept one callback.
    ///
    /// A replay with the same id and body returns `replay: true`; the caller
    /// must not process it again. A replay that changes the signed body is
    /// refused.
    pub fn accept(
        &mut self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        now_est: i64,
    ) -> Result<InboundOutcome, WebhookError> {
        let event = self.verifier.verify_event(headers, body, now_est)?;
        let event_id = event.event_id();
        if let Some(previous) = self.seen.get(&event_id) {
            if previous == &event {
                return Ok(InboundOutcome {
                    event,
                    replay: true,
                });
            }
            return Err(WebhookError::PayloadConflict);
        }
        self.seen.insert(event_id, event.clone());
        Ok(InboundOutcome {
            event,
            replay: false,
        })
    }

    /// Number of distinct accepted events.
    pub fn accepted(&self) -> usize {
        self.seen.len()
    }
}
