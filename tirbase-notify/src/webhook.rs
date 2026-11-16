// SPDX-License-Identifier: Apache-2.0

//! HTTPS webhook connector.
//!
//! The request is fully described here — URL, headers, body — and performed by a
//! caller-supplied [`HttpPoster`], so this crate carries no HTTP stack and a
//! deployment keeps its own TLS settings.
//!
//! Headers:
//!
//! * `X-TirBase-Delivery` — the alert id this delivery is for,
//! * `X-TirBase-Timestamp` — Unix seconds used in the signature,
//! * `X-TirBase-Escalation` — escalation level,
//! * `X-TirBase-Signature` — `sha256=<hex HMAC-SHA256(secret, "timestamp.body")>`
//!   (omitted only when the channel has no secret reference),
//! * `Idempotency-Key` — the alert's deduplication key, so a receiver that keys
//!   on it collapses a retried delivery into one notification instead of paging
//!   twice.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::message::AlertMessage;
use crate::secrets::{SecretRef, SecretStore, SecretValue};
use crate::transport::{DeliveryFailure, DeliveryReceipt, DeliveryTarget, NotifyTransport};

/// One HTTP request, ready to be performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRequest {
    /// Absolute endpoint URL.
    pub url: String,
    /// Method, always `POST` today.
    pub method: &'static str,
    /// Headers in deterministic order.
    pub headers: BTreeMap<String, String>,
    /// JSON body.
    pub body: String,
}

/// Performs the request. Returns the HTTP status code, or a transport error.
pub trait HttpPoster: Send + Sync + std::fmt::Debug {
    /// POST `request`, returning the response status.
    fn post(&self, request: &WebhookRequest) -> Result<u16, String>;
}

/// What an HTTP status means for delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookDisposition {
    /// 2xx.
    Delivered,
    /// 408, 425, 429 and 5xx: try again later.
    Retriable,
    /// Everything else (bad request, auth, not found): do not retry.
    Permanent,
}

/// Classify a response status.
pub fn classify_status(status: u16) -> WebhookDisposition {
    match status {
        200..=299 => WebhookDisposition::Delivered,
        408 | 425 | 429 | 500..=599 => WebhookDisposition::Retriable,
        _ => WebhookDisposition::Permanent,
    }
}

/// The bytes the signature covers.
pub fn signing_bytes(timestamp: i64, body: &str) -> Vec<u8> {
    format!("{timestamp}.{body}").into_bytes()
}

/// HMAC-SHA256 of the timestamp and body, as `sha256=<hex>`.
pub fn signature_header(secret: &SecretValue, timestamp: i64, body: &str) -> String {
    format!(
        "sha256={}",
        hex::encode(hmac_sha256(
            secret.expose().as_bytes(),
            &signing_bytes(timestamp, body)
        ))
    )
}

/// Build the request for one delivery.
///
/// `secret` is `None` for a channel configured without a secret reference; the
/// signature header is then omitted rather than computed from an empty key.
pub fn build_request(
    url: &str,
    message: &AlertMessage,
    secret: Option<&SecretValue>,
    now_est: i64,
    allow_insecure_local: bool,
) -> Result<WebhookRequest, DeliveryFailure> {
    let secure = url.starts_with("https://");
    let local = url.starts_with("http://127.0.0.1")
        || url.starts_with("http://[::1]")
        || url.starts_with("http://localhost");
    if !secure && !(allow_insecure_local && local) {
        return Err(DeliveryFailure::permanent(
            "webhook endpoint must use https:// (loopback http only when explicitly allowed)",
        ));
    }
    let body = message.to_json();
    let mut headers = BTreeMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("Idempotency-Key".to_string(), message.dedup_key.clone());
    headers.insert("X-TirBase-Delivery".to_string(), message.alert_id.clone());
    headers.insert("X-TirBase-Timestamp".to_string(), now_est.to_string());
    headers.insert(
        "X-TirBase-Escalation".to_string(),
        message.escalation_level.to_string(),
    );
    if let Some(secret) = secret {
        headers.insert(
            "X-TirBase-Signature".to_string(),
            signature_header(secret, now_est, &body),
        );
    }
    Ok(WebhookRequest {
        url: url.to_string(),
        method: "POST",
        headers,
        body,
    })
}

/// Webhook channel: resolves the channel secret by reference, builds the
/// request, posts it, and classifies the response.
#[derive(Debug)]
pub struct WebhookTransport {
    channel: String,
    poster: Box<dyn HttpPoster>,
    secrets: Box<dyn SecretStore>,
    allow_insecure_local: bool,
}

impl WebhookTransport {
    /// A webhook connector for `channel`.
    pub fn new(
        channel: impl Into<String>,
        poster: Box<dyn HttpPoster>,
        secrets: Box<dyn SecretStore>,
    ) -> Self {
        Self {
            channel: channel.into(),
            poster,
            secrets,
            allow_insecure_local: false,
        }
    }

    /// Permit `http://` to a loopback address (local development only).
    pub fn allow_insecure_local(mut self, allow: bool) -> Self {
        self.allow_insecure_local = allow;
        self
    }

    fn resolve_secret(&self, reference: &SecretRef) -> Result<SecretValue, DeliveryFailure> {
        self.secrets
            .get(reference)
            .map_err(|error| DeliveryFailure::permanent(format!("secret {reference}: {error}")))
    }
}

impl NotifyTransport for WebhookTransport {
    fn channel(&self) -> &str {
        &self.channel
    }

    fn deliver(
        &self,
        message: &AlertMessage,
        target: &DeliveryTarget,
    ) -> Result<DeliveryReceipt, DeliveryFailure> {
        let secret = match target.secret_ref.as_ref() {
            Some(reference) => Some(self.resolve_secret(reference)?),
            None => None,
        };
        let request = build_request(
            &target.address,
            message,
            secret.as_ref(),
            message.occurred_est,
            self.allow_insecure_local,
        )?;
        match self.poster.post(&request) {
            Ok(status) => match classify_status(status) {
                WebhookDisposition::Delivered => Ok(DeliveryReceipt { provider_id: None }),
                WebhookDisposition::Retriable => {
                    Err(DeliveryFailure::retriable(format!("webhook HTTP {status}")))
                }
                WebhookDisposition::Permanent => {
                    Err(DeliveryFailure::permanent(format!("webhook HTTP {status}")))
                }
            },
            Err(error) => Err(DeliveryFailure::retriable(format!("webhook post: {error}"))),
        }
    }
}

/// RFC 2104 HMAC-SHA256.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Severity;
    use crate::secrets::MemorySecretStore;

    #[derive(Debug, Default)]
    struct RecordingPoster {
        status: u16,
        requests: std::sync::Mutex<Vec<WebhookRequest>>,
    }

    impl HttpPoster for RecordingPoster {
        fn post(&self, request: &WebhookRequest) -> Result<u16, String> {
            self.requests.lock().unwrap().push(request.clone());
            Ok(self.status)
        }
    }

    #[test]
    fn statuses_classify_into_retry_advice() {
        assert_eq!(classify_status(204), WebhookDisposition::Delivered);
        assert_eq!(classify_status(429), WebhookDisposition::Retriable);
        assert_eq!(classify_status(503), WebhookDisposition::Retriable);
        assert_eq!(classify_status(400), WebhookDisposition::Permanent);
        assert_eq!(classify_status(404), WebhookDisposition::Permanent);
    }

    #[test]
    fn delivery_signs_the_body_and_sends_an_idempotency_key() {
        let message = AlertMessage::new("alert-1", "dedup-1", Severity::Critical, "too warm");
        let secret = SecretValue::new("hook-secret");
        let request = build_request(
            "https://hooks.example.com/tirbase",
            &message,
            Some(&secret),
            1_770_000_000,
            false,
        )
        .expect("request");
        assert_eq!(request.method, "POST");
        assert_eq!(request.headers["Idempotency-Key"], "dedup-1");
        assert_eq!(request.headers["X-TirBase-Delivery"], "alert-1");
        assert_eq!(request.headers["X-TirBase-Timestamp"], "1770000000");
        let expected = signature_header(&secret, 1_770_000_000, &request.body);
        assert_eq!(request.headers["X-TirBase-Signature"], expected);
        assert!(expected.starts_with("sha256="));
        assert_eq!(expected.len(), "sha256=".len() + 64);
        // The secret never reaches the wire.
        assert!(!format!("{request:?}").contains("hook-secret"));
        assert!(!request.body.contains("hook-secret"));
    }

    #[test]
    fn insecure_endpoints_are_refused_unless_local_is_allowed() {
        let message = AlertMessage::new("a", "d", Severity::Warning, "t");
        assert!(build_request("http://example.com/hook", &message, None, 1, false).is_err());
        assert!(build_request("https://example.com/hook", &message, None, 1, false).is_ok());
        assert!(build_request("http://127.0.0.1:8080/hook", &message, None, 1, true).is_ok());
        assert!(build_request("http://127.0.0.1:8080/hook", &message, None, 1, false).is_err());
    }

    #[test]
    fn a_five_hundred_is_retriable_and_a_four_hundred_is_not() {
        let secrets = MemorySecretStore::new().with("hook", "s3cret");
        let target = DeliveryTarget {
            channel: "webhook".into(),
            address: "https://hooks.example.com/tirbase".into(),
            secret_ref: Some(SecretRef::new("hook").expect("ref")),
        };
        let message = AlertMessage::new("alert-1", "dedup-1", Severity::Critical, "too warm");

        let poster = Box::new(RecordingPoster {
            status: 503,
            ..Default::default()
        });
        let transport = WebhookTransport::new("webhook", poster, Box::new(secrets.clone()));
        assert!(
            transport
                .deliver(&message, &target)
                .expect_err("503")
                .retriable
        );

        let poster = Box::new(RecordingPoster {
            status: 422,
            ..Default::default()
        });
        let transport = WebhookTransport::new("webhook", poster, Box::new(secrets.clone()));
        let failure = transport.deliver(&message, &target).expect_err("422");
        assert!(!failure.retriable, "{failure}");

        // A missing secret is permanent and names only the reference.
        let transport = WebhookTransport::new(
            "webhook",
            Box::new(RecordingPoster::default()),
            Box::new(MemorySecretStore::new()),
        );
        let failure = transport
            .deliver(&message, &target)
            .expect_err("missing secret");
        assert!(!failure.retriable);
        assert!(failure.detail.contains("hook"), "{failure}");
    }
}
