// SPDX-License-Identifier: Apache-2.0

//! The connector interface the AGPL runtime delivers through.
//!
//! A connector is one channel: an SMTP relay, a webhook endpoint, the local
//! console, or a closed vendor plugin (Slack, Teams, PagerDuty, SMS). The runtime
//! owns retries, deduplication, escalation and the audit; the connector owns only
//! "put this message on that wire" and reports whether a failure is worth
//! retrying.

use serde::{Deserialize, Serialize};

use crate::message::AlertMessage;
use crate::secrets::SecretRef;

/// What a channel is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    /// SMTP email.
    Email,
    /// HTTPS webhook.
    Webhook,
    /// Local console/test sink.
    Console,
}

impl ConnectorKind {
    /// Stable name used in configuration and audit rows.
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectorKind::Email => "email",
            ConnectorKind::Webhook => "webhook",
            ConnectorKind::Console => "console",
        }
    }

    /// Parse the stable name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "email" => Some(ConnectorKind::Email),
            "webhook" => Some(ConnectorKind::Webhook),
            "console" => Some(ConnectorKind::Console),
            _ => None,
        }
    }

    /// `true` when `DeliveryTarget::address` is a person's address rather than
    /// the channel's own endpoint.
    ///
    /// Email addresses a mailbox, so the routing layer fills in the on-call
    /// member's address. A webhook or the console has one fixed endpoint, and the
    /// recipient is described inside the payload instead.
    pub fn is_person_directed(self) -> bool {
        matches!(self, ConnectorKind::Email)
    }
}

/// Where one delivery goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryTarget {
    /// Configured channel name (the transport is registered under it).
    pub channel: String,
    /// Recipient mailbox, webhook URL or console label.
    pub address: String,
    /// Secret the channel needs, by reference only.
    pub secret_ref: Option<SecretRef>,
}

/// A delivery the transport accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceipt {
    /// Provider-side identifier, when the connector has one (webhook request id,
    /// SMTP queue id). Never a secret.
    pub provider_id: Option<String>,
}

/// A delivery the transport did not accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryFailure {
    /// `true` when retrying later could succeed (transport error, 5xx, 429);
    /// `false` when the message or target is wrong (bad address, 4xx, missing
    /// secret) and retrying would only delay the dead letter.
    pub retriable: bool,
    /// Redacted detail safe to persist in the audit trail.
    pub detail: String,
}

impl DeliveryFailure {
    /// Failure worth retrying.
    pub fn retriable(detail: impl Into<String>) -> Self {
        Self {
            retriable: true,
            detail: detail.into(),
        }
    }

    /// Failure that will not succeed on retry.
    pub fn permanent(detail: impl Into<String>) -> Self {
        Self {
            retriable: false,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for DeliveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.detail,
            if self.retriable {
                "retriable"
            } else {
                "permanent"
            }
        )
    }
}

/// One delivery channel.
///
/// Implementations must be synchronous and must not block indefinitely; the
/// runtime treats an `Err` as "not delivered" and decides whether to retry.
/// Implementations must never log or persist a secret.
pub trait NotifyTransport: Send + Sync + std::fmt::Debug {
    /// Channel name this transport is registered under.
    fn channel(&self) -> &str;

    /// Attempt one delivery.
    fn deliver(
        &self,
        message: &AlertMessage,
        target: &DeliveryTarget,
    ) -> Result<DeliveryReceipt, DeliveryFailure>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_kinds_round_trip_and_email_is_person_directed() {
        for kind in [
            ConnectorKind::Email,
            ConnectorKind::Webhook,
            ConnectorKind::Console,
        ] {
            assert_eq!(ConnectorKind::parse(kind.as_str()), Some(kind));
        }
        assert!(ConnectorKind::Email.is_person_directed());
        assert!(!ConnectorKind::Webhook.is_person_directed());
        assert_eq!(ConnectorKind::parse("slack"), None);
    }

    #[test]
    fn failures_state_whether_a_retry_can_help() {
        assert!(DeliveryFailure::retriable("connect timeout").retriable);
        assert!(!DeliveryFailure::permanent("malformed address").retriable);
        assert_eq!(
            DeliveryFailure::retriable("timeout").to_string(),
            "timeout (retriable)"
        );
    }
}
