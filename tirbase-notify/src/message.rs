// SPDX-License-Identifier: Apache-2.0

//! Alert model: severity, the alert message every connector receives, and its
//! deterministic renderings.
//!
//! Rendering never reads a clock and never iterates a `HashMap`, so the same
//! alert always produces the same payload, email body and console line.
//! Acknowledgement state is part of the message so a connector can render "acked
//! by X at Y", and the message carries the escalation level it was delivered at.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Alert severity, ordered from informational to paging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// No action needed.
    Info,
    /// Worth knowing, still no page.
    Notice,
    /// Degraded but non-urgent.
    Warning,
    /// Pages a human; escalates if unacknowledged.
    Critical,
}

impl Severity {
    /// Stable lower-case name, used in payloads and routing.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    /// Parse the stable name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "info" => Some(Severity::Info),
            "notice" => Some(Severity::Notice),
            "warning" => Some(Severity::Warning),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// Numeric rank, so a severity threshold is comparable in SQL too.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Notice => 1,
            Severity::Warning => 2,
            Severity::Critical => 3,
        }
    }

    /// Upper-case name for subjects and console lines.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Notice => "NOTICE",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// One alert handed to a connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertMessage {
    /// Stable alert id (unique per alert, not per delivery).
    pub alert_id: String,
    /// Deduplication key: two alerts with the same key are the same page.
    pub dedup_key: String,
    /// Routing rule (or reason code) the alert was raised under.
    pub rule_id: String,
    /// Severity.
    pub severity: Severity,
    /// Tenant owning the alert.
    pub tenant: String,
    /// Site the alert is about.
    pub site_id: String,
    /// On-call role this delivery is addressed to.
    pub role: String,
    /// Short human-readable title.
    pub title: String,
    /// Longer human-readable detail.
    pub body: String,
    /// Structured labels (sorted, so rendering is stable).
    pub labels: BTreeMap<String, String>,
    /// When the condition was observed (authenticated-time estimate, seconds).
    pub occurred_est: i64,
    /// Escalation level this delivery belongs to (1 is the first page).
    pub escalation_level: u32,
    /// Whether a human must acknowledge the alert.
    pub ack_required: bool,
    /// Deadline after which the alert escalates, if one was computed.
    pub ack_by_est: Option<i64>,
    /// When the alert was acknowledged, if it was.
    pub acknowledged_est: Option<i64>,
}

impl AlertMessage {
    /// Minimal well-formed message, for connector tests and local sinks.
    pub fn new(
        alert_id: impl Into<String>,
        dedup_key: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
    ) -> Self {
        Self {
            alert_id: alert_id.into(),
            dedup_key: dedup_key.into(),
            rule_id: "default".to_string(),
            severity,
            tenant: "default".to_string(),
            site_id: "unknown".to_string(),
            role: "on-call".to_string(),
            title: title.into(),
            body: String::new(),
            labels: BTreeMap::new(),
            occurred_est: 0,
            escalation_level: 1,
            ack_required: severity >= Severity::Critical,
            ack_by_est: None,
            acknowledged_est: None,
        }
    }

    /// `true` once a human acknowledged the alert.
    pub fn is_acknowledged(&self) -> bool {
        self.acknowledged_est.is_some()
    }

    /// One-line summary used as an email subject and a page title.
    pub fn subject(&self) -> String {
        let mut subject = format!(
            "[{}] {} {}: {}",
            self.severity.label(),
            self.site_id,
            self.rule_id,
            self.title
        );
        if self.acknowledged_est.is_some() {
            subject.push_str(" (acknowledged)");
        }
        subject
    }

    /// Plain-text body: title, detail, labels, identifiers and ack state.
    pub fn plain_text(&self) -> String {
        let mut text = String::new();
        text.push_str(&self.subject());
        text.push('\n');
        text.push_str(&format!(
            "severity: {}\nsite: {}\nrole: {}\nescalation level: {}\noccurred_est: {}\n",
            self.severity.as_str(),
            self.site_id,
            self.role,
            self.escalation_level,
            self.occurred_est
        ));
        if self.ack_required {
            match self.ack_by_est {
                Some(deadline) => text.push_str(&format!("acknowledge by est: {deadline}\n")),
                None => text.push_str("acknowledgement required\n"),
            }
        }
        match self.acknowledged_est {
            Some(at) => text.push_str(&format!("acknowledged at est: {at}\n")),
            None => text.push_str("unacknowledged\n"),
        }
        if !self.body.is_empty() {
            text.push('\n');
            text.push_str(&self.body);
            if !self.body.ends_with('\n') {
                text.push('\n');
            }
        }
        if !self.labels.is_empty() {
            text.push('\n');
            for (key, value) in &self.labels {
                text.push_str(&format!("{key}={value}\n"));
            }
        }
        text.push_str(&format!(
            "\nalert_id: {}\ndedup_key: {}\n",
            self.alert_id, self.dedup_key
        ));
        text
    }

    /// Deterministic JSON payload (object keys sorted by `serde_json`).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("alert message is serializable")
    }
}

/// Stable deduplication key for an alert.
///
/// The components are joined with a NUL byte, which identifiers cannot contain,
/// so distinct tuples cannot collide. `detail` is whatever distinguishes two
/// alerts of the same rule at the same site (for example the excursion record
/// id), so re-raising the same condition yields the same key.
pub fn dedup_key(tenant: &str, rule_id: &str, site_id: &str, detail: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(b"TirBase/v1/AlertDedupKey\0");
    for part in [tenant, rule_id, site_id, detail] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_and_round_trips() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Notice);
        assert!(Severity::Notice > Severity::Info);
        for severity in [
            Severity::Info,
            Severity::Notice,
            Severity::Warning,
            Severity::Critical,
        ] {
            assert_eq!(Severity::parse(severity.as_str()), Some(severity));
        }
        assert_eq!(Severity::Critical.rank(), 3);
        assert_eq!(Severity::parse("urgent"), None);
    }

    #[test]
    fn dedup_keys_are_stable_and_distinct() {
        let first = dedup_key("t", "excursion", "site-1", "rec-1");
        assert_eq!(first, dedup_key("t", "excursion", "site-1", "rec-1"));
        assert_eq!(first.len(), 64);
        assert_ne!(first, dedup_key("t", "excursion", "site-1", "rec-2"));
        assert_ne!(first, dedup_key("t", "excursion", "site-2", "rec-1"));
        assert_ne!(first, dedup_key("u", "excursion", "site-1", "rec-1"));
    }

    #[test]
    fn renderings_are_deterministic_and_carry_the_ack_state() {
        let mut message = AlertMessage::new("alert-1", "key-1", Severity::Critical, "too warm");
        message.body = "temperature out of band for 12 min".to_string();
        message.labels.insert("record_id".into(), "rec-1".into());
        message.labels.insert("lot".into(), "LOT-A".into());
        assert_eq!(message.to_json(), message.to_json());
        assert!(message.to_json().contains("\"ack_by_est\":null"));
        let text = message.plain_text();
        assert!(text.starts_with("[CRITICAL] unknown default: too warm"));
        assert!(text.contains("lot=LOT-A\nrecord_id=rec-1"));
        assert!(text.contains("acknowledgement required"));
        assert!(text.contains("unacknowledged"));

        message.acknowledged_est = Some(1_000);
        assert!(message.subject().ends_with("(acknowledged)"));
        assert!(message.is_acknowledged());
    }
}
