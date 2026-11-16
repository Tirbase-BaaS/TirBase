// SPDX-License-Identifier: AGPL-3.0-only

//! Alerts and notification framework (CC-17).
//!
//! The runtime side of alerting: it decides who is paged, how often a delivery is
//! retried, when an unacknowledged alert escalates, and it keeps the audit trail.
//! The transports themselves live in the Apache-2.0 `tirbase-notify` crate so a
//! vendor can ship a closed connector (Slack, Teams, PagerDuty, SMS) against a
//! permissive interface; this module is the AGPL orchestration that a closed
//! plugin never has to link.
//!
//! Guarantees:
//!
//! * **At-least-once.** A delivery row is written before any transport is called
//!   and is only marked delivered after the transport accepts, so a crash between
//!   "sent" and "recorded" re-sends rather than losing the page. Re-sent
//!   deliveries carry the same alert id, deduplication key and delivery id, so a
//!   receiver that keys on them collapses the repeat.
//! * **No duplicate pages.** [`Alert`]s are deduplicated by
//!   `(tenant, dedup_key)`; raising the same event again returns
//!   [`RaiseOutcome::Duplicate`] and creates no second delivery. Deliveries are
//!   additionally unique per `(alert, channel, address, level)`.
//! * **Escalation.** An alert routed with `escalate_after_secs` and more than one
//!   level pages the next on-call level once the deadline passes without an
//!   acknowledgement.
//! * **Dead letters.** A delivery that fails permanently, or exhausts the retry
//!   policy, moves to the dead-letter table with its last error instead of
//!   disappearing.
//! * **Secrets by reference.** Channels carry a [`SecretRef`], never a value; the
//!   transport resolves it at delivery time and only a redacted reference ever
//!   reaches the database or the audit trail.
//!
//! See `docs/alerting.md` for the routing model, the config surface and the
//! acknowledgement workflow.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tirbase_notify::{SecretRef, Severity};

pub mod config;
pub mod engine;
pub mod routing;
pub mod store;

pub use config::AlertsConfig;
pub use engine::AlertRouter;
pub use routing::{ChannelConfig, PlannedDelivery, RouteRule, RoutingTable};
pub use store::AlertStore;

use crate::excursion::notifier::ExcursionNotification;

/// An alert to raise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    /// Stable alert id chosen by the caller.
    pub alert_id: String,
    /// Deduplication key: two alerts with the same key are one page.
    pub dedup_key: String,
    /// Routing rule (or reason code) the alert belongs to.
    pub rule_id: String,
    /// Severity, which route rules filter on.
    pub severity: Severity,
    /// Tenant owning the alert.
    pub tenant: String,
    /// Site the alert is about.
    pub site_id: String,
    /// Short title.
    pub title: String,
    /// Longer detail.
    pub body: String,
    /// Structured labels (sorted).
    pub labels: BTreeMap<String, String>,
    /// When the condition was observed (authenticated-time estimate).
    pub occurred_est: i64,
    /// Whether a human must acknowledge the alert.
    pub ack_required: bool,
}

impl Alert {
    /// A critical alert about `site_id`, which is the common case for a page.
    pub fn critical(
        alert_id: impl Into<String>,
        rule_id: impl Into<String>,
        tenant: impl Into<String>,
        site_id: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Self::new(
            alert_id,
            rule_id,
            Severity::Critical,
            tenant,
            site_id,
            title,
        )
    }

    /// An alert of any severity.
    pub fn new(
        alert_id: impl Into<String>,
        rule_id: impl Into<String>,
        severity: Severity,
        tenant: impl Into<String>,
        site_id: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Self {
            alert_id: alert_id.into(),
            dedup_key: String::new(),
            rule_id: rule_id.into(),
            severity,
            tenant: tenant.into(),
            site_id: site_id.into(),
            title: title.into(),
            body: String::new(),
            labels: BTreeMap::new(),
            occurred_est: 0,
            ack_required: severity >= Severity::Critical,
        }
    }

    /// Set the deduplication key explicitly.
    ///
    /// Without one, [`Alert::dedup_key`] is derived from the tenant, rule, site
    /// and alert id, so raising the same alert twice is one page.
    pub fn with_dedup_key(mut self, key: impl Into<String>) -> Self {
        self.dedup_key = key.into();
        self
    }

    /// Set the detail body.
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    /// Add a label.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Set the observation time.
    pub fn observed_at(mut self, occurred_est: i64) -> Self {
        self.occurred_est = occurred_est;
        self
    }

    /// Require (or not) a human acknowledgement.
    pub fn requiring_ack(mut self, required: bool) -> Self {
        self.ack_required = required;
        self
    }

    /// The deduplication key used by the store: the explicit one, or the derived
    /// default.
    pub fn effective_dedup_key(&self) -> String {
        if self.dedup_key.is_empty() {
            tirbase_notify::message::dedup_key(
                &self.tenant,
                &self.rule_id,
                &self.site_id,
                &self.alert_id,
            )
        } else {
            self.dedup_key.clone()
        }
    }

    /// Raise a CC-11 excursion notification as an alert.
    ///
    /// The excursion's own deduplication key is preserved, so the workflow and
    /// the alerting framework cannot disagree about whether two notifications are
    /// the same event.
    pub fn from_excursion(notification: &ExcursionNotification, severity: Severity) -> Self {
        let mut alert = Alert::new(
            notification.notification_id.clone(),
            format!("excursion:{}", notification.event.as_str()),
            severity,
            notification.tenant.clone(),
            notification.site_id.clone(),
            format!(
                "excursion {} on lot {}",
                notification.event.as_str().replace('_', " "),
                notification
                    .reasons
                    .first()
                    .cloned()
                    .unwrap_or_else(|| notification.record_id.clone())
            ),
        )
        .with_dedup_key(notification.notification_id.clone())
        .with_body(format!(
            "record {} reasons {}",
            notification.record_id,
            notification.reasons.join(",")
        ))
        .with_label("record_id", notification.record_id.clone())
        .observed_at(notification.enqueued_est);
        for reason in &notification.reasons {
            alert
                .labels
                .entry("reason".to_string())
                .or_insert_with(|| reason.clone());
        }
        alert
    }
}

/// What a raise did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaiseOutcome {
    /// First time this alert was raised: deliveries were queued.
    Raised {
        /// Alert id.
        alert_id: String,
        /// Deliveries queued (one per channel and recipient).
        deliveries: usize,
    },
    /// The deduplication key was already known: nothing was queued, so a repeated
    /// event cannot page twice.
    Duplicate {
        /// Id of the existing alert.
        alert_id: String,
        /// Deliveries that already exist for it.
        deliveries: usize,
    },
    /// No route matched: recorded and audited, but nobody was paged.
    Unrouted {
        /// Alert id.
        alert_id: String,
        /// Why no route matched.
        reason: String,
    },
}

impl RaiseOutcome {
    /// The alert id either way.
    pub fn alert_id(&self) -> &str {
        match self {
            RaiseOutcome::Raised { alert_id, .. }
            | RaiseOutcome::Duplicate { alert_id, .. }
            | RaiseOutcome::Unrouted { alert_id, .. } => alert_id,
        }
    }
}

/// What an acknowledgement did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckOutcome {
    /// This call acknowledged the alert.
    Acknowledged {
        /// Alert id.
        alert_id: String,
    },
    /// Someone already acknowledged it; the alert will escalate no further.
    AlreadyAcknowledged {
        /// Alert id.
        alert_id: String,
        /// Who acknowledged it first.
        by: String,
        /// When.
        at_est: i64,
    },
}

/// A stored alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRecord {
    /// Alert id.
    pub alert_id: String,
    /// Tenant.
    pub tenant: String,
    /// Deduplication key.
    pub dedup_key: String,
    /// Routing rule.
    pub rule_id: String,
    /// Severity.
    pub severity: Severity,
    /// Site.
    pub site_id: String,
    /// Title.
    pub title: String,
    /// Detail.
    pub body: String,
    /// Labels.
    pub labels: BTreeMap<String, String>,
    /// Observation time.
    pub occurred_est: i64,
    /// Whether acknowledgement is required.
    pub ack_required: bool,
    /// When it was acknowledged.
    pub acknowledged_est: Option<i64>,
    /// Who acknowledged it.
    pub acknowledged_by: Option<String>,
    /// Highest escalation level paged so far.
    pub escalation_level: u32,
    /// `open` until the alert is acknowledged or its deliveries all resolve.
    pub state: String,
    /// When the alert row was written.
    pub created_est: i64,
}

impl AlertRecord {
    /// `true` when the alert still needs a human.
    pub fn is_open(&self) -> bool {
        self.state == "open"
    }

    /// `true` when a human acknowledged it.
    pub fn is_acknowledged(&self) -> bool {
        self.acknowledged_est.is_some()
    }
}

/// One delivery attempt series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRecord {
    /// Delivery id, stable across retries.
    pub delivery_id: String,
    /// Alert it belongs to.
    pub alert_id: String,
    /// Channel name (transport registry key).
    pub channel: String,
    /// Recipient address or endpoint.
    pub address: String,
    /// Role that was paged.
    pub role: String,
    /// Escalation level.
    pub level: u32,
    /// Secret the channel needs, by reference only.
    pub secret_ref: Option<SecretRef>,
    /// `pending`, `delivered` or `dead_letter`.
    pub state: String,
    /// Attempts made so far.
    pub attempts: u32,
    /// When the next attempt is due.
    pub next_attempt_est: i64,
    /// Last redacted error.
    pub last_error: Option<String>,
    /// When the delivery was queued.
    pub created_est: i64,
    /// When it was accepted.
    pub delivered_est: Option<i64>,
}

/// A delivery that will not be attempted again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetter {
    /// Delivery id.
    pub delivery_id: String,
    /// Alert it belongs to.
    pub alert_id: String,
    /// Channel.
    pub channel: String,
    /// Address.
    pub address: String,
    /// Role.
    pub role: String,
    /// Level.
    pub level: u32,
    /// Attempts made.
    pub attempts: u32,
    /// Why it stopped.
    pub last_error: String,
    /// When it was queued.
    pub created_est: i64,
}

/// One audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Monotonic sequence.
    pub seq: i64,
    /// Alert the row belongs to.
    pub alert_id: String,
    /// When the row was written.
    pub at_est: i64,
    /// What happened (`raised`, `queued`, `delivered`, `retry`, `dead_letter`,
    /// `escalated`, `acknowledged`, `unrouted`).
    pub kind: String,
    /// Redacted detail.
    pub detail: String,
}

/// Outcome of one [`AlertNotifier::run_due`] pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliveryReport {
    /// Deliveries accepted this pass.
    pub delivered: usize,
    /// Deliveries that failed and are still pending.
    pub retried: usize,
    /// Deliveries that moved to the dead-letter table.
    pub dead_lettered: usize,
    /// Alerts that paged a higher escalation level.
    pub escalated: usize,
}

/// Why an alert operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertError {
    /// The store failed.
    Store(String),
    /// The alert does not exist.
    NotFound(String),
    /// Configuration is inconsistent (unknown channel, missing on-call rotation).
    Config(String),
}

impl std::fmt::Display for AlertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertError::Store(detail) => write!(f, "alert store: {detail}"),
            AlertError::NotFound(alert_id) => write!(f, "alert {alert_id:?} not found"),
            AlertError::Config(detail) => write!(f, "alert configuration: {detail}"),
        }
    }
}

impl std::error::Error for AlertError {}

/// The alerting surface the runtime depends on.
///
/// This trait is AGPL: it is the boundary between the runtime's delivery
/// bookkeeping and whatever channel plugins a deployment installs. Connectors
/// implement the Apache-2.0 `tirbase_notify::NotifyTransport` instead, so a
/// closed vendor plugin never links this trait.
pub trait AlertNotifier {
    /// Raise an alert: deduplicate, route, queue and attempt delivery.
    fn raise(&self, alert: &Alert) -> Result<RaiseOutcome, AlertError>;

    /// Acknowledge an alert, which stops its escalation.
    fn acknowledge(&self, alert_id: &str, by: &str, at_est: i64) -> Result<AckOutcome, AlertError>;

    /// Attempt every due delivery and escalate every overdue unacknowledged
    /// alert.
    fn run_due(&self, now_est: i64) -> Result<DeliveryReport, AlertError>;

    /// Open, unacknowledged alerts for a tenant.
    fn open_alerts(&self, tenant: &str) -> Result<Vec<AlertRecord>, AlertError>;

    /// One stored alert.
    fn record(&self, alert_id: &str) -> Result<AlertRecord, AlertError>;

    /// Every delivery series for an alert, in queue order.
    fn deliveries(&self, alert_id: &str) -> Result<Vec<DeliveryRecord>, AlertError>;

    /// Deliveries that will not be attempted again.
    fn dead_letters(&self) -> Result<Vec<DeadLetter>, AlertError>;

    /// Audit rows for an alert, oldest first.
    fn audit(&self, alert_id: &str) -> Result<Vec<AuditEntry>, AlertError>;
}

/// Secret reference a channel needs, exposed for configuration validation.
pub fn channel_secret(channel: &ChannelConfig) -> Option<&SecretRef> {
    channel.secret_ref.as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::excursion::notifier::NotificationEvent;

    fn notification() -> ExcursionNotification {
        ExcursionNotification {
            notification_id: "notif-1".to_string(),
            record_id: "rec-1".to_string(),
            channel: "pager".to_string(),
            event: NotificationEvent::QuarantineOpened,
            tenant: "tenant-a".to_string(),
            site_id: "site-1".to_string(),
            reasons: vec!["temperature_out_of_band".to_string()],
            mkt_c: None,
            opened_est: 1_000,
            enqueued_est: 1_010,
        }
    }

    #[test]
    fn an_alert_derives_its_dedup_key_when_none_is_given() {
        let alert = Alert::critical(
            "alert-1",
            "excursion:quarantine",
            "tenant-a",
            "site-1",
            "warm",
        );
        assert_eq!(alert.dedup_key, "");
        let derived = alert.effective_dedup_key();
        assert_eq!(derived.len(), 64);
        assert_eq!(derived, alert.effective_dedup_key());
        assert_ne!(
            derived,
            Alert::critical(
                "alert-2",
                "excursion:quarantine",
                "tenant-a",
                "site-1",
                "warm"
            )
            .effective_dedup_key()
        );
        let explicit = alert.clone().with_dedup_key("stored-key");
        assert_eq!(explicit.effective_dedup_key(), "stored-key");
    }

    #[test]
    fn an_excursion_notification_keeps_its_deduplication_identity() {
        let alert = Alert::from_excursion(&notification(), Severity::Critical);
        assert_eq!(alert.dedup_key, "notif-1");
        assert_eq!(alert.alert_id, "notif-1");
        assert_eq!(alert.tenant, "tenant-a");
        assert_eq!(alert.site_id, "site-1");
        assert_eq!(alert.rule_id, "excursion:quarantine_opened");
        assert_eq!(alert.occurred_est, 1_010);
        assert!(alert.ack_required);
        assert_eq!(alert.labels.get("record_id"), Some(&"rec-1".to_string()));
        assert_eq!(
            alert.labels.get("reason"),
            Some(&"temperature_out_of_band".to_string())
        );
    }

    #[test]
    fn only_critical_alerts_require_acknowledgement_by_default() {
        assert!(Alert::critical("a", "r", "t", "s", "x").ack_required);
        let warning = Alert::new("a", "r", Severity::Warning, "t", "s", "x");
        assert!(!warning.ack_required);
        assert!(warning.requiring_ack(true).ack_required);
    }
}
