// SPDX-License-Identifier: AGPL-3.0-only

//! Alerting configuration (CC-17).
//!
//! ```toml
//! [alerts]
//! secrets_dir = "/etc/tirbase/secrets"
//!
//! [alerts.retry]
//! max_attempts = 6
//! base_secs = 15
//! max_secs = 900
//!
//! [[alerts.channels]]
//! name = "email"
//! kind = "email"
//! endpoint = "alerts@tirbase.local"
//! secret_ref = "smtp/alerting"      # a name, never a value
//!
//! [[alerts.channels]]
//! name = "console"
//! kind = "console"
//! endpoint = "-"
//!
//! [[alerts.routes]]
//! rule_id = "excursion"
//! min_severity = "warning"
//! site_id = "site-1"                # optional; omit for every site
//! roles = ["cold-chain"]
//! channels = ["email", "console"]
//! ack_required = true
//! escalate_after_secs = 900
//! max_level = 2
//!
//! [[alerts.on_call]]
//! role = "cold-chain"
//! level = 1
//! start_est = 1770000000
//! period_secs = 604800
//! members = ["ana@example.com", "bo@example.com"]
//! ```
//!
//! Secrets are configuration **references**. Every struct denies unknown fields,
//! so an inline `secret`/`password`/`token` key is a hard error rather than a
//! value that quietly ends up in a config file and in the repository.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tirbase_notify::backoff::RetryPolicy;
use tirbase_notify::oncall::{OnCallSchedule, Rotation};
use tirbase_notify::{ConnectorKind, SecretRef, Severity};

use crate::alerts::routing::{ChannelConfig, RouteRule, RoutingTable};
use crate::alerts::AlertError;

/// The `[alerts]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsConfig {
    /// Directory holding one file per secret, resolved by reference.
    pub secrets_dir: PathBuf,
    /// Retry policy; defaults are used when absent.
    #[serde(default)]
    pub retry: RetryDocument,
    /// Channels.
    #[serde(default)]
    pub channels: Vec<ChannelDocument>,
    /// Routes.
    #[serde(default)]
    pub routes: Vec<RouteDocument>,
    /// On-call rotations.
    #[serde(default)]
    pub on_call: Vec<OnCallDocument>,
}

/// `[alerts.retry]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryDocument {
    /// Attempts before dead-lettering.
    pub max_attempts: u32,
    /// First delay.
    pub base_secs: i64,
    /// Delay ceiling.
    pub max_secs: i64,
}

impl Default for RetryDocument {
    fn default() -> Self {
        let policy = RetryPolicy::default();
        Self {
            max_attempts: policy.max_attempts,
            base_secs: policy.base_secs,
            max_secs: policy.max_secs,
        }
    }
}

/// `[[alerts.channels]]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelDocument {
    /// Channel name.
    pub name: String,
    /// `email`, `webhook` or `console`.
    pub kind: String,
    /// Sender mailbox, webhook URL or console label.
    pub endpoint: String,
    /// Secret name, never a secret value.
    #[serde(default)]
    pub secret_ref: Option<String>,
}

/// `[[alerts.routes]]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDocument {
    /// Rule id.
    pub rule_id: String,
    /// `info`, `notice`, `warning` or `critical`.
    pub min_severity: String,
    /// Site the rule is limited to.
    #[serde(default)]
    pub site_id: Option<String>,
    /// Roles to page.
    pub roles: Vec<String>,
    /// Channels to use.
    pub channels: Vec<String>,
    /// Whether acknowledgement is required; defaults from the severity.
    #[serde(default)]
    pub ack_required: Option<bool>,
    /// Escalation delay.
    #[serde(default)]
    pub escalate_after_secs: Option<i64>,
    /// Highest escalation level.
    #[serde(default)]
    pub max_level: Option<u32>,
}

/// `[[alerts.on_call]]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnCallDocument {
    /// Role.
    pub role: String,
    /// Escalation level.
    pub level: u32,
    /// When member 0 took over.
    pub start_est: i64,
    /// Rotation length.
    pub period_secs: i64,
    /// Members in handover order.
    pub members: Vec<String>,
}

/// The gateway document's `[alerts]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertsDocument {
    alerts: AlertsConfig,
}

impl AlertsConfig {
    /// Parse a document containing the `[alerts]` section.
    pub fn from_toml(text: &str) -> Result<Self, AlertError> {
        let document: AlertsDocument = toml::from_str(text)
            .map_err(|error| AlertError::Config(format!("alerts configuration: {error}")))?;
        Ok(document.alerts)
    }

    /// The secret store root.
    pub fn secrets_dir(&self) -> &Path {
        &self.secrets_dir
    }

    /// The retry policy.
    pub fn retry_policy(&self) -> Result<RetryPolicy, AlertError> {
        RetryPolicy::new(
            self.retry.max_attempts,
            self.retry.base_secs,
            self.retry.max_secs,
        )
        .map_err(AlertError::Config)
    }

    /// The on-call schedule.
    pub fn on_call_schedule(&self) -> Result<OnCallSchedule, AlertError> {
        let rotations = self
            .on_call
            .iter()
            .map(|rotation| Rotation {
                role: rotation.role.clone(),
                level: rotation.level,
                start_est: rotation.start_est,
                period_secs: rotation.period_secs,
                members: rotation.members.clone(),
            })
            .collect::<Vec<_>>();
        OnCallSchedule::new(rotations).map_err(AlertError::Config)
    }

    /// Validate and build the routing table.
    pub fn routing(&self) -> Result<RoutingTable, AlertError> {
        let mut channels = Vec::with_capacity(self.channels.len());
        for channel in &self.channels {
            let kind = ConnectorKind::parse(&channel.kind).ok_or_else(|| {
                AlertError::Config(format!(
                    "channel {:?} has unknown kind {:?}",
                    channel.name, channel.kind
                ))
            })?;
            let secret_ref = channel
                .secret_ref
                .as_ref()
                .map(|name| SecretRef::new(name.clone()))
                .transpose()
                .map_err(|error| {
                    AlertError::Config(format!("channel {:?}: {error}", channel.name))
                })?;
            if kind == ConnectorKind::Webhook && !channel.endpoint.starts_with("https://") {
                return Err(AlertError::Config(format!(
                    "webhook channel {:?} must use an https:// endpoint",
                    channel.name
                )));
            }
            if kind == ConnectorKind::Email && !channel.endpoint.contains('@') {
                return Err(AlertError::Config(format!(
                    "email channel {:?} needs a sender mailbox",
                    channel.name
                )));
            }
            // Authentication may be optional (a local relay), so a missing
            // secret reference is not an error; a present one is always a name.
            channels.push(ChannelConfig {
                name: channel.name.clone(),
                kind,
                endpoint: channel.endpoint.clone(),
                secret_ref,
            });
        }

        let mut rules = Vec::with_capacity(self.routes.len());
        for route in &self.routes {
            let min_severity = Severity::parse(&route.min_severity).ok_or_else(|| {
                AlertError::Config(format!(
                    "route {:?} has unknown severity {:?}",
                    route.rule_id, route.min_severity
                ))
            })?;
            let mut rule = RouteRule::new(
                route.rule_id.clone(),
                min_severity,
                route.roles.first().cloned().unwrap_or_default(),
                route.channels.first().cloned().unwrap_or_default(),
            );
            rule.roles = route.roles.clone();
            rule.channels = route.channels.clone();
            rule.site_id = route.site_id.clone();
            rule.ack_required = route
                .ack_required
                .unwrap_or(min_severity >= Severity::Critical);
            if let Some(seconds) = route.escalate_after_secs {
                rule = rule.escalating(seconds, route.max_level.unwrap_or(2));
            } else if let Some(level) = route.max_level {
                if level > 1 {
                    return Err(AlertError::Config(format!(
                        "route {:?} sets max_level without escalate_after_secs",
                        route.rule_id
                    )));
                }
            }
            rules.push(rule);
        }

        RoutingTable::new(rules, channels, self.on_call_schedule()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &str = r#"
[alerts]
secrets_dir = "/etc/tirbase/secrets"

[[alerts.channels]]
name = "email"
kind = "email"
endpoint = "alerts@tirbase.local"
secret_ref = "smtp/alerting"

[[alerts.channels]]
name = "console"
kind = "console"
endpoint = "-"

[[alerts.routes]]
rule_id = "excursion"
min_severity = "warning"
roles = ["cold-chain"]
channels = ["email", "console"]
escalate_after_secs = 900
max_level = 2

[[alerts.on_call]]
role = "cold-chain"
level = 1
start_est = 1770000000
period_secs = 604800
members = ["ana@example.com", "bo@example.com"]

[[alerts.on_call]]
role = "cold-chain"
level = 2
start_est = 1770000000
period_secs = 604800
members = ["lead@example.com"]
"#;

    #[test]
    fn a_complete_document_builds_a_routing_table() {
        let config = AlertsConfig::from_toml(DOCUMENT).expect("config");
        let routing = config.routing().expect("routing");
        assert_eq!(routing.channels().len(), 2);
        assert_eq!(routing.rules().len(), 1);
        assert_eq!(
            routing
                .channels()
                .get("email")
                .and_then(|channel| channel.secret_ref.as_ref())
                .map(|reference| reference.as_str()),
            Some("smtp/alerting")
        );
        assert_eq!(config.retry_policy().expect("retry").max_attempts, 6);
        assert_eq!(config.secrets_dir(), Path::new("/etc/tirbase/secrets"));
    }

    #[test]
    fn an_inline_secret_is_an_unknown_field_not_a_value() {
        let document = DOCUMENT.replace("secret_ref = \"smtp/alerting\"", "secret = \"hunter2\"");
        let error = AlertsConfig::from_toml(&document).expect_err("inline secret");
        assert!(error.to_string().contains("unknown field"), "{error}");
        assert!(error.to_string().contains("secret"), "{error}");
        // Nothing was parsed, so nothing could be stored: the only way to give
        // a channel a secret is a reference.
        assert!(AlertsConfig::from_toml(DOCUMENT).is_ok());
    }

    #[test]
    fn invalid_kinds_severities_and_escalation_are_rejected() {
        let unknown_kind = DOCUMENT.replace("kind = \"console\"", "kind = \"carrier-pigeon\"");
        assert!(AlertsConfig::from_toml(&unknown_kind)
            .expect("config")
            .routing()
            .is_err());

        let unknown_severity =
            DOCUMENT.replace("min_severity = \"warning\"", "min_severity = \"urgent\"");
        assert!(AlertsConfig::from_toml(&unknown_severity)
            .expect("config")
            .routing()
            .is_err());

        let level_without_delay = DOCUMENT
            .replace("escalate_after_secs = 900\n", "")
            .replace("max_level = 2", "max_level = 3");
        let config = AlertsConfig::from_toml(&level_without_delay).expect("config");
        assert!(config.routing().is_err());

        let plain_http = DOCUMENT
            .replace("kind = \"console\"", "kind = \"webhook\"")
            .replace(
                "endpoint = \"-\"",
                "endpoint = \"http://hooks.example.com/x\"",
            );
        let config = AlertsConfig::from_toml(&plain_http).expect("config");
        assert!(config.routing().is_err());
    }
}
