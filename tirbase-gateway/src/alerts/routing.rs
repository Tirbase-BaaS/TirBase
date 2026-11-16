// SPDX-License-Identifier: AGPL-3.0-only

//! Routing: severity, site, role and on-call schedule (CC-17).
//!
//! A [`RouteRule`] says which severities and sites it covers, which on-call roles
//! it pages and which channels carry the page. Resolution is deterministic:
//!
//! 1. A site-specific rule wins over a global one; among equally specific rules
//!    the lowest `rule_id` wins, so a configuration cannot page twice because of
//!    list order.
//! 2. Each role is resolved through the on-call rotation **at the alert's own
//!    observation time**, so replaying a historical alert pages the person who
//!    was on call then.
//! 3. Person-directed channels (email) are addressed to the on-call member;
//!    group channels (webhook, console) use the channel's own endpoint and
//!    describe the role inside the payload.
//! 4. Duplicate `(channel, address)` pairs are collapsed, so a rule listing two
//!    roles that resolve to the same mailbox sends one page, not two.

use std::collections::{BTreeMap, BTreeSet};

use tirbase_notify::oncall::OnCallSchedule;
use tirbase_notify::{ConnectorKind, SecretRef, Severity};

use crate::alerts::{Alert, AlertError};

/// One configured channel: a transport plus where it points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelConfig {
    /// Name the transport is registered under.
    pub name: String,
    /// What kind of channel it is.
    pub kind: ConnectorKind,
    /// Endpoint: mailbox of the sender for email relays, URL for a webhook, a
    /// label for the console.
    pub endpoint: String,
    /// Secret the channel needs, by reference only.
    pub secret_ref: Option<SecretRef>,
}

/// One routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRule {
    /// Rule id; also the lowest-precedence tie-break.
    pub rule_id: String,
    /// Minimum severity the rule covers.
    pub min_severity: Severity,
    /// Site the rule is limited to; `None` matches every site.
    pub site_id: Option<String>,
    /// On-call roles to page.
    pub roles: Vec<String>,
    /// Channels to deliver on.
    pub channels: Vec<String>,
    /// Whether the alert needs acknowledgement.
    pub ack_required: bool,
    /// Seconds after which an unacknowledged alert escalates.
    pub escalate_after_secs: Option<i64>,
    /// Highest escalation level to page.
    pub max_level: u32,
}

impl RouteRule {
    /// A global rule for one severity and above, paging one role on one channel.
    pub fn new(
        rule_id: impl Into<String>,
        min_severity: Severity,
        role: impl Into<String>,
        channel: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            min_severity,
            site_id: None,
            roles: vec![role.into()],
            channels: vec![channel.into()],
            ack_required: min_severity >= Severity::Critical,
            escalate_after_secs: None,
            max_level: 1,
        }
    }

    /// Limit the rule to one site.
    pub fn for_site(mut self, site_id: impl Into<String>) -> Self {
        self.site_id = Some(site_id.into());
        self
    }

    /// Page several roles.
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Deliver on several channels.
    pub fn with_channels(mut self, channels: Vec<String>) -> Self {
        self.channels = channels;
        self
    }

    /// Escalate after `seconds` without an acknowledgement, up to `max_level`.
    pub fn escalating(mut self, seconds: i64, max_level: u32) -> Self {
        self.escalate_after_secs = Some(seconds);
        self.max_level = max_level.max(1);
        self
    }

    /// Whether the rule covers `alert`.
    pub fn matches(&self, alert: &Alert) -> bool {
        alert.severity >= self.min_severity
            && self
                .site_id
                .as_deref()
                .map(|site| site == alert.site_id)
                .unwrap_or(true)
    }
}

/// One delivery the router will queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedDelivery {
    /// Channel name.
    pub channel: String,
    /// Recipient address or endpoint.
    pub address: String,
    /// Role being paged.
    pub role: String,
    /// Escalation level.
    pub level: u32,
    /// Secret the channel needs, by reference.
    pub secret_ref: Option<SecretRef>,
}

/// The rules, channels and on-call schedule a deployment runs.
#[derive(Debug, Clone)]
pub struct RoutingTable {
    rules: Vec<RouteRule>,
    channels: BTreeMap<String, ChannelConfig>,
    on_call: OnCallSchedule,
}

impl RoutingTable {
    /// Validate and assemble a routing table.
    ///
    /// Every referenced channel must be configured, rule ids must be unique, and
    /// every rule must page at least one role on at least one channel — otherwise
    /// a rule could silently swallow a page.
    pub fn new(
        rules: Vec<RouteRule>,
        channels: Vec<ChannelConfig>,
        on_call: OnCallSchedule,
    ) -> Result<Self, AlertError> {
        let mut by_name: BTreeMap<String, ChannelConfig> = BTreeMap::new();
        for channel in channels {
            if channel.name.trim().is_empty() {
                return Err(AlertError::Config("channel without a name".to_string()));
            }
            if by_name.insert(channel.name.clone(), channel).is_some() {
                return Err(AlertError::Config("duplicate channel name".to_string()));
            }
        }
        let mut seen_rules = BTreeSet::new();
        for rule in &rules {
            if rule.rule_id.trim().is_empty() {
                return Err(AlertError::Config("route rule without an id".to_string()));
            }
            if !seen_rules.insert(rule.rule_id.clone()) {
                return Err(AlertError::Config(format!(
                    "duplicate route rule {:?}",
                    rule.rule_id
                )));
            }
            if rule.roles.is_empty() {
                return Err(AlertError::Config(format!(
                    "route rule {:?} pages no role",
                    rule.rule_id
                )));
            }
            if rule.channels.is_empty() {
                return Err(AlertError::Config(format!(
                    "route rule {:?} uses no channel",
                    rule.rule_id
                )));
            }
            if let Some(seconds) = rule.escalate_after_secs {
                if seconds <= 0 {
                    return Err(AlertError::Config(format!(
                        "route rule {:?} must escalate after a positive delay",
                        rule.rule_id
                    )));
                }
                if rule.max_level < 2 {
                    return Err(AlertError::Config(format!(
                        "route rule {:?} escalates but allows only level {}",
                        rule.rule_id, rule.max_level
                    )));
                }
            }
            for channel in &rule.channels {
                if !by_name.contains_key(channel) {
                    return Err(AlertError::Config(format!(
                        "route rule {:?} references unknown channel {channel:?}",
                        rule.rule_id
                    )));
                }
            }
        }
        let mut rules = rules;
        rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        Ok(Self {
            rules,
            channels: by_name,
            on_call,
        })
    }

    /// The rule that handles `alert`, if any.
    ///
    /// Site-specific rules win; otherwise the lowest-id global rule wins.
    pub fn rule_for(&self, alert: &Alert) -> Option<&RouteRule> {
        self.rules
            .iter()
            .filter(|rule| rule.matches(alert))
            .min_by_key(|rule| (rule.site_id.is_none(), rule.rule_id.clone()))
    }

    /// One rule by id.
    pub fn rule_by_id(&self, rule_id: &str) -> Option<&RouteRule> {
        self.rules.iter().find(|rule| rule.rule_id == rule_id)
    }

    /// Planned deliveries for `alert` at `level`.
    ///
    /// Fails when a role has no on-call member at that level: silently dropping a
    /// page because a rotation is misconfigured is exactly the failure this
    /// module exists to prevent.
    pub fn resolve(
        &self,
        alert: &Alert,
        level: u32,
        at_est: i64,
    ) -> Result<(Vec<PlannedDelivery>, &RouteRule), AlertError> {
        let rule = self
            .rule_for(alert)
            .ok_or_else(|| AlertError::Config(format!("no route matches {}", alert.rule_id)))?;
        let mut planned: Vec<PlannedDelivery> = Vec::new();
        for role in &rule.roles {
            let member = self.on_call.on_call(role, level, at_est).ok_or_else(|| {
                AlertError::Config(format!(
                    "no on-call rotation for role {role:?} at level {level}"
                ))
            })?;
            for channel_name in &rule.channels {
                let channel = self.channels.get(channel_name).ok_or_else(|| {
                    AlertError::Config(format!("unknown channel {channel_name:?}"))
                })?;
                let address = if channel.kind.is_person_directed() {
                    member.to_string()
                } else {
                    channel.endpoint.clone()
                };
                let delivery = PlannedDelivery {
                    channel: channel.name.clone(),
                    address,
                    role: role.clone(),
                    level,
                    secret_ref: channel.secret_ref.clone(),
                };
                if !planned.contains(&delivery) {
                    planned.push(delivery);
                }
            }
        }
        planned.sort_by(|left, right| {
            (&left.channel, &left.address, left.level).cmp(&(
                &right.channel,
                &right.address,
                right.level,
            ))
        });
        Ok((planned, rule))
    }

    /// Configured channels.
    pub fn channels(&self) -> &BTreeMap<String, ChannelConfig> {
        &self.channels
    }

    /// The on-call schedule.
    pub fn on_call(&self) -> &OnCallSchedule {
        &self.on_call
    }

    /// Configured rules, sorted by id.
    pub fn rules(&self) -> &[RouteRule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_notify::oncall::Rotation;

    fn schedule() -> OnCallSchedule {
        OnCallSchedule::new(vec![
            Rotation {
                role: "cold-chain".to_string(),
                level: 1,
                start_est: 0,
                period_secs: 86_400,
                members: vec!["ana@example.com".to_string()],
            },
            Rotation {
                role: "cold-chain".to_string(),
                level: 2,
                start_est: 0,
                period_secs: 86_400,
                members: vec!["lead@example.com".to_string()],
            },
        ])
        .expect("schedule")
    }

    fn channels() -> Vec<ChannelConfig> {
        vec![
            ChannelConfig {
                name: "email".to_string(),
                kind: ConnectorKind::Email,
                endpoint: "alerts@tirbase.local".to_string(),
                secret_ref: None,
            },
            ChannelConfig {
                name: "console".to_string(),
                kind: ConnectorKind::Console,
                endpoint: "-".to_string(),
                secret_ref: None,
            },
        ]
    }

    #[test]
    fn site_rules_win_and_global_rules_still_apply_elsewhere() {
        let global = RouteRule::new("global", Severity::Warning, "cold-chain", "console");
        let site =
            RouteRule::new("site-1", Severity::Warning, "cold-chain", "email").for_site("site-1");
        let table = RoutingTable::new(vec![global, site], channels(), schedule()).expect("routing");
        let alert = Alert::new("a", "r", Severity::Critical, "t", "site-1", "x");
        assert_eq!(
            table.rule_for(&alert).map(|rule| rule.rule_id.as_str()),
            Some("site-1")
        );
        let delivery = table.resolve(&alert, 1, 10).expect("resolve").0;
        assert_eq!(delivery.len(), 1);
        assert_eq!(delivery[0].address, "ana@example.com");

        let other = Alert::new("a", "r", Severity::Critical, "t", "site-2", "x");
        assert_eq!(
            table.rule_for(&other).map(|rule| rule.rule_id.as_str()),
            Some("global")
        );
    }

    #[test]
    fn severity_below_the_threshold_is_not_routed() {
        let table = RoutingTable::new(
            vec![RouteRule::new(
                "critical-only",
                Severity::Critical,
                "cold-chain",
                "console",
            )],
            channels(),
            schedule(),
        )
        .expect("routing");
        let warning = Alert::new("a", "r", Severity::Warning, "t", "site-1", "x");
        assert!(table.rule_for(&warning).is_none());
        assert!(table.resolve(&warning, 1, 10).is_err());
    }

    #[test]
    fn duplicate_recipients_are_collapsed_and_levels_use_their_own_rotation() {
        let rule = RouteRule::new("r", Severity::Critical, "cold-chain", "email")
            .with_roles(vec!["cold-chain".to_string(), "cold-chain".to_string()]);
        let table = RoutingTable::new(vec![rule], channels(), schedule()).expect("routing");
        let alert = Alert::new("a", "r", Severity::Critical, "t", "site-1", "x");
        assert_eq!(table.resolve(&alert, 1, 10).expect("level 1").0.len(), 1);
        let level_two = table.resolve(&alert, 2, 10).expect("level 2").0;
        assert_eq!(level_two[0].address, "lead@example.com");
        assert_eq!(level_two[0].level, 2);
    }

    #[test]
    fn an_inconsistent_table_is_rejected() {
        let rule = RouteRule::new("r", Severity::Critical, "cold-chain", "pager");
        assert!(RoutingTable::new(vec![rule], channels(), schedule()).is_err());
        let empty = RouteRule {
            roles: Vec::new(),
            ..RouteRule::new("r", Severity::Critical, "cold-chain", "console")
        };
        assert!(RoutingTable::new(vec![empty], channels(), schedule()).is_err());
        let repeated = RouteRule::new("r", Severity::Critical, "cold-chain", "console");
        assert!(
            RoutingTable::new(vec![repeated.clone(), repeated], channels(), schedule()).is_err()
        );
        let stub =
            RouteRule::new("r", Severity::Critical, "cold-chain", "console").escalating(60, 1);
        assert!(RoutingTable::new(vec![stub], channels(), schedule()).is_err());
    }

    #[test]
    fn a_missing_on_call_rotation_is_an_error_not_a_silent_drop() {
        let rule = RouteRule::new("r", Severity::Critical, "nobody", "console");
        let table = RoutingTable::new(vec![rule], channels(), schedule()).expect("routing");
        let alert = Alert::new("a", "r", Severity::Critical, "t", "site-1", "x");
        let error = table.resolve(&alert, 1, 10).expect_err("no rotation");
        assert!(error.to_string().contains("no on-call rotation"), "{error}");
    }
}
