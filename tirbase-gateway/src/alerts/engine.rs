// SPDX-License-Identifier: AGPL-3.0-only

//! The alert engine: deduplicate, route, deliver, retry, escalate, audit (CC-17).
//!
//! Delivery is at-least-once: a delivery row is written before the transport is
//! called and is only marked delivered once the transport accepts it, so a crash
//! between "sent" and "recorded" re-sends with the same delivery id and
//! deduplication key. Deduplication happens on the alert, not on the delivery:
//! raising the same `(tenant, dedup_key)` again queues nothing at all.
//!
//! The engine never reads a clock. `raise` uses the alert's own observation time
//! as its creation time, and [`AlertNotifier::run_due`] takes the current time
//! from its caller, so every decision is reproducible from stored state.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use tirbase_notify::backoff::RetryPolicy;
use tirbase_notify::message::AlertMessage;
use tirbase_notify::{DeliveryFailure, DeliveryTarget, NotifyTransport};

use crate::alerts::routing::{PlannedDelivery, RoutingTable};
use crate::alerts::{
    AckOutcome, Alert, AlertError, AlertNotifier, AlertRecord, AlertStore, AuditEntry, DeadLetter,
    DeliveryRecord, DeliveryReport, RaiseOutcome,
};

/// The runtime's alert notifier.
pub struct AlertRouter {
    store: AlertStore,
    routing: RoutingTable,
    transports: BTreeMap<String, Box<dyn NotifyTransport>>,
    retry: RetryPolicy,
}

impl std::fmt::Debug for AlertRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertRouter")
            .field("channels", &self.transports.keys())
            .field("rules", &self.routing.rules().len())
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

impl AlertRouter {
    /// Assemble a router.
    ///
    /// Every configured channel needs exactly one transport, and a transport for
    /// an unconfigured channel is an error: a typo must not leave a channel that
    /// silently never delivers.
    pub fn new(
        store: AlertStore,
        routing: RoutingTable,
        transports: Vec<Box<dyn NotifyTransport>>,
        retry: RetryPolicy,
    ) -> Result<Self, AlertError> {
        let mut by_name: BTreeMap<String, Box<dyn NotifyTransport>> = BTreeMap::new();
        for transport in transports {
            let name = transport.channel().to_string();
            if !routing.channels().contains_key(&name) {
                return Err(AlertError::Config(format!(
                    "transport registered for unconfigured channel {name:?}"
                )));
            }
            if by_name.insert(name.clone(), transport).is_some() {
                return Err(AlertError::Config(format!(
                    "two transports registered for channel {name:?}"
                )));
            }
        }
        for name in routing.channels().keys() {
            if !by_name.contains_key(name) {
                return Err(AlertError::Config(format!(
                    "channel {name:?} has no transport"
                )));
            }
        }
        Ok(Self {
            store,
            routing,
            transports: by_name,
            retry,
        })
    }

    /// Assemble a router with the default retry policy.
    pub fn with_default_retry(
        store: AlertStore,
        routing: RoutingTable,
        transports: Vec<Box<dyn NotifyTransport>>,
    ) -> Result<Self, AlertError> {
        Self::new(store, routing, transports, RetryPolicy::default())
    }

    /// The routing table, for inspection.
    pub fn routing(&self) -> &RoutingTable {
        &self.routing
    }

    /// The retry policy.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }

    /// Raise and attempt delivery.
    pub fn raise_alert(&self, alert: &Alert) -> Result<RaiseOutcome, AlertError> {
        let dedup_key = alert.effective_dedup_key();
        if let Some(existing) = self.store.find_by_dedup(&alert.tenant, &dedup_key)? {
            return Ok(RaiseOutcome::Duplicate {
                deliveries: self.store.delivery_count(&existing.alert_id)?,
                alert_id: existing.alert_id,
            });
        }
        if !self
            .store
            .insert_alert(alert, &dedup_key, alert.occurred_est)?
        {
            // Another writer won the race: this is still the same event.
            let existing = self.store.find_by_dedup(&alert.tenant, &dedup_key)?;
            return Ok(match existing {
                Some(existing) => RaiseOutcome::Duplicate {
                    deliveries: self.store.delivery_count(&existing.alert_id)?,
                    alert_id: existing.alert_id,
                },
                None => RaiseOutcome::Unrouted {
                    alert_id: alert.alert_id.clone(),
                    reason: "alert could not be stored".to_string(),
                },
            });
        }
        self.store.audit(
            &alert.alert_id,
            alert.occurred_est,
            "raised",
            &format!(
                "rule={} severity={} dedup_key={}",
                alert.rule_id,
                alert.severity.as_str(),
                dedup_key
            ),
        )?;

        let planned = match self.routing.resolve(alert, 1, alert.occurred_est) {
            Ok((planned, _rule)) => planned,
            Err(error) => {
                self.store.audit(
                    &alert.alert_id,
                    alert.occurred_est,
                    "unrouted",
                    &error.to_string(),
                )?;
                return Ok(RaiseOutcome::Unrouted {
                    alert_id: alert.alert_id.clone(),
                    reason: error.to_string(),
                });
            }
        };

        let mut queued = 0usize;
        for planned in &planned {
            let delivery = self.delivery_for(alert, planned, alert.occurred_est);
            if self.store.insert_delivery(&delivery)? {
                queued += 1;
                self.store.audit(
                    &alert.alert_id,
                    alert.occurred_est,
                    "queued",
                    &format!(
                        "channel={} address={} role={} level={}",
                        delivery.channel, delivery.address, delivery.role, delivery.level
                    ),
                )?;
            }
        }

        let record = self
            .store
            .record(&alert.alert_id)?
            .ok_or_else(|| AlertError::NotFound(alert.alert_id.clone()))?;
        let mut report = DeliveryReport::default();
        self.attempt_due_for(&record, alert.occurred_est, &mut report)?;
        Ok(RaiseOutcome::Raised {
            alert_id: alert.alert_id.clone(),
            deliveries: queued,
        })
    }

    /// Attempt every due delivery and escalate overdue unacknowledged alerts.
    pub fn run(&self, now_est: i64) -> Result<DeliveryReport, AlertError> {
        let mut report = DeliveryReport::default();
        let due = self.store.due_deliveries(now_est)?;
        for delivery in &due {
            let Some(record) = self.store.record(&delivery.alert_id)? else {
                // The alert row is gone; the delivery cannot be rendered.
                self.store.dead_letter(
                    delivery,
                    delivery.attempts.saturating_add(1),
                    "alert record missing",
                )?;
                report.dead_lettered += 1;
                continue;
            };
            self.attempt(delivery, &record, now_est, &mut report)?;
        }

        for record in self.store.open_alerts_all()? {
            if !record.ack_required || record.is_acknowledged() {
                continue;
            }
            let Some(rule) = self.routing.rule_by_id(&record.rule_id) else {
                continue;
            };
            let Some(after) = rule.escalate_after_secs else {
                continue;
            };
            if record.escalation_level >= rule.max_level {
                continue;
            }
            let deadline = record
                .occurred_est
                .saturating_add(after.saturating_mul(i64::from(record.escalation_level)));
            if now_est < deadline {
                continue;
            }
            let next_level = record.escalation_level + 1;
            let alert = alert_from_record(&record);
            match self.routing.resolve(&alert, next_level, now_est) {
                Ok((planned, _rule)) => {
                    let mut queued = 0usize;
                    for planned in &planned {
                        let delivery = self.delivery_for(&alert, planned, now_est);
                        if self.store.insert_delivery(&delivery)? {
                            queued += 1;
                            self.store.audit(
                                &record.alert_id,
                                now_est,
                                "queued",
                                &format!(
                                    "channel={} address={} role={} level={} escalation=true",
                                    delivery.channel,
                                    delivery.address,
                                    delivery.role,
                                    delivery.level
                                ),
                            )?;
                        }
                    }
                    self.store
                        .set_escalation_level(&record.alert_id, next_level)?;
                    self.store.audit(
                        &record.alert_id,
                        now_est,
                        "escalated",
                        &format!("level={next_level} deliveries={queued} reason=unacknowledged"),
                    )?;
                    report.escalated += 1;
                    let refreshed = self
                        .store
                        .record(&record.alert_id)?
                        .ok_or_else(|| AlertError::NotFound(record.alert_id.clone()))?;
                    self.attempt_due_for(&refreshed, now_est, &mut report)?;
                }
                Err(error) => {
                    // Record the attempt so a broken rotation is visible instead
                    // of retrying silently on every pass.
                    self.store
                        .set_escalation_level(&record.alert_id, next_level)?;
                    self.store.audit(
                        &record.alert_id,
                        now_est,
                        "escalation_unrouted",
                        &error.to_string(),
                    )?;
                }
            }
        }
        Ok(report)
    }

    fn attempt_due_for(
        &self,
        record: &AlertRecord,
        now_est: i64,
        report: &mut DeliveryReport,
    ) -> Result<(), AlertError> {
        for delivery in self.store.deliveries(&record.alert_id)? {
            if delivery.state == "pending" && delivery.next_attempt_est <= now_est {
                self.attempt(&delivery, record, now_est, report)?;
            }
        }
        Ok(())
    }

    fn attempt(
        &self,
        delivery: &DeliveryRecord,
        record: &AlertRecord,
        now_est: i64,
        report: &mut DeliveryReport,
    ) -> Result<(), AlertError> {
        let attempts = delivery.attempts.saturating_add(1);
        let Some(transport) = self.transports.get(&delivery.channel) else {
            return self.fail(
                delivery,
                attempts,
                DeliveryFailure::permanent(format!(
                    "no transport registered for channel {:?}",
                    delivery.channel
                )),
                now_est,
                report,
            );
        };
        let message = self.message_for(record, &delivery.role, delivery.level);
        let target = DeliveryTarget {
            channel: delivery.channel.clone(),
            address: delivery.address.clone(),
            secret_ref: delivery.secret_ref.clone(),
        };
        match transport.deliver(&message, &target) {
            Ok(receipt) => {
                self.store.mark_delivered(&delivery.delivery_id, now_est)?;
                self.store.audit(
                    &record.alert_id,
                    now_est,
                    "delivered",
                    &format!(
                        "channel={} address={} level={} attempts={attempts} provider_id={}",
                        delivery.channel,
                        delivery.address,
                        delivery.level,
                        receipt.provider_id.unwrap_or_default()
                    ),
                )?;
                report.delivered += 1;
                Ok(())
            }
            Err(failure) => self.fail(delivery, attempts, failure, now_est, report),
        }
    }

    fn fail(
        &self,
        delivery: &DeliveryRecord,
        attempts: u32,
        failure: DeliveryFailure,
        now_est: i64,
        report: &mut DeliveryReport,
    ) -> Result<(), AlertError> {
        let exhausted = !failure.retriable || self.retry.is_exhausted(attempts);
        if exhausted {
            self.store
                .dead_letter(delivery, attempts, &failure.detail)?;
            self.store.audit(
                &delivery.alert_id,
                now_est,
                "dead_letter",
                &format!(
                    "channel={} address={} level={} attempts={attempts} error={}",
                    delivery.channel, delivery.address, delivery.level, failure.detail
                ),
            )?;
            report.dead_lettered += 1;
        } else {
            let delay = self.retry.delay_secs(attempts, &delivery.alert_id);
            let next_attempt_est = now_est.saturating_add(delay);
            self.store.record_retry(
                &delivery.delivery_id,
                attempts,
                next_attempt_est,
                &failure.detail,
            )?;
            self.store.audit(
                &delivery.alert_id,
                now_est,
                "retry",
                &format!(
                    "channel={} address={} level={} attempts={attempts} next_attempt_est={next_attempt_est} error={}",
                    delivery.channel, delivery.address, delivery.level, failure.detail
                ),
            )?;
            report.retried += 1;
        }
        Ok(())
    }

    fn delivery_for(
        &self,
        alert: &Alert,
        planned: &PlannedDelivery,
        created_est: i64,
    ) -> DeliveryRecord {
        DeliveryRecord {
            delivery_id: delivery_id(
                &alert.alert_id,
                &planned.channel,
                &planned.address,
                planned.level,
            ),
            alert_id: alert.alert_id.clone(),
            channel: planned.channel.clone(),
            address: planned.address.clone(),
            role: planned.role.clone(),
            level: planned.level,
            secret_ref: planned.secret_ref.clone(),
            state: "pending".to_string(),
            attempts: 0,
            next_attempt_est: created_est,
            last_error: None,
            created_est,
            delivered_est: None,
        }
    }

    fn message_for(&self, record: &AlertRecord, role: &str, level: u32) -> AlertMessage {
        let ack_by_est = self
            .routing
            .rule_by_id(&record.rule_id)
            .and_then(|rule| rule.escalate_after_secs)
            .map(|seconds| record.occurred_est.saturating_add(seconds));
        AlertMessage {
            alert_id: record.alert_id.clone(),
            dedup_key: record.dedup_key.clone(),
            rule_id: record.rule_id.clone(),
            severity: record.severity,
            tenant: record.tenant.clone(),
            site_id: record.site_id.clone(),
            role: role.to_string(),
            title: record.title.clone(),
            body: record.body.clone(),
            labels: record.labels.clone(),
            occurred_est: record.occurred_est,
            escalation_level: level,
            ack_required: record.ack_required,
            ack_by_est,
            acknowledged_est: record.acknowledged_est,
        }
    }
}

impl AlertNotifier for AlertRouter {
    fn raise(&self, alert: &Alert) -> Result<RaiseOutcome, AlertError> {
        self.raise_alert(alert)
    }

    fn acknowledge(&self, alert_id: &str, by: &str, at_est: i64) -> Result<AckOutcome, AlertError> {
        let record = self
            .store
            .record(alert_id)?
            .ok_or_else(|| AlertError::NotFound(alert_id.to_string()))?;
        if let (Some(acknowledged_est), Some(acknowledged_by)) =
            (record.acknowledged_est, record.acknowledged_by.clone())
        {
            return Ok(AckOutcome::AlreadyAcknowledged {
                alert_id: record.alert_id,
                by: acknowledged_by,
                at_est: acknowledged_est,
            });
        }
        self.store.acknowledge(alert_id, by, at_est)?;
        self.store
            .audit(alert_id, at_est, "acknowledged", &format!("by={by}"))?;
        Ok(AckOutcome::Acknowledged {
            alert_id: alert_id.to_string(),
        })
    }

    fn run_due(&self, now_est: i64) -> Result<DeliveryReport, AlertError> {
        self.run(now_est)
    }

    fn open_alerts(&self, tenant: &str) -> Result<Vec<AlertRecord>, AlertError> {
        self.store.open_alerts(tenant)
    }

    fn record(&self, alert_id: &str) -> Result<AlertRecord, AlertError> {
        self.store
            .record(alert_id)?
            .ok_or_else(|| AlertError::NotFound(alert_id.to_string()))
    }

    fn deliveries(&self, alert_id: &str) -> Result<Vec<DeliveryRecord>, AlertError> {
        self.store.deliveries(alert_id)
    }

    fn dead_letters(&self) -> Result<Vec<DeadLetter>, AlertError> {
        self.store.dead_letters()
    }

    fn audit(&self, alert_id: &str) -> Result<Vec<AuditEntry>, AlertError> {
        self.store.audit_entries(alert_id)
    }
}

/// Stable delivery id for one `(alert, channel, address, level)`.
///
/// Deterministic, so a re-queued delivery for the same target is the same row and
/// a receiver can key on it.
pub fn delivery_id(alert_id: &str, channel: &str, address: &str, level: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"TirBase/v1/AlertDelivery\0");
    for part in [alert_id, channel, address] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    hasher.update(level.to_le_bytes());
    hex::encode(&hasher.finalize()[..16])
}

fn alert_from_record(record: &AlertRecord) -> Alert {
    Alert {
        alert_id: record.alert_id.clone(),
        dedup_key: record.dedup_key.clone(),
        rule_id: record.rule_id.clone(),
        severity: record.severity,
        tenant: record.tenant.clone(),
        site_id: record.site_id.clone(),
        title: record.title.clone(),
        body: record.body.clone(),
        labels: record.labels.clone(),
        occurred_est: record.occurred_est,
        ack_required: record.ack_required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_ids_are_stable_and_distinct_per_target_and_level() {
        let first = delivery_id("alert-1", "email", "ana@example.com", 1);
        assert_eq!(first, delivery_id("alert-1", "email", "ana@example.com", 1));
        assert_eq!(first.len(), 32);
        assert_ne!(first, delivery_id("alert-1", "email", "bo@example.com", 1));
        assert_ne!(first, delivery_id("alert-1", "email", "ana@example.com", 2));
        assert_ne!(first, delivery_id("alert-2", "email", "ana@example.com", 1));
    }
}
