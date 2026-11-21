// SPDX-License-Identifier: Apache-2.0

//! Notifier conformance suite.
//!
//! A closed alert connector is certified by running this suite against a
//! provider sandbox or a local mock. The suite makes real deliveries, so the
//! [`DeliveryTarget`] it receives must point at that fixture; a transport
//! configured for a production tenant is not a valid certification run.
//!
//! The suite checks the contract the gateway relies on:
//!
//! * **identity** — a non-empty, bounded channel name without whitespace;
//! * **delivery** — the provider accepts a well-formed alert;
//! * **replay** — delivering the same alert again is accepted as the *same*
//!   page (same provider id), never a second page;
//! * **fresh** — a different alert produces a different provider id.
//!
//! It deliberately does not grade payload wording, templates or escalation
//! policy: those are product configuration, documented by each connector and
//! tested by its own contract suite.

use serde::{Deserialize, Serialize};

use crate::message::{AlertMessage, Severity};
use crate::transport::{DeliveryReceipt, DeliveryTarget, NotifyTransport};

/// One check in a certification run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifierCheck {
    /// Check name.
    pub name: String,
    /// Whether it passed.
    pub passed: bool,
    /// Secret-free evidence.
    pub detail: String,
}

/// The result of certifying one transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifierReport {
    /// Channel name.
    pub channel: String,
    /// Individual checks, in order.
    pub checks: Vec<NotifierCheck>,
    /// Whether every check passed.
    pub certified: bool,
    /// When certification ran.
    pub checked_est: i64,
}

impl NotifierReport {
    /// Failed checks.
    pub fn failures(&self) -> Vec<&NotifierCheck> {
        self.checks.iter().filter(|check| !check.passed).collect()
    }

    /// Structured JSON form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "channel": self.channel,
            "certified": self.certified,
            "checked_est": self.checked_est,
            "checks": self.checks,
        })
    }
}

fn sample(alert_id: &str, dedup_key: &str, tenant: &str) -> AlertMessage {
    let mut message = AlertMessage::new(
        alert_id,
        dedup_key,
        Severity::Critical,
        "TirBase notifier conformance",
    );
    message.tenant = tenant.to_string();
    message.site_id = "site-conformance".to_string();
    message.role = "on-call".to_string();
    message.body = "Synthetic conformance alert; safe to ignore.".to_string();
    message.occurred_est = 1_000;
    message.ack_required = true;
    message.ack_by_est = Some(1_300);
    message
}

fn receipt_id(receipt: &DeliveryReceipt) -> Option<String> {
    receipt.provider_id.clone()
}

/// Certify `transport` against `target` for `tenant`.
///
/// `target` must address the connector's sandbox or mock provider, and `tenant`
/// must be the tenant the connector is bound to: a tenant-bound connector
/// rejects a sample alert from any other tenant.
pub fn certify(
    transport: &dyn NotifyTransport,
    target: &DeliveryTarget,
    tenant: &str,
    checked_est: i64,
) -> NotifierReport {
    let channel = transport.channel().to_string();
    let mut checks = Vec::new();

    let identity_ok = !channel.trim().is_empty()
        && channel.len() <= 64
        && !channel.chars().any(char::is_whitespace);
    checks.push(NotifierCheck {
        name: "identity".to_string(),
        passed: identity_ok,
        detail: format!("channel {channel:?}"),
    });

    let first = sample("conformance-alert-1", "conformance-dedup-1", tenant);
    let first_result = transport.deliver(&first, target);
    let first_id = first_result.as_ref().ok().and_then(receipt_id);
    checks.push(NotifierCheck {
        name: "delivery".to_string(),
        passed: first_result.is_ok(),
        detail: match &first_result {
            Ok(receipt) => format!("accepted, provider id {:?}", receipt.provider_id),
            Err(failure) => format!("not accepted: {failure}"),
        },
    });

    let replay_result = transport.deliver(&first, target);
    let replay_id = replay_result.as_ref().ok().and_then(receipt_id);
    let replay_ok = replay_result.is_ok() && replay_id == first_id;
    checks.push(NotifierCheck {
        name: "replay".to_string(),
        passed: replay_ok,
        detail: match (&first_result, &replay_result) {
            (Ok(_), Ok(receipt)) => format!("same page, provider id {:?}", receipt.provider_id),
            (_, Err(failure)) => format!("replay not accepted: {failure}"),
            _ => "replay produced a different provider id".to_string(),
        },
    });

    let fresh = sample("conformance-alert-2", "conformance-dedup-2", tenant);
    let fresh_result = transport.deliver(&fresh, target);
    let fresh_id = fresh_result.as_ref().ok().and_then(receipt_id);
    let fresh_ok = fresh_result.is_ok() && fresh_id != first_id;
    checks.push(NotifierCheck {
        name: "fresh".to_string(),
        passed: fresh_ok,
        detail: match &fresh_result {
            Ok(receipt) => format!("distinct page, provider id {:?}", receipt.provider_id),
            Err(failure) => format!("fresh alert not accepted: {failure}"),
        },
    });

    let certified = checks.iter().all(|check| check.passed);
    NotifierReport {
        channel,
        checks,
        certified,
        checked_est,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretRef;
    use crate::transport::DeliveryFailure;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct Fake {
        seen: Mutex<BTreeMap<String, String>>,
        dedupe: bool,
    }

    impl NotifyTransport for Fake {
        fn channel(&self) -> &str {
            "fake"
        }

        fn deliver(
            &self,
            message: &AlertMessage,
            _target: &DeliveryTarget,
        ) -> Result<DeliveryReceipt, DeliveryFailure> {
            let mut seen = self.seen.lock().expect("seen");
            let id = if self.dedupe {
                seen.get(&message.dedup_key)
                    .cloned()
                    .unwrap_or_else(|| format!("id-{}", seen.len()))
            } else {
                format!("id-{}", seen.len())
            };
            seen.insert(message.dedup_key.clone(), id.clone());
            Ok(DeliveryReceipt {
                provider_id: Some(id),
            })
        }
    }

    fn target() -> DeliveryTarget {
        DeliveryTarget {
            channel: "fake".to_string(),
            address: "sandbox".to_string(),
            secret_ref: SecretRef::new("test").ok(),
        }
    }

    #[test]
    fn certifies_a_transport_that_replays_as_the_same_page() {
        let fake = Fake {
            seen: Mutex::new(BTreeMap::new()),
            dedupe: true,
        };
        let report = certify(&fake, &target(), "conformance", 1_000);
        assert!(report.certified, "{:?}", report.failures());
        assert_eq!(report.checks.len(), 4);
    }

    #[test]
    fn rejects_a_transport_that_pages_twice() {
        let fake = Fake {
            seen: Mutex::new(BTreeMap::new()),
            dedupe: false,
        };
        let report = certify(&fake, &target(), "conformance", 1_000);
        assert!(!report.certified);
        assert!(report.failures().iter().any(|check| check.name == "replay"));
    }
}
