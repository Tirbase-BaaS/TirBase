// SPDX-License-Identifier: Apache-2.0

//! Conformance suite and contract-test harness.
//!
//! The suite proves the two things a connector must never get wrong: it reports
//! what actually happened, and it is idempotent. Point it at a connector wired to
//! the mock vendor (or a vendor sandbox) and it either certifies it or names the
//! check that failed.

use crate::connector::{
    Connector, ConnectorKind, DeliveryOutcome, DeliveryRequest, IntegrationEvent,
};

/// Smallest payload ceiling a connector may declare and still be certified.
pub const MIN_CERTIFIED_MAX_PAYLOAD_BYTES: usize = 1024;

/// One check in a certification report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// Check name.
    pub name: String,
    /// Whether it passed.
    pub passed: bool,
    /// What was observed.
    pub detail: String,
}

/// Result of certifying one connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationReport {
    /// Connector name.
    pub connector: String,
    /// Connector family.
    pub kind: ConnectorKind,
    /// Individual checks, in order.
    pub checks: Vec<CheckOutcome>,
    /// Whether every check passed.
    pub certified: bool,
    /// When certification ran.
    pub checked_est: i64,
}

impl CertificationReport {
    /// Failed checks.
    pub fn failures(&self) -> Vec<&CheckOutcome> {
        self.checks.iter().filter(|check| !check.passed).collect()
    }

    /// Structured JSON form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "connector": self.connector,
            "kind": self.kind.as_str(),
            "certified": self.certified,
            "checked_est": self.checked_est,
            "checks": self.checks.iter().map(|check| serde_json::json!({
                "name": check.name,
                "passed": check.passed,
                "detail": check.detail,
            })).collect::<Vec<_>>(),
        })
    }

    /// Compact human summary.
    pub fn summary(&self) -> String {
        let passed = self.checks.iter().filter(|check| check.passed).count();
        let failures: Vec<&str> = self
            .failures()
            .iter()
            .map(|check| check.name.as_str())
            .collect();
        if self.certified {
            format!("{} certified ({} checks)", self.connector, passed)
        } else {
            format!(
                "{} not certified: {}/{} checks passed, failed: {}",
                self.connector,
                passed,
                self.checks.len(),
                failures.join(", ")
            )
        }
    }
}

/// Outcome a contract case expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedOutcome {
    /// The connector should report the event delivered.
    Delivered,
    /// The connector should recognise the idempotency key.
    Duplicate,
    /// The connector should classify a transient failure as retryable.
    Retryable,
    /// The connector should classify a permanent failure as permanent.
    Permanent,
}

impl ExpectedOutcome {
    /// The matching delivery outcome.
    pub fn outcome(self) -> DeliveryOutcome {
        match self {
            ExpectedOutcome::Delivered => DeliveryOutcome::Delivered,
            ExpectedOutcome::Duplicate => DeliveryOutcome::Duplicate,
            ExpectedOutcome::Retryable => DeliveryOutcome::Retryable,
            ExpectedOutcome::Permanent => DeliveryOutcome::Permanent,
        }
    }

    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        self.outcome().as_str()
    }
}

/// One case in a contract harness.
#[derive(Debug, Clone)]
pub struct ContractCase {
    /// Case name.
    pub name: String,
    /// Request to deliver.
    pub request: DeliveryRequest,
    /// Expected classification.
    pub expected: ExpectedOutcome,
}

impl ContractCase {
    /// A case expecting `expected`.
    pub fn new(
        name: impl Into<String>,
        request: DeliveryRequest,
        expected: ExpectedOutcome,
    ) -> Self {
        Self {
            name: name.into(),
            request,
            expected,
        }
    }
}

/// An ordered set of contract cases.
#[derive(Debug, Clone, Default)]
pub struct ContractHarness {
    cases: Vec<ContractCase>,
}

impl ContractHarness {
    /// An empty harness.
    pub fn new() -> Self {
        Self { cases: Vec::new() }
    }

    /// Add a case.
    pub fn case(mut self, case: ContractCase) -> Self {
        self.cases.push(case);
        self
    }

    /// The cases.
    pub fn cases(&self) -> &[ContractCase] {
        &self.cases
    }

    /// Run every case against `connector`.
    pub fn run(&self, connector: &dyn Connector, checked_est: i64) -> CertificationReport {
        let checks: Vec<CheckOutcome> = self
            .cases
            .iter()
            .map(|case| {
                let result = connector.deliver(&case.request);
                let passed = result.outcome == case.expected.outcome();
                CheckOutcome {
                    name: case.name.clone(),
                    passed,
                    detail: format!(
                        "expected {}, got {} ({})",
                        case.expected.as_str(),
                        result.outcome.as_str(),
                        result.detail
                    ),
                }
            })
            .collect();
        let certified = checks.iter().all(|check| check.passed);
        CertificationReport {
            connector: connector.name().to_string(),
            kind: connector.kind(),
            checks,
            certified,
            checked_est,
        }
    }
}

fn event(id: &str, payload: serde_json::Value) -> IntegrationEvent {
    IntegrationEvent::new(id, "conformance.check", "conformance", 1_000, payload)
}

/// Certify a connector against the standard suite.
///
/// The connector must be wired to a vendor fixture that enforces idempotency
/// (the [`MockVendorServer`] does). The suite delivers the same event twice and
/// requires the second attempt to be reported as a duplicate, then delivers a
/// fresh event and requires it to be accepted.
pub fn certify(connector: &dyn Connector, checked_est: i64) -> CertificationReport {
    let name = connector.name().to_string();
    let mut checks = Vec::new();

    let capabilities = connector.capabilities();

    checks.push(CheckOutcome {
        name: "identity".to_string(),
        passed: !name.trim().is_empty() && name.len() <= 64,
        detail: format!("name {name:?}"),
    });
    checks.push(CheckOutcome {
        name: "idempotent-capability".to_string(),
        passed: capabilities.idempotent,
        detail: format!(
            "declares idempotent={} with {} auth mechanism(s)",
            capabilities.idempotent,
            capabilities.auth.len()
        ),
    });
    checks.push(CheckOutcome {
        name: "payload-ceiling".to_string(),
        passed: capabilities.max_payload_bytes >= MIN_CERTIFIED_MAX_PAYLOAD_BYTES,
        detail: format!(
            "declares a {}-byte ceiling (minimum {})",
            capabilities.max_payload_bytes, MIN_CERTIFIED_MAX_PAYLOAD_BYTES
        ),
    });
    let health = connector.health();
    checks.push(CheckOutcome {
        name: "health".to_string(),
        passed: !health.detail.trim().is_empty(),
        detail: health.detail.clone(),
    });

    let first = event(
        "conformance-event-1",
        serde_json::json!({ "value": 1, "note": "suite" }),
    );
    let request = DeliveryRequest::new(&first, &name, 1, checked_est);
    let harness = ContractHarness::new()
        .case(ContractCase::new(
            "deliver".to_string(),
            request.clone(),
            ExpectedOutcome::Delivered,
        ))
        .case(ContractCase::new(
            "duplicate".to_string(),
            DeliveryRequest {
                attempt: 2,
                ..request
            },
            ExpectedOutcome::Duplicate,
        ));
    let mut report = harness.run(connector, checked_est);
    checks.append(&mut report.checks);

    let fresh = event("conformance-event-2", serde_json::json!({ "value": 2 }));
    let fresh_request = DeliveryRequest::new(&fresh, &name, 1, checked_est);
    let oversized = event(
        "conformance-event-3",
        serde_json::json!({ "blob": "x".repeat(capabilities.max_payload_bytes.saturating_add(16)) }),
    );
    let oversized_request = DeliveryRequest::new(&oversized, &name, 1, checked_est);
    let harness = ContractHarness::new()
        .case(ContractCase::new(
            "fresh-event".to_string(),
            fresh_request,
            ExpectedOutcome::Delivered,
        ))
        .case(ContractCase::new(
            "oversized-payload".to_string(),
            oversized_request,
            ExpectedOutcome::Permanent,
        ));
    let mut report = harness.run(connector, checked_est);
    checks.append(&mut report.checks);

    let certified = checks.iter().all(|check| check.passed);
    CertificationReport {
        connector: name,
        kind: connector.kind(),
        checks,
        certified,
        checked_est,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::{ConnectorBuildError, ConnectorCapabilities, ConnectorHealth};

    struct AlwaysDelivered {
        name: String,
    }

    impl Connector for AlwaysDelivered {
        fn name(&self) -> &str {
            &self.name
        }
        fn kind(&self) -> ConnectorKind {
            ConnectorKind::Http
        }
        fn capabilities(&self) -> ConnectorCapabilities {
            ConnectorCapabilities::default()
        }
        fn deliver(&self, _request: &DeliveryRequest) -> crate::connector::DeliveryResult {
            crate::connector::DeliveryResult::delivered("always")
        }
        fn health(&self) -> ConnectorHealth {
            ConnectorHealth::healthy("always")
        }
    }

    #[test]
    fn a_connector_that_ignores_idempotency_is_not_certified() {
        let connector = AlwaysDelivered {
            name: "always-delivered".to_string(),
        };
        let report = certify(&connector, 1_000);
        assert!(!report.certified);
        let failures = report.failures();
        assert!(failures.iter().any(|check| check.name == "duplicate"));
        assert!(report.summary().contains("not certified"));
        assert_eq!(report.to_json()["certified"], false);
    }

    #[test]
    fn build_errors_are_typed() {
        let error = ConnectorBuildError::new("url", "must be http");
        assert_eq!(error.field, "url");
        assert!(error.to_string().contains("must be http"));
    }
}
