// SPDX-License-Identifier: Apache-2.0

//! Reconciliation hooks: local settlements against the vendor's.
//!
//! A connector exposes the vendor's side through
//! [`ReconciliationSource`]; the register exposes its own through
//! [`crate::pos::runtime::PosRuntime::reconcile`]. The comparison here is pure
//! and clock-free: it reports missing lines in either direction, duplicates, an
//! amount outside tolerance and a settlement the vendor has not confirmed, and it
//! never "fixes" anything — a discrepancy is a human decision.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::config::ConfigError;
use super::Amount;

/// Default interval between reconciliation runs, in seconds.
pub const DEFAULT_RECONCILIATION_SECS: u64 = 3_600;

/// Default age at which an unconfirmed settlement is reported, in seconds.
pub const DEFAULT_UNSETTLED_AFTER_SECS: i64 = 3_600;

/// Shortest reconciliation interval accepted, in seconds.
pub const MIN_RECONCILIATION_SECS: u64 = 60;

/// When and how strictly to reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReconciliationPolicy {
    /// Whether reconciliation runs at all.
    pub enabled: bool,
    /// Interval between runs, in seconds.
    pub interval_secs: u64,
    /// Largest difference accepted before it is reported, in minor units.
    pub tolerance_minor: i64,
    /// Age after which an unconfirmed settlement is reported, in seconds.
    pub unsettled_after_secs: i64,
}

impl Default for ReconciliationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: DEFAULT_RECONCILIATION_SECS,
            tolerance_minor: 0,
            unsettled_after_secs: DEFAULT_UNSETTLED_AFTER_SECS,
        }
    }
}

impl ReconciliationPolicy {
    /// A policy that reconciles every `interval_secs` with zero tolerance.
    pub fn every(interval_secs: u64) -> Self {
        Self {
            interval_secs,
            ..Self::default()
        }
    }

    /// A policy that never reconciles.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// Validate the section.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled && self.interval_secs < MIN_RECONCILIATION_SECS {
            return Err(ConfigError::new(
                "reconciliation.interval_secs",
                format!("must be at least {MIN_RECONCILIATION_SECS} seconds"),
            ));
        }
        if self.tolerance_minor < 0 {
            return Err(ConfigError::new(
                "reconciliation.tolerance_minor",
                "must not be negative",
            ));
        }
        Ok(())
    }

    /// Whether a run is due at `now_est`, given the previous run.
    pub fn applies(&self, now_est: i64, last_run_est: Option<i64>) -> bool {
        if !self.enabled {
            return false;
        }
        match last_run_est {
            None => true,
            Some(last) => now_est.saturating_sub(last) >= self.interval_secs as i64,
        }
    }
}

/// What the register believes it settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSettlement {
    /// Payment intent, invoice, delivery or journal reference.
    pub reference: String,
    /// Net amount recorded locally.
    pub amount: Amount,
    /// When it was settled.
    pub settled_est: i64,
}

/// What the vendor reports it settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSettlement {
    /// Reference the vendor knows.
    pub reference: String,
    /// Amount the vendor recorded.
    pub amount: Amount,
    /// When the vendor confirmed it, if it has.
    pub settled_est: Option<i64>,
}

/// Where the vendor's settlements come from.
///
/// A closed connector implements this over the vendor's settlement report; the
/// framework never guesses.
pub trait ReconciliationSource {
    /// Settlements the vendor reports for `tenant`.
    fn settlements(&self, tenant: &str) -> Vec<RemoteSettlement>;
}

/// Why a reference does not reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancyKind {
    /// The register settled it; the vendor has no line.
    MissingRemote,
    /// The vendor has a line; the register did not settle it.
    MissingLocal,
    /// The vendor reports the reference more than once.
    DuplicateRemote,
    /// The amounts differ beyond tolerance, or the currencies differ.
    AmountMismatch,
    /// The vendor has not confirmed the settlement yet.
    Unsettled,
}

impl DiscrepancyKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            DiscrepancyKind::MissingRemote => "missing_remote",
            DiscrepancyKind::MissingLocal => "missing_local",
            DiscrepancyKind::DuplicateRemote => "duplicate_remote",
            DiscrepancyKind::AmountMismatch => "amount_mismatch",
            DiscrepancyKind::Unsettled => "unsettled",
        }
    }
}

/// One reference that does not reconcile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discrepancy {
    /// Reference involved.
    pub reference: String,
    /// What kind of difference it is.
    pub kind: DiscrepancyKind,
    /// Local amount in minor units, when there is one.
    pub local_minor: Option<i64>,
    /// Vendor amount in minor units, when there is one.
    pub remote_minor: Option<i64>,
    /// Short explanation, safe to log.
    pub detail: String,
}

/// Result of one reconciliation run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationReport {
    /// Tenant reconciled.
    pub tenant: String,
    /// When the run happened.
    pub checked_est: i64,
    /// References that agreed within tolerance.
    pub matched: usize,
    /// References that did not.
    pub discrepancies: Vec<Discrepancy>,
}

impl ReconciliationReport {
    /// Whether every reference agreed.
    pub fn balanced(&self) -> bool {
        self.discrepancies.is_empty()
    }

    /// Structured JSON form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tenant": self.tenant,
            "checked_est": self.checked_est,
            "matched": self.matched,
            "balanced": self.balanced(),
            "discrepancies": self.discrepancies.iter().map(|entry| serde_json::json!({
                "reference": entry.reference,
                "kind": entry.kind.as_str(),
                "local_minor": entry.local_minor,
                "remote_minor": entry.remote_minor,
                "detail": entry.detail,
            })).collect::<Vec<_>>(),
        })
    }

    /// Compact human summary.
    pub fn summary(&self) -> String {
        if self.balanced() {
            format!("{} reconciled ({} matched)", self.tenant, self.matched)
        } else {
            format!(
                "{} has {} discrepancy(ies) across {} matched references",
                self.tenant,
                self.discrepancies.len(),
                self.matched
            )
        }
    }
}

/// Compare the register's settlements with the vendor's.
///
/// Pure and deterministic: the same inputs and the same `checked_est` always
/// produce the same report, and the report never mutates either side.
pub fn reconcile(
    tenant: &str,
    local: &[LocalSettlement],
    remote: &[RemoteSettlement],
    policy: &ReconciliationPolicy,
    checked_est: i64,
) -> ReconciliationReport {
    let mut remote_by_reference: BTreeMap<&str, Vec<&RemoteSettlement>> = BTreeMap::new();
    for line in remote {
        remote_by_reference
            .entry(line.reference.as_str())
            .or_default()
            .push(line);
    }

    let mut local_references: BTreeSet<&str> = BTreeSet::new();
    let mut matched = 0usize;
    let mut discrepancies = Vec::new();

    for entry in local {
        local_references.insert(entry.reference.as_str());
        match remote_by_reference.get(entry.reference.as_str()) {
            None => discrepancies.push(Discrepancy {
                reference: entry.reference.clone(),
                kind: DiscrepancyKind::MissingRemote,
                local_minor: Some(entry.amount.minor),
                remote_minor: None,
                detail: "the vendor has no settlement for this reference".to_string(),
            }),
            Some(lines) if lines.len() > 1 => discrepancies.push(Discrepancy {
                reference: entry.reference.clone(),
                kind: DiscrepancyKind::DuplicateRemote,
                local_minor: Some(entry.amount.minor),
                remote_minor: Some(lines.iter().map(|line| line.amount.minor).sum()),
                detail: format!("{} vendor settlements for one reference", lines.len()),
            }),
            Some(lines) => {
                let line = lines[0];
                if line.amount.currency != entry.amount.currency {
                    discrepancies.push(Discrepancy {
                        reference: entry.reference.clone(),
                        kind: DiscrepancyKind::AmountMismatch,
                        local_minor: Some(entry.amount.minor),
                        remote_minor: Some(line.amount.minor),
                        detail: format!(
                            "currency {} locally, {} at the vendor",
                            entry.amount.currency, line.amount.currency
                        ),
                    });
                } else if (line.amount.minor - entry.amount.minor).saturating_abs()
                    > policy.tolerance_minor
                {
                    discrepancies.push(Discrepancy {
                        reference: entry.reference.clone(),
                        kind: DiscrepancyKind::AmountMismatch,
                        local_minor: Some(entry.amount.minor),
                        remote_minor: Some(line.amount.minor),
                        detail: format!(
                            "local {} vs vendor {} (tolerance {})",
                            entry.amount.minor, line.amount.minor, policy.tolerance_minor
                        ),
                    });
                } else if line.settled_est.is_none()
                    && policy.unsettled_after_secs > 0
                    && checked_est.saturating_sub(entry.settled_est) > policy.unsettled_after_secs
                {
                    discrepancies.push(Discrepancy {
                        reference: entry.reference.clone(),
                        kind: DiscrepancyKind::Unsettled,
                        local_minor: Some(entry.amount.minor),
                        remote_minor: Some(line.amount.minor),
                        detail: "the vendor has not confirmed the settlement".to_string(),
                    });
                } else {
                    matched += 1;
                }
            }
        }
    }

    for (reference, lines) in &remote_by_reference {
        if local_references.contains(reference) {
            continue;
        }
        discrepancies.push(Discrepancy {
            reference: (*reference).to_string(),
            kind: DiscrepancyKind::MissingLocal,
            local_minor: None,
            remote_minor: Some(lines[0].amount.minor),
            detail: "the vendor settled a reference the register does not know".to_string(),
        });
    }

    ReconciliationReport {
        tenant: tenant.to_string(),
        checked_est,
        matched,
        discrepancies,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(reference: &str, minor: i64, settled_est: i64) -> LocalSettlement {
        LocalSettlement {
            reference: reference.to_string(),
            amount: Amount::new("EUR", minor).expect("valid"),
            settled_est,
        }
    }

    fn remote(reference: &str, minor: i64, settled_est: Option<i64>) -> RemoteSettlement {
        RemoteSettlement {
            reference: reference.to_string(),
            amount: Amount::new("EUR", minor).expect("valid"),
            settled_est,
        }
    }

    #[test]
    fn every_kind_of_difference_is_reported() {
        let local_side = vec![
            local("ok", 1_000, 100),
            local("missing-remote", 500, 100),
            local("mismatch", 900, 100),
            local("duplicate", 100, 100),
        ];
        let remote_side = vec![
            remote("ok", 1_000, Some(101)),
            remote("mismatch", 950, Some(101)),
            remote("duplicate", 100, Some(101)),
            remote("duplicate", 100, Some(102)),
            remote("missing-local", 700, Some(101)),
        ];
        let report = reconcile(
            "acme",
            &local_side,
            &remote_side,
            &ReconciliationPolicy::default(),
            200,
        );
        assert!(!report.balanced());
        assert_eq!(report.matched, 1);
        let kinds: Vec<DiscrepancyKind> = report
            .discrepancies
            .iter()
            .map(|entry| entry.kind)
            .collect();
        assert!(kinds.contains(&DiscrepancyKind::MissingRemote));
        assert!(kinds.contains(&DiscrepancyKind::MissingLocal));
        assert!(kinds.contains(&DiscrepancyKind::DuplicateRemote));
        assert!(kinds.contains(&DiscrepancyKind::AmountMismatch));
        assert_eq!(report.to_json()["balanced"], false);
        assert!(report.summary().contains("discrepancy"));
    }

    #[test]
    fn tolerance_and_unsettled_age_are_honoured() {
        let policy = ReconciliationPolicy {
            tolerance_minor: 5,
            unsettled_after_secs: 1_000,
            ..ReconciliationPolicy::default()
        };
        let report = reconcile(
            "acme",
            &[local("a", 1_000, 10), local("b", 1_000, 10)],
            &[remote("a", 1_004, Some(10)), remote("b", 1_000, None)],
            &policy,
            5_000,
        );
        assert!(report
            .discrepancies
            .iter()
            .all(|entry| entry.kind == DiscrepancyKind::Unsettled));
        assert_eq!(report.discrepancies.len(), 1);
        assert_eq!(report.discrepancies[0].reference, "b");
    }

    #[test]
    fn a_policy_only_runs_when_due() {
        let policy = ReconciliationPolicy::every(600);
        assert!(policy.applies(1_000, None));
        assert!(!policy.applies(1_100, Some(1_000)));
        assert!(policy.applies(1_600, Some(1_000)));
        assert!(!ReconciliationPolicy::disabled().applies(9_999, None));
        assert!(ReconciliationPolicy {
            interval_secs: 1,
            ..ReconciliationPolicy::default()
        }
        .validate()
        .is_err());
    }
}
