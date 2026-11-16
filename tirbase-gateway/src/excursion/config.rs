// SPDX-License-Identifier: AGPL-3.0-only

//! Pack-driven excursion policy (CC-13).
//!
//! The excursion workflow's limits are data, not code. A pack ships a
//! `workflow.toml` (schema owned by the Apache-2.0 `tirbase-demo` crate, which
//! validates it field by field); [`ExcursionPolicy`] turns that document into the
//! values the AGPL workflow consumes — [`DetectionThresholds`], [`MktParameters`],
//! the assessment and quarantine windows, the debounce gate, the notification
//! routes and the disposition codes — so an operator changes a threshold by
//! editing the file and restarting the gateway, not by rebuilding it.
//!
//! # Debounce
//!
//! [`DebounceGate`] implements the configured rule: a quarantine is raised only
//! when at least `min_findings` findings fall inside `window_secs`, and only once
//! `cooldown_secs` has passed since the last raised quarantine for the same lot.
//! Detection itself still runs on every sample; the gate decides whether a
//! finding series becomes an operator-visible quarantine.
//!
//! # Secrets
//!
//! A workflow document cannot carry credentials: the loader refuses secret-looking
//! keys, and route entries name a channel only. Channel credentials stay in the
//! gateway's secret/key store.

use tirbase_demo::workflow::{
    NotificationRoute, WorkflowConfig, WorkflowConfigError, WORKFLOW_DISPOSITION_KINDS,
};

use crate::excursion::mkt::MktParameters;
use crate::excursion::notifier::NotificationEvent;
use crate::excursion::{DetectionThresholds, DispositionKind};

/// Why a pack workflow could not be turned into a policy.
#[derive(Debug)]
pub enum PolicyError {
    /// The pack failed to load or validate.
    Pack(String),
    /// The workflow document failed to load or validate.
    Config(WorkflowConfigError),
    /// The pack ships no `workflow.toml`.
    MissingWorkflow {
        /// Pack id whose workflow is missing.
        pack: String,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Pack(detail) => write!(f, "pack: {detail}"),
            PolicyError::Config(error) => write!(f, "{error}"),
            PolicyError::MissingWorkflow { pack } => {
                write!(f, "pack '{pack}' declares no workflow configuration")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<WorkflowConfigError> for PolicyError {
    fn from(error: WorkflowConfigError) -> Self {
        PolicyError::Config(error)
    }
}

/// One notification route resolved to a workflow event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRoute {
    /// Channel name registered with the dispatcher.
    pub channel: String,
    /// Event the channel receives.
    pub event: NotificationEvent,
    /// Whether the route is active.
    pub enabled: bool,
}

/// An excursion policy built from a validated workflow document.
#[derive(Debug, Clone)]
pub struct ExcursionPolicy {
    config: WorkflowConfig,
}

impl ExcursionPolicy {
    /// Load the workflow document a pack declares and build its policy.
    pub fn from_pack_dir(dir: impl AsRef<std::path::Path>) -> Result<Self, PolicyError> {
        let pack =
            tirbase_demo::load_pack(dir).map_err(|error| PolicyError::Pack(error.to_string()))?;
        let pack_id = pack.manifest.id.clone();
        let config = pack
            .workflow
            .ok_or(PolicyError::MissingWorkflow { pack: pack_id })?;
        Ok(Self { config })
    }

    /// Wrap an already validated workflow document.
    pub fn from_config(config: WorkflowConfig) -> Self {
        Self { config }
    }

    /// Parse a workflow document and build its policy.
    ///
    /// `source` is only used in error messages. This is the path an operator's
    /// edited file takes: parse → field-level validation → policy.
    pub fn from_toml(text: &str, source: &str) -> Result<Self, PolicyError> {
        Ok(Self::from_config(WorkflowConfig::parse(text, source)?))
    }

    /// The underlying document.
    pub fn config(&self) -> &WorkflowConfig {
        &self.config
    }

    /// Detection thresholds the workflow evaluates against.
    pub fn thresholds(&self) -> DetectionThresholds {
        let thresholds = &self.config.thresholds;
        DetectionThresholds {
            band_min_c: thresholds.band_min_c,
            band_max_c: thresholds.band_max_c,
            max_rate_c_per_sec: thresholds.max_rate_c_per_sec,
            drift_budget_c: thresholds.drift_budget_c,
            max_door_open_secs: thresholds.max_door_open_secs,
            max_defrost_secs: thresholds.max_defrost_secs,
            compressor_max_runtime_secs: thresholds.compressor_max_runtime_secs,
            max_telemetry_gap_secs: thresholds.max_telemetry_gap_secs,
            mkt_limit_c: thresholds.mkt_limit_c,
            mkt: self.mkt(),
        }
    }

    /// MKT parameters the workflow computes with.
    pub fn mkt(&self) -> MktParameters {
        MktParameters {
            activation_energy_j_per_mol: self.config.mkt.activation_energy_j_per_mol,
            gas_constant_milli_j_per_mol_k: self.config.mkt.gas_constant_milli_j_per_mol_k,
            max_samples: self.config.mkt.max_samples,
        }
    }

    /// How long an operator has to disposition a quarantine.
    pub fn assessment_secs(&self) -> u32 {
        self.config.windows.assessment_secs
    }

    /// Hard cap on an open quarantine.
    pub fn max_quarantine_secs(&self) -> u32 {
        self.config.windows.max_quarantine_secs
    }

    /// Sample interval the pack expects.
    pub fn sampling_interval_secs(&self) -> u32 {
        self.config.windows.sampling_interval_secs
    }

    /// MKT reporting interval.
    pub fn reporting_interval_secs(&self) -> u32 {
        self.config.windows.reporting_interval_secs
    }

    /// When the assessment window of a quarantine opened at `opened_est` closes.
    pub fn assessment_deadline_est(&self, opened_est: i64) -> i64 {
        opened_est + i64::from(self.assessment_secs())
    }

    /// Whether a quarantine opened at `opened_est` has outlived its hard cap.
    pub fn quarantine_overdue(&self, opened_est: i64, now_est: i64) -> bool {
        now_est > opened_est + i64::from(self.max_quarantine_secs())
    }

    /// The configured debounce gate.
    pub fn debounce(&self) -> DebounceGate {
        DebounceGate {
            min_findings: self.config.debounce.min_findings,
            window_secs: self.config.debounce.window_secs,
            cooldown_secs: self.config.debounce.cooldown_secs,
        }
    }

    /// Every route, enabled or not.
    pub fn routes(&self) -> Vec<PolicyRoute> {
        self.config
            .notification
            .routes
            .iter()
            .filter_map(route_to_policy)
            .collect()
    }

    /// Routes that are active.
    pub fn enabled_routes(&self) -> Vec<PolicyRoute> {
        self.routes()
            .into_iter()
            .filter(|route| route.enabled)
            .collect()
    }

    /// Disposition code registered for `kind`.
    pub fn disposition_code(&self, kind: DispositionKind) -> Option<&str> {
        self.config.disposition_code_for(kind.as_str())
    }

    /// Disposition kinds the document covers, in declaration order.
    pub fn disposition_kinds(&self) -> Vec<&str> {
        let mut kinds: Vec<&str> = Vec::new();
        for entry in &self.config.dispositions.codes {
            if !kinds.contains(&entry.kind.as_str()) {
                kinds.push(entry.kind.as_str());
            }
        }
        kinds
    }

    /// Lot metadata defaults for identities created under this pack.
    pub fn lot_defaults(&self) -> LotDefaults<'_> {
        LotDefaults {
            lot_kind: &self.config.lot.lot_kind,
            uom: &self.config.lot.uom,
            label_prefix: &self.config.lot.label_prefix,
        }
    }
}

/// Lot metadata defaults exposed by a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LotDefaults<'a> {
    /// `lot`, `batch`, or `repack`.
    pub lot_kind: &'a str,
    /// Unit of measure for quantities.
    pub uom: &'a str,
    /// Prefix for generated labels.
    pub label_prefix: &'a str,
}

/// Debounce rule resolved from the workflow document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebounceGate {
    min_findings: u32,
    window_secs: u32,
    cooldown_secs: u32,
}

impl DebounceGate {
    /// Findings required inside the window.
    pub fn min_findings(&self) -> u32 {
        self.min_findings
    }

    /// Sliding window in seconds (`0` disables the window).
    pub fn window_secs(&self) -> u32 {
        self.window_secs
    }

    /// Minimum gap between two raised quarantines for one lot.
    pub fn cooldown_secs(&self) -> u32 {
        self.cooldown_secs
    }

    /// Whether a finding series raises a quarantine now.
    ///
    /// `finding_times_est` are the observation times of the findings; findings
    /// older than `window_secs` (when the window is enabled) do not count.
    /// `last_raised_est` is the last quarantine this lot raised, if any.
    pub fn admits(
        &self,
        finding_times_est: &[i64],
        last_raised_est: Option<i64>,
        now_est: i64,
    ) -> bool {
        if let Some(last) = last_raised_est {
            if now_est - last < i64::from(self.cooldown_secs) {
                return false;
            }
        }
        let window_start = if self.window_secs == 0 {
            i64::MIN
        } else {
            now_est - i64::from(self.window_secs)
        };
        let count = finding_times_est
            .iter()
            .filter(|at| **at >= window_start && **at <= now_est)
            .count();
        count >= self.min_findings as usize
    }
}

fn route_to_policy(route: &NotificationRoute) -> Option<PolicyRoute> {
    let event = match route.event.as_str() {
        "quarantine_opened" => NotificationEvent::QuarantineOpened,
        "disposition_recorded" => NotificationEvent::DispositionRecorded,
        "resolution_signed" => NotificationEvent::ResolutionSigned,
        _ => return None,
    };
    Some(PolicyRoute {
        channel: route.channel.clone(),
        event,
        enabled: route.enabled,
    })
}

/// Every disposition kind a workflow document may declare; re-exported for
/// callers that validate a document against the engine's vocabulary.
pub const DISPOSITION_KINDS: &[&str] = WORKFLOW_DISPOSITION_KINDS;
