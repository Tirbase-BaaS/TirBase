// SPDX-License-Identifier: Apache-2.0

//! Versioned workflow-pack configuration (CC-13).
//!
//! A workflow document (`workflow.toml`) is the data an operator edits to change
//! how the excursion workflow treats a pack: the detection thresholds, the
//! assessment and reporting windows, the debounce rule, the notification routes,
//! the disposition codes a lot may be given, the mean-kinetic-temperature
//! parameters, and the lot metadata used for new identities. Nothing here is
//! code — [`load_workflow_config`] and [`WorkflowConfig::parse`] read the
//! document, and the gateway builds its `DetectionThresholds` from it at boot, so
//! changing a threshold is a file edit and a restart, not a rebuild.
//!
//! # Schema (version 1)
//!
//! ```toml
//! schema_version = 1
//! id = "cold-room-workflow"
//! pack = "cold-room"
//! title = "Cold-room excursion workflow"
//! tirbase_min_version = "0.1.0"
//!
//! [thresholds]
//! band_min_c = { mantissa = 0, exponent = -1, unit_id = 1 }
//! band_max_c = { mantissa = 80, exponent = -1, unit_id = 1 }
//! max_rate_c_per_sec = { mantissa = 5, exponent = -1, unit_id = 1 }
//! drift_budget_c = { mantissa = 20, exponent = -1, unit_id = 1 }
//! max_door_open_secs = 120
//! max_defrost_secs = 900
//! compressor_max_runtime_secs = 21600
//! max_telemetry_gap_secs = 300
//! mkt_limit_c = { mantissa = 80, exponent = -1, unit_id = 1 }
//!
//! [windows]
//! assessment_secs = 3600
//! max_quarantine_secs = 86400
//! reporting_interval_secs = 3600
//! sampling_interval_secs = 300
//!
//! [debounce]
//! min_findings = 1
//! window_secs = 0
//! cooldown_secs = 300
//!
//! [mkt]
//! activation_energy_j_per_mol = 83144
//! gas_constant_milli_j_per_mol_k = 8314
//! max_samples = 10000
//!
//! [[notification.routes]]
//! channel = "pager"
//! event = "quarantine_opened"
//! enabled = true
//!
//! [[dispositions.codes]]
//! code = "CR-REJ-003"
//! kind = "reject"
//! label = "Lot rejected"
//!
//! [lot]
//! lot_kind = "lot"
//! uom = "kg"
//! label_prefix = "CR"
//! ```
//!
//! # Validation
//!
//! [`WorkflowConfig`] rejects unknown fields at every level, requires every
//! field, and then validates semantics field by field: units (temperatures must
//! be 0.1 °C with `unit_id = 1`), ranges (band ordering, positive intervals,
//! reporting ≥ sampling, quarantine ≥ assessment), version compatibility
//! (`schema_version` must be 1 and `tirbase_min_version` must not be newer than
//! this crate), notification routes (known events, unique channel/event pairs,
//! at least one enabled route), disposition codes (unique, each kind covered),
//! MKT parameters (non-zero, bounded sample count) and lot metadata. Configs are
//! also scanned for secret-looking keys before parsing, so a password or token
//! cannot be stored in a workflow pack even under a new field name.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use serde::Deserialize;
use tirbase_types::FixedPointValue;

/// File name of a workflow document inside a pack.
pub const WORKFLOW_CONFIG_FILE: &str = "workflow.toml";

/// Workflow schema version understood by this crate.
pub const WORKFLOW_SCHEMA_VERSION: u32 = 1;

/// Notification events a route may subscribe to.
pub const WORKFLOW_NOTIFICATION_EVENTS: &[&str] = &[
    "quarantine_opened",
    "disposition_recorded",
    "resolution_signed",
];

/// Disposition kinds a code may map to.
pub const WORKFLOW_DISPOSITION_KINDS: &[&str] = &["release", "hold", "reject", "destroy"];

/// Lot identity kinds `[lot].lot_kind` may name.
pub const WORKFLOW_LOT_KINDS: &[&str] = &["lot", "batch", "repack"];

/// Largest accepted value for `[debounce].min_findings`.
pub const WORKFLOW_MAX_MIN_FINDINGS: u32 = 32;

/// Largest accepted value for `[mkt].max_samples`.
pub const WORKFLOW_MAX_MKT_SAMPLES: usize = 100_000;

/// Key fragments that mark a field as secret material.
const SECRET_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "bearer",
    "authorization",
    "access_key",
];

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// One validated workflow document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowConfig {
    /// Schema version. Must equal [`WORKFLOW_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Workflow identity.
    pub id: String,
    /// Pack id this workflow configures; must match the manifest `id`.
    pub pack: String,
    /// Human-readable title.
    pub title: String,
    /// Oldest TirBase release the document is valid for.
    pub tirbase_min_version: String,
    /// Detection thresholds.
    pub thresholds: WorkflowThresholds,
    /// Assessment and reporting windows.
    pub windows: WorkflowWindows,
    /// Debounce rule.
    pub debounce: WorkflowDebounce,
    /// Mean-kinetic-temperature parameters.
    pub mkt: WorkflowMkt,
    /// Notification routes.
    pub notification: WorkflowNotification,
    /// Disposition codes.
    pub dispositions: WorkflowDispositions,
    /// Lot metadata defaults.
    pub lot: WorkflowLotMetadata,
}

/// Detection thresholds, in the units the detection engine expects.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowThresholds {
    /// Lower bound of the labelled storage band (0.1 °C).
    pub band_min_c: FixedPointValue,
    /// Upper bound of the labelled storage band (0.1 °C).
    pub band_max_c: FixedPointValue,
    /// Maximum accepted rate of change (0.1 °C per second).
    pub max_rate_c_per_sec: FixedPointValue,
    /// Cumulative drift budget inside the profile's window (0.1 °C).
    pub drift_budget_c: FixedPointValue,
    /// Longest tolerated door-open interval.
    pub max_door_open_secs: u32,
    /// Longest tolerated defrost interval.
    pub max_defrost_secs: u32,
    /// Longest tolerated compressor runtime.
    pub compressor_max_runtime_secs: u32,
    /// Longest tolerated telemetry gap.
    pub max_telemetry_gap_secs: u32,
    /// MKT limit for the storage class (0.1 °C).
    pub mkt_limit_c: FixedPointValue,
}

/// Assessment, reporting and sampling windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowWindows {
    /// How long an operator has to disposition a quarantine.
    pub assessment_secs: u32,
    /// Hard cap on how long a quarantine may stay open.
    pub max_quarantine_secs: u32,
    /// MKT reporting interval.
    pub reporting_interval_secs: u32,
    /// Monitoring sample interval.
    pub sampling_interval_secs: u32,
}

/// Debounce rule: how many findings, inside what window, with what cooldown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDebounce {
    /// Findings required before a quarantine is raised.
    pub min_findings: u32,
    /// Sliding window the findings must fall inside (`0` disables the window).
    pub window_secs: u32,
    /// Earliest delay between two raised quarantines for the same lot.
    pub cooldown_secs: u32,
}

/// Arrhenius parameters for the MKT calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowMkt {
    /// Activation energy `ΔH`, joules per mole.
    pub activation_energy_j_per_mol: u32,
    /// Gas constant `R`, millijoules per mole per kelvin (8314 ⇒ 8.314).
    pub gas_constant_milli_j_per_mol_k: u32,
    /// Maximum samples in one calculation.
    pub max_samples: usize,
}

/// Notification section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNotification {
    /// Routes, one per channel/event pair.
    pub routes: Vec<NotificationRoute>,
}

/// One notification route.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRoute {
    /// Channel name registered with the dispatcher.
    pub channel: String,
    /// One of [`WORKFLOW_NOTIFICATION_EVENTS`].
    pub event: String,
    /// Whether the route is active.
    pub enabled: bool,
}

/// Disposition-code section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDispositions {
    /// Codes a lot may be given.
    pub codes: Vec<DispositionCode>,
}

/// One disposition code.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispositionCode {
    /// Stable code (`GDP-REJ-006`).
    pub code: String,
    /// One of [`WORKFLOW_DISPOSITION_KINDS`].
    pub kind: String,
    /// Operator-facing label.
    pub label: String,
}

/// Lot metadata defaults.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLotMetadata {
    /// One of [`WORKFLOW_LOT_KINDS`].
    pub lot_kind: String,
    /// Unit of measure for lot quantities.
    pub uom: String,
    /// Prefix for generated labels.
    pub label_prefix: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure loading or validating a workflow document.
#[derive(Debug)]
pub enum WorkflowConfigError {
    /// The file could not be read.
    Io {
        /// Path as given by the caller.
        path: String,
        /// Underlying error.
        error: std::io::Error,
    },
    /// The document is not valid TOML or does not match the schema.
    Toml {
        /// Path as given by the caller.
        path: String,
        /// Parser error (carries line/column and the field name).
        error: toml::de::Error,
    },
    /// A field is present but invalid.
    Field {
        /// Dotted field path, e.g. `thresholds.band_min_c`.
        field: String,
        /// What is wrong with it.
        message: String,
    },
}

impl WorkflowConfigError {
    /// The field this error names, when one can be determined.
    ///
    /// Schema errors report the offending field when TOML names it (a missing or
    /// unknown field), so callers and tests can assert on the field path rather
    /// than on prose.
    pub fn field(&self) -> Option<String> {
        match self {
            WorkflowConfigError::Field { field, .. } => Some(field.clone()),
            WorkflowConfigError::Toml { error, .. } => {
                let message = error.message();
                for marker in ["missing field `", "unknown field `"] {
                    if let Some(start) = message.find(marker) {
                        let rest = &message[start + marker.len()..];
                        if let Some(end) = rest.find('`') {
                            return Some(rest[..end].to_string());
                        }
                    }
                }
                None
            }
            WorkflowConfigError::Io { .. } => None,
        }
    }
}

impl fmt::Display for WorkflowConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkflowConfigError::Io { path, error } => {
                write!(f, "workflow config '{path}': {error}")
            }
            WorkflowConfigError::Toml { path, error } => {
                write!(f, "workflow config '{path}': {error}")
            }
            WorkflowConfigError::Field { field, message } => {
                write!(f, "workflow config field '{field}': {message}")
            }
        }
    }
}

impl std::error::Error for WorkflowConfigError {}

fn field_error(field: impl Into<String>, message: impl Into<String>) -> WorkflowConfigError {
    WorkflowConfigError::Field {
        field: field.into(),
        message: message.into(),
    }
}

// ---------------------------------------------------------------------------
// Loading and validation
// ---------------------------------------------------------------------------

impl WorkflowConfig {
    /// Read and validate a workflow document from `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, WorkflowConfigError> {
        let path = path.as_ref();
        let source = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|error| WorkflowConfigError::Io {
            path: source.clone(),
            error,
        })?;
        Self::parse(&text, &source)
    }

    /// Parse and validate a workflow document held in memory.
    ///
    /// `source` is only used in error messages.
    pub fn parse(text: &str, source: &str) -> Result<Self, WorkflowConfigError> {
        let value: toml::Value =
            toml::from_str(text).map_err(|error| WorkflowConfigError::Toml {
                path: source.to_string(),
                error,
            })?;
        // Reject secrets before the typed parse, so a secret under an otherwise
        // unknown key is reported as a secret rather than as a schema mistake.
        reject_secret_keys(&value, "")?;
        let config: WorkflowConfig =
            value
                .try_into()
                .map_err(|error: toml::de::Error| WorkflowConfigError::Toml {
                    path: source.to_string(),
                    error,
                })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate every semantic rule. Unknown and missing fields are already
    /// rejected during deserialization.
    pub fn validate(&self) -> Result<(), WorkflowConfigError> {
        self.validate_identity()?;
        self.validate_thresholds()?;
        self.validate_windows()?;
        self.validate_debounce()?;
        self.validate_mkt()?;
        self.validate_notification()?;
        self.validate_dispositions()?;
        self.validate_lot()
    }

    /// The disposition code registered for `kind` (`release`, `hold`, …).
    pub fn disposition_code_for(&self, kind: &str) -> Option<&str> {
        self.dispositions
            .codes
            .iter()
            .find(|code| code.kind == kind)
            .map(|code| code.code.as_str())
    }

    /// Enabled routes only.
    pub fn enabled_routes(&self) -> impl Iterator<Item = &NotificationRoute> {
        self.notification
            .routes
            .iter()
            .filter(|route| route.enabled)
    }

    fn validate_identity(&self) -> Result<(), WorkflowConfigError> {
        if self.schema_version != WORKFLOW_SCHEMA_VERSION {
            return Err(field_error(
                "schema_version",
                format!(
                    "unsupported schema_version {}; this engine reads {WORKFLOW_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        if self.id.trim().is_empty() {
            return Err(field_error("id", "must not be empty"));
        }
        if self.pack.trim().is_empty() {
            return Err(field_error(
                "pack",
                "must name the pack this workflow configures",
            ));
        }
        if self.title.trim().is_empty() {
            return Err(field_error("title", "must not be empty"));
        }
        let required = parse_version(&self.tirbase_min_version).ok_or_else(|| {
            field_error(
                "tirbase_min_version",
                format!(
                    "'{}' must be a numeric major.minor.patch",
                    self.tirbase_min_version
                ),
            )
        })?;
        let running = parse_version(env!("CARGO_PKG_VERSION")).unwrap_or((0, 0, 0));
        if required > running {
            return Err(field_error(
                "tirbase_min_version",
                format!(
                    "config requires TirBase {} but this build is {}",
                    self.tirbase_min_version,
                    env!("CARGO_PKG_VERSION")
                ),
            ));
        }
        Ok(())
    }

    fn validate_thresholds(&self) -> Result<(), WorkflowConfigError> {
        let t = &self.thresholds;
        deci_celsius("thresholds.band_min_c", &t.band_min_c)?;
        deci_celsius("thresholds.band_max_c", &t.band_max_c)?;
        deci_celsius("thresholds.drift_budget_c", &t.drift_budget_c)?;
        deci_celsius("thresholds.mkt_limit_c", &t.mkt_limit_c)?;
        deci_celsius("thresholds.max_rate_c_per_sec", &t.max_rate_c_per_sec)?;

        if t.band_min_c.mantissa >= t.band_max_c.mantissa {
            return Err(field_error(
                "thresholds.band_min_c",
                "must be lower than thresholds.band_max_c",
            ));
        }
        if t.max_rate_c_per_sec.mantissa <= 0 {
            return Err(field_error(
                "thresholds.max_rate_c_per_sec",
                "must be greater than zero",
            ));
        }
        if t.drift_budget_c.mantissa < 0 {
            return Err(field_error(
                "thresholds.drift_budget_c",
                "must not be negative",
            ));
        }
        for (field, value) in [
            ("thresholds.max_door_open_secs", t.max_door_open_secs),
            ("thresholds.max_defrost_secs", t.max_defrost_secs),
            (
                "thresholds.compressor_max_runtime_secs",
                t.compressor_max_runtime_secs,
            ),
            (
                "thresholds.max_telemetry_gap_secs",
                t.max_telemetry_gap_secs,
            ),
        ] {
            if value == 0 {
                return Err(field_error(field, "must be greater than zero"));
            }
        }
        Ok(())
    }

    fn validate_windows(&self) -> Result<(), WorkflowConfigError> {
        let w = &self.windows;
        if w.sampling_interval_secs == 0 {
            return Err(field_error(
                "windows.sampling_interval_secs",
                "must be greater than zero",
            ));
        }
        if w.reporting_interval_secs < w.sampling_interval_secs {
            return Err(field_error(
                "windows.reporting_interval_secs",
                "must be at least windows.sampling_interval_secs",
            ));
        }
        if w.assessment_secs < w.reporting_interval_secs {
            return Err(field_error(
                "windows.assessment_secs",
                "must be at least windows.reporting_interval_secs",
            ));
        }
        if w.max_quarantine_secs < w.assessment_secs {
            return Err(field_error(
                "windows.max_quarantine_secs",
                "must be at least windows.assessment_secs",
            ));
        }
        Ok(())
    }

    fn validate_debounce(&self) -> Result<(), WorkflowConfigError> {
        let d = &self.debounce;
        if d.min_findings == 0 || d.min_findings > WORKFLOW_MAX_MIN_FINDINGS {
            return Err(field_error(
                "debounce.min_findings",
                format!("must be between 1 and {WORKFLOW_MAX_MIN_FINDINGS}"),
            ));
        }
        if d.window_secs > 0 && d.window_secs < self.windows.sampling_interval_secs {
            return Err(field_error(
                "debounce.window_secs",
                "must be 0 (disabled) or at least windows.sampling_interval_secs",
            ));
        }
        if d.cooldown_secs >= self.windows.max_quarantine_secs {
            return Err(field_error(
                "debounce.cooldown_secs",
                "must be shorter than windows.max_quarantine_secs",
            ));
        }
        Ok(())
    }

    fn validate_mkt(&self) -> Result<(), WorkflowConfigError> {
        let m = &self.mkt;
        if m.activation_energy_j_per_mol == 0 {
            return Err(field_error(
                "mkt.activation_energy_j_per_mol",
                "must be greater than zero",
            ));
        }
        if m.gas_constant_milli_j_per_mol_k == 0 {
            return Err(field_error(
                "mkt.gas_constant_milli_j_per_mol_k",
                "must be greater than zero",
            ));
        }
        if m.max_samples == 0 || m.max_samples > WORKFLOW_MAX_MKT_SAMPLES {
            return Err(field_error(
                "mkt.max_samples",
                format!("must be between 1 and {WORKFLOW_MAX_MKT_SAMPLES}"),
            ));
        }
        Ok(())
    }

    fn validate_notification(&self) -> Result<(), WorkflowConfigError> {
        if self.notification.routes.is_empty() {
            return Err(field_error(
                "notification.routes",
                "must declare at least one route",
            ));
        }
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        let mut enabled = 0usize;
        for (index, route) in self.notification.routes.iter().enumerate() {
            let channel_field = format!("notification.routes[{index}].channel");
            if route.channel.trim().is_empty() {
                return Err(field_error(channel_field, "must not be empty"));
            }
            if !route.channel.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
            }) {
                return Err(field_error(
                    channel_field,
                    "must be lowercase ASCII letters, digits, '-' or '_'",
                ));
            }
            if !WORKFLOW_NOTIFICATION_EVENTS.contains(&route.event.as_str()) {
                return Err(field_error(
                    format!("notification.routes[{index}].event"),
                    format!(
                        "unknown event '{}'; expected one of {}",
                        route.event,
                        WORKFLOW_NOTIFICATION_EVENTS.join(", ")
                    ),
                ));
            }
            if !seen.insert((route.channel.clone(), route.event.clone())) {
                return Err(field_error(
                    format!("notification.routes[{index}]"),
                    format!(
                        "duplicate route for channel '{}' and event '{}'",
                        route.channel, route.event
                    ),
                ));
            }
            if route.enabled {
                enabled += 1;
            }
        }
        if enabled == 0 {
            return Err(field_error(
                "notification.routes",
                "at least one route must be enabled",
            ));
        }
        Ok(())
    }

    fn validate_dispositions(&self) -> Result<(), WorkflowConfigError> {
        if self.dispositions.codes.is_empty() {
            return Err(field_error(
                "dispositions.codes",
                "must declare at least one disposition code",
            ));
        }
        let mut codes: BTreeSet<&str> = BTreeSet::new();
        let mut kinds: BTreeSet<&str> = BTreeSet::new();
        for (index, entry) in self.dispositions.codes.iter().enumerate() {
            let code_field = format!("dispositions.codes[{index}].code");
            if entry.code.len() < 3
                || entry.code.len() > 32
                || !entry
                    .code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(field_error(
                    code_field,
                    "must be 3..=32 uppercase ASCII letters, digits or '-'",
                ));
            }
            if !codes.insert(entry.code.as_str()) {
                return Err(field_error(code_field, "duplicate disposition code"));
            }
            if !WORKFLOW_DISPOSITION_KINDS.contains(&entry.kind.as_str()) {
                return Err(field_error(
                    format!("dispositions.codes[{index}].kind"),
                    format!(
                        "unknown kind '{}'; expected one of {}",
                        entry.kind,
                        WORKFLOW_DISPOSITION_KINDS.join(", ")
                    ),
                ));
            }
            kinds.insert(entry.kind.as_str());
            if entry.label.trim().is_empty() {
                return Err(field_error(
                    format!("dispositions.codes[{index}].label"),
                    "must not be empty",
                ));
            }
        }
        for kind in WORKFLOW_DISPOSITION_KINDS {
            if !kinds.contains(kind) {
                return Err(field_error(
                    "dispositions.codes",
                    format!("no disposition code is declared for kind '{kind}'"),
                ));
            }
        }
        Ok(())
    }

    fn validate_lot(&self) -> Result<(), WorkflowConfigError> {
        if !WORKFLOW_LOT_KINDS.contains(&self.lot.lot_kind.as_str()) {
            return Err(field_error(
                "lot.lot_kind",
                format!(
                    "unknown kind '{}'; expected one of {}",
                    self.lot.lot_kind,
                    WORKFLOW_LOT_KINDS.join(", ")
                ),
            ));
        }
        if self.lot.uom.trim().is_empty() || self.lot.uom.len() > 16 {
            return Err(field_error("lot.uom", "must be 1..=16 characters"));
        }
        if self.lot.label_prefix.trim().is_empty() || self.lot.label_prefix.len() > 32 {
            return Err(field_error("lot.label_prefix", "must be 1..=32 characters"));
        }
        Ok(())
    }
}

/// Load the workflow document referenced by a pack manifest.
pub fn load_workflow_config(path: impl AsRef<Path>) -> Result<WorkflowConfig, WorkflowConfigError> {
    WorkflowConfig::load(path)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Require a value to be in 0.1 °C with the degC unit id.
fn deci_celsius(field: &str, value: &FixedPointValue) -> Result<(), WorkflowConfigError> {
    if value.unit_id != 1 {
        return Err(field_error(
            field,
            format!("must use unit_id 1 (degC), found {}", value.unit_id),
        ));
    }
    if value.exponent != -1 {
        return Err(field_error(
            field,
            format!(
                "must be expressed in 0.1 °C (exponent -1), found exponent {}",
                value.exponent
            ),
        ));
    }
    Ok(())
}

/// Parse `major.minor.patch`, rejecting anything else.
fn parse_version(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Walk a TOML value and refuse keys that look like secret material.
fn reject_secret_keys(value: &toml::Value, path: &str) -> Result<(), WorkflowConfigError> {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table {
                let field = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                let lowered = key.to_ascii_lowercase();
                if SECRET_KEY_FRAGMENTS
                    .iter()
                    .any(|fragment| lowered.contains(fragment))
                {
                    return Err(field_error(
                        field,
                        "secrets must not be stored in a workflow config; use the gateway secret store",
                    ));
                }
                reject_secret_keys(child, &field)?;
            }
            Ok(())
        }
        toml::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                reject_secret_keys(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
