// SPDX-License-Identifier: AGPL-3.0-only

//! Asset and calibration registry (CC-18).
//!
//! Every sensor and controller the gateway reads has an identity, a model, a
//! serial, firmware, and a site/location. That identity is **versioned**: a
//! change appends the next version and closes the previous version's half-open
//! effective range `[from, to)` at the new start, so an event keeps resolving
//! against the asset record that was in force when it happened, and replacing or
//! retiring an asset never deletes its history.
//!
//! # Calibration
//!
//! A [`CalibrationRecord`] carries the applied reference points, the interval,
//! the laboratory, the uncertainty, the computed due date, and a
//! [`CertificateRef`]. The certificate is attached **by hash**: the registry
//! stores the SHA-256 digest, the byte length and the issuing metadata, never the
//! certificate bytes and never any secret inside them.
//! [`AssetRegistry::verify_certificate`] re-hashes caller-supplied bytes and
//! fails closed on any difference.
//!
//! # Drift
//!
//! [`ReferenceCheck`]s are periodic checks against a known reference (an ice
//! point, a calibrated bath). [`AssetRegistry::record_reference_check`] compares
//! the reading with the applied reference *and* with the asset's earliest check
//! at the same reference, so a slow drift away from the original baseline is
//! caught even while each individual check is inside its tolerance.
//!
//! # Release gate
//!
//! [`AssetRegistry::evaluate_lot_release`] answers whether a CC-12 lot may be
//! released given the assets that observed it. An expired calibration (and,
//! fail-closed, a missing one or an out-of-tolerance reference check) writes an
//! append-only [`ReleaseBlock`] against the lot; a lot with any unresolved block
//! cannot be released, even if the sensor was recalibrated afterwards, until the
//! block is explicitly resolved with an actor and a reason.
//! [`AssetRegistry::raise_expiry_excursion`] turns an expired calibration into a
//! CC-11 excursion (`sensor_fault` / `calibration_expired`) that quarantines the
//! lot through the existing workflow.
//!
//! # Audit
//!
//! [`AssetRegistry::history`] is the append-only asset history, and
//! [`AssetRegistry::export_json`] / [`AssetRegistry::export_csv`] are the
//! canonical digested and flat reporting exports.

pub mod store;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::asset_registry::store::AssetStore;
use crate::excursion::{
    DetectionFinding, DetectionOutcome, ExcursionReason, ExcursionRecord, ExcursionWorkflow,
};
use crate::lot::LotRecord;
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

/// Domain-separation context for an asset version's content digest.
pub const CONTEXT_ASSET_VERSION: &str = "TirBase/v1/AssetVersion";

/// Domain-separation context for the audit export digest.
pub const CONTEXT_ASSET_EXPORT: &str = "TirBase/v1/AssetRegistryExport";

/// Domain-separation context for a release block id.
pub const CONTEXT_ASSET_BLOCK: &str = "TirBase/v1/AssetReleaseBlock";

/// Longest accepted identifier.
pub const MAX_ID_LEN: usize = 64;

/// Longest accepted free-text field (model, serial, firmware, reason).
pub const MAX_TEXT_LEN: usize = 128;

/// Fewest calibration points a record may carry.
pub const MIN_CALIBRATION_POINTS: usize = 2;

/// Most calibration points a record may carry.
pub const MAX_CALIBRATION_POINTS: usize = 16;

/// Most records one query or export returns.
pub const MAX_QUERY_RESULTS: usize = 500;

/// Largest certificate the hash may pin.
pub const MAX_CERTIFICATE_BYTES: u64 = 16 * 1024 * 1024;

/// Divisor that turns a calibration interval into its warning window.
pub const WARNING_WINDOW_FRACTION: i64 = 10;

/// Release block code: the observing asset's calibration expired.
pub const BLOCK_CALIBRATION_EXPIRED: &str = "CAL-BLK-001";

/// Release block code: a calibration-required asset has no calibration record.
pub const BLOCK_CALIBRATION_MISSING: &str = "CAL-BLK-002";

/// Release block code: the asset's latest reference check is out of tolerance.
pub const BLOCK_REFERENCE_DRIFT: &str = "CAL-BLK-003";

/// Schema name written into the audit export.
pub const EXPORT_SCHEMA: &str = "TirBase/v1/AssetRegistryExport";

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Kind of asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    /// A temperature/humidity sensor or probe.
    Sensor,
    /// A controller or logger that owns sensors.
    Controller,
}

impl AssetKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AssetKind::Sensor => "sensor",
            AssetKind::Controller => "controller",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, AssetError> {
        match value {
            "sensor" => Ok(AssetKind::Sensor),
            "controller" => Ok(AssetKind::Controller),
            other => Err(AssetError::Invalid {
                field: "kind".to_string(),
                detail: format!("unknown asset kind {other:?}"),
            }),
        }
    }
}

/// Lifecycle status of an asset version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetStatus {
    /// In service.
    Active,
    /// Temporarily out of service; may return to `Active`.
    Suspended,
    /// Permanently out of service; terminal.
    Retired,
    /// Superseded by another asset; terminal.
    Replaced,
}

impl AssetStatus {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AssetStatus::Active => "active",
            AssetStatus::Suspended => "suspended",
            AssetStatus::Retired => "retired",
            AssetStatus::Replaced => "replaced",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, AssetError> {
        match value {
            "active" => Ok(AssetStatus::Active),
            "suspended" => Ok(AssetStatus::Suspended),
            "retired" => Ok(AssetStatus::Retired),
            "replaced" => Ok(AssetStatus::Replaced),
            other => Err(AssetError::Invalid {
                field: "status".to_string(),
                detail: format!("unknown asset status {other:?}"),
            }),
        }
    }

    /// Whether `next` is a legal successor. `Retired` and `Replaced` are terminal.
    pub fn can_transition_to(self, next: AssetStatus) -> bool {
        use AssetStatus::{Active, Replaced, Retired, Suspended};
        matches!(
            (self, next),
            (Active, Active | Suspended | Retired | Replaced)
                | (Suspended, Suspended | Active | Retired | Replaced)
                | (Retired, Retired)
                | (Replaced, Replaced)
        )
    }

    /// Whether the asset is still in service in this status.
    pub fn is_in_service(self) -> bool {
        matches!(self, AssetStatus::Active | AssetStatus::Suspended)
    }

    /// Whether the status is terminal (no further change is possible).
    pub fn is_terminal(self) -> bool {
        matches!(self, AssetStatus::Retired | AssetStatus::Replaced)
    }
}

/// The versioned content of one asset record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetIdentity {
    /// Tenant owning the asset.
    pub tenant: String,
    /// Sensor or controller.
    pub kind: AssetKind,
    /// Manufacturer's model designation.
    pub model: String,
    /// Manufacturer's serial number (unique among in-service assets).
    pub serial: String,
    /// Manufacturer.
    pub manufacturer: String,
    /// Installed firmware version string.
    pub firmware: String,
    /// Site the asset is installed at.
    pub site_id: String,
    /// Location within the site.
    pub location_id: String,
    /// When the asset was installed.
    pub installed_est: i64,
    /// Whether the asset must hold a valid calibration to be used.
    pub calibration_required: bool,
    /// Longest calibration interval the asset class permits, when calibrated.
    pub max_calibration_interval_secs: Option<u64>,
    /// Asset this one replaces, when it is a replacement.
    pub replaces: Option<String>,
    /// Asset that replaced this one, when this version is `Replaced`.
    pub replaced_by: Option<String>,
}

impl AssetIdentity {
    /// Start an identity for `kind` with the identity fields that never default.
    pub fn new(
        kind: AssetKind,
        tenant: impl Into<String>,
        model: impl Into<String>,
        serial: impl Into<String>,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            kind,
            model: model.into(),
            serial: serial.into(),
            manufacturer: String::new(),
            firmware: String::new(),
            site_id: String::new(),
            location_id: String::new(),
            installed_est: 0,
            calibration_required: false,
            max_calibration_interval_secs: None,
            replaces: None,
            replaced_by: None,
        }
    }

    /// Set the manufacturer.
    pub fn with_manufacturer(mut self, manufacturer: impl Into<String>) -> Self {
        self.manufacturer = manufacturer.into();
        self
    }

    /// Set the installed firmware version.
    pub fn with_firmware(mut self, firmware: impl Into<String>) -> Self {
        self.firmware = firmware.into();
        self
    }

    /// Set the install site and location.
    pub fn with_location(
        mut self,
        site_id: impl Into<String>,
        location_id: impl Into<String>,
    ) -> Self {
        self.site_id = site_id.into();
        self.location_id = location_id.into();
        self
    }

    /// Set the installation time.
    pub fn with_installed_est(mut self, installed_est: i64) -> Self {
        self.installed_est = installed_est;
        self
    }

    /// Require a calibration no older than `max_interval_secs`.
    pub fn with_calibration_required(mut self, max_interval_secs: u64) -> Self {
        self.calibration_required = true;
        self.max_calibration_interval_secs = Some(max_interval_secs);
        self
    }

    /// Mark this asset as the replacement for `asset_id`.
    pub fn replacing(mut self, asset_id: impl Into<String>) -> Self {
        self.replaces = Some(asset_id.into());
        self
    }
}

/// One immutable version of an asset record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetVersion {
    /// Asset identifier.
    pub asset_id: String,
    /// Version number, starting at 1.
    pub version: u32,
    /// Inclusive start of the effective range.
    pub effective_from_est: i64,
    /// Exclusive end of the effective range, `None` while newest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_to_est: Option<i64>,
    /// Versioned content.
    pub identity: AssetIdentity,
    /// Lifecycle status of this version.
    pub status: AssetStatus,
    /// Content digest, stable across re-puts of the same content.
    pub digest: String,
    /// Actor that wrote this version.
    pub actor_did: String,
    /// When this version row was written.
    pub created_est: i64,
}

impl AssetVersion {
    /// Whether `at_est` falls inside this version's effective range.
    pub fn is_effective_at(&self, at_est: i64) -> bool {
        at_est >= self.effective_from_est && self.effective_to_est.is_none_or(|end| at_est < end)
    }
}

/// A request to register or revise an asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetDraft {
    /// Asset identifier.
    pub asset_id: String,
    /// When this version takes effect.
    pub effective_from_est: i64,
    /// Versioned content.
    pub identity: AssetIdentity,
    /// Lifecycle status this version should carry; `None` means `Active`.
    pub status: Option<AssetStatus>,
    /// Actor making the change.
    pub actor_did: String,
    /// Why the change was made (recorded in the history).
    pub reason: String,
}

impl AssetDraft {
    /// Start a draft for `identity`.
    pub fn new(
        asset_id: impl Into<String>,
        identity: AssetIdentity,
        actor_did: impl Into<String>,
    ) -> Self {
        let effective_from_est = identity.installed_est;
        Self {
            asset_id: asset_id.into(),
            effective_from_est,
            identity,
            status: None,
            actor_did: actor_did.into(),
            reason: String::new(),
        }
    }

    /// Set the lifecycle status this version should carry.
    pub fn with_status(mut self, status: AssetStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// The lifecycle status a `put` writes: explicit when set, else `Active`.
    fn status_of_put(&self) -> AssetStatus {
        self.status.unwrap_or(AssetStatus::Active)
    }

    /// Set when this version takes effect (defaults to the install time).
    pub fn effective_from(mut self, at_est: i64) -> Self {
        self.effective_from_est = at_est;
        self
    }

    /// Record why the change was made.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
}

/// What an asset history row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetAction {
    /// The asset's first version.
    Registered,
    /// A new version of an existing asset.
    Revised,
    /// The asset was rendered permanently out of service.
    Retired,
    /// The asset was superseded by another asset.
    Replaced,
}

impl AssetAction {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AssetAction::Registered => "registered",
            AssetAction::Revised => "revised",
            AssetAction::Retired => "retired",
            AssetAction::Replaced => "replaced",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, AssetError> {
        match value {
            "registered" => Ok(AssetAction::Registered),
            "revised" => Ok(AssetAction::Revised),
            "retired" => Ok(AssetAction::Retired),
            "replaced" => Ok(AssetAction::Replaced),
            other => Err(AssetError::Invalid {
                field: "action".to_string(),
                detail: format!("unknown asset action {other:?}"),
            }),
        }
    }
}

/// One append-only history row for an asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetHistoryEntry {
    /// Monotonic sequence number.
    pub seq: i64,
    /// Asset identifier.
    pub asset_id: String,
    /// Version the action produced.
    pub version: u32,
    /// Action taken.
    pub action: AssetAction,
    /// Actor that made the change.
    pub actor_did: String,
    /// When the change was recorded.
    pub at_est: i64,
    /// Content digest of the produced version.
    pub digest: String,
    /// Reason recorded with the change.
    pub reason: String,
    /// Extra detail (previous digest, status, replaced_by).
    pub detail: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------

/// One calibration point: the applied reference and the asset's reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationPoint {
    /// Reference value applied to the asset, in deci-degrees Celsius.
    pub reference_c: FixedPointValue,
    /// The asset's reading at that reference, in deci-degrees Celsius.
    pub measured_c: FixedPointValue,
}

impl CalibrationPoint {
    /// A point from deci-degree Celsius values.
    pub fn new(reference_deci_c: i64, measured_deci_c: i64) -> Self {
        Self {
            reference_c: FixedPointValue::new(reference_deci_c, -1, UNIT_DEG_C),
            measured_c: FixedPointValue::new(measured_deci_c, -1, UNIT_DEG_C),
        }
    }

    /// Signed error at this point (measured − reference), in deci-degrees.
    pub fn error_deci_c(&self) -> i64 {
        self.measured_c
            .mantissa
            .saturating_sub(self.reference_c.mantissa)
    }
}

/// A calibration certificate, pinned by digest rather than stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRef {
    /// Certificate identifier used by the laboratory.
    pub certificate_id: String,
    /// Lower-case hex SHA-256 of the certificate bytes.
    pub sha256: String,
    /// Size of the certificate in bytes.
    pub bytes: u64,
    /// Media type of the certificate (for example `application/pdf`).
    pub media_type: String,
    /// When the certificate was issued.
    pub issued_est: i64,
    /// When the certificate lapses, when it states that.
    pub expires_est: Option<i64>,
    /// Issuing laboratory.
    pub issuer: String,
}

impl CertificateRef {
    /// Pin `bytes` by hash; the bytes themselves are not retained.
    pub fn from_bytes(
        certificate_id: impl Into<String>,
        bytes: &[u8],
        media_type: impl Into<String>,
        issuer: impl Into<String>,
        issued_est: i64,
        expires_est: Option<i64>,
    ) -> Self {
        Self {
            certificate_id: certificate_id.into(),
            sha256: sha256_hex(bytes),
            bytes: bytes.len() as u64,
            media_type: media_type.into(),
            issued_est,
            expires_est,
            issuer: issuer.into(),
        }
    }

    /// Whether `bytes` are the certificate this reference pins.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.bytes == bytes.len() as u64 && self.sha256 == sha256_hex(bytes)
    }
}

/// A request to record one calibration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalibrationDraft {
    /// Calibration record identifier.
    pub calibration_id: String,
    /// Asset calibrated.
    pub asset_id: String,
    /// When the calibration was performed.
    pub performed_est: i64,
    /// Interval until the next calibration is due.
    pub interval_secs: u64,
    /// Calibration method (`comparison-ice-point`, `astm-e74`, …).
    pub method: String,
    /// Laboratory that performed it.
    pub laboratory_party_id: String,
    /// Expanded uncertainty of the calibration, in deci-degrees Celsius.
    pub uncertainty_c: FixedPointValue,
    /// Applied reference points.
    pub points: Vec<CalibrationPoint>,
    /// Certificate pinned by hash.
    pub certificate: CertificateRef,
    /// Actor recording the calibration.
    pub actor_did: String,
}

impl CalibrationDraft {
    /// Start a draft for one asset.
    pub fn new(
        calibration_id: impl Into<String>,
        asset_id: impl Into<String>,
        performed_est: i64,
        interval_secs: u64,
        actor_did: impl Into<String>,
    ) -> Self {
        Self {
            calibration_id: calibration_id.into(),
            asset_id: asset_id.into(),
            performed_est,
            interval_secs,
            method: String::new(),
            laboratory_party_id: String::new(),
            uncertainty_c: FixedPointValue::new(0, -1, UNIT_DEG_C),
            points: Vec::new(),
            certificate: CertificateRef {
                certificate_id: String::new(),
                sha256: String::new(),
                bytes: 0,
                media_type: String::new(),
                issued_est: performed_est,
                expires_est: None,
                issuer: String::new(),
            },
            actor_did: actor_did.into(),
        }
    }

    /// Set the method and laboratory.
    pub fn with_laboratory(
        mut self,
        method: impl Into<String>,
        laboratory_party_id: impl Into<String>,
    ) -> Self {
        self.method = method.into();
        self.laboratory_party_id = laboratory_party_id.into();
        self
    }

    /// Set the expanded uncertainty.
    pub fn with_uncertainty(mut self, uncertainty_c: FixedPointValue) -> Self {
        self.uncertainty_c = uncertainty_c;
        self
    }

    /// Set the applied reference points.
    pub fn with_points(mut self, points: Vec<CalibrationPoint>) -> Self {
        self.points = points;
        self
    }

    /// Set the certificate reference.
    pub fn with_certificate(mut self, certificate: CertificateRef) -> Self {
        self.certificate = certificate;
        self
    }

    /// When the calibration falls due.
    pub fn due_est(&self) -> i64 {
        self.performed_est
            .saturating_add(i64::try_from(self.interval_secs).unwrap_or(i64::MAX))
    }
}

/// One stored calibration record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationRecord {
    /// Calibration record identifier.
    pub calibration_id: String,
    /// Asset calibrated.
    pub asset_id: String,
    /// When the calibration was performed.
    pub performed_est: i64,
    /// When it falls due (performed + interval).
    pub due_est: i64,
    /// Interval until the next calibration.
    pub interval_secs: u64,
    /// Calibration method.
    pub method: String,
    /// Laboratory that performed it.
    pub laboratory_party_id: String,
    /// Expanded uncertainty, in deci-degrees Celsius.
    pub uncertainty_c: FixedPointValue,
    /// Applied reference points.
    pub points: Vec<CalibrationPoint>,
    /// Certificate pinned by hash.
    pub certificate: CertificateRef,
    /// Actor that recorded it.
    pub actor_did: String,
    /// Digest over the canonical record content.
    pub digest: String,
}

impl CalibrationRecord {
    /// Calibration state at `at_est`, with the warning window derived from the
    /// interval.
    pub fn state_at(&self, at_est: i64) -> CalibrationState {
        let window = (self.interval_secs as i64 / WARNING_WINDOW_FRACTION).max(1);
        if at_est >= self.due_est {
            CalibrationState::Expired {
                due_est: self.due_est,
            }
        } else if at_est >= self.due_est.saturating_sub(window) {
            CalibrationState::DueSoon {
                due_est: self.due_est,
            }
        } else {
            CalibrationState::Valid {
                due_est: self.due_est,
            }
        }
    }

    /// Largest absolute error across the calibration points, in deci-degrees.
    pub fn max_error_deci_c(&self) -> i64 {
        self.points
            .iter()
            .map(|point| point.error_deci_c().saturating_abs())
            .max()
            .unwrap_or(0)
    }
}

/// Calibration state of an asset at an instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum CalibrationState {
    /// The asset does not require calibration.
    NotRequired,
    /// The asset requires calibration but none has been recorded.
    Missing,
    /// In calibration, with time to spare.
    Valid {
        /// When the calibration falls due.
        due_est: i64,
    },
    /// In calibration, inside the warning window.
    DueSoon {
        /// When the calibration falls due.
        due_est: i64,
    },
    /// Out of calibration.
    Expired {
        /// When the calibration fell due.
        due_est: i64,
    },
}

impl CalibrationState {
    /// Whether the asset may be used for a release.
    pub fn is_usable(self) -> bool {
        matches!(
            self,
            CalibrationState::NotRequired
                | CalibrationState::Valid { .. }
                | CalibrationState::DueSoon { .. }
        )
    }

    /// Whether the state blocks a release.
    pub fn blocks_release(self) -> bool {
        matches!(
            self,
            CalibrationState::Missing | CalibrationState::Expired { .. }
        )
    }

    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            CalibrationState::NotRequired => "not_required",
            CalibrationState::Missing => "missing",
            CalibrationState::Valid { .. } => "valid",
            CalibrationState::DueSoon { .. } => "due_soon",
            CalibrationState::Expired { .. } => "expired",
        }
    }

    /// The due date, when the state has one.
    pub fn due_est(self) -> Option<i64> {
        match self {
            CalibrationState::Valid { due_est }
            | CalibrationState::DueSoon { due_est }
            | CalibrationState::Expired { due_est } => Some(due_est),
            CalibrationState::NotRequired | CalibrationState::Missing => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

/// A request to record one reference check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceCheckDraft {
    /// Check identifier.
    pub check_id: String,
    /// Asset checked.
    pub asset_id: String,
    /// When the check was performed.
    pub at_est: i64,
    /// Reference applied.
    pub reference_c: FixedPointValue,
    /// The asset's reading at that reference.
    pub measured_c: FixedPointValue,
    /// Allowed absolute error.
    pub tolerance_c: FixedPointValue,
    /// Operator who performed the check.
    pub operator_did: String,
}

impl ReferenceCheckDraft {
    /// A check from deci-degree Celsius values.
    pub fn new(
        check_id: impl Into<String>,
        asset_id: impl Into<String>,
        at_est: i64,
        reference_deci_c: i64,
        measured_deci_c: i64,
        tolerance_deci_c: i64,
        operator_did: impl Into<String>,
    ) -> Self {
        Self {
            check_id: check_id.into(),
            asset_id: asset_id.into(),
            at_est,
            reference_c: FixedPointValue::new(reference_deci_c, -1, UNIT_DEG_C),
            measured_c: FixedPointValue::new(measured_deci_c, -1, UNIT_DEG_C),
            tolerance_c: FixedPointValue::new(tolerance_deci_c, -1, UNIT_DEG_C),
            operator_did: operator_did.into(),
        }
    }
}

/// One stored reference check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceCheck {
    /// Check identifier.
    pub check_id: String,
    /// Asset checked.
    pub asset_id: String,
    /// When the check was performed.
    pub at_est: i64,
    /// Reference applied.
    pub reference_c: FixedPointValue,
    /// The asset's reading at that reference.
    pub measured_c: FixedPointValue,
    /// Allowed absolute error.
    pub tolerance_c: FixedPointValue,
    /// Operator who performed the check.
    pub operator_did: String,
    /// Digest over the canonical check content.
    pub digest: String,
}

/// Result of comparing a reference check with the reference and its baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftReport {
    /// Check the report is about.
    pub check_id: String,
    /// Asset checked.
    pub asset_id: String,
    /// Measured − reference, in deci-degrees Celsius.
    pub error_deci_c: i64,
    /// Allowed absolute error, in deci-degrees Celsius.
    pub tolerance_deci_c: i64,
    /// Whether the error is inside tolerance.
    pub in_tolerance: bool,
    /// Earliest check at the same reference, when there is one.
    pub baseline_check_id: Option<String>,
    /// Measured − baseline measured, in deci-degrees Celsius.
    pub baseline_delta_deci_c: Option<i64>,
    /// Whether the asset is drifting: out of tolerance, or away from its
    /// baseline by more than the tolerance.
    pub drifted: bool,
}

// ---------------------------------------------------------------------------
// Release gate
// ---------------------------------------------------------------------------

/// One lot blocked by a calibration state. Blocks are append-only; resolution
/// records the decision instead of deleting the row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseBlock {
    /// Deterministic block identifier.
    pub block_id: String,
    /// Lot held.
    pub lot_id: String,
    /// Asset whose state caused the hold.
    pub asset_id: String,
    /// Block code (`CAL-BLK-001`, `CAL-BLK-002`, `CAL-BLK-003`).
    pub code: String,
    /// Why the hold was raised.
    pub detail: String,
    /// When the hold was raised.
    pub raised_est: i64,
    /// When the hold was resolved, if it has been.
    pub resolved_est: Option<i64>,
    /// Actor that resolved the hold.
    pub resolved_by: Option<String>,
    /// Reason recorded with the resolution.
    pub resolution_reason: Option<String>,
}

impl ReleaseBlock {
    /// Whether the block still holds the lot.
    pub fn is_open(&self) -> bool {
        self.resolved_est.is_none()
    }
}

/// Whether a lot may be released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum ReleaseDecision {
    /// No open block: the lot may be released.
    Allowed {
        /// Lot evaluated.
        lot_id: String,
        /// Assets whose calibration was checked.
        checked_assets: Vec<String>,
        /// Instant the decision was made.
        checked_est: i64,
    },
    /// At least one open block holds the lot.
    Blocked {
        /// Lot evaluated.
        lot_id: String,
        /// Every open block on the lot.
        blocks: Vec<ReleaseBlock>,
        /// Instant the decision was made.
        checked_est: i64,
    },
}

impl ReleaseDecision {
    /// Whether the lot may be released.
    pub fn is_allowed(&self) -> bool {
        matches!(self, ReleaseDecision::Allowed { .. })
    }

    /// The lot evaluated.
    pub fn lot_id(&self) -> &str {
        match self {
            ReleaseDecision::Allowed { lot_id, .. } | ReleaseDecision::Blocked { lot_id, .. } => {
                lot_id
            }
        }
    }

    /// The open blocks, empty when allowed.
    pub fn blocks(&self) -> &[ReleaseBlock] {
        match self {
            ReleaseDecision::Allowed { .. } => &[],
            ReleaseDecision::Blocked { blocks, .. } => blocks,
        }
    }
}

// ---------------------------------------------------------------------------
// Queries and exports
// ---------------------------------------------------------------------------

/// Filter for [`AssetRegistry::query`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssetQuery {
    /// Restrict to these kinds (empty means all).
    pub kinds: Vec<AssetKind>,
    /// Restrict to this site.
    pub site_id: Option<String>,
    /// Restrict to this status.
    pub status: Option<AssetStatus>,
    /// Case-insensitive substring over id, model, serial, manufacturer, firmware.
    pub text: Option<String>,
    /// Cap on returned records (capped at [`MAX_QUERY_RESULTS`]).
    pub limit: Option<usize>,
}

/// The canonical audit export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetExport {
    /// Export schema name.
    pub schema: String,
    /// Instant the export was taken.
    pub generated_est: i64,
    /// Asset versions in force at that instant (retired and replaced included).
    pub assets: Vec<AssetVersion>,
    /// Calibrations performed at or before that instant.
    pub calibrations: Vec<CalibrationRecord>,
    /// Release blocks raised at or before that instant.
    pub blocks: Vec<ReleaseBlock>,
    /// Digest over the export content.
    pub digest: String,
}

impl AssetExport {
    /// Canonical JSON form.
    pub fn to_json(&self) -> Result<String, AssetError> {
        serde_json::to_string(self)
            .map_err(|error| AssetError::Store(format!("encode export: {error}")))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an asset registry operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetError {
    /// The underlying store failed.
    Store(String),
    /// No such record.
    NotFound {
        /// Record kind.
        kind: &'static str,
        /// Record identifier.
        id: String,
    },
    /// The asset exists but has no version in force at that instant.
    NotEffective {
        /// Asset identifier.
        asset_id: String,
        /// Instant asked about.
        at_est: i64,
    },
    /// A field is invalid.
    Invalid {
        /// Offending field.
        field: String,
        /// Why it is invalid.
        detail: String,
    },
    /// An identifier is malformed.
    InvalidIdentifier {
        /// Offending field.
        field: String,
        /// The value as supplied.
        value: String,
    },
    /// The requested status transition is not legal.
    IllegalStatusTransition {
        /// Current status.
        from: AssetStatus,
        /// Requested status.
        to: AssetStatus,
    },
    /// Another in-service asset already carries that serial.
    SerialConflict {
        /// Serial in conflict.
        serial: String,
        /// Asset already holding it.
        asset_id: String,
    },
    /// A revision or calibration is out of order.
    EffectiveDate {
        /// Explanation.
        detail: String,
    },
    /// The same identifier was reused for different content.
    Conflict(String),
    /// A certificate's bytes do not match the pinned digest.
    CertificateMismatch {
        /// Digest on record.
        expected: String,
        /// Digest of the supplied bytes.
        actual: String,
    },
    /// The asset's calibration is not expired.
    NotExpired {
        /// Asset asked about.
        asset_id: String,
        /// Its state.
        state: CalibrationState,
    },
    /// The excursion workflow refused the escalation.
    Excursion(String),
    /// The condition a block records is still present, so it cannot be resolved.
    BlockStillApplies {
        /// Block asked about.
        block_id: String,
        /// Code whose condition is still present.
        code: String,
    },
}

impl AssetError {
    /// The offending field, when the error is about one.
    pub fn field(&self) -> Option<&str> {
        match self {
            AssetError::Invalid { field, .. } | AssetError::InvalidIdentifier { field, .. } => {
                Some(field)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for AssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetError::Store(detail) => write!(f, "asset registry store: {detail}"),
            AssetError::NotFound { kind, id } => write!(f, "{kind} {id} not found"),
            AssetError::NotEffective { asset_id, at_est } => {
                write!(f, "asset {asset_id} has no version effective at {at_est}")
            }
            AssetError::Invalid { field, detail } => write!(f, "invalid {field}: {detail}"),
            AssetError::InvalidIdentifier { field, value } => {
                write!(f, "invalid {field}: {value:?}")
            }
            AssetError::IllegalStatusTransition { from, to } => {
                write!(
                    f,
                    "status cannot move from {from} to {to}",
                    from = from.as_str(),
                    to = to.as_str()
                )
            }
            AssetError::SerialConflict { serial, asset_id } => {
                write!(
                    f,
                    "serial {serial:?} already in service on asset {asset_id}"
                )
            }
            AssetError::EffectiveDate { detail } => write!(f, "effective date: {detail}"),
            AssetError::Conflict(detail) => write!(f, "asset registry conflict: {detail}"),
            AssetError::CertificateMismatch { expected, actual } => write!(
                f,
                "certificate hash mismatch: expected {expected}, got {actual}"
            ),
            AssetError::NotExpired { asset_id, state } => {
                write!(
                    f,
                    "asset {asset_id} calibration is {} (not expired)",
                    state.as_str()
                )
            }
            AssetError::Excursion(detail) => write!(f, "excursion workflow: {detail}"),
            AssetError::BlockStillApplies { block_id, code } => write!(
                f,
                "release block {block_id} cannot be resolved: {code} still applies"
            ),
        }
    }
}

impl std::error::Error for AssetError {}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// The asset and calibration registry.
///
/// One registry owns one SQLite database (the gateway's `primary.db` in
/// production). All methods are synchronous; the caller supplies the clock.
#[derive(Debug)]
pub struct AssetRegistry {
    store: AssetStore,
}

impl AssetRegistry {
    /// Open (or create) the registry at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, AssetError> {
        Ok(Self {
            store: AssetStore::open(path)?,
        })
    }

    /// Open an in-memory registry (tests and ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, AssetError> {
        Ok(Self {
            store: AssetStore::open_in_memory()?,
        })
    }

    // -----------------------------------------------------------------------
    // Identity
    // -----------------------------------------------------------------------

    /// Register an asset, or append the next version of an existing one.
    ///
    /// Re-registering identical content (same digest and status) returns the
    /// newest version unchanged and writes no history row, so a retried
    /// registration is idempotent. Otherwise the previous version's effective
    /// range is closed at the new start: no version is ever rewritten or deleted,
    /// which is what lets an asset's history survive replacement and retirement.
    pub fn put(&self, draft: AssetDraft) -> Result<AssetVersion, AssetError> {
        validate_draft(&draft)?;
        let digest = identity_digest(&draft.identity)?;
        let status = draft.status_of_put();
        let latest = self.store.latest(&draft.asset_id)?;

        let (version, action) = match latest.as_ref() {
            None => {
                if draft.identity.replaced_by.is_some() {
                    return Err(AssetError::Invalid {
                        field: "replaced_by".to_string(),
                        detail: "a new asset cannot already be replaced".to_string(),
                    });
                }
                if draft.identity.replaces.is_some() {
                    self.require_asset(draft.identity.replaces.as_deref().unwrap_or_default())?;
                }
                (1, AssetAction::Registered)
            }
            Some(previous) => {
                if previous.digest == digest && previous.status == status {
                    return Ok(previous.clone());
                }
                if draft.effective_from_est <= previous.effective_from_est {
                    return Err(AssetError::EffectiveDate {
                        detail: format!(
                            "revision must take effect after version {} ({}), got {}",
                            previous.version, previous.effective_from_est, draft.effective_from_est
                        ),
                    });
                }
                if !previous.status.can_transition_to(status) {
                    return Err(AssetError::IllegalStatusTransition {
                        from: previous.status,
                        to: status,
                    });
                }
                let action = match status {
                    AssetStatus::Retired => AssetAction::Retired,
                    AssetStatus::Replaced => AssetAction::Replaced,
                    _ => AssetAction::Revised,
                };
                (previous.version + 1, action)
            }
        };

        self.check_serial(&draft)?;
        self.check_replacement_links(&draft)?;

        let version = AssetVersion {
            asset_id: draft.asset_id.clone(),
            version,
            effective_from_est: draft.effective_from_est,
            effective_to_est: None,
            identity: draft.identity.clone(),
            status,
            digest: digest.clone(),
            actor_did: draft.actor_did.clone(),
            created_est: draft.effective_from_est,
        };
        if let Some(previous) = latest.as_ref() {
            self.store.close_version(
                &previous.asset_id,
                previous.version,
                draft.effective_from_est,
            )?;
        }
        self.store.insert_version(&version)?;
        self.store.append_history(&AssetHistoryEntry {
            seq: 0,
            asset_id: version.asset_id.clone(),
            version: version.version,
            action,
            actor_did: version.actor_did.clone(),
            at_est: draft.effective_from_est,
            digest: version.digest.clone(),
            reason: draft.reason.clone(),
            detail: serde_json::json!({
                "previous_version": latest.as_ref().map(|previous| previous.version),
                "previous_digest": latest.as_ref().map(|previous| previous.digest.clone()),
                "previous_status": latest.as_ref().map(|previous| previous.status.as_str()),
                "status": version.status.as_str(),
                "serial": version.identity.serial,
                "firmware": version.identity.firmware,
                "replaces": version.identity.replaces,
                "replaced_by": version.identity.replaced_by,
                "reason": draft.reason,
            }),
        })?;
        Ok(version)
    }

    /// Revise an existing asset, keeping its lifecycle status unless `status`
    /// is supplied through [`AssetDraft::with_status`].
    pub fn revise(
        &self,
        asset_id: &str,
        identity: AssetIdentity,
        at_est: i64,
        actor_did: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<AssetVersion, AssetError> {
        let current = self.latest(asset_id)?;
        self.put(AssetDraft {
            asset_id: current.asset_id.clone(),
            effective_from_est: at_est,
            identity,
            status: Some(current.status),
            actor_did: actor_did.into(),
            reason: reason.into(),
        })
    }

    /// Move an asset to `Retired` at `at_est`.
    ///
    /// The retirement is a new version; every earlier version, and its
    /// calibrations and reference checks, remain queryable.
    pub fn retire(
        &self,
        asset_id: &str,
        at_est: i64,
        actor_did: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<AssetVersion, AssetError> {
        let current = self.latest(asset_id)?;
        let mut identity = current.identity.clone();
        identity.replaced_by = None;
        self.put(AssetDraft {
            asset_id: current.asset_id.clone(),
            effective_from_est: at_est,
            identity,
            status: Some(AssetStatus::Retired),
            actor_did: actor_did.into(),
            reason: reason.into(),
        })
    }

    /// Replace `asset_id` with `replacement`, closing the old record at
    /// `at_est`.
    ///
    /// Returns `(closed_old, registered_new)`. The old asset keeps every version
    /// and its full calibration history; it is marked `Replaced` with
    /// `replaced_by`, and the new asset records `replaces`.
    pub fn replace(
        &self,
        asset_id: &str,
        mut replacement: AssetDraft,
        at_est: i64,
        actor_did: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(AssetVersion, AssetVersion), AssetError> {
        if replacement.asset_id == asset_id {
            return Err(AssetError::Invalid {
                field: "asset_id".to_string(),
                detail: "an asset cannot replace itself".to_string(),
            });
        }
        let current = self.latest(asset_id)?;
        if !current.status.can_transition_to(AssetStatus::Replaced) {
            return Err(AssetError::IllegalStatusTransition {
                from: current.status,
                to: AssetStatus::Replaced,
            });
        }
        if at_est <= current.effective_from_est {
            return Err(AssetError::EffectiveDate {
                detail: format!(
                    "replacement must take effect after version {} ({}), got {at_est}",
                    current.version, current.effective_from_est
                ),
            });
        }
        if replacement.effective_from_est < at_est {
            return Err(AssetError::EffectiveDate {
                detail: format!(
                    "replacement takes effect at {} before the old asset closes at {at_est}",
                    replacement.effective_from_est
                ),
            });
        }

        replacement.identity.replaces = Some(asset_id.to_string());
        replacement.identity.replaced_by = None;
        replacement.actor_did = actor_did.into();
        replacement.reason = reason.into();
        validate_draft(&replacement)?;

        // Validate the successor before touching the predecessor.
        let new_digest = identity_digest(&replacement.identity)?;
        if self.store.latest(&replacement.asset_id)?.is_some() {
            return Err(AssetError::Conflict(format!(
                "asset {} already exists",
                replacement.asset_id
            )));
        }
        self.check_serial(&replacement)?;

        // Register the successor first: closing the predecessor records the
        // successor in `replaced_by`, which must already resolve.
        let new = self.put(AssetDraft {
            asset_id: replacement.asset_id.clone(),
            effective_from_est: replacement.effective_from_est,
            identity: replacement.identity,
            status: None,
            actor_did: replacement.actor_did.clone(),
            reason: replacement.reason.clone(),
        })?;
        debug_assert_eq!(new.digest, new_digest);

        let mut closed_identity = current.identity.clone();
        closed_identity.replaced_by = Some(new.asset_id.clone());
        let closed = self.put(AssetDraft {
            asset_id: current.asset_id.clone(),
            effective_from_est: at_est,
            identity: closed_identity,
            status: Some(AssetStatus::Replaced),
            actor_did: replacement.actor_did,
            reason: replacement.reason,
        })?;
        Ok((closed, new))
    }

    /// The version in force at `at_est`.
    pub fn get(&self, asset_id: &str, at_est: i64) -> Result<AssetVersion, AssetError> {
        match self.store.at(asset_id, at_est)? {
            Some(version) => Ok(version),
            None => {
                if self.store.latest(asset_id)?.is_some() {
                    Err(AssetError::NotEffective {
                        asset_id: asset_id.to_string(),
                        at_est,
                    })
                } else {
                    Err(AssetError::NotFound {
                        kind: "asset",
                        id: asset_id.to_string(),
                    })
                }
            }
        }
    }

    /// The newest version, whatever its effective range.
    pub fn latest(&self, asset_id: &str) -> Result<AssetVersion, AssetError> {
        self.store
            .latest(asset_id)?
            .ok_or_else(|| AssetError::NotFound {
                kind: "asset",
                id: asset_id.to_string(),
            })
    }

    /// Every version, oldest first.
    pub fn versions(&self, asset_id: &str) -> Result<Vec<AssetVersion>, AssetError> {
        let versions = self.store.versions(asset_id)?;
        if versions.is_empty() {
            return Err(AssetError::NotFound {
                kind: "asset",
                id: asset_id.to_string(),
            });
        }
        Ok(versions)
    }

    /// Append-only history, oldest first.
    pub fn history(&self, asset_id: &str) -> Result<Vec<AssetHistoryEntry>, AssetError> {
        self.store.history(asset_id)
    }

    /// Assets in force at `at_est`, filtered by `query`.
    pub fn query(&self, query: &AssetQuery, at_est: i64) -> Result<Vec<AssetVersion>, AssetError> {
        let limit = query
            .limit
            .unwrap_or(MAX_QUERY_RESULTS)
            .min(MAX_QUERY_RESULTS);
        let needle = query.text.as_ref().map(|text| text.to_lowercase());
        let mut out = Vec::new();
        for version in self.store.all_at(at_est)? {
            if !query.kinds.is_empty() && !query.kinds.contains(&version.identity.kind) {
                continue;
            }
            if let Some(site) = query.site_id.as_ref() {
                if &version.identity.site_id != site {
                    continue;
                }
            }
            if let Some(status) = query.status {
                if version.status != status {
                    continue;
                }
            }
            if let Some(needle) = needle.as_ref() {
                let identity = &version.identity;
                let haystack = format!(
                    "{} {} {} {} {}",
                    version.asset_id,
                    identity.model,
                    identity.serial,
                    identity.manufacturer,
                    identity.firmware
                )
                .to_lowercase();
                if !haystack.contains(needle) {
                    continue;
                }
            }
            out.push(version);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Calibration
    // -----------------------------------------------------------------------

    /// Record a calibration.
    ///
    /// The certificate is pinned by hash: only [`CertificateRef`] is stored, never
    /// the certificate bytes. Re-recording the same calibration id with the same
    /// content returns the stored record; reusing the id for different content is
    /// a conflict.
    pub fn register_calibration(
        &self,
        draft: CalibrationDraft,
    ) -> Result<CalibrationRecord, AssetError> {
        validate_calibration_draft(&draft)?;
        let asset = self.latest(&draft.asset_id)?;
        if !asset.status.is_in_service() {
            return Err(AssetError::Invalid {
                field: "asset_id".to_string(),
                detail: format!(
                    "asset {} is {} and cannot be calibrated",
                    draft.asset_id,
                    asset.status.as_str()
                ),
            });
        }
        if draft.performed_est < asset.identity.installed_est {
            return Err(AssetError::Invalid {
                field: "performed_est".to_string(),
                detail: "calibration predates the asset installation".to_string(),
            });
        }
        if draft.certificate.issued_est > draft.performed_est {
            return Err(AssetError::Invalid {
                field: "certificate.issued_est".to_string(),
                detail: "certificate is issued after the calibration it records".to_string(),
            });
        }
        if let Some(max) = asset.identity.max_calibration_interval_secs {
            if draft.interval_secs > max {
                return Err(AssetError::Invalid {
                    field: "interval_secs".to_string(),
                    detail: format!(
                        "interval {} s exceeds the asset policy of {max} s",
                        draft.interval_secs
                    ),
                });
            }
        }

        let existing = self.store.calibration(&draft.calibration_id)?;
        let due_est = draft.due_est();
        let record = CalibrationRecord {
            calibration_id: draft.calibration_id.clone(),
            asset_id: draft.asset_id.clone(),
            performed_est: draft.performed_est,
            due_est,
            interval_secs: draft.interval_secs,
            method: draft.method.clone(),
            laboratory_party_id: draft.laboratory_party_id.clone(),
            uncertainty_c: draft.uncertainty_c,
            points: draft.points.clone(),
            certificate: draft.certificate.clone(),
            actor_did: draft.actor_did.clone(),
            digest: calibration_digest(&draft, due_est)?,
        };
        if let Some(existing) = existing {
            if existing.digest == record.digest {
                return Ok(existing);
            }
            return Err(AssetError::Conflict(format!(
                "calibration {} already exists with different content",
                record.calibration_id
            )));
        }

        let previous = self.store.latest_calibration(&draft.asset_id, i64::MAX)?;
        if let Some(previous) = previous {
            if draft.performed_est <= previous.performed_est {
                return Err(AssetError::EffectiveDate {
                    detail: format!(
                        "calibration must be performed after {} ({}), got {}",
                        previous.calibration_id, previous.performed_est, draft.performed_est
                    ),
                });
            }
        }

        self.store.insert_calibration(&record)?;
        Ok(record)
    }

    /// Every calibration of an asset, oldest first.
    pub fn calibrations(&self, asset_id: &str) -> Result<Vec<CalibrationRecord>, AssetError> {
        self.store.calibrations(asset_id)
    }

    /// The newest calibration performed at or before `at_est`.
    pub fn latest_calibration(
        &self,
        asset_id: &str,
        at_est: i64,
    ) -> Result<Option<CalibrationRecord>, AssetError> {
        self.store.latest_calibration(asset_id, at_est)
    }

    /// Calibration state of an asset at `at_est`.
    pub fn calibration_state(
        &self,
        asset_id: &str,
        at_est: i64,
    ) -> Result<CalibrationState, AssetError> {
        let asset = self.get(asset_id, at_est)?;
        if !asset.identity.calibration_required {
            return Ok(CalibrationState::NotRequired);
        }
        let Some(record) = self.store.latest_calibration(asset_id, at_est)? else {
            return Ok(CalibrationState::Missing);
        };
        Ok(record.state_at(at_est))
    }

    /// Verify that `bytes` are the certificate a reference pins.
    pub fn verify_certificate(
        &self,
        certificate: &CertificateRef,
        bytes: &[u8],
    ) -> Result<(), AssetError> {
        let actual = sha256_hex(bytes);
        if certificate.sha256 == actual && certificate.bytes == bytes.len() as u64 {
            Ok(())
        } else {
            Err(AssetError::CertificateMismatch {
                expected: certificate.sha256.clone(),
                actual,
            })
        }
    }

    // -----------------------------------------------------------------------
    // Drift
    // -----------------------------------------------------------------------

    /// Record a reference check and report drift.
    ///
    /// Drift is detected on two axes: the error against the applied reference
    /// (inside/outside tolerance) and the movement away from the asset's earliest
    /// check at the same reference, which catches a sensor drifting slowly while
    /// each individual check looks acceptable.
    pub fn record_reference_check(
        &self,
        draft: ReferenceCheckDraft,
    ) -> Result<(ReferenceCheck, DriftReport), AssetError> {
        validate_check_draft(&draft)?;
        self.latest(&draft.asset_id)?;
        let check = ReferenceCheck {
            check_id: draft.check_id.clone(),
            asset_id: draft.asset_id.clone(),
            at_est: draft.at_est,
            reference_c: draft.reference_c,
            measured_c: draft.measured_c,
            tolerance_c: draft.tolerance_c,
            operator_did: draft.operator_did.clone(),
            digest: check_digest(&draft)?,
        };
        if let Some(existing) = self.store.check(&draft.check_id)? {
            if existing.digest == check.digest {
                let report = self.drift_report_for(&existing)?;
                return Ok((existing, report));
            }
            return Err(AssetError::Conflict(format!(
                "reference check {} already exists with different content",
                check.check_id
            )));
        }

        let baseline = self
            .store
            .baseline_check(&draft.asset_id, draft.reference_c.mantissa)?;
        self.store.insert_check(&check)?;
        let report = drift_report(&check, baseline.as_ref());
        Ok((check, report))
    }

    /// Every reference check of an asset, oldest first.
    pub fn reference_checks(&self, asset_id: &str) -> Result<Vec<ReferenceCheck>, AssetError> {
        self.store.checks(asset_id)
    }

    /// Recompute the drift report for a stored check.
    pub fn drift_report(&self, check_id: &str) -> Result<DriftReport, AssetError> {
        let check = self
            .store
            .check(check_id)?
            .ok_or_else(|| AssetError::NotFound {
                kind: "reference check",
                id: check_id.to_string(),
            })?;
        self.drift_report_for(&check)
    }

    fn drift_report_for(&self, check: &ReferenceCheck) -> Result<DriftReport, AssetError> {
        let baseline = self
            .store
            .baseline_check(&check.asset_id, check.reference_c.mantissa)?;
        Ok(drift_report(check, baseline.as_ref()))
    }

    // -----------------------------------------------------------------------
    // Release gate
    // -----------------------------------------------------------------------

    /// Decide whether a CC-12 lot may be released.
    ///
    /// Every asset that observed the lot is checked at `at_est`. An expired or
    /// missing calibration, or an out-of-tolerance latest reference check, writes
    /// a deterministic block against the lot; the decision reports every open
    /// block on the lot, including blocks raised by earlier evaluations.
    pub fn evaluate_lot_release(
        &self,
        lot: &LotRecord,
        asset_ids: &[String],
        at_est: i64,
    ) -> Result<ReleaseDecision, AssetError> {
        if lot.lot_id.trim().is_empty() {
            return Err(AssetError::Invalid {
                field: "lot_id".to_string(),
                detail: "must be non-empty".to_string(),
            });
        }
        let mut checked: Vec<String> = if asset_ids.is_empty() {
            lot.device_ids.clone()
        } else {
            asset_ids.to_vec()
        };
        checked.sort();
        checked.dedup();

        for asset_id in &checked {
            for (code, detail) in self.block_reasons(asset_id, at_est)? {
                let block = ReleaseBlock {
                    block_id: block_id(&lot.lot_id, asset_id, code, &detail),
                    lot_id: lot.lot_id.clone(),
                    asset_id: asset_id.clone(),
                    code: code.to_string(),
                    detail,
                    raised_est: at_est,
                    resolved_est: None,
                    resolved_by: None,
                    resolution_reason: None,
                };
                self.store.raise_block(&block)?;
            }
        }

        let open = self.store.unresolved_blocks_for_lot(&lot.lot_id)?;
        if open.is_empty() {
            Ok(ReleaseDecision::Allowed {
                lot_id: lot.lot_id.clone(),
                checked_assets: checked,
                checked_est: at_est,
            })
        } else {
            Ok(ReleaseDecision::Blocked {
                lot_id: lot.lot_id.clone(),
                blocks: open,
                checked_est: at_est,
            })
        }
    }

    /// Whether a lot currently has an open release block.
    pub fn is_lot_blocked(&self, lot_id: &str) -> Result<bool, AssetError> {
        Ok(!self.store.unresolved_blocks_for_lot(lot_id)?.is_empty())
    }

    /// Open blocks of a lot, oldest first.
    pub fn release_blocks(&self, lot_id: &str) -> Result<Vec<ReleaseBlock>, AssetError> {
        self.store.unresolved_blocks_for_lot(lot_id)
    }

    /// Resolve a block with an actor and a reason.
    ///
    /// Idempotent: a second resolution leaves the first one, and its evidence,
    /// untouched.
    pub fn resolve_block(
        &self,
        block_id_value: &str,
        at_est: i64,
        actor_did: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<ReleaseBlock, AssetError> {
        let actor = actor_did.into();
        let reason = reason.into();
        if actor.trim().is_empty() {
            return Err(AssetError::Invalid {
                field: "actor_did".to_string(),
                detail: "must be non-empty".to_string(),
            });
        }
        if reason.trim().is_empty() {
            return Err(AssetError::Invalid {
                field: "reason".to_string(),
                detail: "a block resolution must state a reason".to_string(),
            });
        }
        let existing = self
            .store
            .block(block_id_value)?
            .ok_or_else(|| AssetError::NotFound {
                kind: "release block",
                id: block_id_value.to_string(),
            })?;
        if existing.is_open() {
            // Fail closed: a block is only resolvable once its condition has
            // actually been corrected (recalibrated, or an in-tolerance check).
            let still = self
                .block_reasons(&existing.asset_id, at_est)?
                .into_iter()
                .any(|(code, _)| code == existing.code);
            if still {
                return Err(AssetError::BlockStillApplies {
                    block_id: block_id_value.to_string(),
                    code: existing.code,
                });
            }
            self.store
                .resolve_block(block_id_value, at_est, &actor, &reason)?;
        }
        self.store
            .block(block_id_value)?
            .ok_or_else(|| AssetError::NotFound {
                kind: "release block",
                id: block_id_value.to_string(),
            })
    }

    /// Raise a CC-11 excursion for an asset whose calibration has expired.
    ///
    /// The excursion's only finding is `sensor_fault` naming the asset and its
    /// due date, so the affected lot enters the existing quarantine workflow
    /// instead of being released on stale readings. No other detection input is
    /// invented: the record says what was observed and nothing more.
    pub fn raise_expiry_excursion(
        &self,
        workflow: &ExcursionWorkflow,
        record_id: &str,
        tenant: &str,
        lot_id: Option<&str>,
        asset_id: &str,
        at_est: i64,
    ) -> Result<ExcursionRecord, AssetError> {
        let state = self.calibration_state(asset_id, at_est)?;
        let CalibrationState::Expired { due_est } = state else {
            return Err(AssetError::NotExpired {
                asset_id: asset_id.to_string(),
                state,
            });
        };
        let asset = self.latest(asset_id)?;
        let detection = expiry_detection(asset_id, due_est, at_est);
        workflow
            .detect(
                record_id,
                tenant,
                &asset.identity.site_id,
                asset_id,
                lot_id,
                detection,
                at_est,
            )
            .map_err(|error| AssetError::Excursion(error.to_string()))
    }

    // -----------------------------------------------------------------------
    // Audit exports
    // -----------------------------------------------------------------------

    /// Canonical, digested export of the registry as of `at_est`.
    pub fn export_json(&self, at_est: i64) -> Result<AssetExport, AssetError> {
        let assets = self.query(&AssetQuery::default(), at_est)?;
        let calibrations = self.store.calibrations_at(at_est)?;
        let blocks = self.store.blocks_at(at_est)?;
        let digest = export_digest(at_est, &assets, &calibrations, &blocks)?;
        Ok(AssetExport {
            schema: EXPORT_SCHEMA.to_string(),
            generated_est: at_est,
            assets,
            calibrations,
            blocks,
            digest,
        })
    }

    /// Flat reporting export: one row per asset version in force at `at_est`.
    pub fn export_csv(&self, at_est: i64) -> Result<String, AssetError> {
        let assets = self.query(&AssetQuery::default(), at_est)?;
        let mut out = String::from(
            "asset_id,version,kind,status,model,serial,manufacturer,firmware,site_id,location_id,\
             installed_est,calibration_required,effective_from_est,effective_to_est,digest",
        );
        out.push('\n');
        for asset in assets {
            let identity = &asset.identity;
            let fields = [
                asset.asset_id.as_str(),
                &asset.version.to_string(),
                identity.kind.as_str(),
                asset.status.as_str(),
                identity.model.as_str(),
                identity.serial.as_str(),
                identity.manufacturer.as_str(),
                identity.firmware.as_str(),
                identity.site_id.as_str(),
                identity.location_id.as_str(),
                &identity.installed_est.to_string(),
                if identity.calibration_required {
                    "true"
                } else {
                    "false"
                },
                &asset.effective_from_est.to_string(),
                &asset
                    .effective_to_est
                    .map(|end| end.to_string())
                    .unwrap_or_default(),
                asset.digest.as_str(),
            ];
            out.push_str(
                &fields
                    .iter()
                    .map(|field| csv_field(field))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            out.push('\n');
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn require_asset(&self, asset_id: &str) -> Result<AssetVersion, AssetError> {
        self.latest(asset_id)
    }

    fn check_serial(&self, draft: &AssetDraft) -> Result<(), AssetError> {
        let serial = draft.identity.serial.trim();
        for asset in self.store.open_versions()? {
            if asset.asset_id == draft.asset_id {
                continue;
            }
            if !asset.status.is_in_service() {
                continue;
            }
            if asset.identity.serial.eq_ignore_ascii_case(serial) {
                return Err(AssetError::SerialConflict {
                    serial: serial.to_string(),
                    asset_id: asset.asset_id,
                });
            }
        }
        Ok(())
    }

    fn check_replacement_links(&self, draft: &AssetDraft) -> Result<(), AssetError> {
        if let Some(previous) = draft.identity.replaces.as_deref() {
            if previous == draft.asset_id {
                return Err(AssetError::Invalid {
                    field: "replaces".to_string(),
                    detail: "an asset cannot replace itself".to_string(),
                });
            }
            self.require_asset(previous)?;
        }
        if let Some(next) = draft.identity.replaced_by.as_deref() {
            if next == draft.asset_id {
                return Err(AssetError::Invalid {
                    field: "replaced_by".to_string(),
                    detail: "an asset cannot replace itself".to_string(),
                });
            }
            self.require_asset(next)?;
        }
        Ok(())
    }

    /// Block reasons for one asset at `at_est`.
    fn block_reasons(
        &self,
        asset_id: &str,
        at_est: i64,
    ) -> Result<Vec<(&'static str, String)>, AssetError> {
        let mut reasons = Vec::new();
        match self.calibration_state(asset_id, at_est)? {
            CalibrationState::Expired { due_est } => reasons.push((
                BLOCK_CALIBRATION_EXPIRED,
                format!("calibration of asset {asset_id} expired at {due_est}"),
            )),
            CalibrationState::Missing => reasons.push((
                BLOCK_CALIBRATION_MISSING,
                format!("asset {asset_id} requires a calibration and none is recorded"),
            )),
            CalibrationState::NotRequired
            | CalibrationState::Valid { .. }
            | CalibrationState::DueSoon { .. } => {}
        }

        if let Some(check) = self.store.latest_check(asset_id, at_est)? {
            let report = self.drift_report_for(&check)?;
            if report.drifted {
                reasons.push((
                    BLOCK_REFERENCE_DRIFT,
                    format!(
                        "reference check {} on asset {asset_id}: error {} deci-C against \
                         ±{} deci-C tolerance, baseline delta {:?} deci-C",
                        report.check_id,
                        report.error_deci_c,
                        report.tolerance_deci_c,
                        report.baseline_delta_deci_c
                    ),
                ));
            }
        }
        Ok(reasons)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn identity_digest(identity: &AssetIdentity) -> Result<String, AssetError> {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_ASSET_VERSION.as_bytes());
    hasher.update(b"\0");
    hasher.update(
        serde_json::to_vec(identity)
            .map_err(|error| AssetError::Store(format!("encode asset identity: {error}")))?,
    );
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn calibration_digest(draft: &CalibrationDraft, due_est: i64) -> Result<String, AssetError> {
    let mut hasher = Sha256::new();
    hasher.update(b"TirBase/v1/AssetCalibration\0");
    hasher.update(
        serde_json::to_vec(&(
            &draft.calibration_id,
            &draft.asset_id,
            draft.performed_est,
            due_est,
            draft.interval_secs,
            &draft.method,
            &draft.laboratory_party_id,
            draft.uncertainty_c,
            &draft.points,
            &draft.certificate,
            &draft.actor_did,
        ))
        .map_err(|error| AssetError::Store(format!("encode calibration: {error}")))?,
    );
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn check_digest(draft: &ReferenceCheckDraft) -> Result<String, AssetError> {
    let mut hasher = Sha256::new();
    hasher.update(b"TirBase/v1/AssetReferenceCheck\0");
    hasher.update(
        serde_json::to_vec(&(
            &draft.check_id,
            &draft.asset_id,
            draft.at_est,
            draft.reference_c,
            draft.measured_c,
            draft.tolerance_c,
            &draft.operator_did,
        ))
        .map_err(|error| AssetError::Store(format!("encode reference check: {error}")))?,
    );
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn export_digest(
    at_est: i64,
    assets: &[AssetVersion],
    calibrations: &[CalibrationRecord],
    blocks: &[ReleaseBlock],
) -> Result<String, AssetError> {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_ASSET_EXPORT.as_bytes());
    hasher.update(b"\0");
    hasher.update(
        serde_json::to_vec(&(at_est, assets, calibrations, blocks))
            .map_err(|error| AssetError::Store(format!("encode export: {error}")))?,
    );
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn block_id(lot_id: &str, asset_id: &str, code: &str, detail: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_ASSET_BLOCK.as_bytes());
    hasher.update(b"\0");
    hasher.update(lot_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(asset_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(code.as_bytes());
    hasher.update(b"\0");
    hasher.update(detail.as_bytes());
    let hex: String = hasher
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("blk-{hex}")
}

fn drift_report(check: &ReferenceCheck, baseline: Option<&ReferenceCheck>) -> DriftReport {
    let error = check
        .measured_c
        .mantissa
        .saturating_sub(check.reference_c.mantissa);
    let tolerance = check.tolerance_c.mantissa;
    let in_tolerance = error.saturating_abs() <= tolerance;
    let (baseline_check_id, baseline_delta, baseline_drift) = match baseline {
        Some(baseline) if baseline.check_id != check.check_id => {
            let delta = check
                .measured_c
                .mantissa
                .saturating_sub(baseline.measured_c.mantissa);
            (
                Some(baseline.check_id.clone()),
                Some(delta),
                delta.saturating_abs() > tolerance,
            )
        }
        _ => (None, None, false),
    };
    DriftReport {
        check_id: check.check_id.clone(),
        asset_id: check.asset_id.clone(),
        error_deci_c: error,
        tolerance_deci_c: tolerance,
        in_tolerance,
        baseline_check_id,
        baseline_delta_deci_c: baseline_delta,
        drifted: !in_tolerance || baseline_drift,
    }
}

fn expiry_detection(asset_id: &str, due_est: i64, at_est: i64) -> DetectionOutcome {
    DetectionOutcome {
        findings: vec![DetectionFinding {
            reason: ExcursionReason::SensorFault,
            detail: format!("asset {asset_id} calibration expired at {due_est}"),
        }],
        mkt_c: None,
        evaluated_est: at_est,
    }
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn validate_id(field: &str, value: &str) -> Result<(), AssetError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ID_LEN {
        return Err(AssetError::InvalidIdentifier {
            field: field.to_string(),
            value: value.to_string(),
        });
    }
    let mut characters = trimmed.chars();
    let first = characters.next().unwrap_or(' ');
    if !first.is_ascii_alphanumeric()
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
        })
    {
        return Err(AssetError::InvalidIdentifier {
            field: field.to_string(),
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_text(field: &str, value: &str) -> Result<(), AssetError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AssetError::Invalid {
            field: field.to_string(),
            detail: "must be non-empty".to_string(),
        });
    }
    if trimmed.len() > MAX_TEXT_LEN {
        return Err(AssetError::Invalid {
            field: field.to_string(),
            detail: format!("must be at most {MAX_TEXT_LEN} characters"),
        });
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(AssetError::Invalid {
            field: field.to_string(),
            detail: "must not contain control characters".to_string(),
        });
    }
    Ok(())
}

fn validate_deci_c(field: &str, value: &FixedPointValue) -> Result<(), AssetError> {
    if value.unit_id != UNIT_DEG_C || value.exponent != -1 {
        return Err(AssetError::Invalid {
            field: field.to_string(),
            detail: format!(
                "must be a temperature in unit {UNIT_DEG_C} at exponent -1, got unit {} exponent {}",
                value.unit_id, value.exponent
            ),
        });
    }
    Ok(())
}

fn validate_draft(draft: &AssetDraft) -> Result<(), AssetError> {
    validate_id("asset_id", &draft.asset_id)?;
    if draft.actor_did.trim().is_empty() {
        return Err(AssetError::Invalid {
            field: "actor_did".to_string(),
            detail: "must be non-empty".to_string(),
        });
    }
    if draft.reason.len() > MAX_TEXT_LEN {
        return Err(AssetError::Invalid {
            field: "reason".to_string(),
            detail: format!("must be at most {MAX_TEXT_LEN} characters"),
        });
    }
    let identity = &draft.identity;
    validate_id("tenant", &identity.tenant)?;
    validate_text("model", &identity.model)?;
    validate_text("serial", &identity.serial)?;
    validate_text("manufacturer", &identity.manufacturer)?;
    validate_text("firmware", &identity.firmware)?;
    validate_id("site_id", &identity.site_id)?;
    validate_id("location_id", &identity.location_id)?;
    if identity.installed_est < 0 {
        return Err(AssetError::Invalid {
            field: "installed_est".to_string(),
            detail: "must not be negative".to_string(),
        });
    }
    if identity.calibration_required && identity.max_calibration_interval_secs.is_none() {
        return Err(AssetError::Invalid {
            field: "max_calibration_interval_secs".to_string(),
            detail: "a calibration-required asset must state its maximum interval".to_string(),
        });
    }
    if matches!(identity.max_calibration_interval_secs, Some(0)) {
        return Err(AssetError::Invalid {
            field: "max_calibration_interval_secs".to_string(),
            detail: "must be greater than zero".to_string(),
        });
    }
    if identity.replaces.is_some() && identity.replaced_by.is_some() {
        return Err(AssetError::Invalid {
            field: "replaces".to_string(),
            detail: "an asset cannot both replace and be replaced in the same version".to_string(),
        });
    }
    Ok(())
}

fn validate_calibration_draft(draft: &CalibrationDraft) -> Result<(), AssetError> {
    validate_id("calibration_id", &draft.calibration_id)?;
    validate_id("asset_id", &draft.asset_id)?;
    validate_text("method", &draft.method)?;
    validate_id("laboratory_party_id", &draft.laboratory_party_id)?;
    if draft.actor_did.trim().is_empty() {
        return Err(AssetError::Invalid {
            field: "actor_did".to_string(),
            detail: "must be non-empty".to_string(),
        });
    }
    if draft.performed_est < 0 {
        return Err(AssetError::Invalid {
            field: "performed_est".to_string(),
            detail: "must not be negative".to_string(),
        });
    }
    if draft.interval_secs == 0 {
        return Err(AssetError::Invalid {
            field: "interval_secs".to_string(),
            detail: "must be greater than zero".to_string(),
        });
    }
    if draft
        .performed_est
        .checked_add(i64::try_from(draft.interval_secs).unwrap_or(i64::MAX))
        .is_none()
    {
        return Err(AssetError::Invalid {
            field: "interval_secs".to_string(),
            detail: "due date overflows".to_string(),
        });
    }
    validate_deci_c("uncertainty_c", &draft.uncertainty_c)?;
    if draft.uncertainty_c.mantissa < 0 {
        return Err(AssetError::Invalid {
            field: "uncertainty_c".to_string(),
            detail: "must not be negative".to_string(),
        });
    }

    if draft.points.len() < MIN_CALIBRATION_POINTS || draft.points.len() > MAX_CALIBRATION_POINTS {
        return Err(AssetError::Invalid {
            field: "points".to_string(),
            detail: format!(
                "must contain {MIN_CALIBRATION_POINTS}..={MAX_CALIBRATION_POINTS} points"
            ),
        });
    }
    for (index, point) in draft.points.iter().enumerate() {
        validate_deci_c(&format!("points[{index}].reference_c"), &point.reference_c)?;
        validate_deci_c(&format!("points[{index}].measured_c"), &point.measured_c)?;
        if index > 0 && point.reference_c.mantissa <= draft.points[index - 1].reference_c.mantissa {
            return Err(AssetError::Invalid {
                field: format!("points[{index}].reference_c"),
                detail: "reference points must be strictly increasing".to_string(),
            });
        }
    }

    let certificate = &draft.certificate;
    validate_id("certificate.certificate_id", &certificate.certificate_id)?;
    validate_text("certificate.media_type", &certificate.media_type)?;
    validate_text("certificate.issuer", &certificate.issuer)?;
    if certificate.sha256.len() != 64
        || !certificate
            .sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || certificate
            .sha256
            .chars()
            .any(|character| character.is_ascii_uppercase())
    {
        return Err(AssetError::Invalid {
            field: "certificate.sha256".to_string(),
            detail: "must be 64 lower-case hex characters".to_string(),
        });
    }
    if certificate.bytes == 0 || certificate.bytes > MAX_CERTIFICATE_BYTES {
        return Err(AssetError::Invalid {
            field: "certificate.bytes".to_string(),
            detail: format!("must be 1..={MAX_CERTIFICATE_BYTES}"),
        });
    }
    if let Some(expires) = certificate.expires_est {
        if expires <= certificate.issued_est {
            return Err(AssetError::Invalid {
                field: "certificate.expires_est".to_string(),
                detail: "must be after the issue date".to_string(),
            });
        }
    }
    Ok(())
}

fn validate_check_draft(draft: &ReferenceCheckDraft) -> Result<(), AssetError> {
    validate_id("check_id", &draft.check_id)?;
    validate_id("asset_id", &draft.asset_id)?;
    if draft.operator_did.trim().is_empty() {
        return Err(AssetError::Invalid {
            field: "operator_did".to_string(),
            detail: "must be non-empty".to_string(),
        });
    }
    validate_deci_c("reference_c", &draft.reference_c)?;
    validate_deci_c("measured_c", &draft.measured_c)?;
    validate_deci_c("tolerance_c", &draft.tolerance_c)?;
    if draft.tolerance_c.mantissa < 0 {
        return Err(AssetError::Invalid {
            field: "tolerance_c".to_string(),
            detail: "must not be negative".to_string(),
        });
    }
    Ok(())
}
