// SPDX-License-Identifier: Apache-2.0

//! TirBase data-only pack framework and vertical demo packs.
//!
//! A **pack** is a directory of data that configures TirBase for one device
//! family: an `EnvelopeProfile`, controller register maps, adversary scenarios,
//! a simulator config, expected outcomes, a launcher, and documentation. Packs
//! carry no executable code — the only executable file is the pack-format
//! launcher `run.sh`, enforced by `scripts/check-pack-purity.py`.
//!
//! # Pack format (version 1)
//!
//! ```text
//! <pack>/
//!   pack.toml                       # versioned manifest (schema_version = 1)
//!   profiles/<name>.toml            # EnvelopeProfile TOML documents
//!   register-maps/<name>.toml       # Modbus register maps (units pinned)
//!   scenarios/<id>.toml             # adversary scenarios + expected outcome
//!   expected/outcomes.toml          # machine-readable defended output
//!   sim/config.toml                 # simulator configuration
//!   run.sh                          # launcher (the only executable)
//!   docs/README.md                  # intended use, assumptions, non-goals
//! ```
//!
//! [`load_pack`] parses the manifest and every referenced document, and
//! validates the pack as a whole: schema version, identity, contained paths,
//! profile/scenario consistency, replay references, and expected-output
//! coverage. It performs no I/O beyond reading the pack directory and never
//! executes anything.
//!
//! The reference device pack is `tirbase-demo/cold-room/`. The POS-09 offline
//! scenario pack at `tirbase-demo/pos-offline/` uses the [`pos_pack`] schema and
//! is loaded by [`load_pos_pack`]; it carries no device profiles or register
//! maps.
//!
//! ## Demo pack format (CLAIM-46.1, PV-16)
//!
//! The older demo packs (`cold-chain`, `energy-edge`, …) predate the versioned
//! manifest and keep the layout listed in [`DEMO_PACK_FORMAT`]. Both formats
//! share the `profiles/`, `scenarios/`, `sim/config.toml`, `run.sh`, and
//! `docs/` entries.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tirbase_types::FixedPointValue;

pub mod pos_pack;
pub mod workflow;

pub use pos_pack::{
    load_pos_pack, PosApproval, PosCommand, PosExpectedOutputs, PosExpectedScenario, PosInitial,
    PosKds, PosPack, PosPackManifest, PosPartition, PosPricing, PosScenario, PosSplit,
    POS_COMMAND_PERMITS, POS_PACK_KIND, POS_PACK_LICENCE, POS_PACK_MANIFEST_FILE,
    POS_PACK_REQUIRED_SCENARIOS, POS_PACK_SCHEMA_VERSION,
};
pub use workflow::{load_workflow_config, WorkflowConfig, WorkflowConfigError};

/// Relative paths that define a complete legacy demo pack (CLAIM-46.1).
pub const DEMO_PACK_FORMAT: &[&str] = &[
    "profiles",
    "scenarios",
    "sim/config.toml",
    "run.sh",
    "docs/README.md",
    "docs/modbus-register-map.md",
];

/// Cold-chain flagship demo pack path relative to the workspace root.
pub const COLD_CHAIN_PACK_DIR: &str = "tirbase-demo/cold-chain";

/// Files required by the cold-chain flagship pack (format + pack-specific assets).
pub const COLD_CHAIN_PACK_FORMAT: &[&str] = &[
    "profiles/cold_chain.toml",
    "scenarios/S1.toml",
    "scenarios/S2.toml",
    "scenarios/S3.toml",
    "sim/config.toml",
    "run.sh",
    "docs/README.md",
    "docs/modbus-register-map.md",
];

/// Returns `true` when every path in `required` exists under `pack_root`.
pub fn pack_has_required_layout(pack_root: &Path, required: &[&str]) -> bool {
    required.iter().all(|rel| pack_root.join(rel).exists())
}

// ---------------------------------------------------------------------------
// Versioned manifest
// ---------------------------------------------------------------------------

/// File name of the versioned pack manifest.
pub const PACK_MANIFEST_FILE: &str = "pack.toml";

/// Manifest schema version understood by this crate.
pub const PACK_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Licence every open pack is published under.
pub const PACK_LICENCE: &str = "Apache-2.0";

/// The only executable entry a pack may contain.
pub const PACK_LAUNCHER: &str = "run.sh";

/// Versioned pack manifest (`pack.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct PackManifest {
    /// Manifest schema version. Must equal [`PACK_MANIFEST_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Pack identity; must match the pack directory name.
    pub id: String,
    /// Pack version (`major.minor.patch`).
    pub version: String,
    /// Human-readable title.
    pub title: String,
    /// One-paragraph description.
    pub description: String,
    /// SPDX licence identifier. Must be [`PACK_LICENCE`].
    pub licence: String,
    /// Device class the profile applies to.
    pub device_class: String,
    /// Minimum TirBase release the pack is validated against.
    pub tirbase_min_version: String,
    /// `EnvelopeProfile` documents, relative to the pack root.
    pub profiles: Vec<String>,
    /// Modbus register maps, relative to the pack root.
    pub register_maps: Vec<String>,
    /// Simulator configuration, relative to the pack root.
    pub sim: String,
    /// Launcher, relative to the pack root. Must be [`PACK_LAUNCHER`].
    pub run: String,
    /// Documentation files, relative to the pack root.
    pub docs: Vec<String>,
    /// Expected-output document, relative to the pack root.
    pub expected: String,
    /// Scenario documents, relative to the pack root.
    pub scenarios: Vec<String>,
    /// Trip-metadata document, relative to the pack root (optional).
    #[serde(default)]
    pub trip: Option<String>,
    /// GDP storage/lot-release policy document, relative to the pack root
    /// (optional).
    #[serde(default)]
    pub gdp: Option<String>,
    /// Calibration-record document, relative to the pack root (optional).
    #[serde(default)]
    pub calibration: Option<String>,
    /// Qualification-checklist document, relative to the pack root (optional).
    #[serde(default)]
    pub qualification: Option<String>,
    /// Workflow-config document, relative to the pack root (optional, CC-13).
    #[serde(default)]
    pub workflow: Option<String>,
}

/// Adversary class the scenario belongs to (docs/adversary-scenarios.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdversaryClass {
    /// Out-of-envelope command.
    S1,
    /// Slow ramp or cumulative drift.
    S2,
    /// Replay or duplicated command.
    S3,
}

impl AdversaryClass {
    /// Canonical `S1`/`S2`/`S3` label.
    pub fn as_str(self) -> &'static str {
        match self {
            AdversaryClass::S1 => "S1",
            AdversaryClass::S2 => "S2",
            AdversaryClass::S3 => "S3",
        }
    }
}

impl<'de> Deserialize<'de> for AdversaryClass {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "S1" => Ok(AdversaryClass::S1),
            "S2" => Ok(AdversaryClass::S2),
            "S3" => Ok(AdversaryClass::S3),
            other => Err(serde::de::Error::custom(format!(
                "unknown adversary class '{other}'; expected S1, S2, or S3"
            ))),
        }
    }
}

impl fmt::Display for AdversaryClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of one scenario step, as expected by the pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepDisposition {
    /// The guard admitted the command and dispatched it.
    Accepted,
    /// The guard rejected the command; nothing was dispatched.
    Rejected,
    /// The command was recognised as a duplicate and the cached result returned
    /// without a second dispatch.
    Deduplicated,
}

/// Scenario-level disposition derived from the step outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScenarioDisposition {
    /// Every step was accepted.
    Accepted,
    /// At least one step was rejected.
    Rejected,
    /// No rejection, and at least one duplicate was answered from the cache.
    Deduplicated,
}

impl ScenarioDisposition {
    /// Derive the scenario-level disposition from its step outcomes.
    pub fn from_steps(steps: &[StepDisposition]) -> Self {
        if steps.contains(&StepDisposition::Rejected) {
            ScenarioDisposition::Rejected
        } else if steps.contains(&StepDisposition::Deduplicated) {
            ScenarioDisposition::Deduplicated
        } else {
            ScenarioDisposition::Accepted
        }
    }

    /// Lowercase label used in expected-output documents.
    pub fn as_str(self) -> &'static str {
        match self {
            ScenarioDisposition::Accepted => "accepted",
            ScenarioDisposition::Rejected => "rejected",
            ScenarioDisposition::Deduplicated => "deduplicated",
        }
    }
}

impl<'de> Deserialize<'de> for ScenarioDisposition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "accepted" => Ok(ScenarioDisposition::Accepted),
            "rejected" => Ok(ScenarioDisposition::Rejected),
            "deduplicated" => Ok(ScenarioDisposition::Deduplicated),
            other => Err(serde::de::Error::custom(format!(
                "unknown scenario disposition '{other}'; expected accepted, rejected, or deduplicated"
            ))),
        }
    }
}

/// One command in an adversary scenario.
#[derive(Debug, Clone, Deserialize)]
pub struct ScenarioStep {
    /// Profile parameter targeted by the command.
    pub param: String,
    /// Commanded value in the profile's canonical unit/exponent.
    pub value: FixedPointValue,
    /// Simulated monotonic second at which the command is issued.
    pub at_secs: i64,
    /// Per-scenario command sequence number (idempotency/replay identity).
    pub sequence: u64,
    /// Replay the command with this sequence number instead of issuing a new
    /// one. The original step must appear earlier in the scenario.
    #[serde(default)]
    pub replay_of: Option<u64>,
    /// Expected outcome of this step.
    pub expect: StepDisposition,
    /// Defense that produces the outcome (`envelope`, `drift`, `dwell`,
    /// `min_off`, `idempotency`). Documentation, cross-checked by the
    /// integration test for rejected steps.
    #[serde(default)]
    pub mechanism: Option<String>,
}

/// One adversary scenario document.
#[derive(Debug, Clone, Deserialize)]
pub struct PackScenario {
    /// Unique scenario id (also the file stem by convention).
    pub id: String,
    /// Adversary class.
    pub class: AdversaryClass,
    /// Human-readable title.
    pub title: String,
    /// Attack description.
    pub attack: String,
    /// Target device id the scenario commands.
    pub target: String,
    /// Ordered commands.
    pub steps: Vec<ScenarioStep>,
}

/// One expected-output row.
#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedScenarioOutcome {
    /// Scenario id this row describes.
    pub id: String,
    /// Adversary class, repeated for readability of the expected document.
    pub class: AdversaryClass,
    /// Scenario-level disposition.
    pub disposition: ScenarioDisposition,
    /// Defense that produced the disposition.
    pub mechanism: String,
    /// Number of commands actually dispatched to the device.
    pub actuations: usize,
    /// Expected outcome per step, in scenario order.
    pub steps: Vec<StepDisposition>,
}

/// Expected-output document (`expected/outcomes.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct PackExpectedOutputs {
    /// Schema version of the expected-output document.
    pub schema_version: u32,
    /// One row per scenario.
    #[serde(default)]
    pub scenario: Vec<ExpectedScenarioOutcome>,
    /// Expected trip-level disposition, for packs that carry a trip document.
    #[serde(default)]
    pub trip: Option<ExpectedTripOutcome>,
    /// Expected lot-release dispositions, for packs that carry a GDP policy.
    #[serde(default)]
    pub release: Vec<ExpectedReleaseOutcome>,
}

// ---------------------------------------------------------------------------
// Trip metadata (transport packs)
// ---------------------------------------------------------------------------

/// Where the container or trailer is, in data-only form.
#[derive(Debug, Clone, Deserialize)]
pub struct TripLocation {
    /// Human-readable place (`Depot Rotterdam 4`, `A15 km 42`).
    pub site: String,
    /// Latitude in micro-degrees (`51_500_000` = 51.5 N).
    pub lat_e6: i64,
    /// Longitude in micro-degrees (`4_400_000` = 4.4 E).
    pub lon_e6: i64,
}

/// Container/trailer identity and trip metadata (`trip.toml`).
///
/// Transport packs declare who and what is moving, where, and under which
/// cargo temperature band. The `max_door_open_secs` figure is the excursion
/// rule the expected output is checked against: a trip whose door stays open
/// longer than that is quarantined.
#[derive(Debug, Clone, Deserialize)]
pub struct TripDocument {
    /// Schema version of the trip document.
    pub schema_version: u32,
    /// ISO 6346 container number (`MSCU1234567` or `MSCU-1234567`).
    pub container_id: String,
    /// Container class (`reefer_40ft`, `reefer_20ft`, …).
    pub container_class: String,
    /// Trailer or chassis id, when the container is road-bound.
    pub trailer_id: String,
    /// Trip identifier the readings and excursions are booked against.
    pub trip_id: String,
    /// Loading site.
    pub origin: String,
    /// Unloading site.
    pub destination: String,
    /// Cargo description.
    pub cargo: String,
    /// Lowest cargo temperature the trip may be dispositioned clear at.
    pub cargo_min_c: FixedPointValue,
    /// Highest cargo temperature the trip may be dispositioned clear at.
    pub cargo_max_c: FixedPointValue,
    /// A door-open interval longer than this quarantines the trip.
    pub max_door_open_secs: u32,
    /// Profile parameter that carries the door state.
    pub door_param: String,
    /// Current location.
    pub location: TripLocation,
}

/// Trip-level disposition derived from the defended door state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripDisposition {
    /// The trip stayed within its excursion rule.
    Clear,
    /// A door-open interval exceeded the trip's excursion rule.
    Quarantined,
}

impl TripDisposition {
    /// Derive the disposition from the longest door-open interval.
    pub fn from_door_open_secs(door_open_secs: i64, max_door_open_secs: u32) -> Self {
        if door_open_secs > i64::from(max_door_open_secs) {
            TripDisposition::Quarantined
        } else {
            TripDisposition::Clear
        }
    }

    /// Lowercase label used in expected-output documents.
    pub fn as_str(self) -> &'static str {
        match self {
            TripDisposition::Clear => "clear",
            TripDisposition::Quarantined => "quarantined",
        }
    }
}

impl<'de> Deserialize<'de> for TripDisposition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "clear" => Ok(TripDisposition::Clear),
            "quarantined" => Ok(TripDisposition::Quarantined),
            other => Err(serde::de::Error::custom(format!(
                "unknown trip disposition '{other}'; expected clear or quarantined"
            ))),
        }
    }
}

/// Expected trip-level disposition (`[trip]` in the expected-output document).
#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedTripOutcome {
    /// Derived disposition the pack claims for the trip.
    pub disposition: TripDisposition,
    /// Excursion rule and defense that produce the disposition.
    pub mechanism: String,
    /// Scenario the disposition is derived from.
    pub scenario: String,
    /// Longest door-open interval in that scenario, in seconds.
    pub door_open_secs: i64,
}

// ---------------------------------------------------------------------------
// GDP storage policy, excursion classification, and lot release (pharma packs)
// ---------------------------------------------------------------------------

/// Release disposition for a finished lot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReleaseDisposition {
    /// The lot may be released: no excursion, valid calibration, MKT in limit.
    Release,
    /// The lot is held for QA assessment before any release decision.
    Hold,
    /// The lot must not be released.
    Reject,
}

/// Stable release codes. These are the identifiers the excursion workflow
/// (CC-11) records against a lot, so a pack, a gateway decision, and a QA
/// disposition all refer to the same string.
pub const RELEASE_CODE_CLEAR: &str = "GDP-REL-001";
/// Release blocked: a sensor's calibration interval has expired.
pub const RELEASE_CODE_CALIBRATION_EXPIRED: &str = "GDP-BLK-002";
/// Release blocked: an open lane-risk event is at or above the hold threshold.
pub const RELEASE_CODE_LANE_RISK: &str = "GDP-BLK-003";
/// Release held: a transient excursion needs QA assessment.
pub const RELEASE_CODE_TRANSIENT_EXCURSION: &str = "GDP-HLD-004";
/// Release blocked: a monitoring sensor failed.
pub const RELEASE_CODE_SENSOR_FAILURE: &str = "GDP-BLK-005";
/// Release rejected: cumulative drift exceeded the excursion budget.
pub const RELEASE_CODE_CUMULATIVE_DRIFT: &str = "GDP-REJ-006";
/// Release rejected: mean kinetic temperature exceeded the product limit.
pub const RELEASE_CODE_MKT_EXCEEDED: &str = "GDP-REJ-007";

impl ReleaseDisposition {
    /// Lowercase label used in expected-output documents.
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseDisposition::Release => "release",
            ReleaseDisposition::Hold => "hold",
            ReleaseDisposition::Reject => "reject",
        }
    }
}

impl<'de> Deserialize<'de> for ReleaseDisposition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "release" => Ok(ReleaseDisposition::Release),
            "hold" => Ok(ReleaseDisposition::Hold),
            "reject" => Ok(ReleaseDisposition::Reject),
            other => Err(serde::de::Error::custom(format!(
                "unknown release disposition '{other}'; expected release, hold, or reject"
            ))),
        }
    }
}

/// Lot identity the pack is released against.
#[derive(Debug, Clone, Deserialize)]
pub struct GdpLot {
    /// Lot/batch identifier.
    pub id: String,
    /// Product name.
    pub product: String,
    /// Dosage form.
    pub dosage_form: String,
    /// Batch size in saleable units.
    pub batch_size_units: u32,
}

/// Mean kinetic temperature parameters. Computing MKT from a temperature series
/// belongs to the excursion workflow (CC-11); a pack declares the constants, the
/// sampling rate, and the reporting interval the calculation is bound to.
#[derive(Debug, Clone, Deserialize)]
pub struct GdpMkt {
    /// Activation energy in joules per mole (Haynes equation ΔH).
    pub activation_energy_j_per_mol: u32,
    /// Gas constant in millijoules per mole per kelvin (8 314 ⇒ 8.314 J/(mol·K)).
    pub gas_constant_milli_j_per_mol_k: u32,
    /// Reference temperature the MKT is reported at.
    pub reference_c: FixedPointValue,
    /// How often MKT is reported, in seconds.
    pub reporting_interval_secs: u32,
    /// How often the temperature series are sampled, in seconds.
    pub sampling_interval_secs: u32,
}

/// Calibration policy for monitoring sensors.
#[derive(Debug, Clone, Deserialize)]
pub struct GdpCalibrationPolicy {
    /// Longest calibration interval a sensor may be released against, in days.
    pub max_interval_days: u32,
}

/// Lane-risk policy for in-transit lots.
#[derive(Debug, Clone, Deserialize)]
pub struct GdpLaneRiskPolicy {
    /// Open lane-risk level (1–5) that blocks release.
    pub hold_at_or_above: u8,
}

/// One storage class the pack covers, bound to one profile document.
#[derive(Debug, Clone, Deserialize)]
pub struct GdpStorage {
    /// Manifest-relative profile this storage class applies to.
    pub profile: String,
    /// Human-readable storage class (`2–8 °C cold chain`, …).
    pub label: String,
    /// Lower edge of the labelled storage band.
    pub band_min_c: FixedPointValue,
    /// Upper edge of the labelled storage band.
    pub band_max_c: FixedPointValue,
    /// Longest out-of-band interval that stays a transient excursion.
    pub transient_max_secs: u32,
    /// Cumulative out-of-band budget, in degree-seconds.
    pub cumulative_budget_degree_secs: i64,
    /// MKT limit for product held under this storage class.
    pub mkt_limit_c: FixedPointValue,
}

/// GDP policy document (`gdp.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct GdpDocument {
    /// Schema version of the policy document.
    pub schema_version: u32,
    /// Lot identity.
    pub lot: GdpLot,
    /// Mean kinetic temperature parameters.
    pub mkt: GdpMkt,
    /// Calibration policy.
    pub calibration: GdpCalibrationPolicy,
    /// Lane-risk policy.
    pub lane_risk: GdpLaneRiskPolicy,
    /// Storage classes covered by the pack.
    #[serde(default)]
    pub storage: Vec<GdpStorage>,
}

/// One monitoring sensor's calibration record (`calibration.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct CalibrationRecord {
    /// Sensor identifier as wired by the site.
    pub sensor_id: String,
    /// Calibration method (`comparison-ice-point`, `astm-e74`, …).
    pub method: String,
    /// Time the calibration was performed, in EST seconds.
    pub calibrated_at_est: i64,
    /// Calibration interval actually applied, in days.
    pub interval_days: u32,
    /// Time the calibration expires, in EST seconds.
    pub expires_at_est: i64,
    /// Certificate reference the record is backed by.
    pub certificate: String,
}

/// Calibration-record document (`calibration.toml`).
#[derive(Debug, Clone, Deserialize)]
pub struct CalibrationDocument {
    /// Schema version of the calibration document.
    pub schema_version: u32,
    /// One record per monitoring sensor.
    #[serde(default)]
    pub sensor: Vec<CalibrationRecord>,
}

/// State of one qualification/validation checklist item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualificationStatus {
    /// The requirement is covered by the evidence cited.
    Qualified,
    /// The requirement does not apply to this pack.
    NotApplicable,
}

/// One qualification/validation checklist item.
#[derive(Debug, Clone, Deserialize)]
pub struct QualificationItem {
    /// Stable checklist id (`DQ-01`, `IQ-03`, …).
    pub id: String,
    /// Requirement being covered.
    pub requirement: String,
    /// Evidence the requirement is covered by.
    pub evidence: String,
    /// Checklist status.
    pub status: QualificationStatus,
}

/// Qualification/validation checklist document (`qualification.toml`).
///
/// The document must state that it is not a certification; the loader refuses a
/// pack that claims one, so the checklist cannot be mistaken for an approval.
#[derive(Debug, Clone, Deserialize)]
pub struct QualificationDocument {
    /// Schema version of the checklist document.
    pub schema_version: u32,
    /// Certification claim. Must be `none` for pack-format v1.
    pub certification: String,
    /// What the checklist does and does not establish.
    pub statement: String,
    /// Boundary of the evidence the checklist cites.
    pub evidence_boundary: String,
    /// Checklist items.
    #[serde(default)]
    pub item: Vec<QualificationItem>,
}

/// Classification of an accepted excursion timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExcursionClass {
    /// The defended timeline stays inside the labelled storage band.
    InBand,
    /// A short out-of-band interval inside the transient allowance.
    Transient,
    /// Cumulative out-of-band time/area exceeded the budget, or the guard
    /// refused a drift step.
    Cumulative,
}

impl ExcursionClass {
    /// Lowercase label used in expected-output documents.
    pub fn as_str(self) -> &'static str {
        match self {
            ExcursionClass::InBand => "in-band",
            ExcursionClass::Transient => "transient",
            ExcursionClass::Cumulative => "cumulative",
        }
    }
}

impl<'de> Deserialize<'de> for ExcursionClass {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "in-band" => Ok(ExcursionClass::InBand),
            "transient" => Ok(ExcursionClass::Transient),
            "cumulative" => Ok(ExcursionClass::Cumulative),
            other => Err(serde::de::Error::custom(format!(
                "unknown excursion class '{other}'; expected in-band, transient, or cumulative"
            ))),
        }
    }
}

/// What the defended timeline of a scenario did to the storage band.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcursionSummary {
    /// Longest accepted out-of-band interval, in seconds.
    pub out_of_band_secs: i64,
    /// Accepted time-weighted out-of-band area, in degree-seconds.
    pub out_of_band_degree_secs: i64,
    /// Rejections the guard produced on this timeline.
    pub rejections: usize,
    /// Classification derived from the figures above.
    pub class: ExcursionClass,
}

/// Inputs to a lot-release decision.
#[derive(Debug, Clone, Default)]
pub struct ReleaseInputs<'a> {
    /// Time of the release decision, in EST seconds.
    pub at_est: i64,
    /// Scenario whose defended timeline is being released against, if any.
    pub excursion: Option<&'a str>,
    /// Mean kinetic temperature measured over the release period.
    pub mkt_c: Option<FixedPointValue>,
    /// Highest open lane-risk level for the shipment, if any.
    pub lane_risk_level: Option<u8>,
    /// Number of monitoring sensors that failed.
    pub sensor_failures: usize,
}

/// The outcome of evaluating a lot release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseDecision {
    /// Release / hold / reject.
    pub disposition: ReleaseDisposition,
    /// Stable code the workflow records (`GDP-…`).
    pub code: &'static str,
    /// True when the decision prevents release until something is fixed.
    pub blocked: bool,
    /// Human-readable reasons, in evaluation order.
    pub reasons: Vec<String>,
}

/// One expected lot-release row (`[[release]]` in the expected-output document).
#[derive(Debug, Clone, Deserialize)]
pub struct ExpectedReleaseOutcome {
    /// Unique check id.
    pub id: String,
    /// Storage class the release is evaluated against.
    pub profile: String,
    /// Time of the release decision, in EST seconds.
    pub at_est: i64,
    /// Scenario whose defended timeline is released, if any.
    pub excursion: Option<String>,
    /// Mean kinetic temperature measured over the release period.
    #[serde(default)]
    pub mkt_c: Option<FixedPointValue>,
    /// Highest open lane-risk level, if any.
    #[serde(default)]
    pub lane_risk_level: Option<u8>,
    /// Number of monitoring sensors that failed.
    #[serde(default)]
    pub sensor_failures: usize,
    /// Expected release disposition.
    pub disposition: ReleaseDisposition,
    /// Expected stable code.
    pub code: String,
    /// Expected blocking flag.
    pub blocked: bool,
}

/// A profile parameter as declared by an `EnvelopeProfile` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackParameter {
    /// Parameter name.
    pub name: String,
    /// Unit id from the unit registry.
    pub unit_id: u16,
}

/// Facts extracted from one profile document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackProfile {
    /// Manifest-relative path of the profile.
    pub path: String,
    /// Device class declared by the profile.
    pub device_class: String,
    /// Declared parameters.
    pub parameters: Vec<PackParameter>,
}

/// A loaded and validated pack.
#[derive(Debug, Clone)]
pub struct Pack {
    /// Pack root directory.
    pub root: PathBuf,
    /// Parsed manifest.
    pub manifest: PackManifest,
    /// Parsed profiles.
    pub profiles: Vec<PackProfile>,
    /// Parsed scenarios.
    pub scenarios: Vec<PackScenario>,
    /// Parsed expected outputs.
    pub expected: PackExpectedOutputs,
    /// Parsed trip metadata, for transport packs.
    pub trip: Option<TripDocument>,
    /// Parsed GDP policy, for pharma packs.
    pub gdp: Option<GdpDocument>,
    /// Parsed calibration records, for pharma packs.
    pub calibration: Option<CalibrationDocument>,
    /// Parsed qualification checklist, for pharma packs.
    pub qualification: Option<QualificationDocument>,
    /// Parsed workflow configuration, for packs that ship one (CC-13).
    pub workflow: Option<WorkflowConfig>,
}

impl Pack {
    /// Scenario by id.
    pub fn scenario(&self, id: &str) -> Option<&PackScenario> {
        self.scenarios.iter().find(|scenario| scenario.id == id)
    }

    /// Expected output by scenario id.
    pub fn expected_outcome(&self, id: &str) -> Option<&ExpectedScenarioOutcome> {
        self.expected.scenario.iter().find(|row| row.id == id)
    }

    /// Every profile parameter name, with the unit the profile declares.
    pub fn parameters(&self) -> BTreeMap<&str, u16> {
        let mut out = BTreeMap::new();
        for profile in &self.profiles {
            for parameter in &profile.parameters {
                out.insert(parameter.name.as_str(), parameter.unit_id);
            }
        }
        out
    }

    /// Adversary classes covered by at least one scenario.
    pub fn covered_classes(&self) -> BTreeSet<AdversaryClass> {
        self.scenarios
            .iter()
            .map(|scenario| scenario.class)
            .collect()
    }

    /// Longest interval, in seconds, that an accepted scenario step leaves the
    /// trip's door parameter open. `None` when the scenario never opens it.
    ///
    /// Only accepted steps count: the point of the pack is that the guard's
    /// decisions, not the attacker's intent, decide the trip's disposition. A
    /// scenario that ends with the door still open closes the interval at its
    /// last timestamp.
    pub fn door_open_secs(&self, scenario_id: &str) -> Option<i64> {
        let door_param = self.trip.as_ref()?.door_param.as_str();
        let scenario = self.scenario(scenario_id)?;
        longest_door_open_secs(scenario, door_param)
    }

    /// Trip disposition derived from an expected scenario's accepted steps.
    pub fn derived_trip_disposition(&self, scenario_id: &str) -> Option<TripDisposition> {
        let trip = self.trip.as_ref()?;
        let door_open_secs = self.door_open_secs(scenario_id)?;
        Some(TripDisposition::from_door_open_secs(
            door_open_secs,
            trip.max_door_open_secs,
        ))
    }

    /// GDP storage class bound to a manifest-relative profile path.
    pub fn storage_for_profile(&self, profile: &str) -> Option<&GdpStorage> {
        self.gdp
            .as_ref()?
            .storage
            .iter()
            .find(|storage| storage.profile == profile)
    }

    /// Classify the defended timeline of `scenario_id` against the storage band
    /// of `profile`. `None` when the pack has no GDP policy for that profile or
    /// the scenario is unknown.
    pub fn excursion(&self, scenario_id: &str, profile: &str) -> Option<ExcursionSummary> {
        let storage = self.storage_for_profile(profile)?;
        let scenario = self.scenario(scenario_id)?;
        Some(classify_excursion(scenario, storage))
    }

    /// Evaluate a lot release against the pack's GDP policy.
    ///
    /// Rules are applied in a fixed order, so an expired calibration always wins
    /// over an excursion assessment: a lot cannot be released on evidence from a
    /// sensor that is out of calibration.
    pub fn evaluate_release(
        &self,
        profile: &str,
        inputs: &ReleaseInputs<'_>,
    ) -> Option<ReleaseDecision> {
        let gdp = self.gdp.as_ref()?;
        let storage = self.storage_for_profile(profile)?;
        let mut reasons = Vec::new();

        let expired: Vec<&str> = self
            .calibration
            .as_ref()
            .map(|document| {
                document
                    .sensor
                    .iter()
                    .filter(|sensor| sensor.expires_at_est <= inputs.at_est)
                    .map(|sensor| sensor.sensor_id.as_str())
                    .collect()
            })
            .unwrap_or_default();
        if !expired.is_empty() {
            reasons.push(format!(
                "calibration expired for {} before release at {} EST",
                expired.join(", "),
                inputs.at_est
            ));
            return Some(ReleaseDecision {
                disposition: ReleaseDisposition::Hold,
                code: RELEASE_CODE_CALIBRATION_EXPIRED,
                blocked: true,
                reasons,
            });
        }

        if inputs.sensor_failures > 0 {
            reasons.push(format!(
                "{} monitoring sensor(s) failed; the temperature record is incomplete",
                inputs.sensor_failures
            ));
            return Some(ReleaseDecision {
                disposition: ReleaseDisposition::Hold,
                code: RELEASE_CODE_SENSOR_FAILURE,
                blocked: true,
                reasons,
            });
        }

        if let Some(level) = inputs.lane_risk_level {
            if level >= gdp.lane_risk.hold_at_or_above {
                reasons.push(format!(
                    "lane-risk level {level} is at or above the hold threshold {}; containment is unconfirmed",
                    gdp.lane_risk.hold_at_or_above
                ));
                return Some(ReleaseDecision {
                    disposition: ReleaseDisposition::Hold,
                    code: RELEASE_CODE_LANE_RISK,
                    blocked: true,
                    reasons,
                });
            }
        }

        if let Some(mkt) = inputs.mkt_c {
            if scaled_to(&mkt, -1) > scaled_to(&storage.mkt_limit_c, -1) {
                reasons.push(format!(
                    "mean kinetic temperature {:?} exceeds the {} limit {:?}",
                    mkt, storage.label, storage.mkt_limit_c
                ));
                return Some(ReleaseDecision {
                    disposition: ReleaseDisposition::Reject,
                    code: RELEASE_CODE_MKT_EXCEEDED,
                    blocked: true,
                    reasons,
                });
            }
        }

        let excursion = match inputs.excursion {
            Some(scenario_id) => self.excursion(scenario_id, profile)?,
            None => ExcursionSummary {
                out_of_band_secs: 0,
                out_of_band_degree_secs: 0,
                rejections: 0,
                class: ExcursionClass::InBand,
            },
        };
        match excursion.class {
            ExcursionClass::InBand => Some(ReleaseDecision {
                disposition: ReleaseDisposition::Release,
                code: RELEASE_CODE_CLEAR,
                blocked: false,
                reasons,
            }),
            ExcursionClass::Transient => {
                reasons.push(format!(
                    "transient excursion of {}s ({} degree-seconds) inside the {} allowance",
                    excursion.out_of_band_secs, excursion.out_of_band_degree_secs, storage.label
                ));
                Some(ReleaseDecision {
                    disposition: ReleaseDisposition::Hold,
                    code: RELEASE_CODE_TRANSIENT_EXCURSION,
                    blocked: false,
                    reasons,
                })
            }
            ExcursionClass::Cumulative => {
                reasons.push(format!(
                    "cumulative excursion of {}s ({} degree-seconds) exceeds the {} budget of {} degree-seconds",
                    excursion.out_of_band_secs,
                    excursion.out_of_band_degree_secs,
                    storage.label,
                    storage.cumulative_budget_degree_secs
                ));
                Some(ReleaseDecision {
                    disposition: ReleaseDisposition::Reject,
                    code: RELEASE_CODE_CUMULATIVE_DRIFT,
                    blocked: true,
                    reasons,
                })
            }
        }
    }
}

fn scaled_to(value: &FixedPointValue, exponent: i8) -> i128 {
    let shift = i32::from(value.exponent) - i32::from(exponent);
    if shift >= 0 {
        i128::from(value.mantissa) * 10i128.pow(shift as u32)
    } else {
        i128::from(value.mantissa) / 10i128.pow((-shift) as u32)
    }
}

/// Classify a defended scenario timeline against one storage band.
///
/// Only accepted steps move the storage temperature: a rejected step dispatches
/// nothing, so it cannot warm or cool the product. Time is measured until the
/// next accepted step, and the last accepted step bounds the final interval.
/// `degree-seconds` weigh out-of-band time by how far outside the band the value
/// sits, so a long shallow excursion and a short deep one can be compared.
pub fn classify_excursion(scenario: &PackScenario, storage: &GdpStorage) -> ExcursionSummary {
    let min = scaled_to(&storage.band_min_c, -1);
    let max = scaled_to(&storage.band_max_c, -1);
    let last_secs = scenario
        .steps
        .iter()
        .map(|step| step.at_secs)
        .max()
        .unwrap_or(0);

    let mut out_of_band_secs = 0i64;
    let mut out_of_band_degree_secs = 0i64;
    let mut previous: Option<(i64, i128)> = None;
    let mut rejections = 0usize;

    for step in &scenario.steps {
        if step.expect != StepDisposition::Accepted {
            rejections += 1;
            continue;
        }
        let value = scaled_to(&step.value, -1);
        if let Some((previous_secs, previous_value)) = previous {
            let duration = step.at_secs - previous_secs;
            accumulate_excursion(
                previous_value,
                duration,
                min,
                max,
                &mut out_of_band_secs,
                &mut out_of_band_degree_secs,
            );
        }
        previous = Some((step.at_secs, value));
    }
    if let Some((previous_secs, previous_value)) = previous {
        accumulate_excursion(
            previous_value,
            (last_secs - previous_secs).max(0),
            min,
            max,
            &mut out_of_band_secs,
            &mut out_of_band_degree_secs,
        );
    }
    let class = if out_of_band_secs == 0 {
        ExcursionClass::InBand
    } else if out_of_band_secs > i64::from(storage.transient_max_secs)
        || out_of_band_degree_secs > storage.cumulative_budget_degree_secs
        || rejections > 0
    {
        ExcursionClass::Cumulative
    } else {
        ExcursionClass::Transient
    };

    ExcursionSummary {
        out_of_band_secs,
        out_of_band_degree_secs,
        rejections,
        class,
    }
}

fn accumulate_excursion(
    value: i128,
    duration: i64,
    min: i128,
    max: i128,
    out_of_band_secs: &mut i64,
    out_of_band_degree_secs: &mut i64,
) {
    if duration <= 0 {
        return;
    }
    let excess = if value > max {
        value - max
    } else if value < min {
        min - value
    } else {
        return;
    };
    *out_of_band_secs = out_of_band_secs.saturating_add(duration);
    // `excess` is in 0.1 °C units (canonical exponent -1); a degree-second is
    // 10 of those units per second.
    let degree_secs = excess.saturating_mul(i128::from(duration)) / 10;
    *out_of_band_degree_secs =
        out_of_band_degree_secs.saturating_add(i64::try_from(degree_secs).unwrap_or(i64::MAX));
}

/// Longest accepted door-open interval in `scenario`, measured on `door_param`.
pub fn longest_door_open_secs(scenario: &PackScenario, door_param: &str) -> Option<i64> {
    let mut open_since: Option<i64> = None;
    let mut longest: Option<i64> = None;
    let mut last_secs = 0i64;
    for step in &scenario.steps {
        last_secs = last_secs.max(step.at_secs);
        if step.param != door_param || step.expect != StepDisposition::Accepted {
            continue;
        }
        match step.value.mantissa {
            1 => open_since = open_since.or(Some(step.at_secs)),
            0 => {
                if let Some(start) = open_since.take() {
                    longest = Some(longest.unwrap_or(0).max(step.at_secs - start));
                }
            }
            _ => {}
        }
    }
    if let Some(start) = open_since {
        longest = Some(longest.unwrap_or(0).max(last_secs - start));
    }
    longest
}

/// Failure loading or validating a pack.
#[derive(Debug)]
pub enum PackError {
    /// A file could not be read.
    Io {
        /// Manifest-relative path.
        path: String,
        /// Underlying error.
        error: std::io::Error,
    },
    /// A document is not valid TOML or does not match its schema.
    Toml {
        /// Manifest-relative path.
        path: String,
        /// Parser error.
        error: toml::de::Error,
    },
    /// The pack is structurally invalid.
    Validation(String),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackError::Io { path, error } => write!(f, "pack file '{path}': {error}"),
            PackError::Toml { path, error } => write!(f, "pack document '{path}': {error}"),
            PackError::Validation(message) => write!(f, "invalid pack: {message}"),
        }
    }
}

impl std::error::Error for PackError {}

fn validation(message: impl Into<String>) -> PackError {
    PackError::Validation(message.into())
}

fn read_document(root: &Path, relative: &str) -> Result<String, PackError> {
    let path = safe_pack_path(root, relative)?;
    std::fs::read_to_string(&path).map_err(|error| PackError::Io {
        path: relative.to_string(),
        error,
    })
}

/// Resolve a manifest-relative path, rejecting absolute paths, parent
/// traversal, symlink escapes, and missing files.
pub fn safe_pack_path(root: &Path, relative: &str) -> Result<PathBuf, PackError> {
    let candidate = Path::new(relative);
    if relative.is_empty() {
        return Err(validation("empty pack path"));
    }
    if candidate.is_absolute() {
        return Err(validation(format!(
            "pack path '{relative}' must be relative to the pack root"
        )));
    }
    if candidate
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(validation(format!(
            "pack path '{relative}' must not traverse parent directories"
        )));
    }
    let joined = root.join(candidate);
    let canonical_root = root.canonicalize().map_err(|error| PackError::Io {
        path: ".".into(),
        error,
    })?;
    let canonical = joined.canonicalize().map_err(|error| PackError::Io {
        path: relative.to_string(),
        error,
    })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(validation(format!(
            "pack path '{relative}' escapes the pack root"
        )));
    }
    Ok(canonical)
}

fn parse_toml<T: serde::de::DeserializeOwned>(relative: &str, text: &str) -> Result<T, PackError> {
    toml::from_str(text).map_err(|error| PackError::Toml {
        path: relative.to_string(),
        error,
    })
}

/// Load and validate a versioned pack from `root`.
pub fn load_pack(root: impl AsRef<Path>) -> Result<Pack, PackError> {
    let root = root.as_ref();
    let manifest_text = read_document(root, PACK_MANIFEST_FILE)?;
    let manifest: PackManifest = parse_toml(PACK_MANIFEST_FILE, &manifest_text)?;
    validate_manifest(root, &manifest)?;

    let mut profiles = Vec::with_capacity(manifest.profiles.len());
    for relative in &manifest.profiles {
        let text = read_document(root, relative)?;
        profiles.push(parse_profile(relative, &text)?);
    }
    let parameters: BTreeMap<&str, u16> = profiles
        .iter()
        .flat_map(|profile| profile.parameters.iter())
        .map(|parameter| (parameter.name.as_str(), parameter.unit_id))
        .collect();
    if parameters.is_empty() {
        return Err(validation("pack profiles declare no parameters"));
    }

    let mut scenarios = Vec::with_capacity(manifest.scenarios.len());
    for relative in &manifest.scenarios {
        let text = read_document(root, relative)?;
        let scenario: PackScenario = parse_toml(relative, &text)?;
        validate_scenario(relative, &scenario, &parameters)?;
        scenarios.push(scenario);
    }
    if scenarios.is_empty() {
        return Err(validation("pack declares no scenarios"));
    }

    let trip = match manifest.trip.as_deref() {
        Some(relative) => {
            let text = read_document(root, relative)?;
            let trip: TripDocument = parse_toml(relative, &text)?;
            validate_trip(relative, &trip, &parameters)?;
            Some(trip)
        }
        None => None,
    };

    let gdp = match manifest.gdp.as_deref() {
        Some(relative) => {
            let text = read_document(root, relative)?;
            let gdp: GdpDocument = parse_toml(relative, &text)?;
            validate_gdp(relative, &gdp, &manifest.profiles)?;
            Some(gdp)
        }
        None => None,
    };
    let calibration = match manifest.calibration.as_deref() {
        Some(relative) => {
            let text = read_document(root, relative)?;
            let calibration: CalibrationDocument = parse_toml(relative, &text)?;
            validate_calibration(relative, &calibration, gdp.as_ref())?;
            Some(calibration)
        }
        None => None,
    };
    let qualification = match manifest.qualification.as_deref() {
        Some(relative) => {
            let text = read_document(root, relative)?;
            let qualification: QualificationDocument = parse_toml(relative, &text)?;
            validate_qualification(relative, &qualification)?;
            Some(qualification)
        }
        None => None,
    };

    let workflow = match manifest.workflow.as_deref() {
        Some(relative) => {
            let text = read_document(root, relative)?;
            let config = WorkflowConfig::parse(&text, relative)
                .map_err(|error| validation(error.to_string()))?;
            if config.pack != manifest.id {
                return Err(validation(format!(
                    "workflow '{relative}' configures pack '{}' but the manifest id is '{}'",
                    config.pack, manifest.id
                )));
            }
            Some(config)
        }
        None => None,
    };

    let expected_text = read_document(root, &manifest.expected)?;
    let expected: PackExpectedOutputs = parse_toml(&manifest.expected, &expected_text)?;
    validate_expected(&expected, &scenarios, trip.as_ref())?;

    // Manifest references must all exist, including files not otherwise parsed.
    for relative in manifest
        .register_maps
        .iter()
        .chain(manifest.docs.iter())
        .chain(std::iter::once(&manifest.sim))
    {
        let _ = safe_pack_path(root, relative)?;
    }

    let pack = Pack {
        root: root.to_path_buf(),
        manifest,
        profiles,
        scenarios,
        expected,
        trip,
        gdp,
        calibration,
        qualification,
        workflow,
    };
    validate_expected_releases(&pack)?;
    Ok(pack)
}

fn validate_gdp(relative: &str, gdp: &GdpDocument, profiles: &[String]) -> Result<(), PackError> {
    if gdp.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
        return Err(validation(format!(
            "GDP document '{relative}' schema_version must be {PACK_MANIFEST_SCHEMA_VERSION}"
        )));
    }
    for (field, value) in [
        ("lot.id", &gdp.lot.id),
        ("lot.product", &gdp.lot.product),
        ("lot.dosage_form", &gdp.lot.dosage_form),
    ] {
        if value.trim().is_empty() {
            return Err(validation(format!(
                "GDP document '{relative}' has an empty {field}"
            )));
        }
    }
    if gdp.lot.batch_size_units == 0 {
        return Err(validation(format!(
            "GDP document '{relative}' lot.batch_size_units must be greater than zero"
        )));
    }
    if gdp.mkt.activation_energy_j_per_mol == 0 || gdp.mkt.gas_constant_milli_j_per_mol_k == 0 {
        return Err(validation(format!(
            "GDP document '{relative}' MKT constants must be non-zero"
        )));
    }
    if gdp.mkt.reporting_interval_secs == 0 || gdp.mkt.sampling_interval_secs == 0 {
        return Err(validation(format!(
            "GDP document '{relative}' MKT reporting and sampling intervals must be non-zero"
        )));
    }
    if gdp.mkt.sampling_interval_secs > gdp.mkt.reporting_interval_secs {
        return Err(validation(format!(
            "GDP document '{relative}' MKT sampling interval must not exceed the reporting interval"
        )));
    }
    if gdp.mkt.reference_c.unit_id != 1 {
        return Err(validation(format!(
            "GDP document '{relative}' MKT reference_c must be in degC (unit 1)"
        )));
    }
    if gdp.calibration.max_interval_days == 0 {
        return Err(validation(format!(
            "GDP document '{relative}' calibration.max_interval_days must be greater than zero"
        )));
    }
    if !(1..=5).contains(&gdp.lane_risk.hold_at_or_above) {
        return Err(validation(format!(
            "GDP document '{relative}' lane_risk.hold_at_or_above must be a level 1–5"
        )));
    }
    if gdp.storage.is_empty() {
        return Err(validation(format!(
            "GDP document '{relative}' declares no storage class"
        )));
    }
    let mut seen = BTreeSet::new();
    for storage in &gdp.storage {
        if !profiles.iter().any(|profile| profile == &storage.profile) {
            return Err(validation(format!(
                "GDP storage class '{}' points at '{}', which the manifest does not declare",
                storage.label, storage.profile
            )));
        }
        if !seen.insert(storage.profile.as_str()) {
            return Err(validation(format!(
                "GDP document '{relative}' declares storage for '{}' more than once",
                storage.profile
            )));
        }
        if storage.label.trim().is_empty() {
            return Err(validation(format!(
                "GDP storage class for '{}' has an empty label",
                storage.profile
            )));
        }
        if storage.band_min_c.unit_id != 1 || storage.band_max_c.unit_id != 1 {
            return Err(validation(format!(
                "GDP storage class '{}' band must be in degC (unit 1)",
                storage.label
            )));
        }
        if scaled_to(&storage.band_min_c, -1) >= scaled_to(&storage.band_max_c, -1) {
            return Err(validation(format!(
                "GDP storage class '{}' band min must be colder than max",
                storage.label
            )));
        }
        if storage.mkt_limit_c.unit_id != 1 {
            return Err(validation(format!(
                "GDP storage class '{}' MKT limit must be in degC (unit 1)",
                storage.label
            )));
        }
        if scaled_to(&storage.mkt_limit_c, -1) < scaled_to(&storage.band_max_c, -1) {
            return Err(validation(format!(
                "GDP storage class '{}' MKT limit must not sit below its storage band",
                storage.label
            )));
        }
        if storage.transient_max_secs == 0 {
            return Err(validation(format!(
                "GDP storage class '{}' transient_max_secs must be greater than zero",
                storage.label
            )));
        }
        if storage.cumulative_budget_degree_secs <= 0 {
            return Err(validation(format!(
                "GDP storage class '{}' cumulative_budget_degree_secs must be greater than zero",
                storage.label
            )));
        }
    }
    Ok(())
}

fn validate_calibration(
    relative: &str,
    calibration: &CalibrationDocument,
    gdp: Option<&GdpDocument>,
) -> Result<(), PackError> {
    if calibration.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
        return Err(validation(format!(
            "calibration document '{relative}' schema_version must be {PACK_MANIFEST_SCHEMA_VERSION}"
        )));
    }
    if calibration.sensor.is_empty() {
        return Err(validation(format!(
            "calibration document '{relative}' records no sensor"
        )));
    }
    let max_interval_days = gdp.map(|gdp| gdp.calibration.max_interval_days);
    let mut seen = BTreeSet::new();
    for sensor in &calibration.sensor {
        if sensor.sensor_id.trim().is_empty() {
            return Err(validation(format!(
                "calibration document '{relative}' has a sensor with an empty id"
            )));
        }
        if !seen.insert(sensor.sensor_id.as_str()) {
            return Err(validation(format!(
                "calibration document '{relative}' records sensor '{}' more than once",
                sensor.sensor_id
            )));
        }
        if sensor.method.trim().is_empty() || sensor.certificate.trim().is_empty() {
            return Err(validation(format!(
                "calibration record for '{}' must name its method and certificate",
                sensor.sensor_id
            )));
        }
        if sensor.interval_days == 0 {
            return Err(validation(format!(
                "calibration record for '{}' must declare a positive interval",
                sensor.sensor_id
            )));
        }
        if let Some(max) = max_interval_days {
            if sensor.interval_days > max {
                return Err(validation(format!(
                    "calibration record for '{}' claims a {} day interval, above the GDP policy maximum of {max} days",
                    sensor.sensor_id, sensor.interval_days
                )));
            }
        }
        if sensor.expires_at_est <= sensor.calibrated_at_est {
            return Err(validation(format!(
                "calibration record for '{}' expires before it was performed",
                sensor.sensor_id
            )));
        }
    }
    Ok(())
}

fn validate_qualification(
    relative: &str,
    qualification: &QualificationDocument,
) -> Result<(), PackError> {
    if qualification.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
        return Err(validation(format!(
            "qualification document '{relative}' schema_version must be {PACK_MANIFEST_SCHEMA_VERSION}"
        )));
    }
    if !qualification.certification.eq_ignore_ascii_case("none") {
        return Err(validation(format!(
            "qualification document '{relative}' claims certification '{}'; a pack may not claim certification",
            qualification.certification
        )));
    }
    if qualification.statement.trim().is_empty() {
        return Err(validation(format!(
            "qualification document '{relative}' must state what the checklist establishes"
        )));
    }
    if qualification.evidence_boundary.trim().is_empty() {
        return Err(validation(format!(
            "qualification document '{relative}' must state the boundary of its evidence"
        )));
    }
    if qualification.item.is_empty() {
        return Err(validation(format!(
            "qualification document '{relative}' has no checklist items"
        )));
    }
    let mut seen = BTreeSet::new();
    for item in &qualification.item {
        if !seen.insert(item.id.as_str()) {
            return Err(validation(format!(
                "qualification document '{relative}' repeats checklist item '{}'",
                item.id
            )));
        }
        if item.requirement.trim().is_empty() || item.evidence.trim().is_empty() {
            return Err(validation(format!(
                "qualification item '{}' must cover a requirement and cite evidence",
                item.id
            )));
        }
    }
    Ok(())
}

fn validate_expected_releases(pack: &Pack) -> Result<(), PackError> {
    let mut seen = BTreeSet::new();
    for release in &pack.expected.release {
        if !seen.insert(release.id.as_str()) {
            return Err(validation(format!(
                "expected release check '{}' is listed more than once",
                release.id
            )));
        }
        let inputs = ReleaseInputs {
            at_est: release.at_est,
            excursion: release.excursion.as_deref(),
            mkt_c: release.mkt_c,
            lane_risk_level: release.lane_risk_level,
            sensor_failures: release.sensor_failures,
        };
        let decision = pack
            .evaluate_release(&release.profile, &inputs)
            .ok_or_else(|| {
                validation(format!(
                    "release check '{}' targets '{}', which has no GDP storage policy",
                    release.id, release.profile
                ))
            })?;
        if let Some(scenario_id) = release.excursion.as_deref() {
            if pack.scenario(scenario_id).is_none() {
                return Err(validation(format!(
                    "release check '{}' releases unknown scenario '{scenario_id}'",
                    release.id
                )));
            }
        }
        if decision.code != release.code {
            return Err(validation(format!(
                "release check '{}' expects code '{}' but the policy derives '{}'",
                release.id, release.code, decision.code
            )));
        }
        if decision.disposition != release.disposition {
            return Err(validation(format!(
                "release check '{}' expects disposition '{}' but the policy derives '{}'",
                release.id,
                release.disposition.as_str(),
                decision.disposition.as_str()
            )));
        }
        if decision.blocked != release.blocked {
            return Err(validation(format!(
                "release check '{}' expects blocked = {} but the policy derives {}",
                release.id, release.blocked, decision.blocked
            )));
        }
    }
    Ok(())
}

fn validate_trip(
    relative: &str,
    trip: &TripDocument,
    parameters: &BTreeMap<&str, u16>,
) -> Result<(), PackError> {
    if trip.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
        return Err(validation(format!(
            "trip document '{relative}' schema_version must be {PACK_MANIFEST_SCHEMA_VERSION}"
        )));
    }
    for (field, value) in [
        ("container_id", &trip.container_id),
        ("container_class", &trip.container_class),
        ("trailer_id", &trip.trailer_id),
        ("trip_id", &trip.trip_id),
        ("origin", &trip.origin),
        ("destination", &trip.destination),
        ("cargo", &trip.cargo),
    ] {
        if value.trim().is_empty() {
            return Err(validation(format!(
                "trip document '{relative}' has an empty {field}"
            )));
        }
    }
    let digits = trip
        .container_id
        .chars()
        .filter(char::is_ascii_digit)
        .count();
    let letters = trip
        .container_id
        .chars()
        .filter(char::is_ascii_uppercase)
        .count();
    if digits != 7 || letters != 4 || trip.container_id.len() > 12 {
        return Err(validation(format!(
            "trip document '{relative}' container_id '{}' is not an ISO 6346 owner code + serial",
            trip.container_id
        )));
    }
    if trip.location.site.trim().is_empty() {
        return Err(validation(format!(
            "trip document '{relative}' has an empty location.site"
        )));
    }
    if !(-90_000_000..=90_000_000).contains(&trip.location.lat_e6)
        || !(-180_000_000..=180_000_000).contains(&trip.location.lon_e6)
    {
        return Err(validation(format!(
            "trip document '{relative}' location is outside the coordinate range"
        )));
    }
    if trip.cargo_min_c.unit_id != 1 || trip.cargo_max_c.unit_id != 1 {
        return Err(validation(format!(
            "trip document '{relative}' cargo band must be in degC (unit 1)"
        )));
    }
    if trip.cargo_min_c.mantissa >= trip.cargo_max_c.mantissa {
        return Err(validation(format!(
            "trip document '{relative}' cargo_min_c must be colder than cargo_max_c"
        )));
    }
    if trip.max_door_open_secs == 0 {
        return Err(validation(format!(
            "trip document '{relative}' max_door_open_secs must be greater than zero"
        )));
    }
    if !parameters.contains_key(trip.door_param.as_str()) {
        return Err(validation(format!(
            "trip document '{relative}' door_param '{}' is not a profile parameter",
            trip.door_param
        )));
    }
    Ok(())
}

fn validate_manifest(root: &Path, manifest: &PackManifest) -> Result<(), PackError> {
    if manifest.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
        return Err(validation(format!(
            "unsupported manifest schema_version {}; this framework reads {}",
            manifest.schema_version, PACK_MANIFEST_SCHEMA_VERSION
        )));
    }
    validate_identity(root, manifest)?;
    if manifest.licence != PACK_LICENCE {
        return Err(validation(format!(
            "pack licence must be '{PACK_LICENCE}', found '{}'",
            manifest.licence
        )));
    }
    if manifest.device_class.trim().is_empty() {
        return Err(validation("manifest device_class must not be empty"));
    }
    validate_version(&manifest.version)?;
    validate_version(&manifest.tirbase_min_version)?;
    if manifest.profiles.is_empty() {
        return Err(validation("manifest must declare at least one profile"));
    }
    if manifest.register_maps.is_empty() {
        return Err(validation(
            "manifest must declare at least one register map",
        ));
    }
    if manifest.docs.is_empty() {
        return Err(validation("manifest must declare pack documentation"));
    }
    if manifest.scenarios.is_empty() {
        return Err(validation("manifest must declare at least one scenario"));
    }
    if manifest.run != PACK_LAUNCHER {
        return Err(validation(format!(
            "manifest run must be '{PACK_LAUNCHER}', the only executable a pack may contain"
        )));
    }
    if manifest.expected.trim().is_empty() {
        return Err(validation("manifest must declare an expected-output file"));
    }
    Ok(())
}

fn validate_identity(root: &Path, manifest: &PackManifest) -> Result<(), PackError> {
    let directory = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| validation("pack directory has no usable name"))?;
    if manifest.id != directory {
        return Err(validation(format!(
            "manifest id '{}' must match the pack directory '{directory}'",
            manifest.id
        )));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), PackError> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(validation(format!(
            "version '{version}' must be a numeric major.minor.patch"
        )));
    }
    Ok(())
}

fn parse_profile(relative: &str, text: &str) -> Result<PackProfile, PackError> {
    let value: toml::Value = parse_toml(relative, text)?;
    let table = value
        .as_table()
        .ok_or_else(|| validation(format!("profile '{relative}' is not a TOML table")))?;
    let device_class = table
        .get("device_class")
        .and_then(|value| value.as_str())
        .ok_or_else(|| validation(format!("profile '{relative}' has no device_class")))?
        .to_string();
    let raw_parameters = table
        .get("parameters")
        .and_then(|value| value.as_array())
        .ok_or_else(|| validation(format!("profile '{relative}' has no parameters")))?;
    let mut parameters = Vec::with_capacity(raw_parameters.len());
    let mut seen = BTreeSet::new();
    for (index, parameter) in raw_parameters.iter().enumerate() {
        let parameter = parameter.as_table().ok_or_else(|| {
            validation(format!(
                "profile '{relative}' parameters[{index}] is not a table"
            ))
        })?;
        let name = parameter
            .get("name")
            .and_then(|value| value.as_str())
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| {
                validation(format!(
                    "profile '{relative}' parameters[{index}] has no name"
                ))
            })?;
        if !seen.insert(name.to_string()) {
            return Err(validation(format!(
                "profile '{relative}' declares parameter '{name}' more than once"
            )));
        }
        let unit_id = parameter
            .get("unit_id")
            .and_then(|value| value.as_integer())
            .ok_or_else(|| {
                validation(format!(
                    "profile '{relative}' parameter '{name}' has no numeric unit_id"
                ))
            })?;
        parameters.push(PackParameter {
            name: name.to_string(),
            unit_id: u16::try_from(unit_id).map_err(|_| {
                validation(format!(
                    "profile '{relative}' parameter '{name}' unit_id {unit_id} is out of range"
                ))
            })?,
        });
    }
    Ok(PackProfile {
        path: relative.to_string(),
        device_class,
        parameters,
    })
}

fn validate_scenario(
    relative: &str,
    scenario: &PackScenario,
    parameters: &BTreeMap<&str, u16>,
) -> Result<(), PackError> {
    if scenario.id.trim().is_empty() {
        return Err(validation(format!("scenario '{relative}' has an empty id")));
    }
    if scenario.title.trim().is_empty() || scenario.attack.trim().is_empty() {
        return Err(validation(format!(
            "scenario '{}' must describe its title and attack",
            scenario.id
        )));
    }
    if scenario.target.trim().is_empty() {
        return Err(validation(format!(
            "scenario '{}' has an empty target device",
            scenario.id
        )));
    }
    if scenario.steps.is_empty() {
        return Err(validation(format!(
            "scenario '{}' has no steps",
            scenario.id
        )));
    }
    let mut sequences: BTreeMap<u64, (usize, StepDisposition)> = BTreeMap::new();
    for (index, step) in scenario.steps.iter().enumerate() {
        let declared_unit = parameters
            .get(step.param.as_str())
            .copied()
            .ok_or_else(|| {
                validation(format!(
                    "scenario '{}' step {index} targets unknown parameter '{}'",
                    scenario.id, step.param
                ))
            })?;
        if step.value.unit_id != declared_unit {
            return Err(validation(format!(
                "scenario '{}' step {index} uses unit {} for '{}', profile declares {}",
                scenario.id, step.value.unit_id, step.param, declared_unit
            )));
        }
        if step.at_secs < 0 {
            return Err(validation(format!(
                "scenario '{}' step {index} has a negative time",
                scenario.id
            )));
        }
        match step.replay_of {
            Some(original) => {
                let (original_index, original_expect) =
                    sequences.get(&original).copied().ok_or_else(|| {
                        validation(format!(
                            "scenario '{}' step {index} replays unknown sequence {original}",
                            scenario.id
                        ))
                    })?;
                if original_index >= index {
                    return Err(validation(format!(
                        "scenario '{}' step {index} replays a later command",
                        scenario.id
                    )));
                }
                if original_expect == StepDisposition::Rejected {
                    return Err(validation(format!(
                        "scenario '{}' step {index} replays a rejected command",
                        scenario.id
                    )));
                }
                if step.expect != StepDisposition::Deduplicated {
                    return Err(validation(format!(
                        "scenario '{}' step {index} replays sequence {original} and must expect 'deduplicated'",
                        scenario.id
                    )));
                }
            }
            None => {
                if sequences
                    .insert(step.sequence, (index, step.expect))
                    .is_some()
                {
                    return Err(validation(format!(
                        "scenario '{}' step {index} reuses sequence {}",
                        scenario.id, step.sequence
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_expected(
    expected: &PackExpectedOutputs,
    scenarios: &[PackScenario],
    trip: Option<&TripDocument>,
) -> Result<(), PackError> {
    if expected.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
        return Err(validation(format!(
            "expected-output schema_version must be {PACK_MANIFEST_SCHEMA_VERSION}"
        )));
    }
    let scenario_ids: BTreeSet<&str> = scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect();
    let expected_ids: BTreeSet<&str> = expected
        .scenario
        .iter()
        .map(|row| row.id.as_str())
        .collect();
    if expected_ids.len() != expected.scenario.len() {
        return Err(validation(
            "expected-output document lists a scenario more than once",
        ));
    }
    if scenario_ids != expected_ids {
        let missing: Vec<&&str> = scenario_ids.difference(&expected_ids).collect();
        let extra: Vec<&&str> = expected_ids.difference(&scenario_ids).collect();
        return Err(validation(format!(
            "expected outputs must cover every scenario exactly once (missing: {missing:?}, unknown: {extra:?})"
        )));
    }
    for scenario in scenarios {
        let row = expected
            .scenario
            .iter()
            .find(|row| row.id == scenario.id)
            .expect("coverage checked above");
        if row.class != scenario.class {
            return Err(validation(format!(
                "expected output for '{}' declares class {} but the scenario is {}",
                scenario.id, row.class, scenario.class
            )));
        }
        if row.mechanism.trim().is_empty() {
            return Err(validation(format!(
                "expected output for '{}' must name the defense mechanism",
                scenario.id
            )));
        }
        let step_expectations: Vec<StepDisposition> =
            scenario.steps.iter().map(|step| step.expect).collect();
        if row.steps != step_expectations {
            return Err(validation(format!(
                "expected output steps for '{}' do not match the scenario steps",
                scenario.id
            )));
        }
        let derived = ScenarioDisposition::from_steps(&step_expectations);
        if row.disposition != derived {
            return Err(validation(format!(
                "expected output for '{}' says '{}' but its steps imply '{}'",
                scenario.id,
                row.disposition.as_str(),
                derived.as_str()
            )));
        }
        let dispatched = step_expectations
            .iter()
            .filter(|step| **step == StepDisposition::Accepted)
            .count();
        if row.actuations != dispatched {
            return Err(validation(format!(
                "expected output for '{}' says {} actuations but {} steps are accepted",
                scenario.id, row.actuations, dispatched
            )));
        }
    }
    match (&expected.trip, trip) {
        (Some(expected_trip), Some(trip)) => {
            validate_expected_trip(expected_trip, scenarios, trip)?;
        }
        (Some(_), None) => {
            return Err(validation(
                "expected output declares a [trip] disposition but the manifest declares no trip document",
            ))
        }
        (None, Some(_)) => {
            return Err(validation(
                "the manifest declares a trip document but the expected output has no [trip] disposition",
            ))
        }
        (None, None) => {}
    }
    Ok(())
}

fn validate_expected_trip(
    expected: &ExpectedTripOutcome,
    scenarios: &[PackScenario],
    trip: &TripDocument,
) -> Result<(), PackError> {
    let scenario = scenarios
        .iter()
        .find(|scenario| scenario.id == expected.scenario)
        .ok_or_else(|| {
            validation(format!(
                "expected trip disposition names unknown scenario '{}'",
                expected.scenario
            ))
        })?;
    if expected.mechanism.trim().is_empty() {
        return Err(validation(
            "expected trip disposition must name the excursion rule and defense",
        ));
    }
    let door_open_secs = longest_door_open_secs(scenario, &trip.door_param).ok_or_else(|| {
        validation(format!(
            "expected trip disposition derives from '{}', which never accepts a door-open command",
            expected.scenario
        ))
    })?;
    if expected.door_open_secs != door_open_secs {
        return Err(validation(format!(
            "expected trip disposition says the door is open {}s but '{}' leaves it open {}s",
            expected.door_open_secs, expected.scenario, door_open_secs
        )));
    }
    let derived = TripDisposition::from_door_open_secs(door_open_secs, trip.max_door_open_secs);
    if expected.disposition != derived {
        return Err(validation(format!(
            "expected trip disposition is '{}' but {}s of open door against the {}s rule derives '{}'",
            expected.disposition.as_str(),
            door_open_secs,
            trip.max_door_open_secs,
            derived.as_str()
        )));
    }
    Ok(())
}

pub use tirbase_types;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_disposition_derivation() {
        use ScenarioDisposition as D;
        use StepDisposition as S;
        assert_eq!(D::from_steps(&[S::Accepted]), D::Accepted);
        assert_eq!(
            D::from_steps(&[S::Accepted, S::Deduplicated]),
            D::Deduplicated
        );
        assert_eq!(D::from_steps(&[S::Accepted, S::Rejected]), D::Rejected);
        assert_eq!(D::from_steps(&[S::Rejected, S::Deduplicated]), D::Rejected);
    }

    #[test]
    fn version_validation_rejects_non_numeric() {
        assert!(validate_version("1.0.0").is_ok());
        assert!(validate_version("1.0").is_err());
        assert!(validate_version("1.0.x").is_err());
        assert!(validate_version("").is_err());
    }

    #[test]
    fn door_open_span_counts_accepted_steps_only() {
        use tirbase_types::FixedPointValue;
        let door = |mantissa: i64, at_secs: i64, expect: StepDisposition| ScenarioStep {
            param: "door_open".to_string(),
            value: FixedPointValue::new(mantissa, 0, 7),
            at_secs,
            sequence: at_secs as u64,
            replay_of: None,
            expect,
            mechanism: None,
        };
        let scenario = PackScenario {
            id: "s".to_string(),
            class: AdversaryClass::S2,
            title: "t".to_string(),
            attack: "a".to_string(),
            target: "reefer-1".to_string(),
            steps: vec![
                door(1, 1000, StepDisposition::Accepted),
                door(0, 1030, StepDisposition::Rejected),
                door(0, 1300, StepDisposition::Accepted),
                door(1, 1400, StepDisposition::Rejected),
            ],
        };
        assert_eq!(longest_door_open_secs(&scenario, "door_open"), Some(300));

        // A scenario that ends with the door still open closes at its last step.
        let open_at_end = PackScenario {
            steps: vec![
                door(1, 1000, StepDisposition::Accepted),
                door(1, 1200, StepDisposition::Rejected),
            ],
            ..scenario.clone()
        };
        assert_eq!(longest_door_open_secs(&open_at_end, "door_open"), Some(200));

        // No accepted open step means no excursion to disposition.
        let never_open = PackScenario {
            steps: vec![door(0, 1000, StepDisposition::Accepted)],
            ..scenario
        };
        assert_eq!(longest_door_open_secs(&never_open, "door_open"), None);
    }

    #[test]
    fn trip_disposition_uses_the_rule_boundary() {
        assert_eq!(
            TripDisposition::from_door_open_secs(120, 120),
            TripDisposition::Clear
        );
        assert_eq!(
            TripDisposition::from_door_open_secs(121, 120),
            TripDisposition::Quarantined
        );
    }

    #[test]
    fn safe_paths_reject_traversal() {
        let root = std::env::temp_dir();
        assert!(safe_pack_path(&root, "../etc/passwd").is_err());
        assert!(safe_pack_path(&root, "/etc/passwd").is_err());
        assert!(safe_pack_path(&root, "").is_err());
    }
}
