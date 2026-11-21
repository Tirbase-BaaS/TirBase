// SPDX-License-Identifier: AGPL-3.0-only

//! Excursion workflow: detect → quarantine → notify → disposition → signed
//! resolution → closed (CC-11).
//!
//! The workflow is the cold-chain answer to "the product left its band; what
//! happens to the lot?". It is a small, persisted state machine:
//!
//! ```text
//! Detected ─▶ Quarantined ─▶ Notified ─▶ Dispositioned ─▶ Resolved ─▶ Closed
//! ```
//!
//! Every state is a committed database row, never an in-memory flag, so a power
//! cut loses nothing: a reopened [`ExcursionWorkflow`] reads the same state, the
//! same detection evidence, the same operator disposition and the same signed
//! resolution. Steps can only move forward, and only by one step, which is what
//! makes "resolve without a disposition" or "close while still quarantined"
//! impossible rather than merely discouraged.
//!
//! # Detection inputs
//!
//! [`DetectionInputs`] carries everything the guard and the drivers already know
//! about the storage: the current and previous temperature, the sampling
//! interval, the windowed drift, door-open, defrost and compressor runtimes, a
//! sensor fault, the telemetry gap, and the sample series used for MKT. Every
//! input is optional or has an explicit sentinel, so "no reading" is never
//! silently treated as "in band": a missing temperature or a telemetry gap is its
//! own reason code.
//!
//! # Quarantine visibility, reads, and sync
//!
//! [`ExcursionWorkflow::quarantine_view`] is the read projection other systems
//! consume. The same view is what a peer gateway receives:
//! [`ExcursionWorkflow::apply_remote_quarantine`] merges it idempotently
//! (higher view version wins), refuses to downgrade a record that already has a
//! local disposition, and never lets a synced view release a lot. Quarantine is
//! therefore visible both to local reads and to a peer that only ever sees the
//! synced projection.
//!
//! # Notifications
//!
//! See [`notifier`] for the at-least-once outbox and the deduplication key. The
//! workflow writes the outbox row and the state change in separate statements
//! inside one transaction, then hands rows to channels; a crash between the two
//! leaves the row pending, and [`ExcursionWorkflow::recover`] retries it.
//!
//! # MKT
//!
//! See [`mkt`] for the Arrhenius calculation, its documented numeric behaviour,
//! and the published reference vectors.

pub mod config;
pub mod mkt;
pub mod notifier;
pub mod store;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_guard::signed_operation::{SignedOperation, SignedOperationPayload};
use tirbase_types::{CommandRole, DeviceSignature, FixedPointValue};

use crate::excursion::mkt::{MktError, MktParameters};
use crate::excursion::notifier::{
    ExcursionNotification, NotificationEvent, NotifierDispatcher, NotifyError,
};
use crate::excursion::store::ExcursionStore;
use crate::lineage_ledger::sink::LedgerSink;
use crate::lineage_ledger::{
    AppendRequest, EVENT_EXCURSION_DISPOSITIONED, EVENT_EXCURSION_RESOLVED,
};

/// Domain-separation context for the signed resolution payload.
pub const CONTEXT_EXCURSION_RESOLUTION: &str = "TirBase/v1/ExcursionResolution";

/// Domain-separation prefix for the operator disposition signature.
pub const CONTEXT_EXCURSION_DISPOSITION: &str = "TirBase/v1/ExcursionDisposition";

/// Maximum reasons accepted in a single detection outcome (bounds the row size).
pub const MAX_DETECTION_FINDINGS: usize = 32;

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Persisted workflow states, in legal transition order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExcursionState {
    /// A detection run produced at least one reason.
    Detected,
    /// The lot/location is held pending assessment.
    Quarantined,
    /// Every configured channel has accepted the quarantine notification.
    Notified,
    /// An operator recorded a disposition with reason, evidence, and signature.
    Dispositioned,
    /// The resolution payload is signed and verified.
    Resolved,
    /// No further transitions are possible.
    Closed,
}

impl ExcursionState {
    /// Stable string form used in the database and in payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            ExcursionState::Detected => "detected",
            ExcursionState::Quarantined => "quarantined",
            ExcursionState::Notified => "notified",
            ExcursionState::Dispositioned => "dispositioned",
            ExcursionState::Resolved => "resolved",
            ExcursionState::Closed => "closed",
        }
    }

    /// Zero-based position in the legal order.
    pub fn rank(self) -> u8 {
        match self {
            ExcursionState::Detected => 0,
            ExcursionState::Quarantined => 1,
            ExcursionState::Notified => 2,
            ExcursionState::Dispositioned => 3,
            ExcursionState::Resolved => 4,
            ExcursionState::Closed => 5,
        }
    }

    /// All states in legal order.
    pub fn all() -> [ExcursionState; 6] {
        [
            ExcursionState::Detected,
            ExcursionState::Quarantined,
            ExcursionState::Notified,
            ExcursionState::Dispositioned,
            ExcursionState::Resolved,
            ExcursionState::Closed,
        ]
    }

    /// The nominal next state in the happy path.
    pub fn next(self) -> Option<ExcursionState> {
        match self {
            ExcursionState::Detected => Some(ExcursionState::Quarantined),
            ExcursionState::Quarantined => Some(ExcursionState::Notified),
            ExcursionState::Notified => Some(ExcursionState::Dispositioned),
            ExcursionState::Dispositioned => Some(ExcursionState::Resolved),
            ExcursionState::Resolved => Some(ExcursionState::Closed),
            ExcursionState::Closed => None,
        }
    }

    /// Whether `next` is a legal forward move from `self`.
    ///
    /// The nominal chain is detect → quarantine → notify → disposition → signed
    /// resolution → closed. `Quarantined → Dispositioned` is also legal so an
    /// operator can act while a channel is still retrying; notification delivery
    /// remains at-least-once and is retried independently.
    pub fn can_transition_to(self, next: ExcursionState) -> bool {
        matches!(
            (self, next),
            (ExcursionState::Detected, ExcursionState::Quarantined)
                | (ExcursionState::Quarantined, ExcursionState::Notified)
                | (ExcursionState::Quarantined, ExcursionState::Dispositioned)
                | (ExcursionState::Notified, ExcursionState::Dispositioned)
                | (ExcursionState::Dispositioned, ExcursionState::Resolved)
                | (ExcursionState::Resolved, ExcursionState::Closed)
        )
    }

    /// Whether the workflow is finished.
    pub fn is_terminal(self) -> bool {
        matches!(self, ExcursionState::Closed)
    }

    /// Whether the lot is still under quarantine control.
    pub fn is_quarantined(self) -> bool {
        matches!(self, ExcursionState::Quarantined | ExcursionState::Notified)
    }
}

/// Why a state change was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    /// State the record was in.
    pub from: ExcursionState,
    /// State the caller asked for.
    pub to: ExcursionState,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "illegal excursion transition {} -> {}",
            self.from.as_str(),
            self.to.as_str()
        )
    }
}

impl std::error::Error for TransitionError {}

/// Validate and apply one forward step.
///
/// Skips, repeats (including self-transitions), and backward moves are refused.
pub fn advance_state(
    from: ExcursionState,
    to: ExcursionState,
) -> Result<ExcursionState, TransitionError> {
    if from.can_transition_to(to) {
        Ok(to)
    } else {
        Err(TransitionError { from, to })
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// A sensor fault reported by the driver layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorFault {
    /// Sensor that failed.
    pub sensor_id: String,
    /// Fault class.
    pub kind: SensorFaultKind,
}

/// Kind of sensor fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorFaultKind {
    /// The reading stopped changing.
    Stuck,
    /// The sensor is not reachable.
    Disconnected,
    /// The reading is physically impossible.
    OutOfRange,
    /// The calibration record lapsed.
    CalibrationExpired,
}

impl SensorFaultKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            SensorFaultKind::Stuck => "stuck",
            SensorFaultKind::Disconnected => "disconnected",
            SensorFaultKind::OutOfRange => "out_of_range",
            SensorFaultKind::CalibrationExpired => "calibration_expired",
        }
    }
}

/// Reason codes a detection run can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExcursionReason {
    /// A reading left the storage band.
    TemperatureOutOfBand,
    /// The rate of change exceeded the profile limit.
    RateExceeded,
    /// Windowed cumulative drift exceeded the profile budget.
    DriftExceeded,
    /// The door was open longer than the policy allows.
    DoorOpenTooLong,
    /// Defrost ran longer than the policy allows.
    DefrostTooLong,
    /// The compressor ran longer than the policy allows.
    CompressorRuntimeExceeded,
    /// A sensor is faulty, so the record is incomplete.
    SensorFault,
    /// Telemetry is missing or late.
    MissingTelemetry,
    /// Mean kinetic temperature exceeded the storage-class limit.
    MktExceeded,
}

impl ExcursionReason {
    /// Stable reason code (snake case, used in payloads and notifications).
    pub fn as_str(self) -> &'static str {
        match self {
            ExcursionReason::TemperatureOutOfBand => "temperature_out_of_band",
            ExcursionReason::RateExceeded => "rate_exceeded",
            ExcursionReason::DriftExceeded => "drift_exceeded",
            ExcursionReason::DoorOpenTooLong => "door_open_too_long",
            ExcursionReason::DefrostTooLong => "defrost_too_long",
            ExcursionReason::CompressorRuntimeExceeded => "compressor_runtime_exceeded",
            ExcursionReason::SensorFault => "sensor_fault",
            ExcursionReason::MissingTelemetry => "missing_telemetry",
            ExcursionReason::MktExceeded => "mkt_exceeded",
        }
    }

    /// The detection input this reason speaks about.
    pub fn input(self) -> &'static str {
        match self {
            ExcursionReason::TemperatureOutOfBand => "temperature",
            ExcursionReason::RateExceeded => "rate",
            ExcursionReason::DriftExceeded => "drift",
            ExcursionReason::DoorOpenTooLong => "door",
            ExcursionReason::DefrostTooLong => "defrost",
            ExcursionReason::CompressorRuntimeExceeded => "compressor",
            ExcursionReason::SensorFault => "sensor_fault",
            ExcursionReason::MissingTelemetry => "missing_telemetry",
            ExcursionReason::MktExceeded => "mkt",
        }
    }
}

/// One reason plus the detail that explains it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionFinding {
    /// Reason code.
    pub reason: ExcursionReason,
    /// Human-readable detail (values, limits, sensor ids).
    pub detail: String,
}

/// Everything one detection run observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionInputs {
    /// Latest temperature reading.
    pub temperature_c: Option<FixedPointValue>,
    /// Previous reading, used for the rate check.
    pub previous_temperature_c: Option<FixedPointValue>,
    /// Seconds between the two readings; `0` skips the rate check.
    pub elapsed_secs: u32,
    /// Windowed cumulative drift from the profile's drift window.
    pub drift_c: Option<FixedPointValue>,
    /// How long the door has been open.
    pub door_open_secs: u32,
    /// How long defrost has been running.
    pub defrost_secs: u32,
    /// How long the compressor has been running.
    pub compressor_on_secs: u32,
    /// Reported sensor fault, if any.
    pub sensor_fault: Option<SensorFault>,
    /// Gap since the last accepted telemetry, if it exceeded the cadence.
    pub telemetry_gap_secs: Option<u32>,
    /// Samples for the MKT calculation (empty skips it).
    pub samples: Vec<FixedPointValue>,
}

impl Default for DetectionInputs {
    fn default() -> Self {
        Self {
            temperature_c: None,
            previous_temperature_c: None,
            elapsed_secs: 0,
            drift_c: None,
            door_open_secs: 0,
            defrost_secs: 0,
            compressor_on_secs: 0,
            sensor_fault: None,
            telemetry_gap_secs: None,
            samples: Vec::new(),
        }
    }
}

/// Policy limits a detection run is evaluated against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionThresholds {
    /// Lower bound of the labelled storage band.
    pub band_min_c: FixedPointValue,
    /// Upper bound of the labelled storage band.
    pub band_max_c: FixedPointValue,
    /// Maximum accepted rate of change, in °C per second.
    pub max_rate_c_per_sec: FixedPointValue,
    /// Cumulative drift budget inside the profile's window.
    pub drift_budget_c: FixedPointValue,
    /// Longest tolerated door-open interval.
    pub max_door_open_secs: u32,
    /// Longest tolerated defrost interval.
    pub max_defrost_secs: u32,
    /// Longest tolerated compressor runtime.
    pub compressor_max_runtime_secs: u32,
    /// Longest tolerated telemetry gap.
    pub max_telemetry_gap_secs: u32,
    /// MKT limit for the storage class.
    pub mkt_limit_c: FixedPointValue,
    /// Arrhenius parameters for the MKT calculation.
    pub mkt: MktParameters,
}

/// Result of one detection run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionOutcome {
    /// Findings in evaluation order (empty means "in band").
    pub findings: Vec<DetectionFinding>,
    /// MKT over the samples, when the series was usable.
    pub mkt_c: Option<FixedPointValue>,
    /// When the run was evaluated (authenticated-time estimate, seconds).
    pub evaluated_est: i64,
}

impl DetectionOutcome {
    /// `true` when at least one reason fired.
    pub fn triggered(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Distinct reason codes in first-seen order.
    pub fn reasons(&self) -> Vec<ExcursionReason> {
        let mut seen = Vec::new();
        for finding in &self.findings {
            if !seen.contains(&finding.reason) {
                seen.push(finding.reason);
            }
        }
        seen
    }

    /// SHA-256 over the canonical JSON encoding of this outcome.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"TirBase/v1/ExcursionDetection\0");
        hasher.update(serde_json::to_vec(self).unwrap_or_default());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Compare a `FixedPointValue` to a limit in a common exponent.
fn scaled(value: &FixedPointValue, exponent: i8) -> i128 {
    let delta = value.exponent as i16 - exponent as i16;
    if delta >= 0 {
        i128::from(value.mantissa) * 10i128.pow(delta as u32)
    } else {
        i128::from(value.mantissa) / 10i128.pow((-delta) as u32)
    }
}

/// Evaluate the detection inputs against the policy limits.
///
/// Evaluation order is fixed (temperature, rate, drift, door, defrost,
/// compressor, sensor, telemetry, MKT) so the findings, and therefore the stored
/// evidence digest, are reproducible.
pub fn evaluate_detection(
    thresholds: &DetectionThresholds,
    inputs: &DetectionInputs,
    now_est: i64,
) -> DetectionOutcome {
    let mut findings = Vec::new();

    if let Some(temperature) = inputs.temperature_c {
        let value = scaled(&temperature, -1);
        let min = scaled(&thresholds.band_min_c, -1);
        let max = scaled(&thresholds.band_max_c, -1);
        if value < min || value > max {
            findings.push(DetectionFinding {
                reason: ExcursionReason::TemperatureOutOfBand,
                detail: format!(
                    "temperature {:.1} °C outside band {:.1}..{:.1} °C",
                    value as f64 / 10.0,
                    min as f64 / 10.0,
                    max as f64 / 10.0
                ),
            });
        }
    }

    if let (Some(previous), Some(current)) = (inputs.previous_temperature_c, inputs.temperature_c) {
        if inputs.elapsed_secs > 0 {
            let delta = (scaled(&current, -1) - scaled(&previous, -1)).abs();
            let rate_milli = delta * 1000 / (i128::from(inputs.elapsed_secs) * 10);
            let limit_milli = scaled(&thresholds.max_rate_c_per_sec, -3);
            if rate_milli > limit_milli {
                findings.push(DetectionFinding {
                    reason: ExcursionReason::RateExceeded,
                    detail: format!(
                        "rate {:.3} °C/s exceeds {:.3} °C/s over {} s",
                        rate_milli as f64 / 1000.0,
                        limit_milli as f64 / 1000.0,
                        inputs.elapsed_secs
                    ),
                });
            }
        }
    }

    if let Some(drift) = inputs.drift_c {
        let drift = scaled(&drift, -1);
        let budget = scaled(&thresholds.drift_budget_c, -1);
        if drift > budget {
            findings.push(DetectionFinding {
                reason: ExcursionReason::DriftExceeded,
                detail: format!(
                    "windowed drift {:.1} °C exceeds budget {:.1} °C",
                    drift as f64 / 10.0,
                    budget as f64 / 10.0
                ),
            });
        }
    }

    if inputs.door_open_secs > thresholds.max_door_open_secs {
        findings.push(DetectionFinding {
            reason: ExcursionReason::DoorOpenTooLong,
            detail: format!(
                "door open {} s exceeds {} s",
                inputs.door_open_secs, thresholds.max_door_open_secs
            ),
        });
    }

    if inputs.defrost_secs > thresholds.max_defrost_secs {
        findings.push(DetectionFinding {
            reason: ExcursionReason::DefrostTooLong,
            detail: format!(
                "defrost {} s exceeds {} s",
                inputs.defrost_secs, thresholds.max_defrost_secs
            ),
        });
    }

    if inputs.compressor_on_secs > thresholds.compressor_max_runtime_secs {
        findings.push(DetectionFinding {
            reason: ExcursionReason::CompressorRuntimeExceeded,
            detail: format!(
                "compressor on {} s exceeds {} s",
                inputs.compressor_on_secs, thresholds.compressor_max_runtime_secs
            ),
        });
    }

    if let Some(fault) = &inputs.sensor_fault {
        findings.push(DetectionFinding {
            reason: ExcursionReason::SensorFault,
            detail: format!("sensor {} fault: {}", fault.sensor_id, fault.kind.as_str()),
        });
    }

    let missing = match (inputs.temperature_c, inputs.telemetry_gap_secs) {
        (None, _) => Some("no temperature reading".to_string()),
        (Some(_), Some(gap)) if gap > thresholds.max_telemetry_gap_secs => Some(format!(
            "telemetry gap {gap} s exceeds {} s",
            thresholds.max_telemetry_gap_secs
        )),
        _ => None,
    };
    if let Some(detail) = missing {
        findings.push(DetectionFinding {
            reason: ExcursionReason::MissingTelemetry,
            detail,
        });
    }

    let mut mkt_c = None;
    if !inputs.samples.is_empty() {
        match mkt::mean_kinetic_temperature_c(&thresholds.mkt, &inputs.samples) {
            Ok(value) => {
                mkt_c = Some(value);
                if scaled(&value, -1) > scaled(&thresholds.mkt_limit_c, -1) {
                    findings.push(DetectionFinding {
                        reason: ExcursionReason::MktExceeded,
                        detail: format!(
                            "MKT {:.1} °C exceeds limit {:.1} °C",
                            scaled(&value, -1) as f64 / 10.0,
                            scaled(&thresholds.mkt_limit_c, -1) as f64 / 10.0
                        ),
                    });
                }
            }
            Err(error) => findings.push(DetectionFinding {
                reason: ExcursionReason::SensorFault,
                detail: format!("MKT unavailable: {error}"),
            }),
        }
    }

    findings.truncate(MAX_DETECTION_FINDINGS);
    DetectionOutcome {
        findings,
        mkt_c,
        evaluated_est: now_est,
    }
}

// ---------------------------------------------------------------------------
// Disposition and resolution
// ---------------------------------------------------------------------------

/// What the operator decided about the lot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispositionKind {
    /// The lot may be released.
    Release,
    /// The lot stays on hold pending more evidence.
    Hold,
    /// The lot must not be released.
    Reject,
    /// The lot must be destroyed.
    Destroy,
}

impl DispositionKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            DispositionKind::Release => "release",
            DispositionKind::Hold => "hold",
            DispositionKind::Reject => "reject",
            DispositionKind::Destroy => "destroy",
        }
    }

    /// All kinds in a stable order.
    pub fn all() -> [DispositionKind; 4] {
        [
            DispositionKind::Release,
            DispositionKind::Hold,
            DispositionKind::Reject,
            DispositionKind::Destroy,
        ]
    }
}

/// Evidence an operator attaches to a disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Number of temperature samples the assessment covered.
    pub temperature_samples: u32,
    /// MKT over those samples, if computed.
    pub mkt_c: Option<FixedPointValue>,
    /// Detection outcome digest the assessment started from.
    pub detection_digest: String,
    /// When the quarantine opened.
    pub quarantine_opened_est: i64,
    /// Optional ledger or export reference.
    pub ledger_entry: Option<String>,
    /// Analyst notes.
    pub notes: String,
}

impl EvidenceBundle {
    /// SHA-256 over the canonical JSON encoding of this bundle.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"TirBase/v1/ExcursionEvidence\0");
        hasher.update(serde_json::to_vec(self).unwrap_or_default());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// The exact bytes an operator signs when recording a disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispositionPayload {
    /// Record being dispositioned.
    pub record_id: String,
    /// Decision.
    pub disposition: DispositionKind,
    /// Reason code (`temperature_out_of_band`, `mkt_exceeded`, …).
    pub reason: String,
    /// Operator DID.
    pub operator_did: String,
    /// Operator role.
    pub operator_role: CommandRole,
    /// Evidence digest.
    pub evidence_digest: String,
    /// Free-form note.
    pub note: String,
    /// Decision time (authenticated-time estimate, seconds).
    pub decided_est: i64,
}

impl DispositionPayload {
    /// Bytes covered by the operator signature:
    /// `context || 0x00 || canonical JSON`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + 256);
        bytes.extend_from_slice(CONTEXT_EXCURSION_DISPOSITION.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&serde_json::to_vec(self).unwrap_or_default());
        bytes
    }
}

/// A recorded operator disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispositionRecord {
    /// Decision.
    pub disposition: DispositionKind,
    /// Reason code.
    pub reason: String,
    /// Operator DID.
    pub operator_did: String,
    /// Role the operator acted under.
    pub operator_role: CommandRole,
    /// Evidence bundle.
    pub evidence: EvidenceBundle,
    /// Evidence digest as signed.
    pub evidence_digest: String,
    /// Operator note.
    pub note: String,
    /// Signature over [`DispositionPayload`].
    pub signature: DeviceSignature,
    /// When the disposition was recorded.
    pub decided_est: i64,
}

/// Request passed to [`ExcursionWorkflow::record_disposition`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispositionRequest {
    /// Decision.
    pub disposition: DispositionKind,
    /// Reason code; must be one the detection run actually reported, or
    /// `mkt_exceeded`/`sensor_fault` when those were observed.
    pub reason: String,
    /// Operator DID.
    pub operator_did: String,
    /// Role the operator claims.
    pub operator_role: CommandRole,
    /// Evidence bundle.
    pub evidence: EvidenceBundle,
    /// Operator note.
    pub note: String,
    /// Signature over the derived [`DispositionPayload`].
    pub signature: DeviceSignature,
    /// Decision time.
    pub decided_est: i64,
}

/// The payload bound by the signed resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionPayload {
    /// Record being resolved.
    pub record_id: String,
    /// Decision carried forward from the disposition.
    pub disposition: DispositionKind,
    /// Reason code.
    pub reason: String,
    /// Operator DID.
    pub operator_did: String,
    /// Evidence digest.
    pub evidence_digest: String,
    /// Decision time.
    pub decided_est: i64,
    /// Site the record belongs to.
    pub site_id: String,
    /// Lot identifier, when the record names one.
    pub lot_id: Option<String>,
}

impl SignedOperationPayload for ResolutionPayload {
    const CONTEXT: &'static str = CONTEXT_EXCURSION_RESOLUTION;
}

/// A signed resolution as stored.
pub type SignedResolution = SignedOperation<ResolutionPayload>;

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// One persisted excursion record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcursionRecord {
    /// Stable record id (caller-supplied or derived from site + detection time).
    pub record_id: String,
    /// Tenant owning the record.
    pub tenant: String,
    /// Site the storage belongs to.
    pub site_id: String,
    /// Device whose telemetry triggered the detection.
    pub device_id: String,
    /// Lot or batch identifier, when the record names one.
    pub lot_id: Option<String>,
    /// Current state.
    pub state: ExcursionState,
    /// When the record was created.
    pub opened_est: i64,
    /// When the record last changed.
    pub updated_est: i64,
    /// Monotonic revision; also the view version used for sync.
    pub revision: u64,
    /// Detection evidence, including the reason codes.
    pub detection: DetectionOutcome,
    /// Operator disposition, once recorded.
    pub disposition: Option<DispositionRecord>,
    /// Signed resolution, once verified.
    pub resolution: Option<SignedResolution>,
    /// When the record was closed.
    pub closed_est: Option<i64>,
}

impl ExcursionRecord {
    /// Distinct reason codes carried by the detection outcome.
    pub fn reasons(&self) -> Vec<ExcursionReason> {
        self.detection.reasons()
    }
}

/// Read projection of a quarantine, shared with local readers and peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineView {
    /// Record id.
    pub record_id: String,
    /// Tenant.
    pub tenant: String,
    /// Site.
    pub site_id: String,
    /// Device.
    pub device_id: String,
    /// Lot, when known.
    pub lot_id: Option<String>,
    /// State the view was taken at.
    pub state: ExcursionState,
    /// Detection evidence.
    pub detection: DetectionOutcome,
    /// Monotonic revision (view version).
    pub version: u64,
    /// When the record was opened.
    pub opened_est: i64,
}

impl QuarantineView {
    /// Reason codes carried by the view.
    pub fn reasons(&self) -> Vec<ExcursionReason> {
        self.detection.reasons()
    }
}

/// Result of merging a peer's quarantine view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// The record did not exist locally and was inserted as quarantined.
    Inserted,
    /// The local record advanced (its view was stale).
    Advanced,
    /// The view was not newer than the local revision.
    IgnoredStale,
    /// The local record already carries a disposition; a peer may not undo it.
    RefusedDispositioned,
}

/// Persisted workflow history entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExcursionHistoryEntry {
    /// Sequence number within the record (1-based).
    pub seq: u64,
    /// Event name (`detected`, `quarantined`, `notified`, …).
    pub event: String,
    /// When it happened.
    pub at_est: i64,
    /// Event detail (JSON).
    pub detail: serde_json::Value,
}

/// Summary of one delivery pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryReport {
    /// Notifications handed to a channel and marked delivered.
    pub delivered: usize,
    /// Notifications a channel refused or that had no notifier.
    pub failed: usize,
    /// Pending rows a retry re-sent and the channel accepted.
    pub retried_delivered: usize,
    /// Pending rows still undelivered after the pass.
    pub still_pending: usize,
    /// `true` when the record advanced to `Notified` in this pass.
    pub advanced_to_notified: bool,
}

/// Summary of a crash-recovery pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Records read from the database.
    pub records: usize,
    /// Records still awaiting notification delivery.
    pub awaiting_notification: usize,
    /// Notification rows that were still pending before the pass.
    pub pending_notifications: usize,
    /// Pending rows delivered during the pass.
    pub delivered_notifications: usize,
    /// Pending rows still undelivered after the pass.
    pub undelivered_notifications: usize,
    /// Records that already carry a recorded disposition.
    pub dispositioned: usize,
    /// Records that already carry a signed resolution.
    pub resolved: usize,
}

/// Why an excursion workflow operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExcursionError {
    /// The underlying store failed.
    Store(String),
    /// No record with that id exists.
    NotFound(String),
    /// The requested state change is not legal.
    Transition(TransitionError),
    /// A notification could not be delivered.
    Notify(NotifyError),
    /// A signature did not verify, or the payload does not match the record.
    Signature(String),
    /// The request is malformed or internally inconsistent.
    InvalidRequest(String),
    /// The MKT calculation was refused.
    Mkt(MktError),
    /// The lineage ledger append failed (CC-14). The record was already updated;
    /// replaying the same disposition or resolution repairs the missing entry.
    Ledger(String),
}

impl std::fmt::Display for ExcursionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExcursionError::Store(detail) => write!(f, "excursion store: {detail}"),
            ExcursionError::NotFound(id) => write!(f, "excursion record {id} not found"),
            ExcursionError::Transition(error) => write!(f, "{error}"),
            ExcursionError::Notify(error) => write!(f, "notification: {error}"),
            ExcursionError::Signature(detail) => write!(f, "signature: {detail}"),
            ExcursionError::InvalidRequest(detail) => write!(f, "invalid request: {detail}"),
            ExcursionError::Mkt(error) => write!(f, "MKT: {error}"),
            ExcursionError::Ledger(detail) => write!(f, "lineage ledger: {detail}"),
        }
    }
}

impl std::error::Error for ExcursionError {}

fn ledger_error(error: crate::lineage_ledger::LedgerError) -> ExcursionError {
    ExcursionError::Ledger(error.to_string())
}

/// Whether `stored` is the same disposition `request` is asking to record.
fn same_disposition(stored: &DispositionRecord, request: &DispositionRequest) -> bool {
    stored.disposition == request.disposition
        && stored.reason == request.reason
        && stored.operator_did == request.operator_did
        && stored.operator_role == request.operator_role
        && stored.note == request.note
        && stored.decided_est == request.decided_est
        && stored.signature == request.signature
        && stored.evidence == request.evidence
}

impl From<TransitionError> for ExcursionError {
    fn from(error: TransitionError) -> Self {
        ExcursionError::Transition(error)
    }
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/// The persisted excursion workflow.
///
/// One workflow owns one SQLite database (the gateway's `primary.db` in
/// production). All methods are synchronous; the caller supplies the clock.
#[derive(Debug)]
pub struct ExcursionWorkflow {
    store: ExcursionStore,
    ledger: Option<Arc<LedgerSink>>,
}

impl ExcursionWorkflow {
    /// Open (or create) the workflow database at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, ExcursionError> {
        Ok(Self {
            store: ExcursionStore::open(path)?,
            ledger: None,
        })
    }

    /// Open an in-memory workflow (tests and ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, ExcursionError> {
        Ok(Self {
            store: ExcursionStore::open_in_memory()?,
            ledger: None,
        })
    }

    /// Append dispositions and signed resolutions to `ledger` (CC-14).
    ///
    /// Share one [`LedgerSink`] with the lot registry so both write a single
    /// chain. Entry ids are derived from the record, so a retried disposition or
    /// resolution is a duplicate rather than a second row.
    pub fn with_ledger(mut self, ledger: Arc<LedgerSink>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// The attached lineage ledger sink, when there is one.
    pub fn ledger(&self) -> Option<&LedgerSink> {
        self.ledger.as_deref()
    }

    /// Persist a detection run as a `Detected` record.
    ///
    /// `record_id` is assigned by the caller so an operator can be handed the id
    /// before the notification goes out. Detecting the same id twice is refused
    /// rather than silently overwritten.
    #[allow(clippy::too_many_arguments)]
    pub fn detect(
        &self,
        record_id: &str,
        tenant: &str,
        site_id: &str,
        device_id: &str,
        lot_id: Option<&str>,
        detection: DetectionOutcome,
        now_est: i64,
    ) -> Result<ExcursionRecord, ExcursionError> {
        if record_id.trim().is_empty() {
            return Err(ExcursionError::InvalidRequest(
                "record_id must be non-empty".to_string(),
            ));
        }
        if tenant.trim().is_empty() || site_id.trim().is_empty() {
            return Err(ExcursionError::InvalidRequest(
                "tenant and site_id must be non-empty".to_string(),
            ));
        }
        if !detection.triggered() {
            return Err(ExcursionError::InvalidRequest(
                "detection outcome has no findings; nothing to quarantine".to_string(),
            ));
        }
        if self.store.load(record_id)?.is_some() {
            return Err(ExcursionError::InvalidRequest(format!(
                "record {record_id} already exists"
            )));
        }

        let record = ExcursionRecord {
            record_id: record_id.to_string(),
            tenant: tenant.to_string(),
            site_id: site_id.to_string(),
            device_id: device_id.to_string(),
            lot_id: lot_id.map(str::to_string),
            state: ExcursionState::Detected,
            opened_est: now_est,
            updated_est: now_est,
            revision: 1,
            detection,
            disposition: None,
            resolution: None,
            closed_est: None,
        };
        self.store.insert(&record)?;
        self.store.append_event(
            record_id,
            "detected",
            now_est,
            serde_json::json!({
                "reasons": record.reasons().iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                "detection_digest": record.detection.digest(),
            }),
        )?;
        Ok(record)
    }

    /// Move a `Detected` record to `Quarantined`.
    pub fn open_quarantine(
        &self,
        record_id: &str,
        now_est: i64,
    ) -> Result<ExcursionRecord, ExcursionError> {
        let mut record = self.load(record_id)?;
        let next = advance_state(record.state, ExcursionState::Quarantined)?;
        record.revision += 1;
        record.state = next;
        record.updated_est = now_est;
        self.store.update(&record)?;
        self.store.append_event(
            record_id,
            "quarantined",
            now_est,
            serde_json::json!({ "revision": record.revision }),
        )?;
        Ok(record)
    }

    /// Enqueue one notification per configured channel and try to deliver them.
    ///
    /// The outbox rows are written first, so a crash mid-delivery leaves a
    /// pending row that [`Self::recover`] retries. The record advances to
    /// `Notified` only when every channel has accepted the notification.
    pub fn notify(
        &self,
        record_id: &str,
        dispatcher: &NotifierDispatcher,
        event: NotificationEvent,
        now_est: i64,
    ) -> Result<DeliveryReport, ExcursionError> {
        let record = self.load(record_id)?;
        if record.state.rank() > ExcursionState::Quarantined.rank() {
            // Nothing to announce for an already-advanced record; this keeps a
            // retried `notify` idempotent instead of reopening a closed record.
            return self.deliver(record_id, dispatcher, now_est);
        }
        self.enqueue(record_id, dispatcher, event, now_est)?;
        self.deliver(record_id, dispatcher, now_est)
    }

    /// Write the outbox rows for `event` without contacting any channel.
    pub fn enqueue(
        &self,
        record_id: &str,
        dispatcher: &NotifierDispatcher,
        event: NotificationEvent,
        now_est: i64,
    ) -> Result<usize, ExcursionError> {
        let record = self.load(record_id)?;
        let mut enqueued = 0usize;
        for channel in dispatcher.channels() {
            let notification = ExcursionNotification {
                notification_id: ExcursionNotification::dedup_key(
                    &record.record_id,
                    &channel,
                    event,
                ),
                record_id: record.record_id.clone(),
                channel: channel.clone(),
                event,
                tenant: record.tenant.clone(),
                site_id: record.site_id.clone(),
                reasons: record
                    .reasons()
                    .iter()
                    .map(|reason| reason.as_str().to_string())
                    .collect(),
                mkt_c: record.detection.mkt_c,
                opened_est: record.opened_est,
                enqueued_est: now_est,
            };
            enqueued += usize::from(self.store.enqueue_notification(&notification, now_est)?);
        }
        Ok(enqueued)
    }

    /// Try to deliver every pending notification of `record_id`.
    ///
    /// On success all pending rows are marked delivered and a `Quarantined`
    /// record advances to `Notified`. Records already past `Quarantined` never
    /// move backwards, but their pending rows are still retried so a crash after a
    /// disposition cannot drop an at-least-once delivery.
    pub fn deliver(
        &self,
        record_id: &str,
        dispatcher: &NotifierDispatcher,
        now_est: i64,
    ) -> Result<DeliveryReport, ExcursionError> {
        let mut report = DeliveryReport::default();
        let pending = self.store.pending_notifications(Some(record_id))?;
        for notification in &pending {
            match dispatcher.deliver(&notification.channel, notification) {
                Ok(()) => {
                    self.store
                        .mark_delivered(record_id, &notification.channel, now_est)?;
                    report.delivered += 1;
                    report.retried_delivered += usize::from(
                        self.store.notification_attempts(
                            record_id,
                            &notification.channel,
                            notification.event,
                        )? > 0,
                    );
                }
                Err(error) => {
                    self.store.record_failure(
                        record_id,
                        &notification.channel,
                        notification.event,
                        &error.to_string(),
                    )?;
                    report.failed += 1;
                }
            }
        }
        report.still_pending = self.store.pending_notifications(Some(record_id))?.len();

        let mut record = self.load(record_id)?;
        if record.state == ExcursionState::Quarantined && report.still_pending == 0 {
            let next = advance_state(record.state, ExcursionState::Notified)?;
            record.revision += 1;
            record.state = next;
            record.updated_est = now_est;
            self.store.update(&record)?;
            self.store.append_event(
                record_id,
                "notified",
                now_est,
                serde_json::json!({ "delivered": report.delivered }),
            )?;
            report.advanced_to_notified = true;
        }
        Ok(report)
    }

    /// Record an operator disposition.
    ///
    /// The operator signature is verified against the derived
    /// [`DispositionPayload`] *before* the record advances, and the reason must be
    /// one the detection run reported, so a disposition cannot invent a reason or
    /// be replayed onto another record.
    pub fn record_disposition(
        &self,
        record_id: &str,
        request: DispositionRequest,
        resolve_operator_key: impl Fn(&str) -> Option<Vec<u8>>,
        now_est: i64,
    ) -> Result<ExcursionRecord, ExcursionError> {
        let mut record = self.load(record_id)?;
        // A retry of an already-recorded disposition is a no-op that still
        // re-attempts the ledger append, so a crash between the store write and
        // the ledger write is repaired by the retry instead of lost.
        if record
            .disposition
            .as_ref()
            .is_some_and(|stored| same_disposition(stored, &request))
        {
            self.record_disposition_entry(&record)?;
            return Ok(record);
        }
        let next = advance_state(record.state, ExcursionState::Dispositioned)?;

        let known_reasons: Vec<&str> = record
            .reasons()
            .iter()
            .map(|reason| reason.as_str())
            .collect();
        if !known_reasons.contains(&request.reason.as_str()) {
            return Err(ExcursionError::InvalidRequest(format!(
                "reason {:?} was not reported by the detection run (reported: {})",
                request.reason,
                known_reasons.join(", ")
            )));
        }
        if request.evidence.detection_digest != record.detection.digest() {
            return Err(ExcursionError::Signature(
                "evidence does not reference this detection outcome".to_string(),
            ));
        }
        if request.evidence.quarantine_opened_est != record.opened_est {
            return Err(ExcursionError::InvalidRequest(
                "evidence quarantine timestamp does not match the record".to_string(),
            ));
        }

        let payload = DispositionPayload {
            record_id: record.record_id.clone(),
            disposition: request.disposition,
            reason: request.reason.clone(),
            operator_did: request.operator_did.clone(),
            operator_role: request.operator_role,
            evidence_digest: request.evidence.digest(),
            note: request.note.clone(),
            decided_est: request.decided_est,
        };
        verify_ed25519(
            &request.operator_did,
            &payload.signing_bytes(),
            &request.signature,
            &resolve_operator_key,
        )?;

        let disposition = DispositionRecord {
            disposition: request.disposition,
            reason: request.reason.clone(),
            operator_did: request.operator_did.clone(),
            operator_role: request.operator_role,
            evidence: request.evidence,
            evidence_digest: payload.evidence_digest.clone(),
            note: request.note,
            signature: request.signature,
            decided_est: request.decided_est,
        };

        record.revision += 1;
        record.state = next;
        record.updated_est = now_est;
        record.disposition = Some(disposition);
        self.store.update(&record)?;
        self.store.append_event(
            record_id,
            "dispositioned",
            now_est,
            serde_json::json!({
                "disposition": record.disposition.as_ref().map(|d| d.disposition.as_str()),
                "reason": request.reason,
                "operator": request.operator_did,
                "evidence_digest": payload.evidence_digest,
            }),
        )?;
        self.record_disposition_entry(&record)?;
        Ok(record)
    }

    /// The payload a resolution must bind for this record.
    pub fn resolution_payload(&self, record_id: &str) -> Result<ResolutionPayload, ExcursionError> {
        let record = self.load(record_id)?;
        let disposition = record.disposition.as_ref().ok_or_else(|| {
            ExcursionError::InvalidRequest("record has no disposition to resolve".to_string())
        })?;
        Ok(ResolutionPayload {
            record_id: record.record_id.clone(),
            disposition: disposition.disposition,
            reason: disposition.reason.clone(),
            operator_did: disposition.operator_did.clone(),
            evidence_digest: disposition.evidence_digest.clone(),
            decided_est: disposition.decided_est,
            site_id: record.site_id.clone(),
            lot_id: record.lot_id.clone(),
        })
    }

    /// Verify and store a signed resolution, then advance to `Resolved`.
    pub fn sign_resolution(
        &self,
        record_id: &str,
        signed: &SignedResolution,
        resolve_signer_key: impl Fn(&str) -> Option<Vec<u8>>,
        now_est: i64,
    ) -> Result<ExcursionRecord, ExcursionError> {
        let mut record = self.load(record_id)?;
        // Retrying an already-stored resolution re-attempts the ledger append and
        // returns the record unchanged.
        if record
            .resolution
            .as_ref()
            .is_some_and(|stored| stored == signed)
        {
            self.record_resolution_entry(&record)?;
            return Ok(record);
        }
        let next = advance_state(record.state, ExcursionState::Resolved)?;
        let expected = self.resolution_payload(record_id)?;
        signed
            .verify(&expected, resolve_signer_key)
            .map_err(|error| ExcursionError::Signature(error.to_string()))?;
        if record.disposition.as_ref().map(|d| d.operator_did.as_str())
            != Some(expected.operator_did.as_str())
        {
            return Err(ExcursionError::Signature(
                "resolution signer is not the dispositioning operator".to_string(),
            ));
        }

        record.revision += 1;
        record.state = next;
        record.updated_est = now_est;
        record.resolution = Some(signed.clone());
        self.store.update(&record)?;
        self.store.append_event(
            record_id,
            "resolved",
            now_est,
            serde_json::json!({
                "disposition": expected.disposition.as_str(),
                "signer": expected.operator_did,
                "payload_hash": signed.payload_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            }),
        )?;
        self.record_resolution_entry(&record)?;
        Ok(record)
    }

    // -----------------------------------------------------------------------
    // Ledger (CC-14)
    // -----------------------------------------------------------------------

    /// Append the operator disposition to the attached ledger.
    ///
    /// The entry id is derived from the record, and the payload from the stored
    /// disposition only, so replaying the call yields the same payload and is a
    /// duplicate rather than a conflict.
    fn record_disposition_entry(&self, record: &ExcursionRecord) -> Result<(), ExcursionError> {
        let Some(sink) = self.ledger.as_ref() else {
            return Ok(());
        };
        let Some(disposition) = record.disposition.as_ref() else {
            return Ok(());
        };
        let mut request = AppendRequest::new(
            format!("excursion-disposition:{}", record.record_id),
            disposition.operator_did.clone(),
            EVENT_EXCURSION_DISPOSITIONED,
            serde_json::json!({
                "record_id": record.record_id,
                "disposition": disposition.disposition.as_str(),
                "reason": disposition.reason,
                "operator_did": disposition.operator_did,
                "operator_role": disposition.operator_role,
                "evidence_digest": disposition.evidence_digest,
                "note": disposition.note,
                "decided_est": disposition.decided_est,
                "site_id": record.site_id,
                "lot_id": record.lot_id,
            }),
            disposition.decided_est,
        )
        .with_device(record.device_id.clone());
        if let Some(lot_id) = record.lot_id.as_ref() {
            request = request.with_lot(lot_id.clone());
        }
        sink.append(request).map_err(ledger_error)?;
        Ok(())
    }

    /// Append the signed resolution to the attached ledger.
    fn record_resolution_entry(&self, record: &ExcursionRecord) -> Result<(), ExcursionError> {
        let Some(sink) = self.ledger.as_ref() else {
            return Ok(());
        };
        let Some(resolution) = record.resolution.as_ref() else {
            return Ok(());
        };
        let disposition = record.disposition.as_ref();
        let actor_did = disposition
            .map(|stored| stored.operator_did.clone())
            .unwrap_or_else(|| sink.actor_did().to_string());
        let mut request = AppendRequest::new(
            format!("excursion-resolution:{}", record.record_id),
            actor_did,
            EVENT_EXCURSION_RESOLVED,
            serde_json::json!({
                "record_id": record.record_id,
                "disposition": disposition.map(|stored| stored.disposition.as_str()),
                "reason": disposition.map(|stored| stored.reason.clone()),
                "operator_did": disposition.map(|stored| stored.operator_did.clone()),
                "evidence_digest": disposition.map(|stored| stored.evidence_digest.clone()),
                "decided_est": disposition.map(|stored| stored.decided_est),
                "site_id": record.site_id,
                "lot_id": record.lot_id,
                "resolution_payload_hash": resolution
                    .payload_hash
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                "resolution_created_est": resolution.created_est,
                "signers": resolution
                    .signatures
                    .iter()
                    .map(|entry| entry.signer_did.clone())
                    .collect::<Vec<_>>(),
            }),
            resolution.created_est,
        )
        .with_device(record.device_id.clone());
        if let Some(lot_id) = record.lot_id.as_ref() {
            request = request.with_lot(lot_id.clone());
        }
        sink.append(request).map_err(ledger_error)?;
        Ok(())
    }

    /// Close a resolved record.
    pub fn close(&self, record_id: &str, now_est: i64) -> Result<ExcursionRecord, ExcursionError> {
        let mut record = self.load(record_id)?;
        let next = advance_state(record.state, ExcursionState::Closed)?;
        record.revision += 1;
        record.state = next;
        record.updated_est = now_est;
        record.closed_est = Some(now_est);
        self.store.update(&record)?;
        self.store.append_event(
            record_id,
            "closed",
            now_est,
            serde_json::json!({ "revision": record.revision }),
        )?;
        Ok(record)
    }

    /// Load one record.
    pub fn get(&self, record_id: &str) -> Result<ExcursionRecord, ExcursionError> {
        self.load(record_id)
    }

    /// List records, newest first, optionally filtered.
    pub fn list(
        &self,
        tenant: Option<&str>,
        state: Option<ExcursionState>,
    ) -> Result<Vec<ExcursionRecord>, ExcursionError> {
        self.store.list(tenant, state)
    }

    /// Persisted history of one record.
    pub fn history(&self, record_id: &str) -> Result<Vec<ExcursionHistoryEntry>, ExcursionError> {
        self.store.events(record_id)
    }

    /// Read projection shared with local readers and peers.
    pub fn quarantine_view(&self, record_id: &str) -> Result<QuarantineView, ExcursionError> {
        let record = self.load(record_id)?;
        Ok(QuarantineView {
            record_id: record.record_id,
            tenant: record.tenant,
            site_id: record.site_id,
            device_id: record.device_id,
            lot_id: record.lot_id,
            state: record.state,
            detection: record.detection,
            version: record.revision,
            opened_est: record.opened_est,
        })
    }

    /// Merge a peer's quarantine view.
    ///
    /// Sync is monotonic in both directions that matter: a newer view can raise a
    /// local `Detected` record to `Quarantined`, and nothing can lower a record
    /// that already carries a disposition. A peer can quarantine a lot; it can
    /// never release one.
    pub fn apply_remote_quarantine(
        &self,
        view: &QuarantineView,
        now_est: i64,
    ) -> Result<SyncOutcome, ExcursionError> {
        let Some(mut record) = self.store.load(&view.record_id)? else {
            let record = ExcursionRecord {
                record_id: view.record_id.clone(),
                tenant: view.tenant.clone(),
                site_id: view.site_id.clone(),
                device_id: view.device_id.clone(),
                lot_id: view.lot_id.clone(),
                state: ExcursionState::Quarantined,
                opened_est: view.opened_est,
                updated_est: now_est,
                revision: view.version.max(1),
                detection: view.detection.clone(),
                disposition: None,
                resolution: None,
                closed_est: None,
            };
            self.store.insert(&record)?;
            self.store.append_event(
                &record.record_id,
                "quarantine_synced",
                now_est,
                serde_json::json!({
                    "origin": "peer",
                    "version": record.revision,
                    "reasons": record.reasons().iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                }),
            )?;
            return Ok(SyncOutcome::Inserted);
        };

        if record.state.rank() > ExcursionState::Quarantined.rank() {
            return Ok(SyncOutcome::RefusedDispositioned);
        }
        if view.version <= record.revision {
            return Ok(SyncOutcome::IgnoredStale);
        }
        if record.state == ExcursionState::Detected {
            record.state = advance_state(record.state, ExcursionState::Quarantined)?;
        }
        record.revision = view.version;
        record.updated_est = now_est;
        record.detection = view.detection.clone();
        self.store.update(&record)?;
        self.store.append_event(
            &record.record_id,
            "quarantine_synced",
            now_est,
            serde_json::json!({
                "origin": "peer",
                "version": record.revision,
                "state": record.state.as_str(),
            }),
        )?;
        Ok(SyncOutcome::Advanced)
    }

    /// Read every record and retry every pending notification.
    ///
    /// This is the boot path: it reports what survived the restart (still
    /// quarantined, already dispositioned, already resolved) and finishes any
    /// delivery a crash interrupted. It never re-enqueues a delivered
    /// notification, so recovery cannot duplicate an alert; it also never drops a
    /// recorded disposition, because those live in the record row, not in memory.
    pub fn recover(
        &self,
        dispatcher: &NotifierDispatcher,
        now_est: i64,
    ) -> Result<RecoveryReport, ExcursionError> {
        let records = self.store.list(None, None)?;
        let mut report = RecoveryReport {
            records: records.len(),
            ..Default::default()
        };
        for record in &records {
            if record.state.is_quarantined() {
                report.awaiting_notification += 1;
            }
            if record.disposition.is_some() {
                report.dispositioned += 1;
            }
            if record.resolution.is_some() {
                report.resolved += 1;
            }
            report.pending_notifications += self
                .store
                .pending_notifications(Some(&record.record_id))?
                .len();
        }

        for record in &records {
            if record.state == ExcursionState::Detected && record.detection.triggered() {
                // The crash happened between detection and quarantine: finish it.
                self.open_quarantine(&record.record_id, now_est)?;
            }
        }

        for record in &records {
            let pending = self
                .store
                .pending_notifications(Some(&record.record_id))?
                .len();
            if pending > 0 || record.state == ExcursionState::Quarantined {
                let delivery = self.deliver(&record.record_id, dispatcher, now_est)?;
                report.delivered_notifications += delivery.delivered;
            }
        }

        report.undelivered_notifications = 0;
        for record in &records {
            report.undelivered_notifications += self
                .store
                .pending_notifications(Some(&record.record_id))?
                .len();
        }
        Ok(report)
    }

    fn load(&self, record_id: &str) -> Result<ExcursionRecord, ExcursionError> {
        self.store
            .load(record_id)?
            .ok_or_else(|| ExcursionError::NotFound(record_id.to_string()))
    }
}

/// Verify an Ed25519 signature over `bytes` for `signer_did`.
fn verify_ed25519(
    signer_did: &str,
    bytes: &[u8],
    signature: &DeviceSignature,
    resolve: &impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<(), ExcursionError> {
    let public_key = resolve(signer_did).ok_or_else(|| {
        ExcursionError::Signature(format!("no public key for operator {signer_did}"))
    })?;
    let public_key: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .map_err(|_| ExcursionError::Signature("operator key is not 32 bytes".to_string()))?;
    let DeviceSignature::Ed25519(raw) = signature else {
        return Err(ExcursionError::Signature(
            "only Ed25519 signatures are supported".to_string(),
        ));
    };
    tirbase_core::identity::keypair::verify(
        &public_key,
        bytes,
        &tirbase_core::crdt::delta::Ed25519Signature::from_bytes(*raw),
    )
    .map_err(|_| ExcursionError::Signature("operator signature did not verify".to_string()))
}
