// SPDX-License-Identifier: Apache-2.0

//! Envelope profile data model (tasks 10.1–10.4 — CLAIM-10.1…CLAIM-10.4,
//! PV-4.5, INV-1).
//!
//! `EnvelopeProfile` is a signed, versioned data document specifying per-
//! parameter bounds, timing interlocks, and cross-parameter constraints for a
//! device class.  Profiles are **policy documents** (signed by `PolicyAuthority`),
//! not migration artifacts.
//!
//! All arithmetic is integer/fixed-point; this module is `no_std`-capable
//! (uses `alloc`).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::fixed_point::FixedPointValue;
use crate::{DeviceSignature, ProfileId, UnitId};

// ── 10.1 ParameterKind ───────────────────────────────────────────────────────

/// The kind of value a [`ParameterSpec`] accepts (PV-4.5).
///
/// Enum/Bool parameters carry a typed domain so the guard can reject values
/// that are numerically in-range but not a valid variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterKind {
    /// Closed numeric range `[min, max]` in the parameter's canonical unit.
    Range {
        min: FixedPointValue,
        max: FixedPointValue,
    },
    /// Named variants mapped to raw `i64` values (total, non-extensible at
    /// runtime; profile changes go through the policy lifecycle).
    Enum { variants: Vec<(String, i64)> },
    /// Boolean parameter: `0 = false`, `1 = true`.
    Bool,
}

// ── 10.2 ParameterSpec ───────────────────────────────────────────────────────

/// Per-parameter specification within an [`EnvelopeProfile`] (PV-4.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterSpec {
    /// Stable parameter name (matches `DeviceModel` / driver parameter names).
    pub name: String,
    /// Unit identifier from the unit registry.
    pub unit_id: UnitId,
    /// All values for this parameter MUST use this exponent (Stage 10).
    pub canonical_exponent: i8,
    /// Value domain.
    pub kind: ParameterKind,
    /// Maximum absolute rate of change per second.
    pub max_rate_per_sec: FixedPointValue,
    /// Minimum dwell time (seconds) before the parameter may change again.
    pub dwell_secs: u32,
    /// Minimum off-time (seconds) for on/off style parameters (0 if N/A).
    pub min_off_secs: u32,
    /// Duration of the cumulative-drift enforcement window (seconds).
    pub drift_window_secs: u32,
    /// Maximum cumulative absolute change within `drift_window_secs`.
    pub max_delta_in_window: FixedPointValue,
    /// Value the actuator SHALL hold on LOCKDOWN or comms loss.
    pub safe_default: FixedPointValue,
    /// Tightening floor reference (authoritative floor lives in
    /// `TrustRootRecord.device_class_floors`; this field records the profile's
    /// view and is validated against the trust root at classification time).
    pub tightening_floor: FixedPointValue,
    /// When `true`, commands targeting this parameter require M-of-N quorum.
    pub critical: bool,
}

// ── 10.3 LinearConstraint ────────────────────────────────────────────────────

/// Comparison operator for a [`LinearConstraint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintOperator {
    /// `Σ coeff_i * value_i ≤ bound`
    Leq,
    /// `Σ coeff_i * value_i ≥ bound`
    Geq,
    /// `Σ coeff_i * value_i == bound`
    Eq,
}

/// A single linear inequality/equality over parameter values (PV-4.5).
///
/// The constraint language is total and non-Turing-complete: an
/// `EnvelopeProfile` carries a conjunction (`cross_constraints: Vec<…>`) of
/// these linear constraints.  Coefficients reference parameters by name; the
/// guard resolves names against the profile's parameter list at evaluation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearConstraint {
    /// `(parameter_name, coefficient)` pairs.
    pub coefficients: Vec<(String, FixedPointValue)>,
    /// Right-hand-side bound.
    pub bound: FixedPointValue,
    /// Comparison operator.
    pub operator: ConstraintOperator,
}

// ── 10.4 EnvelopeProfile ─────────────────────────────────────────────────────

/// Signed, versioned envelope profile for a device class (PV-4.5).
///
/// `signature` is produced by a `PolicyAuthority` over the deterministic CBOR
/// encoding of the profile body (all fields except `signature`).  The guard
/// rejects profiles whose signature does not verify against an authorised
/// `PolicyAuthority` key in the active trust root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeProfile {
    /// Stable profile identifier.
    pub profile_id: ProfileId,
    /// Monotonically increasing profile version (anti-rollback).
    pub version: u64,
    /// Device class this profile applies to (e.g. `"cold_room"`).
    pub device_class: String,
    /// Per-parameter specifications.
    pub parameters: Vec<ParameterSpec>,
    /// Cross-parameter constraints (conjunction).
    pub cross_constraints: Vec<LinearConstraint>,
    /// Governance: M in the loosening M-of-N threshold.
    pub policy_loosen_m: u8,
    /// Governance: N in the loosening M-of-N threshold.
    pub policy_loosen_n: u8,
    /// Governance: time-lock duration for loosening (seconds).
    pub policy_timelock_secs: u32,
    /// Governance: cancel window for pending loosening (seconds).
    pub policy_cancel_window_secs: u32,
    /// `PolicyAuthority` signature over the profile body.
    pub signature: DeviceSignature,
}

/// The unsigned body of an [`EnvelopeProfile`], used to compute/verify the
/// `PolicyAuthority` signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EnvelopeProfileBody<'a> {
    pub profile_id: &'a ProfileId,
    pub version: u64,
    pub device_class: &'a str,
    pub parameters: &'a [ParameterSpec],
    pub cross_constraints: &'a [LinearConstraint],
    pub policy_loosen_m: u8,
    pub policy_loosen_n: u8,
    pub policy_timelock_secs: u32,
    pub policy_cancel_window_secs: u32,
}

impl EnvelopeProfile {
    /// Borrow the unsigned body for signing/verification.
    pub fn body(&self) -> EnvelopeProfileBody<'_> {
        EnvelopeProfileBody {
            profile_id: &self.profile_id,
            version: self.version,
            device_class: &self.device_class,
            parameters: &self.parameters,
            cross_constraints: &self.cross_constraints,
            policy_loosen_m: self.policy_loosen_m,
            policy_loosen_n: self.policy_loosen_n,
            policy_timelock_secs: self.policy_timelock_secs,
            policy_cancel_window_secs: self.policy_cancel_window_secs,
        }
    }
}

// ── DeviceModel view (shared for install-time validation, CLAIM-10.6) ────────
//
// `tirbase-drivers` depends on `tirbase-types` only; placing the validation
// view here lets the guard validate profiles without importing the drivers
// crate, preserving the layering invariant (drivers ↛ guard/core).

/// A parameter descriptor as published by a driver/device model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceParameter {
    /// Parameter name.
    pub name: String,
    /// Unit identifier.
    pub unit_id: UnitId,
    /// Human-readable unit label (diagnostics only).
    pub unit_label: String,
    /// Closed numeric range `[min, max]` in the device's canonical unit.
    pub range: [FixedPointValue; 2],
    /// Whether the parameter is writable/actuatable.
    pub writable: bool,
}

/// Typed descriptor of a device's parameters (validation view, PV-10.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceModel {
    /// Device class identifier.
    pub device_class: String,
    /// Parameter descriptors (MUST be non-empty for a valid model).
    pub parameters: Vec<DeviceParameter>,
}

impl DeviceModel {
    /// Look up a parameter descriptor by name.
    pub fn parameter(&self, name: &str) -> Option<&DeviceParameter> {
        self.parameters.iter().find(|p| p.name == name)
    }
}
