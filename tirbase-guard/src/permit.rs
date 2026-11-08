//! `ActuationPermit` — unforgeable actuation capability (PV-4.3, CLAIM-11.2).
//!
//! Only constructible inside `tirbase-guard` via the crate-visible
//! [`ActuationPermit::new`] constructor.  The permit carries no `Default`,
//! `Clone`, `Copy`, or `Deserialize` implementation and is therefore single-use
//! by construction.  `tirbase-drivers` never receives a permit; it receives
//! only [`ActuationPermitRef`] (a plain data view) from the guard's
//! `DriverProxy`.

use tirbase_types::{FixedPointValue, TargetId};

/// Unforgeable actuation capability token.
///
/// # Construction
/// `ActuationPermit` is `pub` (so other crates can name and hold it) but its
/// fields and constructor are `pub(crate)`, and the private `_sealed` field
/// prevents literal construction outside this crate.  The *only* production
/// issuer is [`crate::guard::CommandGuard::admit()`] (task 13 pipeline), which
/// calls [`ActuationPermit::new`] after a command has passed every pipeline
/// stage.
///
/// # Single-use by construction (CLAIM-11.2)
/// This type intentionally does **not** derive `Clone`, `Copy`, `Default`, or
/// `serde::Deserialize`.  `trybuild` compile-fail tests assert that each of
/// those operations is rejected by the compiler.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "an ActuationPermit must be consumed by DriverProxy::dispatch"]
pub struct ActuationPermit {
    pub(crate) target_id: TargetId,
    pub(crate) param: String,
    pub(crate) value: FixedPointValue,
    pub(crate) entry_id: [u8; 16],
    /// Private field: prevents construction outside this crate, even though the
    /// struct is `pub`.
    _sealed: (),
}

impl ActuationPermit {
    /// Create a permit.  `pub(crate)` — only the guard pipeline may mint one.
    pub(crate) fn new(
        target_id: TargetId,
        param: String,
        value: FixedPointValue,
        entry_id: [u8; 16],
    ) -> Self {
        ActuationPermit {
            target_id,
            param,
            value,
            entry_id,
            _sealed: (),
        }
    }

    pub fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    pub fn param(&self) -> &str {
        &self.param
    }

    pub fn value(&self) -> &FixedPointValue {
        &self.value
    }

    pub fn entry_id(&self) -> &[u8; 16] {
        &self.entry_id
    }

    /// Consume the permit and return the plain data view sent to drivers.
    pub fn into_ref(self) -> ActuationPermitRef {
        ActuationPermitRef {
            target_id: self.target_id,
            param: self.param,
            value: self.value,
            entry_id: self.entry_id,
        }
    }
}

/// Plain-data view of an actuation decision.
///
/// Drivers in `tirbase-drivers` receive this (or the encoded frame derived from
/// it) — **never** an [`ActuationPermit`].  Holding a ref does not grant the
/// ability to actuate a device; only the guard-owned `DriverProxy` can send a
/// frame over the device I/O fd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActuationPermitRef {
    pub target_id: TargetId,
    pub param: String,
    pub value: FixedPointValue,
    pub entry_id: [u8; 16],
}
