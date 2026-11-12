// SPDX-License-Identifier: Apache-2.0

//! `DriverTrait` — pure codec interface for device drivers (CLAIM-33.2, PV-10.1).
//!
//! Drivers are **codecs only**: they encode/decode frames. The guard process
//! owns all device I/O endpoints and sends/receives frames over the
//! guard-created socketpair. Driver code performs no I/O.

use core::fmt;
use core::time::Duration;

use tirbase_types::{FixedPointValue, TargetId, UnitId};

/// Raw frame bytes exchanged with the guard/driver boundary over the socketpair.
pub type Frame = Vec<u8>;

/// Maximum wall time for any single driver codec operation (PV-10.1, CLAIM-33.2).
pub const DRIVER_OPERATION_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Typed timeout for a driver operation that exceeded [`DRIVER_OPERATION_TIMEOUT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutError {
    pub operation: &'static str,
    pub limit_ms: u64,
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "driver operation '{}' exceeded {} ms timeout",
            self.operation, self.limit_ms
        )
    }
}

impl std::error::Error for TimeoutError {}

/// Driver health reported by codec health-check frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverHealth {
    pub healthy: bool,
    pub detail: String,
}

/// Plain-data view of an actuation decision (CLAIM-33.4, PV-4.21).
///
/// Drivers receive this view (never the guard's unforgeable `ActuationPermit`)
/// to encode an actuation frame. Holding this value does not grant authority to
/// actuate a device; only the guard-owned proxy dispatches frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActuationPermitRef {
    pub target_id: TargetId,
    pub param: String,
    pub value: FixedPointValue,
    pub entry_id: [u8; 16],
}

/// Typed errors produced by driver codec operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    Timeout(TimeoutError),
    InvalidFrame(String),
    UnsupportedParam(String),
    Codec(String),
    Capability(String),
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverError::Timeout(e) => write!(f, "{e}"),
            DriverError::InvalidFrame(m) => write!(f, "invalid frame: {m}"),
            DriverError::UnsupportedParam(p) => write!(f, "unsupported parameter: {p}"),
            DriverError::Codec(m) => write!(f, "codec error: {m}"),
            DriverError::Capability(m) => write!(f, "capability error: {m}"),
        }
    }
}

impl std::error::Error for DriverError {}

impl From<TimeoutError> for DriverError {
    fn from(e: TimeoutError) -> Self {
        DriverError::Timeout(e)
    }
}

/// Result of a timed driver operation.
pub type DriverResult<T> = Result<T, DriverError>;

/// Runs `op` and returns [`DriverError::Timeout`] if it exceeds
/// [`DRIVER_OPERATION_TIMEOUT`]. Codec operations are expected to be pure/fast;
/// callers (guard/gateway executors) may also enforce wall-clock deadlines.
///
/// `clock` is the caller-supplied monotonic millisecond clock: drivers never
/// read a clock themselves (PV-3.12), because they may not depend on
/// `tirbase-core`'s `TimeSource`.
pub fn run_with_timeout<T, F>(
    operation: &'static str,
    clock: &dyn Fn() -> u64,
    op: F,
) -> DriverResult<T>
where
    F: FnOnce() -> DriverResult<T>,
{
    let start = clock();
    let out = op()?;
    if clock().saturating_sub(start) > DRIVER_OPERATION_TIMEOUT.as_millis() as u64 {
        return Err(DriverError::Timeout(TimeoutError {
            operation,
            limit_ms: DRIVER_OPERATION_TIMEOUT.as_millis() as u64,
        }));
    }
    Ok(out)
}

/// Device parameter descriptor with runtime unit metadata (CLAIM-33.3, PV-10.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterDescriptor {
    pub name: String,
    pub unit_id: UnitId,
    pub unit_label: String,
    pub range: [FixedPointValue; 2],
    pub writable: bool,
}

/// Typed descriptor of a device's parameters (CLAIM-33.3, PV-10.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceModel {
    pub device_class: String,
    pub parameters: Vec<ParameterDescriptor>,
}

/// Empty device model rejection (CLAIM-33.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyDeviceModelError {
    pub device_class: String,
}

impl fmt::Display for EmptyDeviceModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeviceModel for '{}' must declare at least one parameter",
            self.device_class
        )
    }
}

impl std::error::Error for EmptyDeviceModelError {}

impl DeviceModel {
    /// Constructs a validated model, rejecting empty parameter sets (CLAIM-33.3).
    pub fn try_new(
        device_class: String,
        parameters: Vec<ParameterDescriptor>,
    ) -> Result<Self, EmptyDeviceModelError> {
        let model = Self {
            device_class,
            parameters,
        };
        model.validate()?;
        Ok(model)
    }

    /// Validates model invariants. An empty model (zero parameters) is rejected.
    pub fn validate(&self) -> Result<(), EmptyDeviceModelError> {
        if self.parameters.is_empty() {
            return Err(EmptyDeviceModelError {
                device_class: self.device_class.clone(),
            });
        }
        Ok(())
    }
}

/// Pure codec interface for device drivers (CLAIM-33.2, PV-10.1).
///
/// Implementations encode/decode frames only; they perform no device I/O.
/// Each operation must complete within [`DRIVER_OPERATION_TIMEOUT`] or return
/// [`DriverError::Timeout`]. The guard process owns dispatch and read-back I/O.
pub trait DriverTrait: Send + Sync {
    fn capability_discovery(&self) -> DriverResult<DeviceModel>;

    fn encode_read(&self, param: &str) -> DriverResult<Frame>;
    fn decode_read_response(&self, frame: &[u8]) -> DriverResult<FixedPointValue>;

    /// Encodes an actuation frame from a permit view (CLAIM-33.4). No I/O.
    fn encode_actuation(&self, permit: &ActuationPermitRef) -> DriverResult<Frame>;
    /// Decodes a read-back frame into a fixed-point value (CLAIM-33.4). No I/O.
    fn decode_read_back(&self, frame: &[u8]) -> DriverResult<FixedPointValue>;

    fn encode_health_check(&self) -> DriverResult<Frame>;
    fn decode_health_response(&self, frame: &[u8]) -> DriverResult<DriverHealth>;
}
