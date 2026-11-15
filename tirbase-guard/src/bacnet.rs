// SPDX-License-Identifier: AGPL-3.0-only

//! Guard-owned BACnet/IP read endpoint and polling (CC-04).
//!
//! The guard owns the device endpoint. [`GuardBacnetReader`] wraps the
//! feature-gated [`tirbase_drivers::bacnet::BacnetIpClient`] so the rest of the
//! guard never opens a socket directly. It is read-only: no write method is
//! exposed, and the underlying client rejects writes before sending.
//!
//! [`BacnetPoller`] schedules bounded Present-Value reads for a fixed point
//! list. It is a step function driven by a caller-supplied clock, matching the
//! rest of the guard: it never spawns a thread, reads a clock, or sleeps. Each
//! call reads each due point at most once, caps the point list, and relies on
//! the transport's bounded timeout/retry budget.
#![deny(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;

pub use tirbase_driver_api::bacnet_codec::{
    BacnetError, BacnetValue, ObjectIdentifier, ObjectType,
};
pub use tirbase_drivers::bacnet::{
    BacnetIpClient, BacnetIpConfig, DiscoveredDevice, MonotonicMillisFn,
};
use tirbase_types::{FixedPointValue, UnitId};

/// Maximum points in one poller.
pub const MAX_BACNET_POINTS: usize = 64;
/// Minimum poll interval.
pub const MIN_BACNET_POLL_INTERVAL_MS: u64 = 100;
/// Maximum poll interval (24 hours).
pub const MAX_BACNET_POLL_INTERVAL_MS: u64 = 24 * 60 * 60 * 1_000;
/// Accepted fixed-point exponent range for a point.
pub const MIN_BACNET_POINT_EXPONENT: i8 = -9;
/// Accepted fixed-point exponent range for a point.
pub const MAX_BACNET_POINT_EXPONENT: i8 = 9;

/// One analog or binary Present-Value point to poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacnetPoint {
    /// Stable operator-facing name (unique within a poller).
    pub name: String,
    /// BACnet object whose Present-Value is read.
    pub object: ObjectIdentifier,
    /// Unit used for fixed-point conversion.
    pub unit: UnitId,
    /// Fixed-point exponent used for conversion (for example `-1` for 0.1).
    pub exponent: i8,
}

impl BacnetPoint {
    /// Validates a point before it can be polled.
    pub fn new(
        name: impl Into<String>,
        object: ObjectIdentifier,
        unit: UnitId,
        exponent: i8,
    ) -> Result<Self, BacnetPollError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(BacnetPollError::InvalidPoint {
                name,
                reason: "name must not be empty".into(),
            });
        }
        if !object.object_type.is_readable() {
            return Err(BacnetPollError::InvalidPoint {
                name,
                reason: format!("object type {} is not readable", object.object_type),
            });
        }
        if !(MIN_BACNET_POINT_EXPONENT..=MAX_BACNET_POINT_EXPONENT).contains(&exponent) {
            return Err(BacnetPollError::InvalidPoint {
                name,
                reason: format!(
                    "exponent {exponent} outside {MIN_BACNET_POINT_EXPONENT}..={MAX_BACNET_POINT_EXPONENT}"
                ),
            });
        }
        Ok(Self {
            name,
            object,
            unit,
            exponent,
        })
    }
}

/// One successful read.
#[derive(Debug, Clone, PartialEq)]
pub struct BacnetSample {
    pub point: String,
    pub value: BacnetValue,
    /// `None` when the device returned Null or a value that cannot be scaled.
    pub fixed_point: Option<FixedPointValue>,
    pub sampled_at_ms: u64,
}

/// Per-point poll result. A failure for one point does not stop the others.
#[derive(Debug, Clone, PartialEq)]
pub struct BacnetPollOutcome {
    pub point: String,
    pub result: Result<BacnetSample, BacnetError>,
}

/// Poll configuration/validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BacnetPollError {
    InvalidPoint { name: String, reason: String },
    DuplicatePoint(String),
    TooManyPoints { count: usize, max: usize },
    EmptyPointList,
}

impl fmt::Display for BacnetPollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPoint { name, reason } => {
                write!(f, "invalid BACnet point '{name}': {reason}")
            }
            Self::DuplicatePoint(name) => write!(f, "duplicate BACnet point name '{name}'"),
            Self::TooManyPoints { count, max } => {
                write!(f, "BACnet poller has {count} points, maximum is {max}")
            }
            Self::EmptyPointList => f.write_str("BACnet poller requires at least one point"),
        }
    }
}

impl std::error::Error for BacnetPollError {}

/// Guard-owned BACnet/IP reader for a single device endpoint.
pub struct GuardBacnetReader {
    client: BacnetIpClient,
    target: SocketAddr,
    clock: MonotonicMillisFn,
}

impl fmt::Debug for GuardBacnetReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardBacnetReader")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl GuardBacnetReader {
    /// Binds the guard's UDP socket and fixes the device endpoint. No traffic
    /// is sent until a read or discovery call.
    pub fn connect(
        target: SocketAddr,
        config: &BacnetIpConfig,
        clock: MonotonicMillisFn,
    ) -> Result<Self, BacnetError> {
        let client = BacnetIpClient::bind(config, clock.clone())?;
        Ok(Self {
            client,
            target,
            clock,
        })
    }

    /// Device endpoint this reader polls.
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// Directed Who-Is discovery against the configured endpoint.
    pub fn discover(&self) -> Result<Vec<DiscoveredDevice>, BacnetError> {
        self.client.discover(self.target)
    }

    /// Directed Who-Is discovery limited to an inclusive device-instance range.
    pub fn discover_range(
        &self,
        low: u32,
        high: u32,
    ) -> Result<Vec<DiscoveredDevice>, BacnetError> {
        self.client.discover_range(self.target, low, high)
    }

    /// Reads a point's Present-Value and converts it to fixed point.
    pub fn read_point(&mut self, point: &BacnetPoint) -> Result<BacnetSample, BacnetError> {
        let now = (self.clock)();
        self.read_point_at(point, now)
    }

    /// Reads a point at a caller-supplied timestamp (used by the poller so
    /// scheduling stays deterministic).
    pub fn read_point_at(
        &mut self,
        point: &BacnetPoint,
        sampled_at_ms: u64,
    ) -> Result<BacnetSample, BacnetError> {
        let value = self.client.read_present_value(self.target, point.object)?;
        Ok(BacnetSample {
            point: point.name.clone(),
            fixed_point: value.to_fixed_point(point.unit, point.exponent),
            value,
            sampled_at_ms,
        })
    }

    /// Reads the Present-Value of an analog or binary object directly.
    pub fn read_present_value(
        &mut self,
        object: ObjectIdentifier,
    ) -> Result<BacnetValue, BacnetError> {
        self.client.read_present_value(self.target, object)
    }
}

/// Bounded polling scheduler for a fixed set of BACnet points.
#[derive(Debug)]
pub struct BacnetPoller {
    reader: GuardBacnetReader,
    points: Vec<BacnetPoint>,
    interval_ms: u64,
    next_due_ms: u64,
}

impl BacnetPoller {
    /// Builds a poller. The interval is clamped to
    /// [`MIN_BACNET_POLL_INTERVAL_MS`]..=[`MAX_BACNET_POLL_INTERVAL_MS`], and
    /// `start_ms` makes the first poll due immediately.
    pub fn new(
        reader: GuardBacnetReader,
        points: Vec<BacnetPoint>,
        interval_ms: u64,
        start_ms: u64,
    ) -> Result<Self, BacnetPollError> {
        if points.is_empty() {
            return Err(BacnetPollError::EmptyPointList);
        }
        if points.len() > MAX_BACNET_POINTS {
            return Err(BacnetPollError::TooManyPoints {
                count: points.len(),
                max: MAX_BACNET_POINTS,
            });
        }
        let mut names = BTreeSet::new();
        for point in &points {
            if !names.insert(point.name.as_str()) {
                return Err(BacnetPollError::DuplicatePoint(point.name.clone()));
            }
            if !point.object.object_type.is_readable() {
                return Err(BacnetPollError::InvalidPoint {
                    name: point.name.clone(),
                    reason: format!("object type {} is not readable", point.object.object_type),
                });
            }
        }
        Ok(Self {
            reader,
            points,
            interval_ms: interval_ms
                .clamp(MIN_BACNET_POLL_INTERVAL_MS, MAX_BACNET_POLL_INTERVAL_MS),
            next_due_ms: start_ms,
        })
    }

    /// Configured points, in poll order.
    pub fn points(&self) -> &[BacnetPoint] {
        &self.points
    }

    /// Effective (clamped) interval.
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// Next scheduled poll time.
    pub fn next_due_ms(&self) -> u64 {
        self.next_due_ms
    }

    /// Whether a poll is due at `now_ms`.
    pub fn is_due(&self, now_ms: u64) -> bool {
        now_ms >= self.next_due_ms
    }

    /// Polls every point when due. Returns empty when not due.
    ///
    /// The schedule advances by one interval from `now_ms` (no catch-up storm
    /// after a slow poll), each point is read at most once per call, and a
    /// failed point does not suppress the others.
    pub fn poll_due(&mut self, now_ms: u64) -> Vec<BacnetPollOutcome> {
        if !self.is_due(now_ms) {
            return Vec::new();
        }
        self.next_due_ms = now_ms.saturating_add(self.interval_ms);
        self.points
            .iter()
            .map(|point| BacnetPollOutcome {
                point: point.name.clone(),
                result: self.reader.read_point_at(point, now_ms),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_validation_rejects_bad_configuration() {
        let analog = ObjectIdentifier::new(ObjectType::AnalogInput, 0).unwrap();
        assert!(BacnetPoint::new("  ", analog, 1, 0).is_err());
        assert!(BacnetPoint::new("x", ObjectIdentifier::device(1).unwrap(), 1, 0).is_err());
        assert!(BacnetPoint::new("x", analog, 1, 100).is_err());
        assert!(BacnetPoint::new("temperature", analog, 1, -1).is_ok());
    }

    #[test]
    fn poll_interval_is_clamped() {
        let clock: MonotonicMillisFn = std::sync::Arc::new(|| 0);
        let config = BacnetIpConfig {
            local_addr: "127.0.0.1:0".into(),
            timeout: std::time::Duration::from_millis(10),
            retries: 0,
            max_devices: 1,
        };
        let reader =
            GuardBacnetReader::connect("127.0.0.1:47808".parse().unwrap(), &config, clock).unwrap();
        let point = BacnetPoint::new(
            "t",
            ObjectIdentifier::new(ObjectType::AnalogInput, 0).unwrap(),
            1,
            -1,
        )
        .unwrap();
        let poller = BacnetPoller::new(reader, vec![point], 1, 0).unwrap();
        assert_eq!(poller.interval_ms(), MIN_BACNET_POLL_INTERVAL_MS);
    }
}
