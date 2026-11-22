// SPDX-License-Identifier: AGPL-3.0-only

//! # tirbase-venue-gateway — Venue gateway protocol ingest (ST-02)
//!
//! Ingests read-only building/gate protocols into the ST-01 venue model:
//!
//! * BACnet/IP, Modbus TCP/RTU, KNX/IP and MQTT, each behind a Cargo feature;
//! * point mappings for gates, zone occupancy, environment and equipment;
//! * bounded reconnect health with deterministic backoff, and stale-point
//!   events when a point stops refreshing;
//! * a structural read-only guarantee: this crate exposes no command,
//!   actuation or write frame builder, and rejects write-path frames/addresses.
//!
//! Device I/O belongs to the caller. Frames are decoded with the Apache-2.0
//! `tirbase-driver-api` codecs (or the built-in KNX decode subset) and folded in
//! through [`VenueGateway::ingest`].

#![forbid(unsafe_code)]

pub mod error;
pub mod health;
pub mod hub;
pub mod ids;
pub mod point;
pub mod protocol;
pub mod sim;

pub use error::GatewayError;
pub use health::{BackoffPolicy, ConnectionSupervisor, HealthEvent, HealthEventRecord};
pub use hub::VenueGateway;
pub use ids::{EquipmentId, PointId};
pub use point::{
    DecodedPoint, PointAddress, PointKind, PointMapping, PointTarget, PointUpdate, PointValue,
    Protocol, SafetyClass, VenueSnapshot, MAX_TOPIC_LEN,
};
pub use protocol::ProtocolError;
