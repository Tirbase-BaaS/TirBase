// SPDX-License-Identifier: Apache-2.0

//! TirBase device driver API.
//!
//! This crate is the **Apache-2.0 integration surface** for third-party driver
//! authors. It contains only the pure codec traits, device-model descriptors,
//! register-map format, Modbus/MQTT packet codecs, and the conformance harness. It has
//! no dependency on `tirbase-core`, `tirbase-guard`, or any runtime, so a vendor
//! can implement and test a driver without linking AGPL code.
//!
//! The runtime implementations and the out-of-process isolation machinery live
//! in the AGPL-licensed `tirbase-drivers` crate, which re-exports this API for
//! backwards compatibility (those re-export paths are deprecated).
//!
//! # Vendor quick start
//!
//! ```no_run
//! use tirbase_driver_api::{DriverTrait, DriverResult, Frame, DeviceModel};
//!
//! struct MyDriver;
//!
//! impl DriverTrait for MyDriver {
//!     fn capability_discovery(&self) -> DriverResult<DeviceModel> {
//!         // Describe the device's parameters and units.
//!         # unimplemented!()
//!     }
//!     fn encode_read(&self, param: &str) -> DriverResult<Frame> {
//!         # unimplemented!()
//!     }
//!     fn decode_read_response(&self, frame: &[u8]) -> DriverResult<tirbase_driver_api::tirbase_types::FixedPointValue> {
//!         # unimplemented!()
//!     }
//!     fn encode_actuation(&self, permit: &tirbase_driver_api::ActuationPermitRef) -> DriverResult<Frame> {
//!         # unimplemented!()
//!     }
//!     fn decode_read_back(&self, frame: &[u8]) -> DriverResult<tirbase_driver_api::tirbase_types::FixedPointValue> {
//!         # unimplemented!()
//!     }
//!     fn encode_health_check(&self) -> DriverResult<Frame> {
//!         # unimplemented!()
//!     }
//!     fn decode_health_response(&self, frame: &[u8]) -> DriverResult<tirbase_driver_api::DriverHealth> {
//!         # unimplemented!()
//!     }
//! }
//! ```
//!
//! Run the [`conformance`] harness from an integration test before submitting
//! the driver. See `docs/driver-api.md` for the licence boundary, semver policy,
//! and submission process.

#![deny(unsafe_code)]
#![warn(dead_code)]

pub mod bacnet_codec;
pub mod ble_gatt;
pub mod conformance;
pub mod current_loop;
pub mod driver_trait;
pub mod ds18b20;
pub mod modbus_codec;
pub mod mqtt_codec;
pub mod register_map;
pub mod thermostat;

pub use bacnet_codec::*;
pub use ble_gatt::*;
pub use conformance::*;
pub use current_loop::*;
pub use driver_trait::*;
pub use ds18b20::*;
pub use modbus_codec::*;
pub use mqtt_codec::*;
pub use register_map::*;
pub use thermostat::*;
pub use tirbase_types;
