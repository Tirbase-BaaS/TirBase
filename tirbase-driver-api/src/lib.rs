// SPDX-License-Identifier: Apache-2.0

//! TirBase device driver API.
//!
//! This crate is the **Apache-2.0 integration surface** for third-party driver
//! authors. It contains only the pure codec traits, device-model descriptors,
//! and register-map format. It has no dependency on `tirbase-core`,
//! `tirbase-guard`, or any runtime, so a vendor can implement a driver without
//! linking AGPL code.
//!
//! The runtime implementations and the out-of-process isolation machinery live
//! in the AGPL-licensed `tirbase-drivers` crate, which re-exports this API for
//! backwards compatibility.

#![deny(unsafe_code)]
#![warn(dead_code)]

pub mod driver_trait;
pub mod register_map;

pub use driver_trait::*;
pub use register_map::*;
pub use tirbase_types;
