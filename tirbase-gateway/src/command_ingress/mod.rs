//! Command ingress paths (mesh, cloud API, local admin) — task 11.3 wiring.
//!
//! All three paths converge on [`tirbase_guard::CommandGuard::admit()`] before
//! any actuation reaches [`tirbase_guard::DriverProxy`].  Drivers never receive
//! an `ActuationPermit`; the guard holds it and sends the encoded frame over
//! the guard-owned fd (PV-4.4, CLAIM-11.3).

pub mod mesh;
pub mod cloud;
pub mod local_admin;

pub use tirbase_guard::driver_proxy::IngressSource;
