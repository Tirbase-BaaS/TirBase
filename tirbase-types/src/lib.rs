//! Shared newtypes and value types for TirBase.
//! This crate is `no_std`-capable; only `serde` is a dependency.
//! See design.md §4.1 for the full type list.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

pub use serde;

/// Placeholder — full implementation in task 4.2+.
/// Fixed-point physical value (mantissa × 10^exponent, with unit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FixedPointValue {
    pub mantissa: i64,
    pub exponent: i8,
    pub unit_id: u16,
}

/// Role attached to a Biscuit credential. (PV-3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum CommandRole {
    CommandIssuer,
    PolicyAuthority,
    UpdateSigner,
    RevocationManager,
    Auditor,
    TimeAnchor,
}

/// Unit identifier — integer from docs/unit-registry.md, not a free string.
pub type UnitId = u16;

// ID newtypes
pub type DeltaId = [u8; 32];
pub type MigrationId = [u8; 32];
pub type ProfileId = [u8; 16];

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Did(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TargetId(pub String);

/// Device signature — Ed25519 or P-256.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeviceSignature {
    Ed25519(#[serde(with = "serde_bytes")] Vec<u8>),
    P256(Vec<u8>),
}

/// Key type indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeviceKeyType {
    Ed25519,
    P256,
}
