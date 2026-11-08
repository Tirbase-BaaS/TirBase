#![no_std]
//! Shared newtypes and value types for TirBase.
//! This crate is `no_std`-capable; only `serde` is a dependency.
//! See design.md §4.1 for the full type list.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

// Bring in heap-allocated types (String, Vec, etc.) without std.
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

pub use serde;

// ── fixed_point module ────────────────────────────────────────────────────────
//   Full implementation of FixedPointValue, FixedPointError, BoundsCheck,
//   UnitId constants, UnitDescriptor, and unit_descriptor() lookup.
//   (CLAIM-4.2, CLAIM-4.4, CLAIM-4.6, PV-21.1, INV-1)
pub mod fixed_point;
pub use fixed_point::{
    unit_descriptor, BoundsCheck, FixedPointError, FixedPointValue, UnitDescriptor, UNIT_A,
    UNIT_BAR, UNIT_BOOLEAN, UNIT_DEG_C, UNIT_DESCRIPTORS, UNIT_HZ, UNIT_KPA, UNIT_KW, UNIT_M3H,
    UNIT_PA, UNIT_PERCENT, UNIT_RPM, UNIT_UNKNOWN, UNIT_V,
};

// ── envelope module (CLAIM-10.1…10.4, CLAIM-10.6 view types, PV-4.5) ────────
pub mod envelope;
pub use envelope::{
    ConstraintOperator, DeviceModel, DeviceParameter, EnvelopeProfile, EnvelopeProfileBody,
    LinearConstraint, ParameterKind, ParameterSpec,
};

// ── command module (CLAIM-11.1, PV-4.1, PV-4.2) ────────────────────────────
pub mod command;
pub use command::{
    CoSignature, CommandMessage, CommandMessageBody, CONTEXT_COMMAND_MESSAGE,
};

// ── Role ───────────────────────────────────────────────────────────────────────

/// Role attached to a Biscuit credential.
///
/// Derived from token facts at Stage 4 of the guard pipeline, **never** from a
/// command's self-declared role field. The role is extracted from the Biscuit
/// token's Datalog facts and used to drive the Authorization Matrix checks
/// throughout the guard pipeline.
///
/// Root Keys are offline ceremony keys used only for root rotation ceremonies;
/// they are not issued as Biscuit roles and therefore do not appear in this enum.
///
/// _Requirements: PV-3.1_
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum CommandRole {
    /// Authorised to submit desired-state commands to actuators.
    CommandIssuer,
    /// Authorised to publish, tighten, and initiate loosening of policy bundles.
    PolicyAuthority,
    /// Authorised to sign migration and firmware-manifest deltas.
    UpdateSigner,
    /// Authorised to accumulate M-of-N revocation signatures and decommission devices.
    RevocationManager,
    /// Read-only role; no write or command authority.
    Auditor,
    /// Authorised to submit signed time beacons; cannot issue commands or modify policy.
    TimeAnchor,
}

/// Error returned when parsing a [`CommandRole`] from an unknown string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseCommandRoleError;

impl fmt::Display for ParseCommandRoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown command role")
    }
}

impl FromStr for CommandRole {
    type Err = ParseCommandRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CommandIssuer" => Ok(CommandRole::CommandIssuer),
            "PolicyAuthority" => Ok(CommandRole::PolicyAuthority),
            "UpdateSigner" => Ok(CommandRole::UpdateSigner),
            "RevocationManager" => Ok(CommandRole::RevocationManager),
            "Auditor" => Ok(CommandRole::Auditor),
            "TimeAnchor" => Ok(CommandRole::TimeAnchor),
            _ => Err(ParseCommandRoleError),
        }
    }
}

impl CommandRole {
    /// Returns the canonical string name of the role, matching the Biscuit token fact value.
    ///
    /// This is the string that appears in the Biscuit token's Datalog facts and is used
    /// for token-to-role binding at Stage 4 of the guard pipeline.
    pub fn as_str(&self) -> &'static str {
        match self {
            CommandRole::CommandIssuer => "CommandIssuer",
            CommandRole::PolicyAuthority => "PolicyAuthority",
            CommandRole::UpdateSigner => "UpdateSigner",
            CommandRole::RevocationManager => "RevocationManager",
            CommandRole::Auditor => "Auditor",
            CommandRole::TimeAnchor => "TimeAnchor",
        }
    }

    /// Parses a [`CommandRole`] from a Biscuit token fact string, returning `None`
    /// for unknown roles.
    ///
    /// Unknown role strings MUST be treated as authorization failures by the guard
    /// pipeline. For the standard trait implementation see [`FromStr`].
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        s.parse().ok()
    }

    /// Returns `true` only for [`CommandRole::CommandIssuer`].
    ///
    /// Used in the Authorization Matrix to gate the "Submit command" operation.
    /// All other roles are rejected for command submission with a typed
    /// authorization error.
    ///
    /// _Authorization Matrix: "Submit command" row — only `CommandIssuer` has ✓._
    pub fn can_issue_commands(&self) -> bool {
        matches!(self, CommandRole::CommandIssuer)
    }
}

// ── Unit identifier ────────────────────────────────────────────────────────────

/// Unit identifier — integer from docs/unit-registry.md, not a free string.
/// `UnitId(0)` is reserved as unknown/dimensionless; the guard rejects it at Stage 10.
pub type UnitId = u16;

// ── ID newtypes (CLAIM-4.6) ───────────────────────────────────────────────────

/// 256-bit content-addressed delta identifier.
pub type DeltaId = [u8; 32];

/// 256-bit schema-migration identifier.
pub type MigrationId = [u8; 32];

/// 128-bit envelope-profile identifier.
pub type ProfileId = [u8; 16];

/// Decentralised Identifier newtype.
///
/// Wrapping `String` in a newtype prevents accidental interchange of arbitrary
/// strings with DIDs at the type level. (CLAIM-4.6)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct Did(pub String);

impl Did {
    /// Construct a `Did` from any type that converts into a `String`.
    pub fn new(s: impl Into<String>) -> Self {
        Did(s.into())
    }

    /// Borrow the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Target device / actuator identifier newtype.
///
/// Wrapping `String` in a newtype prevents accidental interchange of arbitrary
/// strings with target IDs at the type level. (CLAIM-4.6)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct TargetId(pub String);

impl TargetId {
    /// Construct a `TargetId` from any type that converts into a `String`.
    pub fn new(s: impl Into<String>) -> Self {
        TargetId(s.into())
    }

    /// Borrow the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ── Device key / signature ─────────────────────────────────────────────────────
// CLAIM-4.8 | _Requirements: PV-3.2_

/// Indicates which signing algorithm was used for a device signature.
///
/// _Requirements: PV-3.2_
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DeviceKeyType {
    /// Edwards-curve Digital Signature Algorithm over Curve25519.
    Ed25519,
    /// Elliptic Curve Digital Signature Algorithm over NIST P-256.
    P256,
}

impl DeviceKeyType {
    /// Returns the canonical string name of the key type.
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceKeyType::Ed25519 => "Ed25519",
            DeviceKeyType::P256 => "P256",
        }
    }
}

/// Device-produced signature.  Variant carries the raw bytes.
///
/// Ed25519 signatures are always exactly 64 bytes.  P-256 signatures are
/// DER-encoded and variable-length (typically 70–72 bytes).
///
/// _Requirements: PV-3.2_
// Manual serde impls below: the `#[derive]` macro cannot serialize `[u8; 64]`
// in no_std mode because serde's const-generic array impls only cover N ≤ 32
// without `std`.  The manual impls store Ed25519 bytes as a sequence of u8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceSignature {
    /// Ed25519 signature — fixed 64-byte array.
    Ed25519([u8; 64]),
    /// P-256 (DER-encoded ECDSA) signature — variable-length bytes.
    P256(Vec<u8>),
}

impl serde::Serialize for DeviceSignature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            DeviceSignature::Ed25519(b) => {
                s.serialize_newtype_variant("DeviceSignature", 0, "Ed25519", b.as_ref())
            }
            DeviceSignature::P256(v) => {
                s.serialize_newtype_variant("DeviceSignature", 1, "P256", v.as_slice())
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for DeviceSignature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use core::fmt;
        use serde::de::{self, EnumAccess, VariantAccess, Visitor};

        struct DeviceSignatureVisitor;

        impl<'de> Visitor<'de> for DeviceSignatureVisitor {
            type Value = DeviceSignature;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a DeviceSignature (Ed25519 or P256)")
            }

            fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
                let (variant, access): (alloc::string::String, _) = data.variant()?;
                match variant.as_str() {
                    "Ed25519" => {
                        let bytes: Vec<u8> = access.newtype_variant()?;
                        if bytes.len() != 64 {
                            return Err(de::Error::invalid_length(
                                bytes.len(),
                                &"exactly 64 bytes for Ed25519 signature",
                            ));
                        }
                        let mut arr = [0u8; 64];
                        arr.copy_from_slice(&bytes);
                        Ok(DeviceSignature::Ed25519(arr))
                    }
                    "P256" => {
                        let bytes: Vec<u8> = access.newtype_variant()?;
                        Ok(DeviceSignature::P256(bytes))
                    }
                    other => Err(de::Error::unknown_variant(other, &["Ed25519", "P256"])),
                }
            }
        }

        d.deserialize_enum(
            "DeviceSignature",
            &["Ed25519", "P256"],
            DeviceSignatureVisitor,
        )
    }
}

impl DeviceSignature {
    /// Returns the [`DeviceKeyType`] that corresponds to this signature variant.
    pub fn key_type(&self) -> DeviceKeyType {
        match self {
            DeviceSignature::Ed25519(_) => DeviceKeyType::Ed25519,
            DeviceSignature::P256(_) => DeviceKeyType::P256,
        }
    }

    /// Returns a byte slice over the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DeviceSignature::Ed25519(b) => b.as_ref(),
            DeviceSignature::P256(v) => v.as_ref(),
        }
    }

    /// Returns the byte length of the signature.
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Returns `true` if the signature contains no bytes.
    ///
    /// For well-formed signatures this is always `false`; the method exists
    /// to satisfy `clippy::len_without_is_empty`.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── units — static UnitDescriptor constants (CLAIM-4.6) ──────────────────────
//
// The integer unit IDs and their `UnitDescriptor` entries are defined in
// `fixed_point.rs` (authoritative source).  This module re-exports them as
// named `UnitDescriptor` constants so callers can write `units::UNIT_DEG_C`
// and get the full descriptor (id + label + dimension) rather than just the
// integer.  The existing top-level re-exports (`UNIT_DEG_C: UnitId`, etc.) are
// preserved for backward compatibility.

/// Static [`UnitDescriptor`] constants for every unit defined in
/// `docs/unit-registry.md` (initial set, IDs 1–12).
///
/// Unit IDs are **append-only**; never renumber or reuse an existing ID.
/// The next available ID is **13**.
pub mod units {
    use super::{UnitDescriptor, UNIT_DESCRIPTORS};

    /// All registered unit descriptors as a static slice, in ID order (0–12).
    /// Use `.iter().find(|u| u.id == id)` for lookup by integer ID.
    pub const ALL_UNITS: &[UnitDescriptor] = UNIT_DESCRIPTORS;

    // Individual constants — each carries the full descriptor (id, label, dimension).

    /// Degrees Celsius — temperature (ID 1).
    pub const UNIT_DEG_C: UnitDescriptor = UNIT_DESCRIPTORS[1];
    /// Pascal — pressure (ID 2).
    pub const UNIT_PA: UnitDescriptor = UNIT_DESCRIPTORS[2];
    /// Revolutions per minute — angular velocity (ID 3).
    pub const UNIT_RPM: UnitDescriptor = UNIT_DESCRIPTORS[3];
    /// Bar — pressure (ID 4).
    pub const UNIT_BAR: UnitDescriptor = UNIT_DESCRIPTORS[4];
    /// Kilowatt — power (ID 5).
    pub const UNIT_KW: UnitDescriptor = UNIT_DESCRIPTORS[5];
    /// Percent — dimensionless ratio (ID 6).
    pub const UNIT_PERCENT: UnitDescriptor = UNIT_DESCRIPTORS[6];
    /// Boolean — dimensionless; mantissa MUST be 0 or 1 (ID 7).
    pub const UNIT_BOOLEAN: UnitDescriptor = UNIT_DESCRIPTORS[7];
    /// Kilopascal — pressure (ID 8).
    pub const UNIT_KPA: UnitDescriptor = UNIT_DESCRIPTORS[8];
    /// Cubic metres per hour — volumetric flow rate (ID 9).
    pub const UNIT_M3H: UnitDescriptor = UNIT_DESCRIPTORS[9];
    /// Volt — electric potential (ID 10).
    pub const UNIT_V: UnitDescriptor = UNIT_DESCRIPTORS[10];
    /// Ampere — electric current (ID 11).
    pub const UNIT_A: UnitDescriptor = UNIT_DESCRIPTORS[11];
    /// Hertz — frequency (ID 12).
    pub const UNIT_HZ: UnitDescriptor = UNIT_DESCRIPTORS[12];
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod command_role_tests {
    use super::CommandRole;

    // All 6 as_str outputs
    #[test]
    fn as_str_command_issuer() {
        assert_eq!(CommandRole::CommandIssuer.as_str(), "CommandIssuer");
    }

    #[test]
    fn as_str_policy_authority() {
        assert_eq!(CommandRole::PolicyAuthority.as_str(), "PolicyAuthority");
    }

    #[test]
    fn as_str_update_signer() {
        assert_eq!(CommandRole::UpdateSigner.as_str(), "UpdateSigner");
    }

    #[test]
    fn as_str_revocation_manager() {
        assert_eq!(CommandRole::RevocationManager.as_str(), "RevocationManager");
    }

    #[test]
    fn as_str_auditor() {
        assert_eq!(CommandRole::Auditor.as_str(), "Auditor");
    }

    #[test]
    fn as_str_time_anchor() {
        assert_eq!(CommandRole::TimeAnchor.as_str(), "TimeAnchor");
    }

    // Round-trip: from_str(role.as_str()) == Some(role) for each variant
    #[test]
    fn roundtrip_all_variants() {
        let variants = [
            CommandRole::CommandIssuer,
            CommandRole::PolicyAuthority,
            CommandRole::UpdateSigner,
            CommandRole::RevocationManager,
            CommandRole::Auditor,
            CommandRole::TimeAnchor,
        ];
        for role in &variants {
            assert_eq!(
                CommandRole::from_str(role.as_str()),
                Some(*role),
                "round-trip failed for {:?}",
                role
            );
        }
    }

    // Unknown string returns None
    #[test]
    fn from_str_unknown_returns_none() {
        assert_eq!(CommandRole::from_str(""), None);
        assert_eq!(CommandRole::from_str("RootKey"), None);
        assert_eq!(CommandRole::from_str("commandissuer"), None); // case-sensitive
        assert_eq!(CommandRole::from_str("COMMANDISSUER"), None);
        assert!("RootKey".parse::<CommandRole>().is_err());
    }

    // can_issue_commands is true only for CommandIssuer
    #[test]
    fn can_issue_commands_only_for_command_issuer() {
        assert!(CommandRole::CommandIssuer.can_issue_commands());
        assert!(!CommandRole::PolicyAuthority.can_issue_commands());
        assert!(!CommandRole::UpdateSigner.can_issue_commands());
        assert!(!CommandRole::RevocationManager.can_issue_commands());
        assert!(!CommandRole::Auditor.can_issue_commands());
        assert!(!CommandRole::TimeAnchor.can_issue_commands());
    }
}

#[cfg(test)]
mod tests {
    // Import the newtypes and type aliases from the crate root.
    use super::{DeltaId, Did, MigrationId, ProfileId, TargetId};
    // Import UnitDescriptor-level constants from the units submodule.
    use super::units;

    // --- Did ---

    #[test]
    fn did_new_and_as_str() {
        let did = Did::new("did:example:abc");
        assert_eq!(did.as_str(), "did:example:abc");
        assert_eq!(did.0, "did:example:abc");
    }

    #[test]
    fn did_clone_eq() {
        let a = Did::new("did:example:1");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn did_newtypes_are_distinct_at_runtime() {
        // Did and TargetId wrap the same string but are different types —
        // the compiler enforces this; this test documents the intent.
        let did = Did::new("sensor-42");
        let tid = TargetId::new("sensor-42");
        assert_eq!(did.as_str(), tid.as_str()); // same inner value
                                                // `did == tid` would be a compile error — that's the point
    }

    // --- TargetId ---

    #[test]
    fn target_id_new_and_as_str() {
        let tid = TargetId::new("pump-01");
        assert_eq!(tid.as_str(), "pump-01");
        assert_eq!(tid.0, "pump-01");
    }

    #[test]
    fn target_id_clone_eq() {
        let a = TargetId::new("chiller-3");
        let b = a.clone();
        assert_eq!(a, b);
    }

    // --- units module — UnitDescriptor constants ---

    #[test]
    fn unit_descriptor_ids_match_registry() {
        assert_eq!(units::UNIT_DEG_C.id, 1);
        assert_eq!(units::UNIT_PA.id, 2);
        assert_eq!(units::UNIT_RPM.id, 3);
        assert_eq!(units::UNIT_BAR.id, 4);
        assert_eq!(units::UNIT_KW.id, 5);
        assert_eq!(units::UNIT_PERCENT.id, 6);
        assert_eq!(units::UNIT_BOOLEAN.id, 7);
        assert_eq!(units::UNIT_KPA.id, 8);
        assert_eq!(units::UNIT_M3H.id, 9);
        assert_eq!(units::UNIT_V.id, 10);
        assert_eq!(units::UNIT_A.id, 11);
        assert_eq!(units::UNIT_HZ.id, 12);
    }

    #[test]
    fn all_units_length() {
        // UNIT_DESCRIPTORS (and thus ALL_UNITS) includes ID 0 (unknown), so 13 entries.
        assert_eq!(units::ALL_UNITS.len(), 13); // IDs 0..=12
    }

    #[test]
    fn all_units_no_duplicate_ids() {
        let mut ids: alloc::vec::Vec<u16> = units::ALL_UNITS.iter().map(|u| u.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), units::ALL_UNITS.len());
    }

    #[test]
    fn unit_descriptors_labels_non_empty() {
        for u in units::ALL_UNITS {
            assert!(!u.label.is_empty(), "unit {} has empty label", u.id);
            assert!(!u.dimension.is_empty(), "unit {} has empty dimension", u.id);
        }
    }

    #[test]
    fn unit_descriptor_is_copy() {
        let u = units::UNIT_DEG_C;
        let v = u; // Copy — no move
        assert_eq!(u.id, v.id);
    }

    // --- Type alias sizes ---

    #[test]
    fn delta_id_is_32_bytes() {
        let id: DeltaId = [0u8; 32];
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn migration_id_is_32_bytes() {
        let id: MigrationId = [0u8; 32];
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn profile_id_is_16_bytes() {
        let id: ProfileId = [0u8; 16];
        assert_eq!(id.len(), 16);
    }

    // --- Serde round-trips (serde_json is a dev-dep; requires std) ---

    extern crate std;

    #[test]
    fn did_serde_roundtrip() {
        let original = Did::new("did:example:roundtrip");
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn target_id_serde_roundtrip() {
        let original = TargetId::new("target-roundtrip-99");
        let json = serde_json::to_string(&original).unwrap();
        let decoded: TargetId = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    // ── DeviceKeyType / DeviceSignature (CLAIM-4.8) ──────────────────────────

    use super::{DeviceKeyType, DeviceSignature};

    #[test]
    fn device_signature_ed25519_key_type() {
        let sig = DeviceSignature::Ed25519([0u8; 64]);
        assert_eq!(sig.key_type(), DeviceKeyType::Ed25519);
    }

    #[test]
    fn device_signature_p256_key_type() {
        let sig = DeviceSignature::P256(alloc::vec![1, 2, 3]);
        assert_eq!(sig.key_type(), DeviceKeyType::P256);
    }

    #[test]
    fn device_signature_ed25519_as_bytes() {
        let bytes = [0xABu8; 64];
        let sig = DeviceSignature::Ed25519(bytes);
        assert_eq!(sig.as_bytes(), &[0xABu8; 64]);
    }

    #[test]
    fn device_signature_p256_as_bytes() {
        let raw = alloc::vec![0x30u8, 0x44, 0x02];
        let sig = DeviceSignature::P256(raw.clone());
        assert_eq!(sig.as_bytes(), raw.as_slice());
    }

    #[test]
    fn device_signature_ed25519_len() {
        let sig = DeviceSignature::Ed25519([0u8; 64]);
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn device_signature_p256_len() {
        let raw = alloc::vec![1u8, 2, 3, 4, 5];
        let sig = DeviceSignature::P256(raw);
        assert_eq!(sig.len(), 5);
    }

    #[test]
    fn device_signature_is_empty_false_for_valid() {
        let sig = DeviceSignature::Ed25519([0u8; 64]);
        assert!(!sig.is_empty());
    }

    #[test]
    fn device_signature_p256_empty_vec_is_empty() {
        let sig = DeviceSignature::P256(alloc::vec![]);
        assert!(sig.is_empty());
    }

    #[test]
    fn device_key_type_as_str() {
        assert_eq!(DeviceKeyType::Ed25519.as_str(), "Ed25519");
        assert_eq!(DeviceKeyType::P256.as_str(), "P256");
    }

    #[test]
    fn device_key_type_copy() {
        let kt = DeviceKeyType::Ed25519;
        let kt2 = kt; // Copy — no move
        assert_eq!(kt, kt2);
    }

    #[test]
    fn device_signature_ed25519_serde_roundtrip() {
        let original = DeviceSignature::Ed25519([0x42u8; 64]);
        let json = serde_json::to_string(&original).unwrap();
        let decoded: DeviceSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn device_signature_p256_serde_roundtrip() {
        let original = DeviceSignature::P256(alloc::vec![0x30, 0x44, 0x02, 0x20]);
        let json = serde_json::to_string(&original).unwrap();
        let decoded: DeviceSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn device_key_type_serde_roundtrip() {
        let original = DeviceKeyType::P256;
        let json = serde_json::to_string(&original).unwrap();
        let decoded: DeviceKeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
