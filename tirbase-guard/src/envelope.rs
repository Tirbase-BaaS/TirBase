//! Envelope profile installation, validation, and target-to-profile hot-swap
//! (10.6 — CLAIM-10.4…CLAIM-10.6, PV-4.5, INV-1).
//!
//! `EnvelopeProfile` data types live in [`tirbase_types::envelope`]. This
//! module provides the **production** install path: verify the
//! `PolicyAuthority` signature against the active trust root, validate the
//! profile against a [`DeviceModel`], and hot-swap it into the per-target
//! profile map used by the guard.

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use ciborium::ser::into_writer;
use sha2::{Digest, Sha256};
use tirbase_types::envelope::{DeviceModel, EnvelopeProfile, ParameterKind};
use tirbase_types::{CommandRole, FixedPointValue, TargetId};

use crate::signed_operation::CONTEXT_ENVELOPE_PROFILE;
use crate::trust_root::{TrustRootError, TrustRootRecord};

/// Errors from profile installation / validation (CLAIM-10.4, CLAIM-10.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileInstallError {
 /// The profile signature did not verify against an authorised
 /// `PolicyAuthority` key in the active trust root (CLAIM-10.4).
    SignatureNotAuthorized {
        signer_did: Option<String>,
        detail: String,
    },
 /// Trust-root / role-registry error while checking the signer.
    TrustRoot(TrustRootError),
 /// Field-level validation failure against the device model (CLAIM-10.6).
    Validation(Vec<FieldError>),
 /// Profile/device class mismatch.
    DeviceClassMismatch { profile: String, device: String },
}

/// A single field-level validation error (CLAIM-10.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
 /// Parameter name, or `"profile"` for profile-level issues.
    pub field: String,
 /// Human-readable reason.
    pub message: String,
}

impl FieldError {
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        FieldError {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl From<TrustRootError> for ProfileInstallError {
    fn from(e: TrustRootError) -> Self {
        ProfileInstallError::TrustRoot(e)
    }
}

/// Domain-separated signing bytes for an [`EnvelopeProfile`] body.
///
/// `CONTEXT_ENVELOPE_PROFILE || 0x00 || SHA-256(CBOR(body))`
pub fn profile_signing_bytes(profile: &EnvelopeProfile) -> Vec<u8> {
    let mut body_bytes = Vec::new();
    into_writer(&profile.body(), &mut body_bytes)
        .expect("EnvelopeProfile body CBOR serialization must not fail");
    let hash = Sha256::digest(&body_bytes);
    let mut out = Vec::with_capacity(CONTEXT_ENVELOPE_PROFILE.len() + 1 + hash.len());
    out.extend_from_slice(CONTEXT_ENVELOPE_PROFILE.as_bytes());
    out.push(0);
    out.extend_from_slice(&hash);
    out
}

/// Verify that `profile.signature` was produced by a DID registered as an
/// authorised `PolicyAuthority` in `trust_root` (CLAIM-10.4).
///
/// The role registry check runs **before** trusting the signature result, and
/// the signature is verified against the registered public key (PV-3.2/PV-3.3).
/// Accepting a profile signed by a non-PolicyAuthority (or unregistered) key
/// returns [`ProfileInstallError::SignatureNotAuthorized`] /
/// [`ProfileInstallError::TrustRoot`].
pub fn verify_profile_signature(
    profile: &EnvelopeProfile,
    trust_root: &TrustRootRecord,
) -> Result<String, ProfileInstallError> {
    let policy = trust_root.role_policy(CommandRole::PolicyAuthority).ok_or(
        ProfileInstallError::TrustRoot(TrustRootError::RoleNotConfigured {
            role: CommandRole::PolicyAuthority,
        }),
    )?;
    let message = profile_signing_bytes(profile);
    for signer in &policy.authorized_signers {
 // Registry gate + signature verification (PV-3.2/PV-3.3).
        if trust_root
            .verify_role_cosignature(
                CommandRole::PolicyAuthority,
                &signer.did,
                &message,
                &profile.signature,
            )
            .is_ok()
        {
            return Ok(signer.did.clone());
        }
    }
    Err(ProfileInstallError::SignatureNotAuthorized {
        signer_did: None,
        detail: "profile signature did not verify against any authorised PolicyAuthority key"
            .to_string(),
    })
}

/// Compare two [`FixedPointValue`]s in the same unit by normalising to the
/// finest (most negative) exponent. Returns `None` on unit mismatch or
/// unrepresentable scale.
fn compare_fpv(a: &FixedPointValue, b: &FixedPointValue) -> Option<std::cmp::Ordering> {
    if a.unit_id != b.unit_id {
        return None;
    }
    let common = a.exponent.min(b.exponent);
    let scale = |m: i64, e: i8| -> Option<i128> {
        let delta = (e as i16 - common as i16) as u32;
        if delta > 38 {
            return None;
        }
        let mut s: i128 = 1;
        for _ in 0..delta {
            s = s.checked_mul(10)?;
        }
        (m as i128).checked_mul(s)
    };
    Some(scale(a.mantissa, a.exponent)?.cmp(&scale(b.mantissa, b.exponent)?))
}

/// Validate an [`EnvelopeProfile`] against a [`DeviceModel`] (CLAIM-10.6).
///
/// Checks, per parameter in the profile:
/// 1. parameter exists in the device model,
/// 2. `unit_id` matches,
/// 3. range `[param.min, param.max]` is contained within the device model range
/// (for `Range` kinds),
/// 4. device parameter is writable.
///
/// Also rejects an empty device model (PV-10.2) and device-class mismatch.
/// Returns all field-level errors found.
pub fn validate_profile(
    profile: &EnvelopeProfile,
    device_model: &DeviceModel,
) -> Result<(), ProfileInstallError> {
    let mut errors: Vec<FieldError> = Vec::new();

    if device_model.parameters.is_empty() {
        errors.push(FieldError::new(
            "device_model.parameters",
            "DeviceModel must have at least one parameter (PV-10.2)",
        ));
    }
    if profile.device_class != device_model.device_class {
        return Err(ProfileInstallError::DeviceClassMismatch {
            profile: profile.device_class.clone(),
            device: device_model.device_class.clone(),
        });
    }

    for param in &profile.parameters {
        let Some(dm) = device_model.parameter(&param.name) else {
            errors.push(FieldError::new(
                &param.name,
                "parameter not present in DeviceModel",
            ));
            continue;
        };
        if param.unit_id != dm.unit_id {
            errors.push(FieldError::new(
                &param.name,
                format!(
                    "unit_id mismatch: profile has {}, device model has {}",
                    param.unit_id, dm.unit_id
                ),
            ));
        }
        if !dm.writable {
            errors.push(FieldError::new(
                &param.name,
                "parameter is not writable in DeviceModel",
            ));
        }
        if let ParameterKind::Range { min, max } = &param.kind {
            let dm_min = &dm.range[0];
            let dm_max = &dm.range[1];
            match (compare_fpv(min, dm_min), compare_fpv(max, dm_max)) {
                (Some(min_cmp), Some(max_cmp)) => {
 // profile [min,max] must be ⊆ device [dm_min,dm_max]
                    if min_cmp == std::cmp::Ordering::Less {
                        errors.push(FieldError::new(
                            &param.name,
                            format!("range min {:?} is below DeviceModel min {:?}", min, dm_min),
                        ));
                    }
                    if max_cmp == std::cmp::Ordering::Greater {
                        errors.push(FieldError::new(
                            &param.name,
                            format!("range max {:?} is above DeviceModel max {:?}", max, dm_max),
                        ));
                    }
                }
                _ => {
                    errors.push(FieldError::new(
                        &param.name,
                        "range/unit comparison failed (unit mismatch or scale overflow)",
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ProfileInstallError::Validation(errors))
    }
}

// ── 10.5 Target-to-profile map with hot-swap ─────────────────────────────────

/// Per-target envelope profiles with lock-free hot-swap (CLAIM-10.5, PV-4.5).
///
/// Uses `BTreeMap` (deterministic iteration; `HashMap` is banned in guard/sim
/// by 38.7) mapping each [`TargetId`] to an `Arc<ArcSwap<EnvelopeProfile>>` so
/// readers take a snapshot without blocking writers.
#[derive(Clone, Default)]
pub struct ProfileMap {
    inner: Arc<BTreeMap<TargetId, Arc<ArcSwap<EnvelopeProfile>>>>,
}

impl ProfileMap {
 /// An empty profile map.
    pub fn new() -> Self {
        Self::default()
    }

 /// Build a map from an initial set of target/profile pairs.
    pub fn from_profiles(entries: impl IntoIterator<Item = (TargetId, EnvelopeProfile)>) -> Self {
        let mut map = BTreeMap::new();
        for (target, profile) in entries {
            map.insert(target, Arc::new(ArcSwap::from_pointee(profile)));
        }
        ProfileMap {
            inner: Arc::new(map),
        }
    }

 /// Load the current profile for `target`, if installed.
    pub fn load(&self, target: &TargetId) -> Option<Arc<EnvelopeProfile>> {
        self.inner.get(target).map(|cell| cell.load_full())
    }

 /// Hot-swap the profile for `target`. Returns `false` if the target is not
 /// present in the map (use [`Self::with_profile`] to add targets).
    pub fn swap(&self, target: &TargetId, profile: EnvelopeProfile) -> bool {
        if let Some(cell) = self.inner.get(target) {
            cell.store(Arc::new(profile));
            true
        } else {
            false
        }
    }

 /// Return a new map with `target` installed or replaced. (The map itself is
 /// rebuilt; hot-swap of an *existing* target uses [`Self::swap`].)
    pub fn with_profile(&self, target: TargetId, profile: EnvelopeProfile) -> Self {
        let mut map = (*self.inner).clone();
        map.insert(target, Arc::new(ArcSwap::from_pointee(profile)));
        ProfileMap {
            inner: Arc::new(map),
        }
    }
}

// ── 10.6 Install path (production caller) ────────────────────────────────────

/// Install-time profile installation: verify `PolicyAuthority` signature, then
/// validate against the device model (CLAIM-10.4, CLAIM-10.6).
///
/// On success returns the verified signer DID. The caller (gateway/guard) is
/// responsible for placing the profile into the [`ProfileMap`] for its target.
pub fn install_profile(
    profile: &EnvelopeProfile,
    device_model: &DeviceModel,
    trust_root: &TrustRootRecord,
) -> Result<String, ProfileInstallError> {
 // 1. Signature / role gate (CLAIM-10.4) — reject non-PolicyAuthority.
    let signer = verify_profile_signature(profile, trust_root)?;
 // 2. Field-level validation against device model (CLAIM-10.6).
    validate_profile(profile, device_model)?;
    Ok(signer)
}

// suppress unused import warning in builds that don't exercise the helper path
