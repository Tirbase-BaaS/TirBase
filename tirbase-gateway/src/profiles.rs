//! EnvelopeProfile TOML loading and schema validation (CLAIM-34.5, PV-10.6).
//!
//! Production caller: profile install path in `tirbase-gateway` (admin/config).

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use tirbase_guard::envelope::{install_profile, profile_signing_bytes};
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_guard::{DeviceModel, DeviceParameter, EnvelopeProfile, ParameterKind, ParameterSpec};
use tirbase_types::{CommandRole, DeviceSignature, FixedPointValue, UnitId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileTomlError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ProfileTomlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "profile field '{}': {}", self.field, self.message)
    }
}
impl std::error::Error for ProfileTomlError {}

#[derive(Debug, Deserialize)]
struct FpvToml {
    mantissa: i64,
    exponent: i8,
    unit_id: UnitId,
}
impl FpvToml {
    fn into_fpv(self) -> FixedPointValue {
        FixedPointValue::new(self.mantissa, self.exponent, self.unit_id)
    }
}
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum KindToml {
    Range { min: FpvToml, max: FpvToml },
    Bool,
}
#[derive(Debug, Deserialize)]
struct ParamToml {
    name: String,
    unit_id: UnitId,
    canonical_exponent: i8,
    kind: KindToml,
    max_rate_per_sec: FpvToml,
    dwell_secs: u32,
    #[serde(default)]
    min_off_secs: u32,
    drift_window_secs: u32,
    max_delta_in_window: FpvToml,
    safe_default: FpvToml,
    tightening_floor: FpvToml,
    #[serde(default)]
    critical: bool,
}
#[derive(Debug, Deserialize)]
struct ProfileToml {
    profile_id: String,
    version: u64,
    device_class: String,
    #[serde(default)]
    policy_loosen_m: u8,
    #[serde(default)]
    policy_loosen_n: u8,
    #[serde(default)]
    policy_timelock_secs: u32,
    #[serde(default)]
    policy_cancel_window_secs: u32,
    #[serde(default)]
    signature_hex: String,
    #[serde(default)]
    parameters: Vec<ParamToml>,
}

fn parse_profile_id(s: &str) -> Result<[u8; 16], ProfileTomlError> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(ProfileTomlError {
            field: "profile_id".into(),
            message: "expected 16-byte hex/uuid".into(),
        });
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| ProfileTomlError {
            field: "profile_id".into(),
            message: "invalid hex".into(),
        })?;
    }
    Ok(out)
}

fn parse_signature(hex_s: &str) -> Result<DeviceSignature, ProfileTomlError> {
    if hex_s.trim().is_empty() {
        return Ok(DeviceSignature::Ed25519([0u8; 64]));
    }
    let hex: String = hex_s.chars().filter(|c| !c.is_whitespace()).collect();
    if hex.len() != 128 {
        return Err(ProfileTomlError {
            field: "signature_hex".into(),
            message: "expected 64-byte Ed25519 hex signature".into(),
        });
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| ProfileTomlError {
            field: "signature_hex".into(),
            message: "invalid hex".into(),
        })?;
    }
    Ok(DeviceSignature::Ed25519(out))
}

pub fn parse_profile_toml(input: &str) -> Result<EnvelopeProfile, ProfileTomlError> {
    let doc: ProfileToml = toml::from_str(input).map_err(|e| {
        // Try to surface field-level messages from toml errors.
        let msg = e.to_string();
        let field = msg
            .split_whitespace()
            .find(|w| {
                [
                    "profile_id",
                    "version",
                    "device_class",
                    "parameters",
                    "kind",
                    "name",
                    "unit_id",
                ]
                .contains(w)
            })
            .unwrap_or("toml")
            .to_string();
        ProfileTomlError {
            field,
            message: msg,
        }
    })?;
    if doc.device_class.trim().is_empty() {
        return Err(ProfileTomlError {
            field: "device_class".into(),
            message: "must not be empty".into(),
        });
    }
    if doc.parameters.is_empty() {
        return Err(ProfileTomlError {
            field: "parameters".into(),
            message: "at least one parameter is required".into(),
        });
    }
    let profile_id = parse_profile_id(&doc.profile_id)?;
    let signature = parse_signature(&doc.signature_hex)?;
    let mut parameters = Vec::with_capacity(doc.parameters.len());
    for (i, p) in doc.parameters.into_iter().enumerate() {
        if p.name.trim().is_empty() {
            return Err(ProfileTomlError {
                field: format!("parameters[{i}].name"),
                message: "must not be empty".into(),
            });
        }
        let kind = match p.kind {
            KindToml::Range { min, max } => ParameterKind::Range {
                min: min.into_fpv(),
                max: max.into_fpv(),
            },
            KindToml::Bool => ParameterKind::Bool,
        };
        parameters.push(ParameterSpec {
            name: p.name,
            unit_id: p.unit_id,
            canonical_exponent: p.canonical_exponent,
            kind,
            max_rate_per_sec: p.max_rate_per_sec.into_fpv(),
            dwell_secs: p.dwell_secs,
            min_off_secs: p.min_off_secs,
            drift_window_secs: p.drift_window_secs,
            max_delta_in_window: p.max_delta_in_window.into_fpv(),
            safe_default: p.safe_default.into_fpv(),
            tightening_floor: p.tightening_floor.into_fpv(),
            critical: p.critical,
        });
    }
    Ok(EnvelopeProfile {
        profile_id,
        version: doc.version,
        device_class: doc.device_class,
        parameters,
        cross_constraints: Vec::new(),
        policy_loosen_m: if doc.policy_loosen_m == 0 {
            2
        } else {
            doc.policy_loosen_m
        },
        policy_loosen_n: if doc.policy_loosen_n == 0 {
            3
        } else {
            doc.policy_loosen_n
        },
        policy_timelock_secs: doc.policy_timelock_secs,
        policy_cancel_window_secs: doc.policy_cancel_window_secs,
        signature,
    })
}

pub fn load_profile_from_path(path: &Path) -> Result<EnvelopeProfile, ProfileTomlError> {
    let body = std::fs::read_to_string(path).map_err(|e| ProfileTomlError {
        field: "path".into(),
        message: format!("{}: {e}", path.display()),
    })?;
    parse_profile_toml(&body)
}

/// Production install path (CLAIM-34.5): parse TOML, optionally sign/verify, and
/// validate against device model via task 10.6 path.
pub fn install_profile_toml(
    toml: &str,
    device_model: &DeviceModel,
    trust_root: &TrustRootRecord,
) -> Result<EnvelopeProfile, String> {
    let profile = parse_profile_toml(toml).map_err(|e| e.to_string())?;
    install_profile(&profile, device_model, trust_root).map_err(|e| format!("{e:?}"))?;
    Ok(profile)
}

/// Helper to build a PA-signed test profile from parsed TOML (test use).
pub fn sign_parsed_profile(
    mut profile: EnvelopeProfile,
    pa: &tirbase_core::identity::file_key_provider::InMemoryKeyProvider,
) -> EnvelopeProfile {
    use tirbase_core::traits::KeyProvider;
    profile.signature = pa
        .sign(&profile_signing_bytes(&profile))
        .unwrap_or(DeviceSignature::Ed25519([0u8; 64]));
    profile
}

pub fn pa_trust_root(pa_did: &str, pa_pk: Vec<u8>) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: pa_did.to_string(),
                public_key: pa_pk,
            }],
        ),
    );
    TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![vec![1; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    }
}

pub fn cold_room_device_model() -> DeviceModel {
    DeviceModel {
        device_class: "cold_room".to_string(),
        parameters: vec![DeviceParameter {
            name: "setpoint_c".to_string(),
            unit_id: 1,
            unit_label: "degC".to_string(),
            range: [
                FixedPointValue::new(-400, -1, 1),
                FixedPointValue::new(150, -1, 1),
            ],
            writable: true,
        }],
    }
}
