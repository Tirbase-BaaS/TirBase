// SPDX-License-Identifier: Apache-2.0

//! OTA update bundle, release channel, compatibility, and version-skew types.
//!
//! These types are the shared wire/validation surface for F-11: signed update
//! bundles, release channels (including tenant-pinned), component compatibility
//! metadata, and typed version-skew errors.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Component whose version participates in OTA compatibility and skew checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtaComponent {
    Gateway,
    Guard,
    Driver,
    Sdk,
}

impl OtaComponent {
    pub const ALL: [OtaComponent; 4] = [
        OtaComponent::Gateway,
        OtaComponent::Guard,
        OtaComponent::Driver,
        OtaComponent::Sdk,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            OtaComponent::Gateway => "gateway",
            OtaComponent::Guard => "guard",
            OtaComponent::Driver => "driver",
            OtaComponent::Sdk => "sdk",
        }
    }
}

/// Release channel for an update bundle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReleaseChannel {
    Dev,
    Staging,
    Pilot,
    Production,
    /// Tenant-pinned channel: only devices/clients bound to `tenant_id` may
    /// consume this bundle.
    TenantPinned { tenant_id: String },
}

impl ReleaseChannel {
    pub fn as_str(&self) -> &str {
        match self {
            ReleaseChannel::Dev => "dev",
            ReleaseChannel::Staging => "staging",
            ReleaseChannel::Pilot => "pilot",
            ReleaseChannel::Production => "production",
            ReleaseChannel::TenantPinned { .. } => "tenant_pinned",
        }
    }
}

/// Declares the component versions a bundle provides and the peer versions it
/// is compatible with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OtaCompatibility {
    /// Concrete version shipped for each component contained in the bundle.
    #[serde(default)]
    pub component_versions: BTreeMap<OtaComponent, String>,
    /// Inclusive minimum compatible version required of each peer component.
    /// A peer whose version is lower receives a typed skew error instead of a
    /// successful negotiation.
    #[serde(default)]
    pub min_compatible: BTreeMap<OtaComponent, String>,
    /// Inclusive maximum compatible version accepted for each peer component.
    /// A peer whose version is higher than a declared ceiling receives a typed
    /// skew error instead of a successful negotiation.
    #[serde(default)]
    pub max_compatible: BTreeMap<OtaComponent, String>,
}

/// Unsigned OTA bundle body. The signature covers the canonical bytes of this
/// structure (domain-separated) so any tampering — including channel, version,
/// artifact hash, or compatibility metadata — is detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtaBundleBody {
    /// Monotonically increasing bundle version for a given component/artifact
    /// stream. Used for anti-downgrade and anti-rollback checks.
    pub bundle_version: u64,
    /// Human-readable release version (e.g. "1.4.2").
    pub release_version: String,
    /// Release channel this bundle belongs to.
    pub channel: ReleaseChannel,
    /// SHA-256 hash of the artifact payload (hex, 32 bytes / 64 chars).
    pub artifact_hash_sha256_hex: String,
    /// Size of the artifact payload in bytes (integrity/transport hint).
    pub artifact_size: u64,
    /// Compatibility and skew rules.
    pub compatibility: OtaCompatibility,
    /// Optional opaque metadata (build id, notes). Not interpreted by the
    /// verifier but covered by the signature.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Ed25519-signed OTA update bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOtaBundle {
    pub body: OtaBundleBody,
    /// DID of the update signer.
    pub signer_did: String,
    /// Hex-encoded Ed25519 signature (64 bytes).
    pub signature_hex: String,
}

/// Typed errors produced when a peer/client/component version is incompatible
/// with the active or requested bundle. Callers must surface this as a typed
/// error and MUST NOT continue with a partially-applied or corrupted state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VersionSkewError {
    /// A peer component is below the minimum compatible version.
    BelowMinimum {
        component: OtaComponent,
        peer_version: String,
        minimum_required: String,
    },
    /// A peer component is above the maximum compatible version declared by the
    /// bundle/protocol.
    AboveMaximum {
        component: OtaComponent,
        peer_version: String,
        maximum_supported: String,
    },
    /// The peer did not report a version for a component whose version is
    /// required to establish compatibility.
    MissingVersion { component: OtaComponent },
    /// The peer reported a version string that cannot be compared.
    InvalidVersion {
        component: OtaComponent,
        peer_version: String,
        detail: String,
    },
}

impl core::fmt::Display for VersionSkewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VersionSkewError::BelowMinimum {
                component,
                peer_version,
                minimum_required,
            } => write!(
                f,
                "version skew: {} {} is below minimum compatible {}",
                component.as_str(),
                peer_version,
                minimum_required
            ),
            VersionSkewError::AboveMaximum {
                component,
                peer_version,
                maximum_supported,
            } => write!(
                f,
                "version skew: {} {} is above maximum compatible {}",
                component.as_str(),
                peer_version,
                maximum_supported
            ),
            VersionSkewError::MissingVersion { component } => write!(
                f,
                "version skew: missing version for {}",
                component.as_str()
            ),
            VersionSkewError::InvalidVersion {
                component,
                peer_version,
                detail,
            } => write!(
                f,
                "version skew: invalid {} version '{}': {}",
                component.as_str(),
                peer_version,
                detail
            ),
        }
    }
}

/// Parse a dotted numeric version (`major.minor.patch`, with missing trailing
/// components treated as 0) into a comparable tuple.
pub fn parse_version(v: &str) -> Result<(u64, u64, u64), String> {
    let trimmed = v.trim();
    if trimmed.is_empty() {
        return Err("empty version".to_string());
    }
    let mut parts = trimmed.split('.');
    let major = parse_component(parts.next().unwrap_or("0"))?;
    let minor = parts.next().map(parse_component).transpose()?.unwrap_or(0);
    let patch = parts.next().map(parse_component).transpose()?.unwrap_or(0);
    if parts.next().is_some() {
        // Accept but ignore further components (build metadata handled outside).
    }
    Ok((major, minor, patch))
}

fn parse_component(part: &str) -> Result<u64, String> {
    // Allow pre-release/build suffixes by taking the leading numeric prefix.
    let numeric: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
    if numeric.is_empty() {
        return Err(alloc::format!("non-numeric version component '{part}'"));
    }
    numeric
        .parse::<u64>()
        .map_err(|e| alloc::format!("invalid version component '{part}': {e}"))
}

/// Compare dotted numeric versions.
pub fn compare_versions(a: &str, b: &str) -> Result<core::cmp::Ordering, String> {
    Ok(parse_version(a)?.cmp(&parse_version(b)?))
}

/// Evaluate compatibility of a set of peer component versions against declared
/// `min_compatible`/`max_compatible` rules. Returns the first typed skew error
/// found, or `Ok(())` if compatible.
///
/// A rule is enforced only when a bound is declared for that component. If a
/// bound is declared, the peer MUST report a comparable version.
pub fn check_version_skew(
    peer_versions: &BTreeMap<OtaComponent, String>,
    compatibility: &OtaCompatibility,
) -> Result<(), VersionSkewError> {
    for component in OtaComponent::ALL {
        let min = compatibility.min_compatible.get(&component);
        let max = compatibility.max_compatible.get(&component);
        if min.is_none() && max.is_none() {
            continue;
        }
        let peer = peer_versions
            .get(&component)
            .ok_or(VersionSkewError::MissingVersion { component })?;
        if let Some(min_v) = min {
            match compare_versions(peer, min_v) {
                Ok(core::cmp::Ordering::Less) => {
                    return Err(VersionSkewError::BelowMinimum {
                        component,
                        peer_version: peer.clone(),
                        minimum_required: min_v.clone(),
                    })
                }
                Ok(_) => {}
                Err(detail) => {
                    return Err(VersionSkewError::InvalidVersion {
                        component,
                        peer_version: peer.clone(),
                        detail,
                    })
                }
            }
        }
        if let Some(max_v) = max {
            match compare_versions(peer, max_v) {
                Ok(core::cmp::Ordering::Greater) => {
                    return Err(VersionSkewError::AboveMaximum {
                        component,
                        peer_version: peer.clone(),
                        maximum_supported: max_v.clone(),
                    })
                }
                Ok(_) => {}
                Err(detail) => {
                    return Err(VersionSkewError::InvalidVersion {
                        component,
                        peer_version: peer.clone(),
                        detail,
                    })
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;

    #[test]
    fn parse_and_compare_versions() {
        assert_eq!(parse_version("1.2.3").unwrap(), (1, 2, 3));
        assert_eq!(parse_version("2.0").unwrap(), (2, 0, 0));
        assert_eq!(parse_version("3").unwrap(), (3, 0, 0));
        assert_eq!(compare_versions("1.2.3", "1.2.4").unwrap(), core::cmp::Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.9.9").unwrap(), core::cmp::Ordering::Greater);
    }

    #[test]
    fn skew_below_minimum_is_typed() {
        let mut peer = BTreeMap::new();
        peer.insert(OtaComponent::Sdk, "1.0.0".to_string());
        let compat = OtaCompatibility {
            min_compatible: BTreeMap::from([(OtaComponent::Sdk, "1.1.0".to_string())]),
            ..Default::default()
        };
        let err = check_version_skew(&peer, &compat).unwrap_err();
        assert!(matches!(err, VersionSkewError::BelowMinimum { .. }));
    }

    #[test]
    fn skew_above_maximum_is_typed() {
        let mut peer = BTreeMap::new();
        peer.insert(OtaComponent::Gateway, "3.0.0".to_string());
        let compat = OtaCompatibility {
            max_compatible: BTreeMap::from([(OtaComponent::Gateway, "2.9.9".to_string())]),
            ..Default::default()
        };
        let err = check_version_skew(&peer, &compat).unwrap_err();
        assert!(matches!(err, VersionSkewError::AboveMaximum { .. }));
    }

    #[test]
    fn missing_version_for_bound_component_is_typed() {
        let peer = BTreeMap::new();
        let compat = OtaCompatibility {
            min_compatible: BTreeMap::from([(OtaComponent::Driver, "1.0.0".to_string())]),
            ..Default::default()
        };
        let err = check_version_skew(&peer, &compat).unwrap_err();
        assert_eq!(err, VersionSkewError::MissingVersion { component: OtaComponent::Driver });
    }
}
