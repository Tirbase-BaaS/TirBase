// SPDX-License-Identifier: AGPL-3.0-only

//! Biscuit-backed operator capabilities (F-03).
//!
//! Capabilities are Biscuit tokens signed by the operator authority key. The
//! authority block carries the effective [`OperatorCapability`] as a JSON fact.
//! Attenuation and delegation produce derived tokens whose effective scope is
//! strictly narrower than the parent (never wider). Verification enforces:
//! signature, expiry, tenant/permission/scope consistency, delegation rules, and
//! revocation on every request.

use std::collections::BTreeSet;
use std::time::{Duration, UNIX_EPOCH};

use biscuit_auth::{
    builder::{date, fact, Algorithm},
    builder_ext::{AuthorizerExt, BuilderExt},
    AuthorizerBuilder, Biscuit, KeyPair, PrivateKey, PublicKey,
};
use serde::{Deserialize, Serialize};
use tirbase_types::identity::{
    CapabilityScope, DelegationConstraints, OperatorCapability, OperatorPermission, OperatorRole,
    TenantPath, Vertical,
};

use crate::errors::TirBaseError;

/// Result of a successful capability verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedCapability {
    /// Effective (possibly attenuated/delegated) capability.
    pub capability: OperatorCapability,
    /// Whether this capability was derived (attenuated or delegated) from a
    /// parent capability token rather than directly issued.
    pub derived: bool,
    /// Parent capability id when derived.
    pub parent_capability_id: Option<String>,
}

/// Verification inputs for revocation checks.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityVerification<'a> {
    /// Capability ids that have been revoked.
    pub revoked_capability_ids: &'a BTreeSet<String>,
    /// Principal ids that have been revoked.
    pub revoked_principal_ids: &'a BTreeSet<String>,
    /// Current time (Unix seconds).
    pub now_secs: i64,
}

impl<'a> CapabilityVerification<'a> {
    /// Construct verification inputs.
    pub fn new(
        revoked_capability_ids: &'a BTreeSet<String>,
        revoked_principal_ids: &'a BTreeSet<String>,
        now_secs: i64,
    ) -> Self {
        Self {
            revoked_capability_ids,
            revoked_principal_ids,
            now_secs,
        }
    }
}

/// Internal wire claims stored in the Biscuit token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CapabilityClaims {
    capability: OperatorCapability,
    derived: bool,
    parent_capability_id: Option<String>,
}

/// Issue a root capability token signed by the authority key.
pub fn issue_capability_token(
    capability: &OperatorCapability,
    authority_private_key: &[u8],
) -> Result<Vec<u8>, TirBaseError> {
    let claims = CapabilityClaims {
        capability: capability.clone(),
        derived: false,
        parent_capability_id: None,
    };
    mint_token(&claims, authority_private_key)
}

/// Attenuate a capability to a strictly narrower scope.
///
/// The caller must present the parent token; the derived token is signed by the
/// same authority key and is valid only if `narrowed` is not wider than the
/// parent's effective scope. Delegation permission is not required for
/// attenuation performed by the holder for their own use, but the scope must
/// still narrow.
pub fn attenuate_capability_token(
    parent_token: &[u8],
    narrowed: &OperatorCapability,
    authority_private_key: &[u8],
    authority_public_key: &[u8],
    revocation: &CapabilityVerification<'_>,
) -> Result<Vec<u8>, TirBaseError> {
    let parent = verify_capability_token(parent_token, authority_public_key, revocation)?;
    ensure_not_wider(&parent.capability, narrowed, "attenuation")?;
    let claims = CapabilityClaims {
        capability: narrowed.clone(),
        derived: true,
        parent_capability_id: Some(parent.capability.capability_id.clone()),
    };
    mint_token(&claims, authority_private_key)
}

/// Delegate a capability to another principal within the delegator's scope.
///
/// Delegation requires the parent to be delegatable, have remaining depth, and
/// the delegated capability must be strictly non-widening.
pub fn delegate_capability_token(
    parent_token: &[u8],
    delegated: &OperatorCapability,
    authority_private_key: &[u8],
    authority_public_key: &[u8],
    revocation: &CapabilityVerification<'_>,
) -> Result<Vec<u8>, TirBaseError> {
    let parent = verify_capability_token(parent_token, authority_public_key, revocation)?;
    if !parent.capability.delegation.delegatable || parent.capability.delegation.max_depth == 0 {
        return Err(TirBaseError::AuthorisationFailed {
            reason: "capability is not delegatable".to_string(),
        });
    }
    if delegated.delegation.max_depth >= parent.capability.delegation.max_depth {
        return Err(TirBaseError::AuthorisationFailed {
            reason: "delegation cannot increase or preserve delegation depth".to_string(),
        });
    }
    ensure_not_wider(&parent.capability, delegated, "delegation")?;
    let claims = CapabilityClaims {
        capability: delegated.clone(),
        derived: true,
        parent_capability_id: Some(parent.capability.capability_id.clone()),
    };
    mint_token(&claims, authority_private_key)
}

/// Verify a capability token and enforce expiry, revocation, and scope sanity.
pub fn verify_capability_token(
    token_bytes: &[u8],
    authority_public_key: &[u8],
    revocation: &CapabilityVerification<'_>,
) -> Result<VerifiedCapability, TirBaseError> {
    let public_key = PublicKey::from_bytes(authority_public_key, Algorithm::Ed25519).map_err(
        |e| TirBaseError::AuthorisationFailed {
            reason: format!("invalid capability authority public key: {e}"),
        },
    )?;
    let token = Biscuit::from(token_bytes, public_key).map_err(|e| {
        TirBaseError::AuthorisationFailed {
            reason: format!("capability token signature/parse failed: {e}"),
        }
    })?;

    let now = UNIX_EPOCH + Duration::from_secs(revocation.now_secs.max(0) as u64);
    let time_fact = fact("time", &[date(&now)]);
    let mut authorizer = AuthorizerBuilder::new()
        .fact(time_fact)
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("capability authorizer build error: {e}"),
        })?
        .allow_all()
        .build(&token)
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("capability authorizer construction failed: {e}"),
        })?;

    let limits = biscuit_auth::AuthorizerLimits {
        max_facts: 10_000,
        max_iterations: 10_000,
        max_time: Duration::from_secs(5),
    };
    authorizer.authorize_with_limits(limits.clone()).map_err(|e| {
        TirBaseError::AuthorisationFailed {
            reason: format!("capability authorization failed (possibly expired): {e}"),
        }
    })?;

    let claims_json: Vec<(String,)> = authorizer
        .query_with_limits("data($c) <- operator_capability($c)", limits)
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("capability claims query failed: {e}"),
        })?;
    let claims_str = claims_json
        .into_iter()
        .next()
        .map(|(c,)| c)
        .ok_or_else(|| TirBaseError::AuthorisationFailed {
            reason: "capability token missing operator_capability fact".to_string(),
        })?;
    let claims: CapabilityClaims =
        serde_json::from_str(&claims_str).map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("capability claims malformed: {e}"),
        })?;

    if revocation.now_secs > claims.capability.scope.expires_at {
        return Err(TirBaseError::AuthorisationFailed {
            reason: "capability expired".to_string(),
        });
    }
    if revocation
        .revoked_capability_ids
        .contains(&claims.capability.capability_id)
    {
        return Err(TirBaseError::AuthorisationFailed {
            reason: "capability revoked".to_string(),
        });
    }
    if revocation
        .revoked_principal_ids
        .contains(&claims.capability.subject.id)
    {
        return Err(TirBaseError::AuthorisationFailed {
            reason: "principal revoked".to_string(),
        });
    }

    Ok(VerifiedCapability {
        capability: claims.capability,
        derived: claims.derived,
        parent_capability_id: claims.parent_capability_id,
    })
}

fn mint_token(
    claims: &CapabilityClaims,
    authority_private_key: &[u8],
) -> Result<Vec<u8>, TirBaseError> {
    let private_key = PrivateKey::from_bytes(authority_private_key, Algorithm::Ed25519).map_err(
        |e| TirBaseError::AuthorisationFailed {
            reason: format!("invalid capability authority private key: {e}"),
        },
    )?;
    let keypair = KeyPair::from(&private_key);
    let claims_json =
        serde_json::to_string(claims).map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to serialize capability claims: {e}"),
        })?;
    let expires_at = claims.capability.scope.expires_at.max(0) as u64;
    let expiry = UNIX_EPOCH + Duration::from_secs(expires_at);

    let token = Biscuit::builder()
        .fact(format!("operator_capability({claims_json:?})").as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to add capability fact: {e}"),
        })?
        .fact(format!("cap_id({:?})", claims.capability.capability_id).as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to add cap_id fact: {e}"),
        })?
        .fact(format!("principal({:?})", claims.capability.subject.id).as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to add principal fact: {e}"),
        })?
        .fact(format!("role({:?})", claims.capability.role.as_str()).as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to add role fact: {e}"),
        })?
        .check_expiration_date(expiry)
        .build(&keypair)
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("failed to build capability token: {e}"),
        })?;

    token.to_vec().map_err(|e| TirBaseError::AuthorisationFailed {
        reason: format!("failed to serialize capability token: {e}"),
    })
}

fn ensure_not_wider(
    parent: &OperatorCapability,
    child: &OperatorCapability,
    operation: &str,
) -> Result<(), TirBaseError> {
    // Subject/role/issuer binding: delegation may change subject (to delegatee)
    // but never to an unrelated tenant outside parent scope; attenuation keeps
    // the same subject. We enforce scope non-widening strictly.
    if !parent.scope.can_attenuate_to(&child.scope) {
        return Err(TirBaseError::AuthorisationFailed {
            reason: format!("{operation} cannot widen tenant, permissions, vertical, or expiry"),
        });
    }
    // Role must not escalate via attenuation/delegation: child role is allowed to
    // differ only when narrowing to a role whose permission set is a subset in the
    // active matrix check context; to be safe, require equal role unless explicit
    // narrowing is represented in permissions. We enforce "not wider" by requiring
    // that the child's declared role is the same or that it carries no extra
    // permissions beyond parent scope (permissions already subset-checked).
    if child.role != parent.role && !role_not_wider(parent.role, child.role) {
        return Err(TirBaseError::AuthorisationFailed {
            reason: format!("{operation} cannot escalate operator role"),
        });
    }
    // Tenant of subject must remain within the effective scope.
    if !child.scope.tenant.contains(&child.subject.tenant) {
        // allow subject tenant equal-or-within scope (typical) but never outside
        return Err(TirBaseError::AuthorisationFailed {
            reason: format!("{operation} subject tenant must be within capability scope"),
        });
    }
    // Break-glass permission cannot be introduced if absent.
    if child
        .scope
        .permissions
        .iter()
        .any(|p| matches!(p, OperatorPermission::BreakGlass))
        && !parent
            .scope
            .permissions
            .iter()
            .any(|p| matches!(p, OperatorPermission::BreakGlass))
    {
        return Err(TirBaseError::AuthorisationFailed {
            reason: format!("{operation} cannot introduce break-glass permission"),
        });
    }
    // Capability id must differ for a derived token to allow independent revocation.
    if child.capability_id == parent.capability_id {
        return Err(TirBaseError::AuthorisationFailed {
            reason: format!("{operation} must assign a distinct capability id"),
        });
    }
    Ok(())
}

/// Conservative role non-widening relation: a "lower" operational role may be
/// delegated from a higher one only in specific cases; default to equal.
fn role_not_wider(parent: OperatorRole, child: OperatorRole) -> bool {
    use OperatorRole::*;
    match (parent, child) {
        (a, b) if a == b => true,
        (Admin, Operator)
        | (Admin, Supervisor)
        | (Admin, Qa)
        | (Admin, Auditor)
        | (Admin, Integrator) => true,
        (Supervisor, Operator) => true,
        _ => false,
    }
}

/// Helper: build a capability scope restricted to a tenant and permission set.
pub fn scope(
    tenant: TenantPath,
    permissions: Vec<OperatorPermission>,
    vertical: Option<Vertical>,
    expires_at: i64,
) -> CapabilityScope {
    CapabilityScope::new(tenant, permissions, vertical, expires_at)
}

/// Helper: delegation constraints.
pub fn delegation(delegatable: bool, max_depth: u8) -> DelegationConstraints {
    DelegationConstraints {
        delegatable,
        max_depth,
    }
}
