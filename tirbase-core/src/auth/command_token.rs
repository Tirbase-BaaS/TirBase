//! Command-token verification and scope binding for the guard admit path
//! (task 14.5, 14.6 — CLAIM-14.5, CLAIM-14.6, PV-3.2, PV-4.6).
//!
//! Extends the base Biscuit token facts (`did`, `role`, `issued_at`,
//! `expires_at`, `check_expiration_date`) with command-scope facts:
//! * `command("target_id")` — attenuates to a target (may be `"*"`)
//! * `scope("param")` / `param("param")` — attenuates to a parameter (may be `"*"`)
//!
//! The guard derives [`CommandRole`] from the verified token's `role` fact and
//! NEVER trusts `cmd.role`. Missing scope facts are treated as unrestricted for
//! that dimension only when the token explicitly carries `scope_unrestricted("true")`;
//! otherwise a command-scoped token must carry both `command(...)` and
//! `scope(...)`/`param(...)` facts.

use crate::auth::biscuit::{BiscuitClaims, TokenVerifyError};
use crate::errors::TirBaseError;
use biscuit_auth::{
    builder::{date, fact, Algorithm},
    builder_ext::{AuthorizerExt, BuilderExt},
    AuthorizerBuilder, Biscuit, KeyPair, PrivateKey, PublicKey,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tirbase_types::CommandRole;

/// Claims extracted from a command-scoped Biscuit token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandTokenClaims {
    pub did: String,
    pub role: CommandRole,
    pub role_raw: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub target_scope: Option<String>,
    pub param_scope: Option<String>,
    pub scope_unrestricted: bool,
}

/// Verify a command-scoped Biscuit token against `root_ca_public_key` using
/// `now_secs` (seconds since Unix epoch, derived from `now_est` by callers).
pub fn verify_command_token(
    token_bytes: &[u8],
    root_ca_public_key: &[u8],
    now_secs: i64,
) -> Result<CommandTokenClaims, TokenVerifyError> {
    let public_key =
        PublicKey::from_bytes(root_ca_public_key, Algorithm::Ed25519).map_err(|e| {
            TokenVerifyError::OtherFailure(TirBaseError::AuthorisationFailed {
                reason: format!("invalid root CA public key: {e}"),
            })
        })?;

    let token = match Biscuit::from(token_bytes, public_key) {
        Ok(t) => t,
        Err(e) => {
            return Err(TokenVerifyError::OtherFailure(
                TirBaseError::AuthorisationFailed {
                    reason: format!("failed to parse/verify Biscuit token: {e}"),
                },
            ));
        }
    };

    let fake_now = UNIX_EPOCH + Duration::from_secs(now_secs.max(0) as u64);
    let time_fact = fact("time", &[date(&fake_now)]);

    let mut authorizer = AuthorizerBuilder::new()
        .fact(time_fact)
        .map_err(|e| {
            TokenVerifyError::OtherFailure(TirBaseError::AuthorisationFailed {
                reason: format!("authorizer build error: {e}"),
            })
        })?
        .allow_all()
        .build(&token)
        .map_err(|e| {
            TokenVerifyError::OtherFailure(TirBaseError::AuthorisationFailed {
                reason: format!("authorizer construction failed: {e}"),
            })
        })?;

    let generous = biscuit_auth::AuthorizerLimits {
        max_facts: 10_000,
        max_iterations: 10_000,
        max_time: Duration::from_secs(5),
    };

    if let Err(e) = authorizer.authorize_with_limits(generous.clone()) {
        let msg = e.to_string().to_lowercase();
        if msg.contains("expired") || msg.contains("authorization failed") {
            return Err(TokenVerifyError::TokenExpired);
        }
        return Err(TokenVerifyError::OtherFailure(
            TirBaseError::AuthorisationFailed {
                reason: format!("token authorization failed: {e}"),
            },
        ));
    }

    let did = query_string(&mut authorizer, "data($v) <- did($v)", &generous).unwrap_or_default();
    let role_raw =
        query_string(&mut authorizer, "data($v) <- role($v)", &generous).unwrap_or_default();
    let role = parse_command_role(&role_raw).ok_or_else(|| {
        TokenVerifyError::OtherFailure(TirBaseError::AuthorisationFailed {
            reason: format!("unknown or missing token role: {role_raw:?}"),
        })
    })?;
    let issued_at = query_i64(&mut authorizer, "data($v) <- issued_at($v)", &generous).unwrap_or(0);
    let expires_at =
        query_i64(&mut authorizer, "data($v) <- expires_at($v)", &generous).unwrap_or(now_secs);
    let target_scope = query_string(&mut authorizer, "data($v) <- command($v)", &generous);
    let param_scope = query_string(&mut authorizer, "data($v) <- scope($v)", &generous)
        .or_else(|| query_string(&mut authorizer, "data($v) <- param($v)", &generous));
    let scope_unrestricted = query_string(
        &mut authorizer,
        "data($v) <- scope_unrestricted($v)",
        &generous,
    )
    .map(|v| v == "true")
    .unwrap_or(false);

    Ok(CommandTokenClaims {
        did,
        role,
        role_raw,
        issued_at,
        expires_at,
        target_scope,
        param_scope,
        scope_unrestricted,
    })
}

/// Check that token claims bind to `target_id` and `param` (Stage 4).
pub fn check_command_binding(
    claims: &CommandTokenClaims,
    target_id: &str,
    param: &str,
) -> Result<(), String> {
    if !claims.scope_unrestricted {
        match &claims.target_scope {
            Some(t) if t == "*" || t == target_id => {}
            Some(t) => {
                return Err(format!(
                    "token target scope {t:?} does not match {target_id:?}"
                ))
            }
            None => return Err("token missing command(target) scope fact".to_string()),
        }
        match &claims.param_scope {
            Some(p) if p == "*" || p == param => {}
            Some(p) => return Err(format!("token param scope {p:?} does not match {param:?}")),
            None => return Err("token missing scope(param) fact".to_string()),
        }
    }
    Ok(())
}

pub fn parse_command_role(raw: &str) -> Option<CommandRole> {
    Some(match raw {
        "CommandIssuer" => CommandRole::CommandIssuer,
        "PolicyAuthority" => CommandRole::PolicyAuthority,
        "UpdateSigner" => CommandRole::UpdateSigner,
        "RevocationManager" => CommandRole::RevocationManager,
        "Auditor" => CommandRole::Auditor,
        "TimeAnchor" => CommandRole::TimeAnchor,
        _ => return None,
    })
}

fn query_string(
    authorizer: &mut biscuit_auth::Authorizer,
    query: &str,
    limits: &biscuit_auth::AuthorizerLimits,
) -> Option<String> {
    let results: Vec<(String,)> = authorizer.query_with_limits(query, limits.clone()).ok()?;
    results.into_iter().next().map(|(v,)| v)
}

fn query_i64(
    authorizer: &mut biscuit_auth::Authorizer,
    query: &str,
    limits: &biscuit_auth::AuthorizerLimits,
) -> Option<i64> {
    let results: Vec<(i64,)> = authorizer.query_with_limits(query, limits.clone()).ok()?;
    results.into_iter().next().map(|(v,)| v)
}

/// Create a command-scoped Biscuit token for guard admit tests and admin minting.
///
/// Includes standard facts plus `command(target)` and `scope(param)`. Use `"*"`
/// for unrestricted dimensions. `extra_facts` may include caveats.
pub fn create_command_token(
    did: &str,
    role: &str,
    ttl_secs: u64,
    target_scope: &str,
    param_scope: &str,
    extra_facts: &[&str],
    root_ca_private_key: &[u8],
) -> Result<Vec<u8>, TirBaseError> {
    let private_key =
        PrivateKey::from_bytes(root_ca_private_key, Algorithm::Ed25519).map_err(|e| {
            TirBaseError::AuthorisationFailed {
                reason: format!("invalid root CA private key: {e}"),
            }
        })?;
    let keypair = KeyPair::from(&private_key);
    let now = SystemTime::now();
    let issued_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let expiry_secs = issued_secs + ttl_secs;
    let expiry = now + Duration::from_secs(ttl_secs);

    let did_s = did.to_string();
    let role_s = role.to_string();
    let target_s = target_scope.to_string();
    let param_s = param_scope.to_string();
    let mut builder = Biscuit::builder()
        .fact(format!("did(\"{did_s}\")").as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: e.to_string(),
        })?
        .fact(format!("role(\"{role_s}\")").as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: e.to_string(),
        })?
        .fact(format!("issued_at({issued_secs})").as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: e.to_string(),
        })?
        .fact(format!("expires_at({expiry_secs})").as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: e.to_string(),
        })?
        .fact(format!("command(\"{target_s}\")").as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: e.to_string(),
        })?
        .fact(format!("scope(\"{param_s}\")").as_str())
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: e.to_string(),
        })?
        .check_expiration_date(expiry);
    for f in extra_facts {
        builder = builder
            .fact(*f)
            .map_err(|e| TirBaseError::AuthorisationFailed {
                reason: e.to_string(),
            })?;
    }
    let token = builder
        .build(&keypair)
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: e.to_string(),
        })?;
    token
        .to_vec()
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: e.to_string(),
        })
}

impl From<BiscuitClaims> for CommandTokenClaims {
    fn from(c: BiscuitClaims) -> Self {
        CommandTokenClaims {
            did: c.did,
            role: parse_command_role(&c.role).unwrap_or(CommandRole::CommandIssuer),
            role_raw: c.role,
            issued_at: c.issued_at,
            expires_at: c.expires_at,
            target_scope: None,
            param_scope: None,
            scope_unrestricted: true,
        }
    }
}
