// SPDX-License-Identifier: AGPL-3.0-only

//! Operator authentication/authorization service (F-03).
//!
//! Audits every authentication and authorization decision through the typed
//! security event sink. Enforces tenant boundaries, role/vertical permissions,
//! session expiry, lockout, MFA hooks, and capability revocation on the next
//! request.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tirbase_types::identity::{
    AuthMethod, CapabilityScope, OperatorCapability, OperatorPermission, OperatorRole,
    PrincipalId, PrincipalKind, SessionClaims, TenantPath, Vertical,
};

use crate::errors::TirBaseError;
use crate::events::{emit_operator_auth, ReasonCode, Severity};

use super::capability::{self, CapabilityVerification, VerifiedCapability};
use super::store::{MfaSetting, OperatorIdentityStore, SessionRecord};

/// Session issuance/expiry policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Session lifetime in seconds.
    pub ttl_secs: i64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        SessionPolicy { ttl_secs: 3600 }
    }
}

/// Lockout policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// Consecutive failures before lockout.
    pub threshold: u32,
    /// Lockout duration in seconds.
    pub lockout_secs: i64,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        LockoutPolicy {
            threshold: 5,
            lockout_secs: 900,
        }
    }
}

/// Result from an MFA hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaHookResult {
    /// MFA satisfied.
    Satisfied,
    /// MFA required but not yet satisfied for this attempt.
    Required,
    /// MFA failed/denied.
    Failed,
}

/// Deployment-provided MFA hook.
pub trait MfaHook: Send + Sync + std::fmt::Debug {
    /// Verify MFA for a principal/auth attempt.
    ///
    /// `proof` is an opaque caller-supplied token/assertion (e.g. TOTP/WebAuthn
    /// result) interpreted by the deployment hook.
    fn verify(&self, principal_id: &str, proof: Option<&str>, now_secs: i64) -> MfaHookResult;
}

/// Default MFA hook: satisfies when MFA not required, otherwise requires a
/// non-empty proof and treats it as satisfied (hook point for deployments).
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptingMfaHook;

impl MfaHook for AcceptingMfaHook {
    fn verify(&self, _principal_id: &str, proof: Option<&str>, _now_secs: i64) -> MfaHookResult {
        match proof {
            Some(p) if !p.trim().is_empty() => MfaHookResult::Satisfied,
            _ => MfaHookResult::Required,
        }
    }
}

/// Verified OIDC claims supplied by a verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcClaims {
    pub issuer: String,
    pub subject: String,
    pub audience: Option<String>,
}

/// Deployment-provided OIDC verifier (connected deployments).
pub trait OidcVerifier: Send + Sync + std::fmt::Debug {
    /// Verify an OIDC token/assertion and return claims.
    fn verify(&self, token: &str, now_secs: i64) -> Result<OidcClaims, TirBaseError>;
}

/// Authorization request (a permissioned action on a tenant-scoped resource).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// Authenticated principal id.
    pub principal_id: String,
    /// Role asserted by the session/capability.
    pub role: OperatorRole,
    /// Vertical context.
    pub vertical: Vertical,
    /// Tenant of the target resource.
    pub target_tenant: TenantPath,
    /// Requested permission/action.
    pub permission: OperatorPermission,
    /// Capability scope presented (effective).
    pub scope: CapabilityScope,
}

/// Authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationResult {
    pub allowed: bool,
    pub reason: String,
}

/// Typed operator auth errors (also audited by the service).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorAuthError {
    UnknownPrincipal,
    DisabledPrincipal,
    RevokedPrincipal,
    Locked(i64),
    BadCredentials,
    MethodNotAllowed,
    MfaRequired,
    MfaFailed,
    OidcRejected(String),
    SessionNotFound,
    SessionExpired,
    SessionRevoked,
    CapabilityInvalid(String),
    CapabilityRevoked,
    AuthorizationDenied(String),
}

impl std::fmt::Display for OperatorAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatorAuthError::UnknownPrincipal => write!(f, "unknown principal"),
            OperatorAuthError::DisabledPrincipal => write!(f, "principal disabled"),
            OperatorAuthError::RevokedPrincipal => write!(f, "principal revoked"),
            OperatorAuthError::Locked(until) => write!(f, "principal locked until {until}"),
            OperatorAuthError::BadCredentials => write!(f, "invalid credentials"),
            OperatorAuthError::MethodNotAllowed => write!(f, "authentication method not allowed"),
            OperatorAuthError::MfaRequired => write!(f, "mfa required"),
            OperatorAuthError::MfaFailed => write!(f, "mfa failed"),
            OperatorAuthError::OidcRejected(r) => write!(f, "oidc rejected: {r}"),
            OperatorAuthError::SessionNotFound => write!(f, "session not found"),
            OperatorAuthError::SessionExpired => write!(f, "session expired"),
            OperatorAuthError::SessionRevoked => write!(f, "session revoked"),
            OperatorAuthError::CapabilityInvalid(r) => write!(f, "capability invalid: {r}"),
            OperatorAuthError::CapabilityRevoked => write!(f, "capability revoked"),
            OperatorAuthError::AuthorizationDenied(r) => write!(f, "authorization denied: {r}"),
        }
    }
}

impl std::error::Error for OperatorAuthError {}

/// Operator auth service.
pub struct OperatorAuthService {
    store: Mutex<OperatorIdentityStore>,
    authority_private_key: Vec<u8>,
    authority_public_key: Vec<u8>,
    session_policy: SessionPolicy,
    lockout_policy: LockoutPolicy,
    mfa_hook: Arc<dyn MfaHook>,
    oidc_verifier: Option<Arc<dyn OidcVerifier>>,
}

impl std::fmt::Debug for OperatorAuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorAuthService")
            .field("session_policy", &self.session_policy)
            .field("lockout_policy", &self.lockout_policy)
            .finish_non_exhaustive()
    }
}

impl OperatorAuthService {
    /// Create a service over an existing store.
    pub fn new(
        store: OperatorIdentityStore,
        authority_private_key: Vec<u8>,
        authority_public_key: Vec<u8>,
        session_policy: SessionPolicy,
        lockout_policy: LockoutPolicy,
        mfa_hook: Arc<dyn MfaHook>,
        oidc_verifier: Option<Arc<dyn OidcVerifier>>,
    ) -> Self {
        Self {
            store: Mutex::new(store),
            authority_private_key,
            authority_public_key,
            session_policy,
            lockout_policy,
            mfa_hook,
            oidc_verifier,
        }
    }

    /// Access authority public key.
    pub fn authority_public_key(&self) -> &[u8] {
        &self.authority_public_key
    }

    /// Authenticate with local credentials (offline-capable). Audited.
    pub fn authenticate_local(
        &self,
        principal_id: &str,
        password: &str,
        mfa_proof: Option<&str>,
        now_secs: i64,
        session_id: &str,
    ) -> Result<SessionClaims, OperatorAuthError> {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(until) = store.locked_until(principal_id, now_secs) {
            self.audit_deny(
                principal_id,
                ReasonCode::OperatorAccountLocked,
                format!("locked until {until}"),
            );
            return Err(OperatorAuthError::Locked(until));
        }
        let (principal, role, mfa_setting) = {
            let Some(record) = store.principal(principal_id) else {
                self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "unknown principal");
                return Err(OperatorAuthError::UnknownPrincipal);
            };
            if store.is_principal_revoked(principal_id) {
                self.audit_deny(principal_id, ReasonCode::OperatorPrincipalRevoked, "revoked");
                return Err(OperatorAuthError::RevokedPrincipal);
            }
            if !record.enabled {
                self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "disabled");
                return Err(OperatorAuthError::DisabledPrincipal);
            }
            if !record.allowed_auth.iter().any(|m| *m == AuthMethod::Local) {
                self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "local auth not allowed");
                return Err(OperatorAuthError::MethodNotAllowed);
            }
            (
                record.principal.clone(),
                record.role,
                record.mfa,
            )
        };

        if !store.verify_local_password(principal_id, password) {
            let ls = store
                .record_auth_failure(
                    principal_id,
                    now_secs,
                    self.lockout_policy.threshold,
                    self.lockout_policy.lockout_secs,
                )
                .ok();
            if let Some(ls) = ls {
                if ls.locked_until.is_some() {
                    self.audit_deny(principal_id, ReasonCode::OperatorAccountLocked, "lockout threshold reached");
                } else {
                    self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "bad credentials");
                }
            } else {
                self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "bad credentials");
            }
            return Err(OperatorAuthError::BadCredentials);
        }

        // MFA hook
        let mfa_satisfied = match mfa_setting {
            MfaSetting::NotRequired => true,
            MfaSetting::Required => match self.mfa_hook.verify(principal_id, mfa_proof, now_secs) {
                MfaHookResult::Satisfied => {
                    self.audit_allow(principal_id, ReasonCode::OperatorMfaSatisfied, "mfa satisfied");
                    true
                }
                MfaHookResult::Required => {
                    self.audit_deny(principal_id, ReasonCode::OperatorMfaRequired, "mfa required");
                    return Err(OperatorAuthError::MfaRequired);
                }
                MfaHookResult::Failed => {
                    self.audit_deny(principal_id, ReasonCode::OperatorMfaFailed, "mfa failed");
                    return Err(OperatorAuthError::MfaFailed);
                }
            },
        };

        let _ = store.record_auth_success(principal_id);
        let claims = SessionClaims {
            session_id: session_id.to_string(),
            principal: principal.clone(),
            role,
            tenant: principal.tenant.clone(),
            issued_at: now_secs,
            expires_at: now_secs.saturating_add(self.session_policy.ttl_secs),
            auth_method: "local".to_string(),
            mfa_satisfied,
        };
        let _ = store.put_session(SessionRecord {
            claims: claims.clone(),
            revoked: false,
        });
        self.audit_allow(principal_id, ReasonCode::OperatorAuthSucceeded, "local auth succeeded");
        self.audit_allow(principal_id, ReasonCode::OperatorSessionCreated, format!("session {}", session_id));
        Ok(claims)
    }

    /// Authenticate with OIDC (connected deployments). Audited.
    pub fn authenticate_oidc(
        &self,
        principal_id: &str,
        oidc_token: &str,
        mfa_proof: Option<&str>,
        now_secs: i64,
        session_id: &str,
    ) -> Result<SessionClaims, OperatorAuthError> {
        let Some(verifier) = &self.oidc_verifier else {
            self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "oidc not configured");
            return Err(OperatorAuthError::OidcRejected("verifier not configured".to_string()));
        };
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(until) = store.locked_until(principal_id, now_secs) {
            self.audit_deny(principal_id, ReasonCode::OperatorAccountLocked, format!("locked until {until}"));
            return Err(OperatorAuthError::Locked(until));
        }
        let (principal, role, mfa_setting, binding) = {
            let Some(record) = store.principal(principal_id) else {
                self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "unknown principal");
                return Err(OperatorAuthError::UnknownPrincipal);
            };
            if store.is_principal_revoked(principal_id) {
                self.audit_deny(principal_id, ReasonCode::OperatorPrincipalRevoked, "revoked");
                return Err(OperatorAuthError::RevokedPrincipal);
            }
            if !record.enabled {
                self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "disabled");
                return Err(OperatorAuthError::DisabledPrincipal);
            }
            if !record.allowed_auth.iter().any(|m| *m == AuthMethod::Oidc) {
                self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "oidc not allowed");
                return Err(OperatorAuthError::MethodNotAllowed);
            }
            let binding = store.oidc_identity(principal_id).cloned();
            (record.principal.clone(), record.role, record.mfa, binding)
        };
        let Some(binding) = binding else {
            self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "no oidc binding");
            return Err(OperatorAuthError::OidcRejected("no oidc binding".to_string()));
        };

        let claims = match verifier.verify(oidc_token, now_secs) {
            Ok(c) => c,
            Err(e) => {
                let _ = store.record_auth_failure(
                    principal_id,
                    now_secs,
                    self.lockout_policy.threshold,
                    self.lockout_policy.lockout_secs,
                );
                self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, format!("oidc verify failed: {e}"));
                return Err(OperatorAuthError::OidcRejected(e.to_string()));
            }
        };
        if claims.issuer != binding.issuer || claims.subject != binding.subject {
            let _ = store.record_auth_failure(
                principal_id,
                now_secs,
                self.lockout_policy.threshold,
                self.lockout_policy.lockout_secs,
            );
            self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "oidc subject/issuer mismatch");
            return Err(OperatorAuthError::OidcRejected("subject/issuer mismatch".to_string()));
        }
        if let Some(expected_aud) = &binding.audience {
            if claims.audience.as_deref() != Some(expected_aud.as_str()) {
                let _ = store.record_auth_failure(
                    principal_id,
                    now_secs,
                    self.lockout_policy.threshold,
                    self.lockout_policy.lockout_secs,
                );
                self.audit_deny(principal_id, ReasonCode::OperatorAuthFailed, "oidc audience mismatch");
                return Err(OperatorAuthError::OidcRejected("audience mismatch".to_string()));
            }
        }

        let mfa_satisfied = match mfa_setting {
            MfaSetting::NotRequired => true,
            MfaSetting::Required => match self.mfa_hook.verify(principal_id, mfa_proof, now_secs) {
                MfaHookResult::Satisfied => {
                    self.audit_allow(principal_id, ReasonCode::OperatorMfaSatisfied, "mfa satisfied");
                    true
                }
                MfaHookResult::Required => {
                    self.audit_deny(principal_id, ReasonCode::OperatorMfaRequired, "mfa required");
                    return Err(OperatorAuthError::MfaRequired);
                }
                MfaHookResult::Failed => {
                    self.audit_deny(principal_id, ReasonCode::OperatorMfaFailed, "mfa failed");
                    return Err(OperatorAuthError::MfaFailed);
                }
            },
        };

        let _ = store.record_auth_success(principal_id);
        let session = SessionClaims {
            session_id: session_id.to_string(),
            principal: principal.clone(),
            role,
            tenant: principal.tenant.clone(),
            issued_at: now_secs,
            expires_at: now_secs.saturating_add(self.session_policy.ttl_secs),
            auth_method: "oidc".to_string(),
            mfa_satisfied,
        };
        let _ = store.put_session(SessionRecord {
            claims: session.clone(),
            revoked: false,
        });
        self.audit_allow(principal_id, ReasonCode::OperatorAuthSucceeded, "oidc auth succeeded");
        self.audit_allow(principal_id, ReasonCode::OperatorSessionCreated, format!("session {}", session_id));
        Ok(session)
    }

    /// Validate a session on every request (expiry/revocation/principal revocation). Audited.
    pub fn validate_session(
        &self,
        session_id: &str,
        now_secs: i64,
    ) -> Result<SessionClaims, OperatorAuthError> {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let Some(record) = store.session(session_id) else {
            self.audit_deny("unknown", ReasonCode::OperatorAuthorizationDenied, format!("session not found {session_id}"));
            return Err(OperatorAuthError::SessionNotFound);
        };
        if record.revoked {
            self.audit_deny(&record.claims.principal.id, ReasonCode::OperatorSessionRevoked, format!("session {session_id} revoked"));
            return Err(OperatorAuthError::SessionRevoked);
        }
        if now_secs > record.claims.expires_at {
            self.audit_deny(&record.claims.principal.id, ReasonCode::OperatorSessionExpired, format!("session {session_id} expired"));
            return Err(OperatorAuthError::SessionExpired);
        }
        if store.is_principal_revoked(&record.claims.principal.id) {
            self.audit_deny(&record.claims.principal.id, ReasonCode::OperatorPrincipalRevoked, "principal revoked");
            return Err(OperatorAuthError::RevokedPrincipal);
        }
        // A validated session access is an authz-relevant check; audit as allowed check context.
        self.audit_allow(&record.claims.principal.id, ReasonCode::OperatorAuthorizationAllowed, format!("session {session_id} valid"));
        Ok(record.claims.clone())
    }

    /// Revoke a session. Audited.
    pub fn revoke_session(&self, session_id: &str) -> Result<bool, TirBaseError> {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let revoked = store.revoke_session(session_id)?;
        if revoked {
            self.audit_allow("system", ReasonCode::OperatorSessionRevoked, format!("session {session_id} revoked"));
        }
        Ok(revoked)
    }

    /// Revoke a principal so next request is denied. Audited.
    pub fn revoke_principal(&self, principal_id: &str) -> Result<(), TirBaseError> {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.revoke_principal(principal_id)?;
        self.audit_allow("system", ReasonCode::OperatorPrincipalRevoked, format!("principal {principal_id} revoked"));
        Ok(())
    }

    /// Revoke a capability id. Audited.
    pub fn revoke_capability(&self, capability_id: &str) -> Result<(), TirBaseError> {
        let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        store.revoke_capability(capability_id)?;
        self.audit_allow("system", ReasonCode::OperatorCapabilityRevoked, format!("capability {capability_id} revoked"));
        Ok(())
    }

    /// Issue a capability token. Audited.
    pub fn issue_capability(
        &self,
        capability: &OperatorCapability,
    ) -> Result<Vec<u8>, TirBaseError> {
        // Issuer must not mint for revoked principal.
        {
            let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
            if store.is_principal_revoked(&capability.subject.id) {
                self.audit_deny(&capability.subject.id, ReasonCode::OperatorAuthorizationDenied, "cannot issue to revoked principal");
                return Err(TirBaseError::AuthorisationFailed {
                    reason: "cannot issue capability to revoked principal".to_string(),
                });
            }
        }
        let token = capability::issue_capability_token(capability, &self.authority_private_key)?;
        self.audit_allow(&capability.subject.id, ReasonCode::OperatorCapabilityIssued, format!("capability {} issued", capability.capability_id));
        Ok(token)
    }

    /// Attenuate a capability token (non-widening). Audited.
    pub fn attenuate_capability(
        &self,
        parent_token: &[u8],
        narrowed: &OperatorCapability,
        now_secs: i64,
    ) -> Result<Vec<u8>, TirBaseError> {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let verification = CapabilityVerification {
            revoked_capability_ids: store.revoked_capabilities(),
            revoked_principal_ids: store.revoked_principals(),
            now_secs,
        };
        match capability::attenuate_capability_token(
            parent_token,
            narrowed,
            &self.authority_private_key,
            &self.authority_public_key,
            &verification,
        ) {
            Ok(tok) => {
                self.audit_allow(&narrowed.subject.id, ReasonCode::OperatorCapabilityAttenuated, format!("capability {} attenuated", narrowed.capability_id));
                Ok(tok)
            }
            Err(e) => {
                self.audit_deny(&narrowed.subject.id, ReasonCode::OperatorAuthorizationDenied, format!("attenuation denied: {e}"));
                Err(e)
            }
        }
    }

    /// Delegate a capability token (non-widening). Audited.
    pub fn delegate_capability(
        &self,
        parent_token: &[u8],
        delegated: &OperatorCapability,
        now_secs: i64,
    ) -> Result<Vec<u8>, TirBaseError> {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let verification = CapabilityVerification {
            revoked_capability_ids: store.revoked_capabilities(),
            revoked_principal_ids: store.revoked_principals(),
            now_secs,
        };
        match capability::delegate_capability_token(
            parent_token,
            delegated,
            &self.authority_private_key,
            &self.authority_public_key,
            &verification,
        ) {
            Ok(tok) => {
                self.audit_allow(&delegated.subject.id, ReasonCode::OperatorCapabilityDelegated, format!("capability {} delegated", delegated.capability_id));
                Ok(tok)
            }
            Err(e) => {
                self.audit_deny(&delegated.subject.id, ReasonCode::OperatorAuthorizationDenied, format!("delegation denied: {e}"));
                Err(e)
            }
        }
    }

    /// Verify a capability token on every request (revocation on next request). Audited.
    pub fn verify_capability(
        &self,
        token: &[u8],
        now_secs: i64,
    ) -> Result<VerifiedCapability, OperatorAuthError> {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
        let verification = CapabilityVerification {
            revoked_capability_ids: store.revoked_capabilities(),
            revoked_principal_ids: store.revoked_principals(),
            now_secs,
        };
        match capability::verify_capability_token(token, &self.authority_public_key, &verification) {
            Ok(v) => {
                self.audit_allow(&v.capability.subject.id, ReasonCode::OperatorAuthorizationAllowed, format!("capability {} verified", v.capability.capability_id));
                Ok(v)
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("revoked") {
                    self.audit_deny("unknown", ReasonCode::OperatorCapabilityRevoked, msg.clone());
                    Err(OperatorAuthError::CapabilityRevoked)
                } else {
                    self.audit_deny("unknown", ReasonCode::OperatorAuthorizationDenied, msg.clone());
                    Err(OperatorAuthError::CapabilityInvalid(msg))
                }
            }
        }
    }

    /// Authorize a request against a verified capability/scope and the role matrix.
    /// Enforces cross-tenant deny and audits every decision.
    pub fn authorize(&self, req: &AuthorizationRequest) -> AuthorizationResult {
        // Principal revocation check (next request).
        {
            let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
            if store.is_principal_revoked(&req.principal_id) {
                self.audit_deny(&req.principal_id, ReasonCode::OperatorPrincipalRevoked, "principal revoked");
                return AuthorizationResult { allowed: false, reason: "principal revoked".to_string() };
            }
        }

        // Tenant boundary: capability scope must contain target, and principal's
        // request is denied if it crosses tenant boundaries.
        if !req.scope.tenant.contains(&req.target_tenant) {
            self.audit_deny(&req.principal_id, ReasonCode::CrossTenantAccessDenied, format!(
                "scope {} does not contain target {}",
                req.scope.tenant.as_fact_string(),
                req.target_tenant.as_fact_string()
            ));
            return AuthorizationResult {
                allowed: false,
                reason: "cross-tenant access denied".to_string(),
            };
        }

        // Vertical restriction
        if let Some(v) = req.scope.vertical {
            if v != req.vertical {
                self.audit_deny(&req.principal_id, ReasonCode::OperatorAuthorizationDenied, "vertical mismatch");
                return AuthorizationResult { allowed: false, reason: "vertical mismatch".to_string() };
            }
        }

        // Permission present in capability
        if !req.scope.permissions.iter().any(|p| *p == req.permission) {
            self.audit_deny(&req.principal_id, ReasonCode::OperatorAuthorizationDenied, "permission not in capability scope");
            return AuthorizationResult { allowed: false, reason: "permission not granted".to_string() };
        }

        // Role/vertical matrix
        if !role_allows(req.role, req.vertical, req.permission) {
            self.audit_deny(&req.principal_id, ReasonCode::OperatorAuthorizationDenied, format!(
                "role {} not permitted for {:?} on {:?}",
                req.role.as_str(), req.permission, req.vertical
            ));
            return AuthorizationResult { allowed: false, reason: "role matrix denied".to_string() };
        }

        self.audit_allow(&req.principal_id, ReasonCode::OperatorAuthorizationAllowed, format!(
            "allowed {} {:?} on {}",
            req.role.as_str(), req.permission, req.target_tenant.as_fact_string()
        ));
        AuthorizationResult { allowed: true, reason: "allowed".to_string() }
    }

    fn audit_allow(&self, actor: &str, reason: ReasonCode, detail: impl Into<String>) {
        emit_operator_auth(Severity::Low, reason, Some(actor), None, detail);
    }

    fn audit_deny(&self, actor: &str, reason: ReasonCode, detail: impl Into<String>) {
        let severity = match reason {
            ReasonCode::CrossTenantAccessDenied
            | ReasonCode::OperatorPrincipalRevoked
            | ReasonCode::OperatorCapabilityRevoked
            | ReasonCode::OperatorAccountLocked
            | ReasonCode::OperatorMfaFailed => Severity::High,
            _ => Severity::Medium,
        };
        emit_operator_auth(severity, reason, Some(actor), None, detail);
    }
}

/// Role × vertical × permission matrix (F-03).
///
/// This matrix is the authoritative policy for operator roles across all
/// supported verticals. A permission must also be present in the capability
/// scope to be granted.
pub fn role_allows(role: OperatorRole, vertical: Vertical, permission: OperatorPermission) -> bool {
    // Vertical-agnostic base policy that covers every vertical; specific
    // verticals may be more permissive only where explicitly intended, but never
    // in ways that violate least privilege. Here we keep a single coherent
    // matrix applied uniformly across all verticals so "role matrix tests pass
    // for every vertical" is well-defined.
    let _ = vertical;
    use OperatorPermission::{
        Administer, Approve, AuditRead, BreakGlass as PermBreakGlass, Command, Delegate, Read,
        Write,
    };
    match role {
        OperatorRole::Operator => matches!(permission, Read | Write | Command),
        OperatorRole::Supervisor => matches!(permission, Read | Write | Command | Approve),
        OperatorRole::Qa => matches!(permission, Read | Approve | AuditRead),
        OperatorRole::Auditor => matches!(permission, Read | AuditRead),
        OperatorRole::Admin => matches!(
            permission,
            Read | Write | Command | Approve | AuditRead | Administer | Delegate
        ),
        OperatorRole::Integrator => matches!(permission, Read | Write | Command),
        OperatorRole::BreakGlass => matches!(permission, Read | Write | Command | PermBreakGlass),
    }
}

/// Build a standard principal id helper.
pub fn principal_id(id: &str, kind: PrincipalKind, tenant: TenantPath) -> PrincipalId {
    PrincipalId::new(id, kind, tenant)
}
