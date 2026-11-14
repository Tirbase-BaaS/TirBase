// SPDX-License-Identifier: AGPL-3.0-only

//! File-backed operator identity store (F-03).
//!
//! Stores principals, local credentials (offline-capable), OIDC identity
//! bindings, sessions, lockout state, and revocations. Credentials are stored as
//! salted HMAC-SHA256 verifiers (no plaintext passwords).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirbase_types::identity::{
    AuthMethod, MfaRequirement, OperatorRole, PrincipalId, PrincipalKind, SessionClaims,
    TenantPath,
};

use crate::errors::TirBaseError;

/// Local credential record (offline authentication).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalCredential {
    /// Principal identifier this credential authenticates.
    pub principal_id: String,
    /// Random salt (hex or raw bytes encoded as hex in storage helpers; stored
    /// as bytes here).
    pub salt: Vec<u8>,
    /// HMAC-SHA256(salt, password) verifier.
    pub verifier: Vec<u8>,
    /// Whether the credential is disabled.
    #[serde(default)]
    pub disabled: bool,
}

/// OIDC identity binding for a principal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcIdentity {
    /// Principal identifier.
    pub principal_id: String,
    /// Expected issuer (iss).
    pub issuer: String,
    /// Expected subject (sub).
    pub subject: String,
    /// Optional audience/client id constraint.
    #[serde(default)]
    pub audience: Option<String>,
}

/// Persisted principal record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorPrincipalRecord {
    /// Principal identity.
    pub principal: PrincipalId,
    /// Assigned operator role.
    pub role: OperatorRole,
    /// Whether the principal is enabled (administratively).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// MFA requirement for this principal.
    #[serde(default)]
    pub mfa: MfaSetting,
    /// Allowed authentication methods.
    #[serde(default = "default_auth_methods")]
    pub allowed_auth: Vec<AuthMethod>,
}

fn default_true() -> bool {
    true
}

fn default_auth_methods() -> Vec<AuthMethod> {
    vec![AuthMethod::Local, AuthMethod::Oidc]
}

/// Static MFA setting for a principal (hook-driven verification at runtime).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MfaSetting {
    /// No MFA required.
    #[default]
    NotRequired,
    /// MFA required; a deployment MFA hook must satisfy it.
    Required,
}

impl MfaSetting {
    /// Convert to runtime requirement expectation.
    pub fn requirement(&self) -> MfaRequirement {
        match self {
            MfaSetting::NotRequired => MfaRequirement::NotRequired,
            MfaSetting::Required => MfaRequirement::Required,
        }
    }
}

/// Active session record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRecord {
    /// Session claims.
    pub claims: SessionClaims,
    /// Whether explicitly revoked.
    #[serde(default)]
    pub revoked: bool,
}

/// Lockout state per principal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LockoutState {
    /// Consecutive failed attempts in the current window.
    #[serde(default)]
    pub failed_attempts: u32,
    /// Unix seconds when lockout expires (if locked).
    #[serde(default)]
    pub locked_until: Option<i64>,
    /// Unix seconds of last failure.
    #[serde(default)]
    pub last_failure_at: Option<i64>,
}

/// Persisted store state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IdentityStoreState {
    /// Principals keyed by principal id.
    #[serde(default)]
    pub principals: BTreeMap<String, OperatorPrincipalRecord>,
    /// Local credentials keyed by principal id.
    #[serde(default)]
    pub local_credentials: BTreeMap<String, LocalCredential>,
    /// OIDC bindings keyed by principal id.
    #[serde(default)]
    pub oidc_identities: BTreeMap<String, OidcIdentity>,
    /// Sessions keyed by session id.
    #[serde(default)]
    pub sessions: BTreeMap<String, SessionRecord>,
    /// Lockout state keyed by principal id.
    #[serde(default)]
    pub lockouts: BTreeMap<String, LockoutState>,
    /// Revoked principal ids.
    #[serde(default)]
    pub revoked_principals: BTreeSet<String>,
    /// Revoked capability ids.
    #[serde(default)]
    pub revoked_capabilities: BTreeSet<String>,
}

/// File-backed operator identity store.
#[derive(Debug, Clone)]
pub struct OperatorIdentityStore {
    path: PathBuf,
    state: IdentityStoreState,
}

impl OperatorIdentityStore {
    /// Load or create a store at `path`.
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, TirBaseError> {
        let path = path.as_ref().to_path_buf();
        let state = if path.exists() {
            let bytes = fs::read(&path).map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("read operator identity store {}: {e}", path.display()),
            })?;
            if bytes.is_empty() {
                IdentityStoreState::default()
            } else {
                serde_json::from_slice(&bytes).map_err(|e| TirBaseError::DeltaMalformed {
                    reason: format!("parse operator identity store {}: {e}", path.display()),
                })?
            }
        } else {
            IdentityStoreState::default()
        };
        Ok(OperatorIdentityStore { path, state })
    }

    /// Persist current state atomically (write temp + rename).
    pub fn save(&self) -> Result<(), TirBaseError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("create operator identity dir {}: {e}", parent.display()),
            })?;
        }
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("serialize operator identity store: {e}"),
            }
        })?;
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, bytes).map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!("write operator identity store temp {}: {e}", tmp.display()),
        })?;
        fs::rename(&tmp, &self.path).map_err(|e| TirBaseError::LocalStoreWriteFailed {
            reason: format!(
                "rename operator identity store {} -> {}: {e}",
                tmp.display(),
                self.path.display()
            ),
        })?;
        Ok(())
    }

    /// Borrow current state.
    pub fn state(&self) -> &IdentityStoreState {
        &self.state
    }

    /// Mutably borrow current state.
    pub fn state_mut(&mut self) -> &mut IdentityStoreState {
        &mut self.state
    }

    /// Store path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Upsert a principal record.
    pub fn upsert_principal(&mut self, record: OperatorPrincipalRecord) -> Result<(), TirBaseError> {
        self.state
            .principals
            .insert(record.principal.id.clone(), record);
        self.save()
    }

    /// Set or replace a local credential (password in plaintext input; stored as
    /// salted HMAC-SHA256 verifier).
    pub fn set_local_password(
        &mut self,
        principal_id: &str,
        password: &str,
        salt: Vec<u8>,
    ) -> Result<(), TirBaseError> {
        let verifier = hmac_sha256(&salt, password.as_bytes());
        self.state.local_credentials.insert(
            principal_id.to_string(),
            LocalCredential {
                principal_id: principal_id.to_string(),
                salt,
                verifier,
                disabled: false,
            },
        );
        self.save()
    }

    /// Upsert an OIDC identity binding.
    pub fn upsert_oidc_identity(&mut self, binding: OidcIdentity) -> Result<(), TirBaseError> {
        self.state
            .oidc_identities
            .insert(binding.principal_id.clone(), binding);
        self.save()
    }

    /// Verify a local password against the stored verifier (constant-time-ish
    /// compare over fixed-length digest; no early exit on length mismatch path
    /// beyond a trivial length check).
    pub fn verify_local_password(&self, principal_id: &str, password: &str) -> bool {
        let Some(cred) = self.state.local_credentials.get(principal_id) else {
            return false;
        };
        if cred.disabled {
            return false;
        }
        let expected = hmac_sha256(&cred.salt, password.as_bytes());
        constant_time_eq(&expected, &cred.verifier)
    }

    /// Record a failed authentication attempt and return updated lockout state.
    pub fn record_auth_failure(
        &mut self,
        principal_id: &str,
        now_secs: i64,
        threshold: u32,
        lockout_secs: i64,
    ) -> Result<LockoutState, TirBaseError> {
        let state = self
            .state
            .lockouts
            .entry(principal_id.to_string())
            .or_default();
        // Reset window if previous lockout expired.
        if state
            .locked_until
            .map(|until| now_secs >= until)
            .unwrap_or(false)
        {
            state.failed_attempts = 0;
            state.locked_until = None;
        }
        state.failed_attempts = state.failed_attempts.saturating_add(1);
        state.last_failure_at = Some(now_secs);
        if state.failed_attempts >= threshold {
            state.locked_until = Some(now_secs.saturating_add(lockout_secs));
        }
        let out = state.clone();
        self.save()?;
        Ok(out)
    }

    /// Clear lockout/failure counters on successful authentication.
    pub fn record_auth_success(&mut self, principal_id: &str) -> Result<(), TirBaseError> {
        self.state.lockouts.insert(
            principal_id.to_string(),
            LockoutState {
                failed_attempts: 0,
                locked_until: None,
                last_failure_at: None,
            },
        );
        self.save()
    }

    /// Returns lockout-until timestamp if the principal is currently locked.
    pub fn locked_until(&self, principal_id: &str, now_secs: i64) -> Option<i64> {
        self.state
            .lockouts
            .get(principal_id)
            .and_then(|s| s.locked_until)
            .filter(|until| now_secs < *until)
    }

    /// Store a session.
    pub fn put_session(&mut self, session: SessionRecord) -> Result<(), TirBaseError> {
        self.state
            .sessions
            .insert(session.claims.session_id.clone(), session);
        self.save()
    }

    /// Get a session by id.
    pub fn session(&self, session_id: &str) -> Option<&SessionRecord> {
        self.state.sessions.get(session_id)
    }

    /// Revoke a session.
    pub fn revoke_session(&mut self, session_id: &str) -> Result<bool, TirBaseError> {
        let Some(session) = self.state.sessions.get_mut(session_id) else {
            return Ok(false);
        };
        session.revoked = true;
        self.save()?;
        Ok(true)
    }

    /// Revoke a principal (next request must be denied).
    pub fn revoke_principal(&mut self, principal_id: &str) -> Result<(), TirBaseError> {
        self.state.revoked_principals.insert(principal_id.to_string());
        self.save()
    }

    /// Revoke a capability id.
    pub fn revoke_capability(&mut self, capability_id: &str) -> Result<(), TirBaseError> {
        self.state
            .revoked_capabilities
            .insert(capability_id.to_string());
        self.save()
    }

    /// Whether a principal is revoked.
    pub fn is_principal_revoked(&self, principal_id: &str) -> bool {
        self.state.revoked_principals.contains(principal_id)
    }

    /// Revoked principal ids.
    pub fn revoked_principals(&self) -> &BTreeSet<String> {
        &self.state.revoked_principals
    }

    /// Revoked capability ids.
    pub fn revoked_capabilities(&self) -> &BTreeSet<String> {
        &self.state.revoked_capabilities
    }

    /// Look up principal record.
    pub fn principal(&self, principal_id: &str) -> Option<&OperatorPrincipalRecord> {
        self.state.principals.get(principal_id)
    }

    /// Look up OIDC binding.
    pub fn oidc_identity(&self, principal_id: &str) -> Option<&OidcIdentity> {
        self.state.oidc_identities.get(principal_id)
    }

    /// Convenience: ensure a basic principal exists (used by tests/bootstrap).
    pub fn ensure_principal(
        &mut self,
        principal: PrincipalId,
        role: OperatorRole,
        kind: PrincipalKind,
        tenant: TenantPath,
    ) -> Result<(), TirBaseError> {
        let record = OperatorPrincipalRecord {
            principal: PrincipalId { kind, tenant, ..principal },
            role,
            enabled: true,
            mfa: MfaSetting::NotRequired,
            allowed_auth: default_auth_methods(),
        };
        self.upsert_principal(record)
    }
}

/// HMAC-SHA256(key=salt, msg=password) per RFC 2104 (using sha2 only).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    if k.len() < BLOCK {
        k.resize(BLOCK, 0);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, b) in k.iter().enumerate() {
        ipad[i] ^= *b;
        opad[i] ^= *b;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().to_vec()
}

/// Constant-time equality for equal-length digests; returns false on length
/// mismatch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generate a random-ish salt using available time/entropy sources is outside
/// this module's scope; callers/tests provide salt bytes. Helper to derive a
/// deterministic salt is not provided to avoid weak defaults.
pub fn derive_salt(seed: &[u8]) -> Vec<u8> {
    Sha256::digest(seed).to_vec()
}
