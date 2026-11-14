// SPDX-License-Identifier: AGPL-3.0-only

//! Operator identity, authentication, RBAC/tenancy, and capability lifecycle (F-03).
//!
//! This module provides the runtime for:
//! - principal/tenant/role model enforcement,
//! - local credentials (offline) and OIDC verification hooks,
//! - session issuance/expiry, lockout, and MFA hooks,
//! - Biscuit capability issuance, attenuation, delegation, and revocation, and
//! - audited authentication and authorization decisions.
//!
//! Data types are defined in `tirbase-types::identity`; this module owns the
//! AGPL runtime behavior and persistence.

pub mod capability;
pub mod service;
pub mod store;

pub use capability::{
    issue_capability_token, attenuate_capability_token, delegate_capability_token,
    verify_capability_token, CapabilityVerification, VerifiedCapability,
};
pub use service::{
    AuthorizationRequest, AuthorizationResult, LockoutPolicy, MfaHook, MfaHookResult,
    OidcVerifier, OperatorAuthError, OperatorAuthService, SessionPolicy,
};
pub use store::{
    LocalCredential, OidcIdentity, OperatorIdentityStore, OperatorPrincipalRecord,
    SessionRecord,
};
