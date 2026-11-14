// SPDX-License-Identifier: Apache-2.0

//! Operator/principal identity, tenancy, role, and capability-scope types.
//!
//! This module defines the shared, `no_std`-capable data model for F-03:
//! principal kinds, the tenant hierarchy, operator roles, and the scope facts
//! carried inside Biscuit capabilities (issuance, attenuation, delegation, and
//! revocation identifiers). Runtime verification, persistence, and audit live in
//! `tirbase-core`.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::Did;

/// Kind of principal that may authenticate or hold a capability.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum PrincipalKind {
    /// Human operator authenticated through local credentials or OIDC.
    User,
    /// Non-interactive workload identity (automation, internal service).
    ServiceAccount,
    /// Physical/device identity acting on behalf of an installation.
    Device,
    /// External integration partner with delegated, scoped access.
    Integrator,
    /// Read-only evidence/audit principal.
    Auditor,
}

impl PrincipalKind {
    /// Canonical string name.
    pub fn as_str(&self) -> &'static str {
        match self {
            PrincipalKind::User => "User",
            PrincipalKind::ServiceAccount => "ServiceAccount",
            PrincipalKind::Device => "Device",
            PrincipalKind::Integrator => "Integrator",
            PrincipalKind::Auditor => "Auditor",
        }
    }
}

/// Error returned when parsing an unknown [`PrincipalKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsePrincipalKindError;

impl fmt::Display for ParsePrincipalKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown principal kind")
    }
}

impl FromStr for PrincipalKind {
    type Err = ParsePrincipalKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "User" => Ok(PrincipalKind::User),
            "ServiceAccount" => Ok(PrincipalKind::ServiceAccount),
            "Device" => Ok(PrincipalKind::Device),
            "Integrator" => Ok(PrincipalKind::Integrator),
            "Auditor" => Ok(PrincipalKind::Auditor),
            _ => Err(ParsePrincipalKindError),
        }
    }
}

/// A principal (human or non-human) that can be authenticated and authorized.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PrincipalId {
    /// Stable principal identifier (e.g. DID or operator id).
    pub id: String,
    /// Kind of principal.
    pub kind: PrincipalKind,
    /// Owning tenant path; operations are scoped to this tenant and its
    /// descendants unless a narrower capability says otherwise.
    pub tenant: TenantPath,
}

impl PrincipalId {
    /// Construct a principal identifier.
    pub fn new(id: impl Into<String>, kind: PrincipalKind, tenant: TenantPath) -> Self {
        PrincipalId {
            id: id.into(),
            kind,
            tenant,
        }
    }

    /// Borrow the stable identifier string.
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// View the identifier as a [`Did`] wrapper.
    pub fn did(&self) -> Did {
        Did::new(self.id.clone())
    }
}

/// Level within the tenant hierarchy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum TenantLevel {
    Organisation,
    Site,
    Store,
    Venue,
    Zone,
    Gate,
    ColdRoom,
}

impl TenantLevel {
    /// Canonical string name.
    pub fn as_str(&self) -> &'static str {
        match self {
            TenantLevel::Organisation => "Organisation",
            TenantLevel::Site => "Site",
            TenantLevel::Store => "Store",
            TenantLevel::Venue => "Venue",
            TenantLevel::Zone => "Zone",
            TenantLevel::Gate => "Gate",
            TenantLevel::ColdRoom => "ColdRoom",
        }
    }

    /// Ordinal depth from the organisation root (0 = organisation).
    pub fn depth(&self) -> u8 {
        match self {
            TenantLevel::Organisation => 0,
            TenantLevel::Site => 1,
            TenantLevel::Store => 2,
            TenantLevel::Venue => 3,
            TenantLevel::Zone => 4,
            TenantLevel::Gate => 5,
            TenantLevel::ColdRoom => 6,
        }
    }
}

/// Error returned when parsing an unknown [`TenantLevel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseTenantLevelError;

impl fmt::Display for ParseTenantLevelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown tenant level")
    }
}

impl FromStr for TenantLevel {
    type Err = ParseTenantLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Organisation" | "organisation" | "org" => Ok(TenantLevel::Organisation),
            "Site" | "site" => Ok(TenantLevel::Site),
            "Store" | "store" => Ok(TenantLevel::Store),
            "Venue" | "venue" => Ok(TenantLevel::Venue),
            "Zone" | "zone" => Ok(TenantLevel::Zone),
            "Gate" | "gate" => Ok(TenantLevel::Gate),
            "ColdRoom" | "cold_room" | "cold-room" => Ok(TenantLevel::ColdRoom),
            _ => Err(ParseTenantLevelError),
        }
    }
}

/// One segment of a tenant path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct TenantSegment {
    /// Hierarchy level of this segment.
    pub level: TenantLevel,
    /// Stable identifier for the segment at this level.
    pub id: String,
}

impl TenantSegment {
    /// Construct a tenant segment.
    pub fn new(level: TenantLevel, id: impl Into<String>) -> Self {
        TenantSegment {
            level,
            id: id.into(),
        }
    }
}

/// Absolute tenant path from organisation down to a specific scope.
///
/// The path is ordered root-first. A capability scoped to a path authorizes the
/// named tenant and all of its descendants, but never ancestors or siblings.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub struct TenantPath {
    /// Ordered root-first segments.
    pub segments: Vec<TenantSegment>,
}

impl TenantPath {
    /// Construct an empty (unscoped) path.
    pub fn root() -> Self {
        TenantPath {
            segments: Vec::new(),
        }
    }

    /// Construct a path from ordered segments.
    pub fn new(segments: Vec<TenantSegment>) -> Self {
        TenantPath { segments }
    }

    /// Append a segment, returning a new path.
    pub fn child(&self, segment: TenantSegment) -> Self {
        let mut segments = self.segments.clone();
        segments.push(segment);
        TenantPath { segments }
    }

    /// Returns `true` if `self` is the same tenant as `other` or an ancestor of
    /// it. Delegation/attenuation may narrow from an ancestor to a descendant
    /// but never the reverse.
    pub fn contains(&self, other: &TenantPath) -> bool {
        if self.segments.len() > other.segments.len() {
            return false;
        }
        self.segments
            .iter()
            .zip(other.segments.iter())
            .all(|(a, b)| a == b)
    }

    /// Returns `true` if `other` is strictly narrower (a descendant) than `self`.
    pub fn strictly_contains(&self, other: &TenantPath) -> bool {
        self.segments.len() < other.segments.len() && self.contains(other)
    }

    /// Canonical `/level:id` rendering for facts and audit records.
    pub fn as_fact_string(&self) -> String {
        if self.segments.is_empty() {
            return String::from("/");
        }
        let mut out = String::new();
        for seg in &self.segments {
            out.push('/');
            out.push_str(seg.level.as_str());
            out.push(':');
            out.push_str(&seg.id);
        }
        out
    }
}

impl fmt::Display for TenantPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_fact_string())
    }
}

/// Operator role used by the F-03 authorization model.
///
/// This is distinct from [`crate::CommandRole`], which models device/guard
/// command roles carried in existing Biscuit tokens.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum OperatorRole {
    Operator,
    Supervisor,
    Qa,
    Auditor,
    Admin,
    Integrator,
    BreakGlass,
}

impl OperatorRole {
    /// Canonical string name used in tokens and audit.
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatorRole::Operator => "operator",
            OperatorRole::Supervisor => "supervisor",
            OperatorRole::Qa => "qa",
            OperatorRole::Auditor => "auditor",
            OperatorRole::Admin => "admin",
            OperatorRole::Integrator => "integrator",
            OperatorRole::BreakGlass => "break-glass",
        }
    }

    /// All defined roles.
    pub const ALL: [OperatorRole; 7] = [
        OperatorRole::Operator,
        OperatorRole::Supervisor,
        OperatorRole::Qa,
        OperatorRole::Auditor,
        OperatorRole::Admin,
        OperatorRole::Integrator,
        OperatorRole::BreakGlass,
    ];
}

/// Error returned when parsing an unknown [`OperatorRole`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOperatorRoleError;

impl fmt::Display for ParseOperatorRoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown operator role")
    }
}

impl FromStr for OperatorRole {
    type Err = ParseOperatorRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "operator" | "Operator" => Ok(OperatorRole::Operator),
            "supervisor" | "Supervisor" => Ok(OperatorRole::Supervisor),
            "qa" | "QA" | "Qa" => Ok(OperatorRole::Qa),
            "auditor" | "Auditor" => Ok(OperatorRole::Auditor),
            "admin" | "Admin" => Ok(OperatorRole::Admin),
            "integrator" | "Integrator" => Ok(OperatorRole::Integrator),
            "break-glass" | "break_glass" | "BreakGlass" => Ok(OperatorRole::BreakGlass),
            _ => Err(ParseOperatorRoleError),
        }
    }
}

/// Vertical context for the role matrix tests.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Vertical {
    Retail,
    ColdChain,
    VenueAccess,
    Manufacturing,
    Healthcare,
}

impl Vertical {
    /// Canonical string name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Vertical::Retail => "retail",
            Vertical::ColdChain => "cold_chain",
            Vertical::VenueAccess => "venue_access",
            Vertical::Manufacturing => "manufacturing",
            Vertical::Healthcare => "healthcare",
        }
    }

    /// All supported verticals.
    pub const ALL: [Vertical; 5] = [
        Vertical::Retail,
        Vertical::ColdChain,
        Vertical::VenueAccess,
        Vertical::Manufacturing,
        Vertical::Healthcare,
    ];
}

/// Error returned when parsing an unknown [`Vertical`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseVerticalError;

impl fmt::Display for ParseVerticalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown vertical")
    }
}

impl FromStr for Vertical {
    type Err = ParseVerticalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "retail" | "Retail" => Ok(Vertical::Retail),
            "cold_chain" | "cold-chain" | "ColdChain" => Ok(Vertical::ColdChain),
            "venue_access" | "venue-access" | "VenueAccess" => Ok(Vertical::VenueAccess),
            "manufacturing" | "Manufacturing" => Ok(Vertical::Manufacturing),
            "healthcare" | "Healthcare" => Ok(Vertical::Healthcare),
            _ => Err(ParseVerticalError),
        }
    }
}

/// A permission that can be granted by an operator capability.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum OperatorPermission {
    /// Read operational state within scope.
    Read,
    /// Write/mutate operational state within scope.
    Write,
    /// Issue operational commands within scope.
    Command,
    /// Approve/override workflow steps (supervision, QA sign-off).
    Approve,
    /// Read audit/evidence material.
    AuditRead,
    /// Administer principals, sessions, and capabilities within scope.
    Administer,
    /// Delegate an attenuated capability within scope.
    Delegate,
    /// Break-glass emergency action (always explicitly audited).
    BreakGlass,
}

impl OperatorPermission {
    /// Canonical string name.
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatorPermission::Read => "read",
            OperatorPermission::Write => "write",
            OperatorPermission::Command => "command",
            OperatorPermission::Approve => "approve",
            OperatorPermission::AuditRead => "audit_read",
            OperatorPermission::Administer => "administer",
            OperatorPermission::Delegate => "delegate",
            OperatorPermission::BreakGlass => "break_glass",
        }
    }

    /// All permissions.
    pub const ALL: [OperatorPermission; 8] = [
        OperatorPermission::Read,
        OperatorPermission::Write,
        OperatorPermission::Command,
        OperatorPermission::Approve,
        OperatorPermission::AuditRead,
        OperatorPermission::Administer,
        OperatorPermission::Delegate,
        OperatorPermission::BreakGlass,
    ];
}

/// Error returned when parsing an unknown [`OperatorPermission`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOperatorPermissionError;

impl fmt::Display for ParseOperatorPermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown operator permission")
    }
}

impl FromStr for OperatorPermission {
    type Err = ParseOperatorPermissionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" | "Read" => Ok(OperatorPermission::Read),
            "write" | "Write" => Ok(OperatorPermission::Write),
            "command" | "Command" => Ok(OperatorPermission::Command),
            "approve" | "Approve" => Ok(OperatorPermission::Approve),
            "audit_read" | "AuditRead" | "audit-read" => Ok(OperatorPermission::AuditRead),
            "administer" | "Administer" => Ok(OperatorPermission::Administer),
            "delegate" | "Delegate" => Ok(OperatorPermission::Delegate),
            "break_glass" | "break-glass" | "BreakGlass" => Ok(OperatorPermission::BreakGlass),
            _ => Err(ParseOperatorPermissionError),
        }
    }
}

/// Scope of an issued, attenuated, or delegated capability.
///
/// A derived scope MUST be equal to or narrower than its parent in tenant path,
/// permissions, and expiry; delegation cannot widen authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityScope {
    /// Tenant boundary; authorizes this path and its descendants only.
    pub tenant: TenantPath,
    /// Granted permissions (set semantics; duplicates are not meaningful).
    pub permissions: Vec<OperatorPermission>,
    /// Optional vertical restriction.
    pub vertical: Option<Vertical>,
    /// Expiry as Unix seconds (inclusive upper bound enforced by verifier).
    pub expires_at: i64,
}

impl CapabilityScope {
    /// Construct a scope.
    pub fn new(
        tenant: TenantPath,
        permissions: Vec<OperatorPermission>,
        vertical: Option<Vertical>,
        expires_at: i64,
    ) -> Self {
        CapabilityScope {
            tenant,
            permissions,
            vertical,
            expires_at,
        }
    }

    /// Returns `true` if `child` is not wider than `self` in any dimension.
    pub fn can_attenuate_to(&self, child: &CapabilityScope) -> bool {
        if !self.tenant.contains(&child.tenant) {
            return false;
        }
        if child.expires_at > self.expires_at {
            return false;
        }
        if let Some(parent_v) = self.vertical {
            match child.vertical {
                Some(v) if v == parent_v => {}
                // Narrowing to "no vertical" would widen reach; disallow.
                _ => return false,
            }
        }
        child
            .permissions
            .iter()
            .all(|p| self.permissions.iter().any(|pp| pp == p))
    }
}

/// Attenuation/delegation constraints attached to a capability block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DelegationConstraints {
    /// Whether this capability may be delegated further.
    pub delegatable: bool,
    /// Maximum additional delegation depth allowed from this capability (0 = no
    /// further delegation).
    pub max_depth: u8,
}

/// Facts carried by an operator capability token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OperatorCapability {
    /// Principal the capability was issued to.
    pub subject: PrincipalId,
    /// Role bound to the capability.
    pub role: OperatorRole,
    /// Effective scope.
    pub scope: CapabilityScope,
    /// Delegation constraints.
    pub delegation: DelegationConstraints,
    /// Issuer principal id (or authority id for root-issued tokens).
    pub issuer: String,
    /// Stable capability identifier (revocation handle).
    pub capability_id: String,
    /// Issuance time (Unix seconds).
    pub issued_at: i64,
}

/// Identifier of a revocable capability or principal binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct RevocationId(pub String);

impl RevocationId {
    /// Construct a revocation identifier.
    pub fn new(id: impl Into<String>) -> Self {
        RevocationId(id.into())
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reason an authentication or authorization decision was made.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AuthDecision {
    Allow,
    Deny,
}

impl AuthDecision {
    /// Canonical string name.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthDecision::Allow => "allow",
            AuthDecision::Deny => "deny",
        }
    }
}

/// Lifecycle of an operator session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionClaims {
    /// Session identifier.
    pub session_id: String,
    /// Authenticated principal.
    pub principal: PrincipalId,
    /// Role active for this session.
    pub role: OperatorRole,
    /// Effective tenant scope for this session.
    pub tenant: TenantPath,
    /// Issued-at (Unix seconds).
    pub issued_at: i64,
    /// Expiry (Unix seconds).
    pub expires_at: i64,
    /// Authentication method used (e.g. "local", "oidc").
    pub auth_method: String,
    /// Whether MFA was satisfied for this session.
    pub mfa_satisfied: bool,
}

/// Local-credential authentication method marker.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AuthMethod {
    /// Local password/credential store (offline-capable).
    Local,
    /// OpenID Connect / connected identity provider.
    Oidc,
}

impl AuthMethod {
    /// Canonical string name.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Local => "local",
            AuthMethod::Oidc => "oidc",
        }
    }
}

/// MFA hook outcome supplied by a deployment-specific verifier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MfaRequirement {
    /// MFA not required for this principal/session.
    NotRequired,
    /// MFA required and satisfied.
    Satisfied,
    /// MFA required but not satisfied.
    Required,
}

impl MfaRequirement {
    /// Returns `true` if authentication may proceed.
    pub fn allows_auth(&self) -> bool {
        !matches!(self, MfaRequirement::Required)
    }
}
