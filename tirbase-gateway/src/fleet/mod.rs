// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-site fleet and tenant isolation (CC-19).
//!
//! A fleet is a tenant-scoped tree of sites, rooms, containers and gateways.
//! Every record carries a [`TenantPath`] (F-03) and every read is authorized
//! against a [`CapabilityScope`] *and* filtered to that tenant's subtree, so
//! isolation is enforced twice: the caller must be permitted to act in the
//! subtree, and the query itself can never return a sibling tenant's row.
//!
//! # What isolation covers
//!
//! - **Data** — [`FleetRegistry::list_nodes`], [`FleetRegistry::fleet_view`] and
//!   [`FleetRegistry::get_node`].
//! - **Keys** — [`TenantKeyRef`] stores a fingerprint and purpose, never key
//!   material; [`FleetRegistry::tenant_keys`] is subtree-scoped.
//! - **Configs** — [`TenantConfig`] and [`FleetRegistry::config_drift`].
//! - **Exports** — [`FleetExport`] and [`FleetRegistry::export_tenant`] /
//!   [`FleetRegistry::list_exports`] / [`FleetRegistry::read_export`].
//!
//! A cross-tenant read fails with [`FleetError::CrossTenantDenied`] instead of an
//! empty result, so an isolation breach is visible rather than silent.
//!
//! # Bulk operations
//!
//! [`FleetRegistry::plan_rollout`] creates a profile or firmware rollout with a
//! bounded batch size, [`FleetRegistry::run_rollout`] applies one batch and
//! **pauses on the first node that is not healthy**, recording the node, its
//! health and the evidence, and [`FleetRegistry::resume_rollout`] continues only
//! after the operator has fixed the fleet. [`FleetRegistry::config_drift`]
//! compares each node's reported configuration with the tenant's desired one.
//!
//! # Cross-site access
//!
//! Reading across sites needs an explicit capability: a stored
//! [`CrossSiteGrant`] naming the sites and an expiry, issued by an administrator
//! through [`FleetRegistry::register_cross_site_grant`] and passed by id to
//! [`FleetRegistry::cross_site_query`]. A plain tenant-scoped read is not enough,
//! and a query that names a site the grant does not cover is refused.

pub mod store;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fleet::store::FleetStore;
use tirbase_types::identity::{CapabilityScope, OperatorPermission, TenantPath, TenantSegment};

/// Domain-separation context for a fleet export digest.
pub const CONTEXT_FLEET_EXPORT: &str = "TirBase/v1/FleetExport";

/// Schema name written into a fleet export.
pub const EXPORT_SCHEMA: &str = "TirBase/v1/FleetExport";

/// Largest accepted identifier.
pub const MAX_ID_LEN: usize = 64;

/// Longest accepted free-text field.
pub const MAX_TEXT_LEN: usize = 128;

/// Default page size for node listings.
pub const DEFAULT_PAGE_SIZE: usize = 50;

/// Largest page a caller may request.
pub const MAX_PAGE_SIZE: usize = 200;

/// Largest rollout batch a single `run_rollout` call may apply.
pub const MAX_ROLLOUT_BATCH: usize = 100;

/// Most sites one cross-site grant may cover.
pub const MAX_GRANT_SITES: usize = 64;

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// Kind of fleet node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetNodeKind {
    /// A site: the top-level operational unit that owns rooms and gateways.
    Site,
    /// A room or storage area inside a site.
    Room,
    /// A container, trailer or other movable unit.
    Container,
    /// An edge gateway reporting for its site.
    Gateway,
}

impl FleetNodeKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            FleetNodeKind::Site => "site",
            FleetNodeKind::Room => "room",
            FleetNodeKind::Container => "container",
            FleetNodeKind::Gateway => "gateway",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, FleetError> {
        match value {
            "site" => Ok(FleetNodeKind::Site),
            "room" => Ok(FleetNodeKind::Room),
            "container" => Ok(FleetNodeKind::Container),
            "gateway" => Ok(FleetNodeKind::Gateway),
            other => Err(FleetError::Invalid {
                field: "kind".to_string(),
                detail: format!("unknown fleet node kind {other:?}"),
            }),
        }
    }

    /// Every kind in a stable order.
    pub fn all() -> [FleetNodeKind; 4] {
        [
            FleetNodeKind::Site,
            FleetNodeKind::Room,
            FleetNodeKind::Container,
            FleetNodeKind::Gateway,
        ]
    }
}

/// Node health, ordered from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Reporting normally.
    Healthy,
    /// Reporting, but outside its expected envelope.
    Degraded,
    /// Not reporting, or reporting a failure.
    Unhealthy,
    /// No health report yet.
    Unknown,
}

impl HealthStatus {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
            HealthStatus::Unknown => "unknown",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, FleetError> {
        match value {
            "healthy" => Ok(HealthStatus::Healthy),
            "degraded" => Ok(HealthStatus::Degraded),
            "unhealthy" => Ok(HealthStatus::Unhealthy),
            "unknown" => Ok(HealthStatus::Unknown),
            other => Err(FleetError::Invalid {
                field: "health".to_string(),
                detail: format!("unknown health status {other:?}"),
            }),
        }
    }

    /// Severity rank, used to aggregate a site: higher is worse.
    pub fn rank(self) -> u8 {
        match self {
            HealthStatus::Healthy => 0,
            HealthStatus::Unknown => 1,
            HealthStatus::Degraded => 2,
            HealthStatus::Unhealthy => 3,
        }
    }

    /// Whether the node may take part in a bulk rollout.
    pub fn is_rollout_ready(self) -> bool {
        self == HealthStatus::Healthy
    }
}

/// Node compliance status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    /// Every requirement the node is measured against is met.
    Compliant,
    /// At least one requirement is not met.
    NonCompliant,
    /// No compliance evidence yet.
    Unknown,
}

impl ComplianceStatus {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ComplianceStatus::Compliant => "compliant",
            ComplianceStatus::NonCompliant => "non_compliant",
            ComplianceStatus::Unknown => "unknown",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, FleetError> {
        match value {
            "compliant" => Ok(ComplianceStatus::Compliant),
            "non_compliant" => Ok(ComplianceStatus::NonCompliant),
            "unknown" => Ok(ComplianceStatus::Unknown),
            other => Err(FleetError::Invalid {
                field: "compliance".to_string(),
                detail: format!("unknown compliance status {other:?}"),
            }),
        }
    }

    /// Aggregation rank: non-compliant dominates, unknown never claims compliance.
    pub fn rank(self) -> u8 {
        match self {
            ComplianceStatus::Compliant => 0,
            ComplianceStatus::Unknown => 1,
            ComplianceStatus::NonCompliant => 2,
        }
    }
}

/// Firmware channel a node is pinned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareChannel {
    /// Production firmware.
    Stable,
    /// Early-access firmware for a limited set of nodes.
    Canary,
    /// No rollouts may target the node.
    Hold,
}

impl FirmwareChannel {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            FirmwareChannel::Stable => "stable",
            FirmwareChannel::Canary => "canary",
            FirmwareChannel::Hold => "hold",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, FleetError> {
        match value {
            "stable" => Ok(FirmwareChannel::Stable),
            "canary" => Ok(FirmwareChannel::Canary),
            "hold" => Ok(FirmwareChannel::Hold),
            other => Err(FleetError::Invalid {
                field: "channel".to_string(),
                detail: format!("unknown firmware channel {other:?}"),
            }),
        }
    }
}

/// Kind of bulk rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutKind {
    /// Roll out a monitoring/configuration profile.
    Profile,
    /// Roll out a firmware version on a channel.
    Firmware,
}

impl RolloutKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            RolloutKind::Profile => "profile",
            RolloutKind::Firmware => "firmware",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, FleetError> {
        match value {
            "profile" => Ok(RolloutKind::Profile),
            "firmware" => Ok(RolloutKind::Firmware),
            other => Err(FleetError::Invalid {
                field: "kind".to_string(),
                detail: format!("unknown rollout kind {other:?}"),
            }),
        }
    }
}

/// Lifecycle state of a rollout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutState {
    /// Planned, nothing applied.
    Pending,
    /// At least one batch applied; more targets remain.
    Running,
    /// Stopped because a target failed its health pre-check.
    Paused,
    /// Every target applied.
    Completed,
    /// Stopped by an operator; applied targets stay applied.
    Aborted,
}

impl RolloutState {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            RolloutState::Pending => "pending",
            RolloutState::Running => "running",
            RolloutState::Paused => "paused",
            RolloutState::Completed => "completed",
            RolloutState::Aborted => "aborted",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, FleetError> {
        match value {
            "pending" => Ok(RolloutState::Pending),
            "running" => Ok(RolloutState::Running),
            "paused" => Ok(RolloutState::Paused),
            "completed" => Ok(RolloutState::Completed),
            "aborted" => Ok(RolloutState::Aborted),
            other => Err(FleetError::Invalid {
                field: "state".to_string(),
                detail: format!("unknown rollout state {other:?}"),
            }),
        }
    }

    /// Whether the rollout has stopped for good.
    pub fn is_terminal(self) -> bool {
        matches!(self, RolloutState::Completed | RolloutState::Aborted)
    }
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

/// One fleet node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetNode {
    /// Node identifier.
    pub node_id: String,
    /// Tenant the node belongs to.
    pub tenant: TenantPath,
    /// Site, room, container or gateway.
    pub kind: FleetNodeKind,
    /// Site the node belongs to (a site node names itself).
    pub site_id: String,
    /// Parent node, for rooms and containers nested in a site.
    pub parent_id: Option<String>,
    /// Human-readable name.
    pub name: String,
    /// Gateway reporting for this node, when there is one.
    pub gateway_id: Option<String>,
    /// Latest health report.
    pub health: HealthStatus,
    /// Latest compliance status.
    pub compliance: ComplianceStatus,
    /// Firmware version reported by the node.
    pub firmware_version: String,
    /// Firmware channel the node is pinned to.
    pub channel: FirmwareChannel,
    /// Profile applied to the node.
    pub profile_id: String,
    /// Reported configuration.
    pub config: BTreeMap<String, String>,
    /// When the node was last updated.
    pub updated_est: i64,
}

/// A request to register one fleet node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetNodeDraft {
    /// Node identifier.
    pub node_id: String,
    /// Tenant the node belongs to.
    pub tenant: TenantPath,
    /// Site, room, container or gateway.
    pub kind: FleetNodeKind,
    /// Site the node belongs to.
    pub site_id: String,
    /// Parent node, when nested.
    pub parent_id: Option<String>,
    /// Human-readable name.
    pub name: String,
    /// Gateway reporting for the node.
    pub gateway_id: Option<String>,
}

impl FleetNodeDraft {
    /// Start a draft.
    pub fn new(
        node_id: impl Into<String>,
        tenant: TenantPath,
        kind: FleetNodeKind,
        site_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            tenant,
            kind,
            site_id: site_id.into(),
            parent_id: None,
            name: name.into(),
            gateway_id: None,
        }
    }

    /// Nest the node under `parent_id`.
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Record the gateway reporting for this node.
    pub fn with_gateway(mut self, gateway_id: impl Into<String>) -> Self {
        self.gateway_id = Some(gateway_id.into());
        self
    }
}

/// A caller's authorized view of the fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetAccess {
    /// Principal making the request.
    pub principal_id: String,
    /// F-03 capability scope (tenant subtree, permissions, expiry).
    pub scope: CapabilityScope,
}

impl FleetAccess {
    /// Build an access from a principal and its verified capability scope.
    pub fn new(principal_id: impl Into<String>, scope: CapabilityScope) -> Self {
        Self {
            principal_id: principal_id.into(),
            scope,
        }
    }

    /// Whether the scope grants `permission`.
    pub fn grants(&self, permission: OperatorPermission) -> bool {
        self.scope.permissions.contains(&permission)
    }
}

/// Per-site health and compliance roll-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteStatus {
    /// Site identifier.
    pub site_id: String,
    /// Worst health among the site's nodes.
    pub health: HealthStatus,
    /// Worst compliance among the site's nodes.
    pub compliance: ComplianceStatus,
    /// Nodes in the site.
    pub nodes: usize,
    /// Nodes reporting healthy.
    pub healthy: usize,
    /// Nodes reporting degraded.
    pub degraded: usize,
    /// Nodes reporting unhealthy.
    pub unhealthy: usize,
    /// Nodes with no health report.
    pub unknown: usize,
    /// Nodes reporting non-compliant.
    pub non_compliant: usize,
}

/// Fleet-wide totals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSummary {
    /// Sites in scope.
    pub sites: usize,
    /// Rooms in scope.
    pub rooms: usize,
    /// Containers in scope.
    pub containers: usize,
    /// Gateways in scope.
    pub gateways: usize,
    /// Every node in scope.
    pub total: usize,
    /// Nodes reporting healthy.
    pub healthy: usize,
    /// Nodes reporting degraded.
    pub degraded: usize,
    /// Nodes reporting unhealthy.
    pub unhealthy: usize,
    /// Nodes with no health report.
    pub unknown: usize,
    /// Nodes reporting non-compliant.
    pub non_compliant: usize,
}

/// A tenant's fleet view: per-site status plus totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetView {
    /// Tenant the view is scoped to.
    pub tenant: String,
    /// Per-site status, ordered by site id.
    pub sites: Vec<SiteStatus>,
    /// Fleet-wide totals.
    pub summary: FleetSummary,
}

/// Filter for a node listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FleetQuery {
    /// Restrict to these kinds.
    pub kinds: Vec<FleetNodeKind>,
    /// Restrict to this site.
    pub site_id: Option<String>,
    /// Restrict to this health status.
    pub health: Option<HealthStatus>,
    /// Resume after this node id.
    pub cursor: Option<String>,
    /// Page size (clamped to [`MAX_PAGE_SIZE`]).
    pub limit: Option<usize>,
}

/// One page of nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetPage {
    /// Nodes on this page, ordered by id.
    pub items: Vec<FleetNode>,
    /// Cursor for the next page, `None` when the listing is exhausted.
    pub next_cursor: Option<String>,
    /// Total nodes matching the filters, across all pages.
    pub total_matched: usize,
}

// ---------------------------------------------------------------------------
// Tenant keys, configs and exports
// ---------------------------------------------------------------------------

/// A tenant key reference: the fingerprint of the key, never the key itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyRef {
    /// Key identifier.
    pub key_id: String,
    /// Tenant owning the key.
    pub tenant: TenantPath,
    /// What the key is for (`export-signing`, `gateway-identity`, …).
    pub purpose: String,
    /// Lower-case hex SHA-256 of the public key or key material.
    pub fingerprint: String,
    /// When the reference was created.
    pub created_est: i64,
    /// When the key was revoked, if it has been.
    pub revoked_est: Option<i64>,
}

/// A tenant's desired configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Config identifier.
    pub config_id: String,
    /// Tenant owning the config.
    pub tenant: TenantPath,
    /// Site the config applies to; `None` means every site in the tenant.
    pub site_id: Option<String>,
    /// Desired key/value settings.
    pub values: BTreeMap<String, String>,
    /// When the config was last written.
    pub updated_est: i64,
}

/// Drift of one node against a desired config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDriftRow {
    /// Node compared.
    pub node_id: String,
    /// Site of the node.
    pub site_id: String,
    /// Desired keys the node does not report.
    pub missing: Vec<String>,
    /// Keys whose values differ.
    pub differing: Vec<String>,
    /// Keys the node reports that the config does not.
    pub unexpected: Vec<String>,
    /// Whether anything differs.
    pub drifted: bool,
}

/// One audit export of a tenant's fleet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetExport {
    /// Deterministic export id (`exp-` plus the digest prefix).
    pub export_id: String,
    /// Tenant the export covers.
    pub tenant: TenantPath,
    /// Sites covered, sorted.
    pub site_ids: Vec<String>,
    /// Export schema name.
    pub schema: String,
    /// Digest over the exported content.
    pub digest: String,
    /// Number of nodes exported.
    pub node_count: usize,
    /// Nodes exported, sorted.
    pub node_ids: Vec<String>,
    /// When the export was taken.
    pub created_est: i64,
}

/// An explicit cross-site capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSiteGrant {
    /// Grant identifier.
    pub grant_id: String,
    /// Tenant the grant applies within.
    pub tenant: TenantPath,
    /// Sites the grant authorizes, sorted.
    pub sites: Vec<String>,
    /// Principal that issued the grant.
    pub issued_by: String,
    /// When the grant was issued.
    pub issued_est: i64,
    /// When the grant lapses.
    pub expires_est: i64,
    /// Why the grant was issued.
    pub reason: String,
}

/// A cross-site query request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrossSiteQuery {
    /// Grant authorizing the query. Required; a tenant-scoped read is not enough.
    pub grant_id: Option<String>,
    /// Sites to query; empty means every site the grant covers.
    pub sites: Vec<String>,
    /// Restrict to these kinds.
    pub kinds: Vec<FleetNodeKind>,
    /// Restrict to this health status.
    pub health: Option<HealthStatus>,
    /// Resume after this node id.
    pub cursor: Option<String>,
    /// Page size (clamped to [`MAX_PAGE_SIZE`]).
    pub limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// Rollouts
// ---------------------------------------------------------------------------

/// State of one rollout target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutTargetStatus {
    /// Not applied yet.
    Pending,
    /// Applied.
    Applied,
}

/// One node in a rollout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutTarget {
    /// Node to apply to.
    pub node_id: String,
    /// Whether it has been applied.
    pub status: RolloutTargetStatus,
}

/// Why a rollout paused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPause {
    /// Node that failed its health pre-check.
    pub node_id: String,
    /// Its health at that moment.
    pub health: HealthStatus,
    /// Human-readable evidence.
    pub detail: String,
    /// When the pause happened.
    pub paused_est: i64,
}

/// A bulk rollout plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutPlan {
    /// Caller-supplied operation id.
    pub operation_id: String,
    /// Tenant the rollout is scoped to.
    pub tenant: TenantPath,
    /// Profile or firmware.
    pub kind: RolloutKind,
    /// Profile id or firmware version.
    pub value: String,
    /// Channel the firmware rollout pins targets to.
    pub channel: FirmwareChannel,
    /// Current state.
    pub state: RolloutState,
    /// Most targets one `run_rollout` call applies.
    pub batch_size: usize,
    /// Targets in application order.
    pub targets: Vec<RolloutTarget>,
    /// Pause evidence, while paused.
    pub pause: Option<RolloutPause>,
    /// When the plan was created.
    pub created_est: i64,
    /// When the plan last changed.
    pub updated_est: i64,
}

impl RolloutPlan {
    /// Targets applied so far.
    pub fn applied(&self) -> Vec<String> {
        self.targets
            .iter()
            .filter(|target| target.status == RolloutTargetStatus::Applied)
            .map(|target| target.node_id.clone())
            .collect()
    }

    /// Targets still to apply.
    pub fn pending(&self) -> Vec<String> {
        self.targets
            .iter()
            .filter(|target| target.status == RolloutTargetStatus::Pending)
            .map(|target| target.node_id.clone())
            .collect()
    }
}

/// A request to plan a bulk rollout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutRequest {
    /// Caller-supplied operation id.
    pub operation_id: String,
    /// Profile or firmware.
    pub kind: RolloutKind,
    /// Profile id or firmware version.
    pub value: String,
    /// Channel for a firmware rollout.
    pub channel: FirmwareChannel,
    /// Nodes to target; empty means every non-site node in the tenant subtree.
    pub node_ids: Vec<String>,
    /// Batch size, clamped to [`MAX_ROLLOUT_BATCH`].
    pub batch_size: usize,
}

impl RolloutRequest {
    /// Plan a rollout for one value.
    pub fn new(
        operation_id: impl Into<String>,
        kind: RolloutKind,
        value: impl Into<String>,
    ) -> Self {
        Self {
            operation_id: operation_id.into(),
            kind,
            value: value.into(),
            channel: FirmwareChannel::Stable,
            node_ids: Vec::new(),
            batch_size: 25,
        }
    }

    /// Target specific nodes.
    pub fn with_targets(mut self, node_ids: Vec<String>) -> Self {
        self.node_ids = node_ids;
        self
    }

    /// Set the firmware channel.
    pub fn with_channel(mut self, channel: FirmwareChannel) -> Self {
        self.channel = channel;
        self
    }

    /// Set the batch size.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a fleet operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetError {
    /// The underlying store failed.
    Store(String),
    /// No such record.
    NotFound {
        /// Record kind.
        kind: &'static str,
        /// Record identifier.
        id: String,
    },
    /// A field is invalid.
    Invalid {
        /// Offending field.
        field: String,
        /// Why it is invalid.
        detail: String,
    },
    /// An identifier is malformed.
    InvalidIdentifier {
        /// Offending field.
        field: String,
        /// The value as supplied.
        value: String,
    },
    /// The read crossed a tenant boundary.
    CrossTenantDenied {
        /// Principal making the request.
        principal: String,
        /// Tenant asked for.
        tenant: String,
    },
    /// The capability lacks the permission the operation needs.
    PermissionDenied {
        /// Permission required.
        permission: &'static str,
    },
    /// The capability has expired.
    CapabilityExpired {
        /// Instant of the request.
        at_est: i64,
        /// Capability expiry.
        expires_est: i64,
    },
    /// A cross-site query was attempted without an explicit grant.
    CrossSiteCapabilityRequired,
    /// The cross-site grant has lapsed.
    CrossSiteGrantExpired {
        /// Grant identifier.
        grant_id: String,
        /// Its expiry.
        expires_est: i64,
    },
    /// The query named a site the grant does not cover.
    CrossSiteScopeDenied {
        /// Site asked for.
        site_id: String,
    },
    /// The firmware channel is on hold, so no rollout may target it.
    ChannelHeld,
    /// The rollout has already finished.
    RolloutFinished {
        /// Operation identifier.
        operation_id: String,
        /// Its terminal state.
        state: RolloutState,
    },
    /// The rollout is paused and must be resumed before it can run again.
    RolloutPaused {
        /// Operation identifier.
        operation_id: String,
    },
    /// The rollout is not paused, so it cannot be resumed.
    RolloutNotPaused {
        /// Operation identifier.
        operation_id: String,
        /// Its current state.
        state: RolloutState,
    },
    /// The same identifier was reused for different content.
    Conflict(String),
}

impl FleetError {
    /// The offending field, when the error is about one.
    pub fn field(&self) -> Option<&str> {
        match self {
            FleetError::Invalid { field, .. } | FleetError::InvalidIdentifier { field, .. } => {
                Some(field)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for FleetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FleetError::Store(detail) => write!(f, "fleet store: {detail}"),
            FleetError::NotFound { kind, id } => write!(f, "{kind} {id} not found"),
            FleetError::Invalid { field, detail } => write!(f, "invalid {field}: {detail}"),
            FleetError::InvalidIdentifier { field, value } => {
                write!(f, "invalid {field}: {value:?}")
            }
            FleetError::CrossTenantDenied { principal, tenant } => {
                write!(f, "cross-tenant access denied for {principal} to {tenant}")
            }
            FleetError::PermissionDenied { permission } => {
                write!(f, "capability does not grant {permission}")
            }
            FleetError::CapabilityExpired {
                at_est,
                expires_est,
            } => write!(
                f,
                "capability expired at {expires_est} (request at {at_est})"
            ),
            FleetError::CrossSiteCapabilityRequired => {
                write!(f, "cross-site query requires an explicit cross-site grant")
            }
            FleetError::CrossSiteGrantExpired {
                grant_id,
                expires_est,
            } => write!(f, "cross-site grant {grant_id} expired at {expires_est}"),
            FleetError::CrossSiteScopeDenied { site_id } => {
                write!(f, "cross-site grant does not cover site {site_id}")
            }
            FleetError::ChannelHeld => {
                write!(f, "firmware channel is on hold; rollouts are refused")
            }
            FleetError::RolloutFinished {
                operation_id,
                state,
            } => write!(f, "rollout {operation_id} is already {}", state.as_str()),
            FleetError::RolloutPaused { operation_id } => {
                write!(f, "rollout {operation_id} is paused; resume it to continue")
            }
            FleetError::RolloutNotPaused {
                operation_id,
                state,
            } => write!(
                f,
                "rollout {operation_id} is {} and cannot be resumed",
                state.as_str()
            ),
            FleetError::Conflict(detail) => write!(f, "fleet conflict: {detail}"),
        }
    }
}

impl std::error::Error for FleetError {}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// The multi-site fleet service.
///
/// One registry owns one SQLite database (the gateway's `primary.db` in
/// production). All methods are synchronous; the caller supplies the clock.
#[derive(Debug)]
pub struct FleetRegistry {
    store: FleetStore,
}

impl FleetRegistry {
    /// Open (or create) the registry at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, FleetError> {
        Ok(Self {
            store: FleetStore::open(path)?,
        })
    }

    /// Open an in-memory registry (tests and ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, FleetError> {
        Ok(Self {
            store: FleetStore::open_in_memory()?,
        })
    }

    // -----------------------------------------------------------------------
    // Nodes
    // -----------------------------------------------------------------------

    /// Register or update one fleet node.
    pub fn register_node(
        &self,
        access: &FleetAccess,
        draft: FleetNodeDraft,
        at_est: i64,
    ) -> Result<FleetNode, FleetError> {
        self.authorize_write(access, &draft.tenant, at_est)?;
        validate_id("node_id", &draft.node_id)?;
        validate_id("site_id", &draft.site_id)?;
        validate_text("name", &draft.name)?;
        if draft.kind == FleetNodeKind::Site && draft.site_id != draft.node_id {
            return Err(FleetError::Invalid {
                field: "site_id".to_string(),
                detail: "a site node's site_id must be its own id".to_string(),
            });
        }
        if draft.kind != FleetNodeKind::Site && draft.node_id == draft.site_id {
            return Err(FleetError::Invalid {
                field: "site_id".to_string(),
                detail: "only a site node may name itself as its site".to_string(),
            });
        }
        if let Some(parent) = draft.parent_id.as_deref() {
            validate_id("parent_id", parent)?;
            let parent_node = self
                .store
                .node(parent)?
                .ok_or_else(|| FleetError::NotFound {
                    kind: "fleet node",
                    id: parent.to_string(),
                })?;
            if !draft.tenant.contains(&parent_node.tenant) {
                return Err(FleetError::CrossTenantDenied {
                    principal: access.principal_id.clone(),
                    tenant: parent_node.tenant.as_fact_string(),
                });
            }
        }
        if let Some(gateway) = draft.gateway_id.as_deref() {
            validate_id("gateway_id", gateway)?;
        }

        let node = FleetNode {
            node_id: draft.node_id,
            tenant: draft.tenant,
            kind: draft.kind,
            site_id: draft.site_id,
            parent_id: draft.parent_id,
            name: draft.name,
            gateway_id: draft.gateway_id,
            health: HealthStatus::Unknown,
            compliance: ComplianceStatus::Unknown,
            firmware_version: String::new(),
            channel: FirmwareChannel::Stable,
            profile_id: String::new(),
            config: BTreeMap::new(),
            updated_est: at_est,
        };
        self.store.upsert_node(&node)?;
        Ok(node)
    }

    /// One node, if the caller's scope covers its tenant.
    pub fn get_node(
        &self,
        access: &FleetAccess,
        node_id: &str,
        at_est: i64,
    ) -> Result<FleetNode, FleetError> {
        self.authorize_read(access, at_est)?;
        let node = self
            .store
            .node(node_id)?
            .ok_or_else(|| FleetError::NotFound {
                kind: "fleet node",
                id: node_id.to_string(),
            })?;
        if !access.scope.tenant.contains(&node.tenant) {
            return Err(self.cross_tenant(access, &node.tenant));
        }
        Ok(node)
    }

    /// Record a node's health and compliance.
    pub fn set_node_status(
        &self,
        access: &FleetAccess,
        node_id: &str,
        health: HealthStatus,
        compliance: ComplianceStatus,
        at_est: i64,
    ) -> Result<FleetNode, FleetError> {
        self.authorize_write_any(access, at_est)?;
        let mut node = self
            .store
            .node(node_id)?
            .ok_or_else(|| FleetError::NotFound {
                kind: "fleet node",
                id: node_id.to_string(),
            })?;
        if !access.scope.tenant.contains(&node.tenant) {
            return Err(self.cross_tenant(access, &node.tenant));
        }
        node.health = health;
        node.compliance = compliance;
        node.updated_est = at_est;
        self.store.upsert_node(&node)?;
        Ok(node)
    }

    /// Record a node's reported configuration (used for drift detection).
    pub fn set_node_config(
        &self,
        access: &FleetAccess,
        node_id: &str,
        config: BTreeMap<String, String>,
        at_est: i64,
    ) -> Result<FleetNode, FleetError> {
        self.authorize_write_any(access, at_est)?;
        let mut node = self
            .store
            .node(node_id)?
            .ok_or_else(|| FleetError::NotFound {
                kind: "fleet node",
                id: node_id.to_string(),
            })?;
        if !access.scope.tenant.contains(&node.tenant) {
            return Err(self.cross_tenant(access, &node.tenant));
        }
        node.config = config;
        node.updated_est = at_est;
        self.store.upsert_node(&node)?;
        Ok(node)
    }

    /// One page of nodes inside the caller's tenant subtree.
    pub fn list_nodes(
        &self,
        access: &FleetAccess,
        query: &FleetQuery,
        at_est: i64,
    ) -> Result<FleetPage, FleetError> {
        self.authorize_read(access, at_est)?;
        let limit = page_size(query.limit);
        let sites: Vec<String> = query.site_id.iter().cloned().collect();
        let tenant_fact = access.scope.tenant.as_fact_string();
        let total = self
            .store
            .count_nodes(&tenant_fact, &sites, &query.kinds, query.health)?;
        let mut items = self.store.page_nodes(
            &tenant_fact,
            &sites,
            &query.kinds,
            query.health,
            query.cursor.as_deref(),
            limit,
        )?;
        let next_cursor = if items.len() > limit {
            items.truncate(limit);
            items.last().map(|node| node.node_id.clone())
        } else {
            None
        };
        Ok(FleetPage {
            items,
            next_cursor,
            total_matched: total,
        })
    }

    /// Per-site health and compliance roll-up, plus fleet totals.
    pub fn fleet_view(&self, access: &FleetAccess, at_est: i64) -> Result<FleetView, FleetError> {
        self.authorize_read(access, at_est)?;
        let tenant_fact = access.scope.tenant.as_fact_string();
        let nodes = self.store.nodes_in_tenant(&tenant_fact)?;
        Ok(build_view(&tenant_fact, &nodes))
    }

    /// Health and compliance of one site.
    pub fn site_status(
        &self,
        access: &FleetAccess,
        site_id: &str,
        at_est: i64,
    ) -> Result<SiteStatus, FleetError> {
        self.authorize_read(access, at_est)?;
        let tenant_fact = access.scope.tenant.as_fact_string();
        let nodes = self.store.nodes_in_tenant(&tenant_fact)?;
        let site_nodes: Vec<FleetNode> = nodes
            .into_iter()
            .filter(|node| node.site_id == site_id)
            .collect();
        if site_nodes.is_empty() {
            return Err(FleetError::NotFound {
                kind: "site",
                id: site_id.to_string(),
            });
        }
        Ok(site_status_of(site_id, &site_nodes))
    }

    // -----------------------------------------------------------------------
    // Tenant keys and configs
    // -----------------------------------------------------------------------

    /// Register a tenant key by fingerprint. Key material is never accepted.
    pub fn register_tenant_key(
        &self,
        access: &FleetAccess,
        key_id: &str,
        tenant: &TenantPath,
        purpose: &str,
        fingerprint: &str,
        at_est: i64,
    ) -> Result<TenantKeyRef, FleetError> {
        self.authorize_write(access, tenant, at_est)?;
        validate_id("key_id", key_id)?;
        validate_id("purpose", purpose)?;
        validate_sha256("fingerprint", fingerprint)?;
        let key = TenantKeyRef {
            key_id: key_id.to_string(),
            tenant: tenant.clone(),
            purpose: purpose.to_string(),
            fingerprint: fingerprint.to_string(),
            created_est: at_est,
            revoked_est: None,
        };
        self.store.insert_tenant_key(&key)?;
        Ok(key)
    }

    /// Tenant keys inside the caller's subtree.
    pub fn tenant_keys(
        &self,
        access: &FleetAccess,
        at_est: i64,
    ) -> Result<Vec<TenantKeyRef>, FleetError> {
        self.authorize_read(access, at_est)?;
        self.store
            .tenant_keys(&access.scope.tenant.as_fact_string())
    }

    /// Write a tenant's desired configuration.
    pub fn set_config(
        &self,
        access: &FleetAccess,
        config_id: &str,
        tenant: &TenantPath,
        site_id: Option<String>,
        values: BTreeMap<String, String>,
        at_est: i64,
    ) -> Result<TenantConfig, FleetError> {
        self.authorize_write(access, tenant, at_est)?;
        validate_id("config_id", config_id)?;
        if let Some(site) = site_id.as_deref() {
            validate_id("site_id", site)?;
        }
        if values.is_empty() {
            return Err(FleetError::Invalid {
                field: "values".to_string(),
                detail: "a config must set at least one key".to_string(),
            });
        }
        for (key, value) in &values {
            validate_id("values.key", key)?;
            validate_text("values.value", value)?;
        }
        let config = TenantConfig {
            config_id: config_id.to_string(),
            tenant: tenant.clone(),
            site_id,
            values,
            updated_est: at_est,
        };
        self.store.upsert_config(&config)?;
        Ok(config)
    }

    /// Configs inside the caller's subtree.
    pub fn tenant_configs(
        &self,
        access: &FleetAccess,
        at_est: i64,
    ) -> Result<Vec<TenantConfig>, FleetError> {
        self.authorize_read(access, at_est)?;
        self.store.configs(&access.scope.tenant.as_fact_string())
    }

    /// Per-node drift against a desired config.
    pub fn config_drift(
        &self,
        access: &FleetAccess,
        config_id: &str,
        at_est: i64,
    ) -> Result<Vec<ConfigDriftRow>, FleetError> {
        self.authorize_read(access, at_est)?;
        let config = self
            .store
            .config(config_id)?
            .ok_or_else(|| FleetError::NotFound {
                kind: "tenant config",
                id: config_id.to_string(),
            })?;
        if !access.scope.tenant.contains(&config.tenant) {
            return Err(self.cross_tenant(access, &config.tenant));
        }
        let nodes = self
            .store
            .nodes_in_tenant(&config.tenant.as_fact_string())?;
        let mut rows = Vec::new();
        for node in nodes {
            if node.kind == FleetNodeKind::Site {
                continue;
            }
            if let Some(site) = config.site_id.as_deref() {
                if node.site_id != site {
                    continue;
                }
            }
            let mut missing = Vec::new();
            let mut differing = Vec::new();
            let mut unexpected = Vec::new();
            for (key, expected) in &config.values {
                match node.config.get(key) {
                    None => missing.push(key.clone()),
                    Some(actual) if actual != expected => differing.push(key.clone()),
                    Some(_) => {}
                }
            }
            for key in node.config.keys() {
                if !config.values.contains_key(key) {
                    unexpected.push(key.clone());
                }
            }
            missing.sort();
            differing.sort();
            unexpected.sort();
            rows.push(ConfigDriftRow {
                node_id: node.node_id,
                site_id: node.site_id,
                drifted: !(missing.is_empty() && differing.is_empty() && unexpected.is_empty()),
                missing,
                differing,
                unexpected,
            });
        }
        rows.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Ok(rows)
    }

    // -----------------------------------------------------------------------
    // Exports
    // -----------------------------------------------------------------------

    /// Export the caller's fleet. Exports are audit material, so the capability
    /// must grant `audit_read` (or `administer`).
    pub fn export_tenant(
        &self,
        access: &FleetAccess,
        at_est: i64,
    ) -> Result<FleetExport, FleetError> {
        self.authorize_audit(access, at_est)?;
        let tenant_fact = access.scope.tenant.as_fact_string();
        let nodes = self.store.nodes_in_tenant(&tenant_fact)?;
        let site_ids: Vec<String> = nodes
            .iter()
            .map(|node| node.site_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let node_ids: Vec<String> = nodes.iter().map(|node| node.node_id.clone()).collect();
        let digest = export_digest(access.scope.tenant.clone(), at_est, &nodes)?;
        let export_id = format!("exp-{}", &digest[..16]);
        if let Some(existing) = self.store.export(&export_id)? {
            return Ok(existing);
        }
        let export = FleetExport {
            export_id,
            tenant: access.scope.tenant.clone(),
            site_ids,
            schema: EXPORT_SCHEMA.to_string(),
            digest,
            node_count: nodes.len(),
            node_ids,
            created_est: at_est,
        };
        self.store.insert_export(&export)?;
        Ok(export)
    }

    /// Exports inside the caller's subtree.
    pub fn list_exports(
        &self,
        access: &FleetAccess,
        at_est: i64,
    ) -> Result<Vec<FleetExport>, FleetError> {
        self.authorize_audit(access, at_est)?;
        self.store.exports(&access.scope.tenant.as_fact_string())
    }

    /// One export, if the caller's scope covers its tenant.
    pub fn read_export(
        &self,
        access: &FleetAccess,
        export_id: &str,
        at_est: i64,
    ) -> Result<FleetExport, FleetError> {
        self.authorize_audit(access, at_est)?;
        let export = self
            .store
            .export(export_id)?
            .ok_or_else(|| FleetError::NotFound {
                kind: "fleet export",
                id: export_id.to_string(),
            })?;
        if !access.scope.tenant.contains(&export.tenant) {
            return Err(self.cross_tenant(access, &export.tenant));
        }
        Ok(export)
    }

    // -----------------------------------------------------------------------
    // Cross-site access
    // -----------------------------------------------------------------------

    /// Issue an explicit cross-site grant. Requires `administer`.
    pub fn register_cross_site_grant(
        &self,
        access: &FleetAccess,
        grant_id: &str,
        sites: Vec<String>,
        expires_est: i64,
        reason: &str,
        at_est: i64,
    ) -> Result<CrossSiteGrant, FleetError> {
        self.authorize(access, OperatorPermission::Administer, at_est)?;
        validate_id("grant_id", grant_id)?;
        if sites.is_empty() {
            return Err(FleetError::Invalid {
                field: "sites".to_string(),
                detail: "a cross-site grant must name at least one site".to_string(),
            });
        }
        if sites.len() > MAX_GRANT_SITES {
            return Err(FleetError::Invalid {
                field: "sites".to_string(),
                detail: format!("must name at most {MAX_GRANT_SITES} sites"),
            });
        }
        let mut sorted = sites;
        for site in &sorted {
            validate_id("sites", site)?;
        }
        sorted.sort();
        sorted.dedup();
        validate_text("reason", reason)?;
        if expires_est <= at_est {
            return Err(FleetError::Invalid {
                field: "expires_est".to_string(),
                detail: "a grant must expire after it is issued".to_string(),
            });
        }
        let grant = CrossSiteGrant {
            grant_id: grant_id.to_string(),
            tenant: access.scope.tenant.clone(),
            sites: sorted,
            issued_by: access.principal_id.clone(),
            issued_est: at_est,
            expires_est,
            reason: reason.to_string(),
        };
        self.store.insert_grant(&grant)?;
        Ok(grant)
    }

    /// Query across sites. Requires a live [`CrossSiteGrant`] covering every site
    /// asked for; a tenant-scoped capability alone is not sufficient.
    pub fn cross_site_query(
        &self,
        access: &FleetAccess,
        query: &CrossSiteQuery,
        at_est: i64,
    ) -> Result<FleetPage, FleetError> {
        self.authorize_read(access, at_est)?;
        let grant_id = query
            .grant_id
            .as_deref()
            .ok_or(FleetError::CrossSiteCapabilityRequired)?;
        let grant = self
            .store
            .grant(grant_id)?
            .ok_or_else(|| FleetError::NotFound {
                kind: "cross-site grant",
                id: grant_id.to_string(),
            })?;
        if !access.scope.tenant.contains(&grant.tenant) {
            return Err(self.cross_tenant(access, &grant.tenant));
        }
        if grant.expires_est <= at_est {
            return Err(FleetError::CrossSiteGrantExpired {
                grant_id: grant.grant_id,
                expires_est: grant.expires_est,
            });
        }
        let sites: Vec<String> = if query.sites.is_empty() {
            grant.sites.clone()
        } else {
            for site in &query.sites {
                if !grant.sites.contains(site) {
                    return Err(FleetError::CrossSiteScopeDenied {
                        site_id: site.clone(),
                    });
                }
            }
            let mut sites = query.sites.clone();
            sites.sort();
            sites.dedup();
            sites
        };

        let limit = page_size(query.limit);
        let tenant_fact = grant.tenant.as_fact_string();
        let total = self
            .store
            .count_nodes(&tenant_fact, &sites, &query.kinds, query.health)?;
        let mut items = self.store.page_nodes(
            &tenant_fact,
            &sites,
            &query.kinds,
            query.health,
            query.cursor.as_deref(),
            limit,
        )?;
        let next_cursor = if items.len() > limit {
            items.truncate(limit);
            items.last().map(|node| node.node_id.clone())
        } else {
            None
        };
        Ok(FleetPage {
            items,
            next_cursor,
            total_matched: total,
        })
    }

    /// Cross-site grants inside the caller's subtree.
    pub fn cross_site_grants(
        &self,
        access: &FleetAccess,
        at_est: i64,
    ) -> Result<Vec<CrossSiteGrant>, FleetError> {
        self.authorize_audit(access, at_est)?;
        self.store.grants(&access.scope.tenant.as_fact_string())
    }

    // -----------------------------------------------------------------------
    // Rollouts
    // -----------------------------------------------------------------------

    /// Plan a bulk profile or firmware rollout.
    pub fn plan_rollout(
        &self,
        access: &FleetAccess,
        request: RolloutRequest,
        at_est: i64,
    ) -> Result<RolloutPlan, FleetError> {
        self.authorize_write_any(access, at_est)?;
        validate_id("operation_id", &request.operation_id)?;
        validate_text("value", &request.value)?;
        if request.channel == FirmwareChannel::Hold {
            return Err(FleetError::ChannelHeld);
        }
        if self.store.rollout(&request.operation_id)?.is_some() {
            return Err(FleetError::Conflict(format!(
                "rollout {} already exists",
                request.operation_id
            )));
        }
        let tenant_fact = access.scope.tenant.as_fact_string();
        let mut node_ids = if request.node_ids.is_empty() {
            self.store
                .nodes_in_tenant(&tenant_fact)?
                .into_iter()
                .filter(|node| node.kind != FleetNodeKind::Site)
                .map(|node| node.node_id)
                .collect::<Vec<_>>()
        } else {
            for node_id in &request.node_ids {
                validate_id("node_ids", node_id)?;
                let node = self
                    .store
                    .node(node_id)?
                    .ok_or_else(|| FleetError::NotFound {
                        kind: "fleet node",
                        id: node_id.clone(),
                    })?;
                if !access.scope.tenant.contains(&node.tenant) {
                    return Err(self.cross_tenant(access, &node.tenant));
                }
            }
            request.node_ids.clone()
        };
        node_ids.sort();
        node_ids.dedup();
        if node_ids.is_empty() {
            return Err(FleetError::Invalid {
                field: "node_ids".to_string(),
                detail: "the tenant has no nodes to roll out to".to_string(),
            });
        }
        let plan = RolloutPlan {
            operation_id: request.operation_id,
            tenant: access.scope.tenant.clone(),
            kind: request.kind,
            value: request.value,
            channel: request.channel,
            state: RolloutState::Pending,
            batch_size: request.batch_size.clamp(1, MAX_ROLLOUT_BATCH),
            targets: node_ids
                .into_iter()
                .map(|node_id| RolloutTarget {
                    node_id,
                    status: RolloutTargetStatus::Pending,
                })
                .collect(),
            pause: None,
            created_est: at_est,
            updated_est: at_est,
        };
        self.store.upsert_rollout(&plan)?;
        Ok(plan)
    }

    /// Apply at most one batch, pausing on the first node that is not healthy.
    pub fn run_rollout(
        &self,
        access: &FleetAccess,
        operation_id: &str,
        at_est: i64,
    ) -> Result<RolloutPlan, FleetError> {
        let mut plan = self.load_plan(access, operation_id, at_est)?;
        self.authorize_write(access, &plan.tenant, at_est)?;
        if plan.state.is_terminal() {
            return Err(FleetError::RolloutFinished {
                operation_id: plan.operation_id,
                state: plan.state,
            });
        }
        if plan.state == RolloutState::Paused {
            return Err(FleetError::RolloutPaused {
                operation_id: plan.operation_id,
            });
        }

        let mut applied = 0;
        for index in 0..plan.targets.len() {
            if plan.targets[index].status == RolloutTargetStatus::Applied {
                continue;
            }
            if applied >= plan.batch_size {
                break;
            }
            let node_id = plan.targets[index].node_id.clone();
            let mut node = self
                .store
                .node(&node_id)?
                .ok_or_else(|| FleetError::NotFound {
                    kind: "fleet node",
                    id: node_id.clone(),
                })?;
            if !access.scope.tenant.contains(&node.tenant) {
                return Err(self.cross_tenant(access, &node.tenant));
            }
            if !node.health.is_rollout_ready() {
                plan.state = RolloutState::Paused;
                plan.pause = Some(RolloutPause {
                    node_id: node.node_id.clone(),
                    health: node.health,
                    detail: format!(
                        "rollout {} paused: node {} is {} (not healthy)",
                        plan.operation_id,
                        node.node_id,
                        node.health.as_str()
                    ),
                    paused_est: at_est,
                });
                plan.updated_est = at_est;
                self.store.upsert_rollout(&plan)?;
                return Ok(plan);
            }

            match plan.kind {
                RolloutKind::Profile => node.profile_id = plan.value.clone(),
                RolloutKind::Firmware => {
                    node.firmware_version = plan.value.clone();
                    node.channel = plan.channel;
                }
            }
            node.updated_est = at_est;
            self.store.upsert_node(&node)?;
            plan.targets[index].status = RolloutTargetStatus::Applied;
            applied += 1;
        }

        plan.state = if plan.pending().is_empty() {
            RolloutState::Completed
        } else {
            RolloutState::Running
        };
        plan.pause = None;
        plan.updated_est = at_est;
        self.store.upsert_rollout(&plan)?;
        Ok(plan)
    }

    /// Resume a paused rollout: clears the pause and applies the next batch.
    pub fn resume_rollout(
        &self,
        access: &FleetAccess,
        operation_id: &str,
        at_est: i64,
    ) -> Result<RolloutPlan, FleetError> {
        let mut plan = self.load_plan(access, operation_id, at_est)?;
        self.authorize_write(access, &plan.tenant, at_est)?;
        if plan.state != RolloutState::Paused {
            return Err(FleetError::RolloutNotPaused {
                operation_id: plan.operation_id,
                state: plan.state,
            });
        }
        plan.state = RolloutState::Pending;
        plan.pause = None;
        plan.updated_est = at_est;
        self.store.upsert_rollout(&plan)?;
        self.run_rollout(access, operation_id, at_est)
    }

    /// Abort a rollout. Applied targets stay applied; pending ones are not.
    pub fn abort_rollout(
        &self,
        access: &FleetAccess,
        operation_id: &str,
        at_est: i64,
    ) -> Result<RolloutPlan, FleetError> {
        let mut plan = self.load_plan(access, operation_id, at_est)?;
        self.authorize_write(access, &plan.tenant, at_est)?;
        if plan.state.is_terminal() {
            return Err(FleetError::RolloutFinished {
                operation_id: plan.operation_id,
                state: plan.state,
            });
        }
        plan.state = RolloutState::Aborted;
        plan.pause = None;
        plan.updated_est = at_est;
        self.store.upsert_rollout(&plan)?;
        Ok(plan)
    }

    /// One rollout, if the caller's scope covers its tenant.
    pub fn rollout_status(
        &self,
        access: &FleetAccess,
        operation_id: &str,
        at_est: i64,
    ) -> Result<RolloutPlan, FleetError> {
        self.load_plan(access, operation_id, at_est)
    }

    /// Rollouts inside the caller's subtree.
    pub fn list_rollouts(
        &self,
        access: &FleetAccess,
        at_est: i64,
    ) -> Result<Vec<RolloutPlan>, FleetError> {
        self.authorize_read(access, at_est)?;
        self.store.rollouts(&access.scope.tenant.as_fact_string())
    }

    // -----------------------------------------------------------------------
    // Authorization internals
    // -----------------------------------------------------------------------

    fn load_plan(
        &self,
        access: &FleetAccess,
        operation_id: &str,
        at_est: i64,
    ) -> Result<RolloutPlan, FleetError> {
        self.authorize_read(access, at_est)?;
        let plan = self
            .store
            .rollout(operation_id)?
            .ok_or_else(|| FleetError::NotFound {
                kind: "rollout",
                id: operation_id.to_string(),
            })?;
        if !access.scope.tenant.contains(&plan.tenant) {
            return Err(self.cross_tenant(access, &plan.tenant));
        }
        Ok(plan)
    }

    fn authorize(
        &self,
        access: &FleetAccess,
        permission: OperatorPermission,
        at_est: i64,
    ) -> Result<(), FleetError> {
        if at_est > access.scope.expires_at {
            return Err(FleetError::CapabilityExpired {
                at_est,
                expires_est: access.scope.expires_at,
            });
        }
        if !access.grants(permission) {
            return Err(FleetError::PermissionDenied {
                permission: permission_str(permission),
            });
        }
        Ok(())
    }

    fn authorize_read(&self, access: &FleetAccess, at_est: i64) -> Result<(), FleetError> {
        self.authorize(access, OperatorPermission::Read, at_est)
    }

    fn authorize_audit(&self, access: &FleetAccess, at_est: i64) -> Result<(), FleetError> {
        if at_est > access.scope.expires_at {
            return Err(FleetError::CapabilityExpired {
                at_est,
                expires_est: access.scope.expires_at,
            });
        }
        if access.grants(OperatorPermission::AuditRead)
            || access.grants(OperatorPermission::Administer)
        {
            return Ok(());
        }
        Err(FleetError::PermissionDenied {
            permission: "audit_read",
        })
    }

    /// Write, with the target tenant checked against the capability scope.
    fn authorize_write(
        &self,
        access: &FleetAccess,
        tenant: &TenantPath,
        at_est: i64,
    ) -> Result<(), FleetError> {
        self.authorize(access, OperatorPermission::Write, at_est)?;
        if !access.scope.tenant.contains(tenant) {
            return Err(self.cross_tenant(access, tenant));
        }
        Ok(())
    }

    /// Write within the caller's own subtree (the target comes from a stored row).
    fn authorize_write_any(&self, access: &FleetAccess, at_est: i64) -> Result<(), FleetError> {
        self.authorize(access, OperatorPermission::Write, at_est)
    }

    fn cross_tenant(&self, access: &FleetAccess, tenant: &TenantPath) -> FleetError {
        FleetError::CrossTenantDenied {
            principal: access.principal_id.clone(),
            tenant: tenant.as_fact_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn permission_str(permission: OperatorPermission) -> &'static str {
    match permission {
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

fn page_size(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE)
}

/// Build a tenant-scoped view from its nodes.
fn build_view(tenant_fact: &str, nodes: &[FleetNode]) -> FleetView {
    let mut summary = FleetSummary {
        total: nodes.len(),
        ..FleetSummary::default()
    };
    let mut sites: BTreeMap<String, Vec<FleetNode>> = BTreeMap::new();
    for node in nodes {
        match node.kind {
            FleetNodeKind::Site => summary.sites += 1,
            FleetNodeKind::Room => summary.rooms += 1,
            FleetNodeKind::Container => summary.containers += 1,
            FleetNodeKind::Gateway => summary.gateways += 1,
        }
        match node.health {
            HealthStatus::Healthy => summary.healthy += 1,
            HealthStatus::Degraded => summary.degraded += 1,
            HealthStatus::Unhealthy => summary.unhealthy += 1,
            HealthStatus::Unknown => summary.unknown += 1,
        }
        if node.compliance == ComplianceStatus::NonCompliant {
            summary.non_compliant += 1;
        }
        sites
            .entry(node.site_id.clone())
            .or_default()
            .push(node.clone());
    }
    FleetView {
        tenant: tenant_fact.to_string(),
        sites: sites
            .iter()
            .map(|(site_id, site_nodes)| site_status_of(site_id, site_nodes))
            .collect(),
        summary,
    }
}

/// Roll one site's nodes up into a status.
fn site_status_of(site_id: &str, nodes: &[FleetNode]) -> SiteStatus {
    let mut status = SiteStatus {
        site_id: site_id.to_string(),
        health: HealthStatus::Healthy,
        compliance: ComplianceStatus::Compliant,
        nodes: nodes.len(),
        healthy: 0,
        degraded: 0,
        unhealthy: 0,
        unknown: 0,
        non_compliant: 0,
    };
    for node in nodes {
        if node.health.rank() > status.health.rank() {
            status.health = node.health;
        }
        if node.compliance.rank() > status.compliance.rank() {
            status.compliance = node.compliance;
        }
        match node.health {
            HealthStatus::Healthy => status.healthy += 1,
            HealthStatus::Degraded => status.degraded += 1,
            HealthStatus::Unhealthy => status.unhealthy += 1,
            HealthStatus::Unknown => status.unknown += 1,
        }
        if node.compliance == ComplianceStatus::NonCompliant {
            status.non_compliant += 1;
        }
    }
    status
}

fn export_digest(
    tenant: TenantPath,
    at_est: i64,
    nodes: &[FleetNode],
) -> Result<String, FleetError> {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_FLEET_EXPORT.as_bytes());
    hasher.update(b"\0");
    hasher.update(
        serde_json::to_vec(&(tenant, at_est, nodes))
            .map_err(|error| FleetError::Store(format!("encode export: {error}")))?,
    );
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn validate_id(field: &str, value: &str) -> Result<(), FleetError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ID_LEN {
        return Err(FleetError::InvalidIdentifier {
            field: field.to_string(),
            value: value.to_string(),
        });
    }
    let mut characters = trimmed.chars();
    let first = characters.next().unwrap_or(' ');
    if !first.is_ascii_alphanumeric()
        || !characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
        })
    {
        return Err(FleetError::InvalidIdentifier {
            field: field.to_string(),
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_text(field: &str, value: &str) -> Result<(), FleetError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(FleetError::Invalid {
            field: field.to_string(),
            detail: "must be non-empty".to_string(),
        });
    }
    if trimmed.len() > MAX_TEXT_LEN {
        return Err(FleetError::Invalid {
            field: field.to_string(),
            detail: format!("must be at most {MAX_TEXT_LEN} characters"),
        });
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(FleetError::Invalid {
            field: field.to_string(),
            detail: "must not contain control characters".to_string(),
        });
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<(), FleetError> {
    if value.len() != 64
        || !value.chars().all(|character| character.is_ascii_hexdigit())
        || value
            .chars()
            .any(|character| character.is_ascii_uppercase())
    {
        return Err(FleetError::Invalid {
            field: field.to_string(),
            detail: "must be 64 lower-case hex characters".to_string(),
        });
    }
    Ok(())
}

/// Build a tenant path from an organisation and an optional site.
pub fn tenant_path(organisation: &str, site: Option<&str>) -> TenantPath {
    let mut segments = vec![TenantSegment::new(
        tirbase_types::identity::TenantLevel::Organisation,
        organisation,
    )];
    if let Some(site) = site {
        segments.push(TenantSegment::new(
            tirbase_types::identity::TenantLevel::Site,
            site,
        ));
    }
    TenantPath::new(segments)
}
