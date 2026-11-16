// SPDX-License-Identifier: AGPL-3.0-only

//! Lot and batch traceability (CC-12).
//!
//! Traceability answers two questions about physical product:
//!
//! * *Forward* — "this lot was affected; where did it go?" (recall)
//! * *Backward* — "what went into this lot, and what was decided about it?"
//!   (disposition)
//!
//! # Identity
//!
//! A [`LotRecord`] is one lot, batch or repack identity. It carries the tenant,
//! a human label, the site and location it is currently held at, the devices
//! that observed it, its custody [`TimeWindow`], the ledger entries recording
//! what happened to it, and the quantity plus unit it represents. Identities are
//! registered once; re-registering an identical record is a no-op and
//! re-registering a *different* record under the same id is refused, so a lot id
//! can never silently change meaning.
//!
//! # Lineage
//!
//! [`LotEdge`]s form a directed acyclic graph. Every edge points *downstream*:
//! the child was produced from, repacked out of, or aggregated out of the
//! parent.
//!
//! | [`EdgeKind`] | Meaning |
//! |---|---|
//! | `Split` | the child is a portion of the parent |
//! | `Merge` | the child is a combination of the parents |
//! | `Repack` | the child is the parent in a new container or location |
//! | `Aggregate` | the child aggregates the parents (a pallet of cases) |
//!
//! Every write path rejects an edge that would close a cycle
//! ([`LotError::CycleDetected`]), including self-edges, and traversal keeps a
//! visited set so even data imported from elsewhere cannot make a query loop.
//!
//! # Operations
//!
//! [`LotRegistry::split`], [`LotRegistry::merge`] and [`LotRegistry::repack`]
//! take a caller-supplied `operation_id`. The first commit records the operation
//! together with a digest of the request; replaying the *same* request returns
//! [`OperationOutcome::Replayed`] and writes nothing, while reusing the id for a
//! *different* request is refused with [`LotError::Conflict`]. Quantity is
//! conserved by construction: a split's children must sum to the parent's
//! quantity, a merge's child must equal the sum of its parents, and a repack
//! keeps the quantity. A lot that already has an outgoing split/repack edge is
//! consumed and cannot be split again.
//!
//! # Queries and export
//!
//! [`LotRegistry::forward_trace`] / [`LotRegistry::backward_trace`] return the
//! reachable lots with depth, path and missing-link markers.
//! [`LotRegistry::recall`] turns a forward trace into the report a recall needs:
//! every affected lot *and* every affected location, plus the union of the
//! ledger entries that mention them. [`LotRegistry::disposition_report`] is the
//! backward counterpart. [`LotRegistry::query`], [`LotRegistry::export_json`]
//! and [`LotRegistry::export_csv`] are the read and hand-off surfaces; the JSON
//! export is canonical and carries a digest over its content.

pub mod store;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::excursion::{ExcursionRecord, ExcursionState};
use crate::lineage_ledger::sink::LedgerSink;
use crate::lineage_ledger::{
    AppendRequest, EVENT_LOT_MERGED, EVENT_LOT_REGISTERED, EVENT_LOT_REPACKED, EVENT_LOT_SPLIT,
};
use crate::lot::store::LotStore;

/// Domain-separation context for the traceability export digest.
pub const CONTEXT_LOT_EXPORT: &str = "TirBase/v1/LotTraceabilityExport";

/// Domain-separation context for the operation request digest.
pub const CONTEXT_LOT_OPERATION: &str = "TirBase/v1/LotOperationRequest";

/// Schema identifier carried by [`LotTraceExport`].
pub const LOT_EXPORT_SCHEMA: &str = "TirBase/v1/LotTraceabilityExport";

/// Deepest lineage a single query walks.
pub const MAX_TRACE_DEPTH: usize = 64;

/// Most lots a single query returns; reaching it sets `truncated`.
pub const MAX_TRACE_NODES: usize = 4096;

/// Most device or ledger links one lot identity may carry.
pub const MAX_LOT_LINKS: usize = 256;

/// Most children one split may create.
pub const MAX_OPERATION_CHILDREN: usize = 128;

// ---------------------------------------------------------------------------
// Identity types
// ---------------------------------------------------------------------------

/// What kind of identity a record is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LotKind {
    /// A manufactured or received lot.
    Lot,
    /// A batch within a lot.
    Batch,
    /// A repacked identity derived from another lot.
    Repack,
}

impl LotKind {
    /// Stable string form used in the database, payloads and exports.
    pub fn as_str(self) -> &'static str {
        match self {
            LotKind::Lot => "lot",
            LotKind::Batch => "batch",
            LotKind::Repack => "repack",
        }
    }

    /// Parse the stable string form.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "lot" => Some(LotKind::Lot),
            "batch" => Some(LotKind::Batch),
            "repack" => Some(LotKind::Repack),
            _ => None,
        }
    }

    /// All kinds in a stable order.
    pub fn all() -> [LotKind; 3] {
        [LotKind::Lot, LotKind::Batch, LotKind::Repack]
    }
}

/// Half-open custody window of a lot: when it was received/opened, and when it
/// was consumed or closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start of custody (authenticated-time estimate, seconds).
    pub start_est: i64,
    /// End of custody, when known.
    pub end_est: Option<i64>,
}

impl TimeWindow {
    /// An open window starting at `start_est`.
    pub fn open(start_est: i64) -> Self {
        Self {
            start_est,
            end_est: None,
        }
    }

    /// A closed window.
    pub fn closed(start_est: i64, end_est: i64) -> Self {
        Self {
            start_est,
            end_est: Some(end_est),
        }
    }

    /// Whether the half-open interval contains `at_est`.
    pub fn contains(&self, at_est: i64) -> bool {
        at_est >= self.start_est && self.end_est.is_none_or(|end| at_est < end)
    }

    /// Whether the window is well formed (`end` is not before `start`).
    pub fn is_valid(&self) -> bool {
        self.end_est.is_none_or(|end| end >= self.start_est)
    }
}

/// Kind of ledger entry a lot is linked to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerKind {
    /// An applied-effects ledger entry.
    AppliedEffect,
    /// An excursion record (CC-11).
    ExcursionRecord,
    /// A security event log entry.
    SecurityEvent,
    /// An external reference (export, ERP, paper record).
    External,
}

impl LedgerKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            LedgerKind::AppliedEffect => "applied_effect",
            LedgerKind::ExcursionRecord => "excursion_record",
            LedgerKind::SecurityEvent => "security_event",
            LedgerKind::External => "external",
        }
    }

    /// Parse the stable string form.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "applied_effect" => Some(LedgerKind::AppliedEffect),
            "excursion_record" => Some(LedgerKind::ExcursionRecord),
            "security_event" => Some(LedgerKind::SecurityEvent),
            "external" => Some(LedgerKind::External),
            _ => None,
        }
    }

    /// All kinds in a stable order.
    pub fn all() -> [LedgerKind; 4] {
        [
            LedgerKind::AppliedEffect,
            LedgerKind::ExcursionRecord,
            LedgerKind::SecurityEvent,
            LedgerKind::External,
        ]
    }
}

/// A link from a lot to one ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerLink {
    /// Entry id in the target ledger.
    pub entry_id: String,
    /// Which ledger the entry lives in.
    pub kind: LedgerKind,
}

impl LedgerLink {
    /// Build a link.
    pub fn new(entry_id: impl Into<String>, kind: LedgerKind) -> Self {
        Self {
            entry_id: entry_id.into(),
            kind,
        }
    }
}

/// A recall or disposition decision recorded against a lot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispositionLink {
    /// Record id of the decision (an excursion record, typically).
    pub record_id: String,
    /// Decision (`release`, `hold`, `reject`, `destroy`, …).
    pub disposition: String,
    /// Reason code the decision cites.
    pub reason: String,
    /// When the decision was reached.
    pub decided_est: i64,
}

/// One persisted lot/batch identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LotRecord {
    /// Lot or batch identifier.
    pub lot_id: String,
    /// Tenant owning the identity.
    pub tenant: String,
    /// Kind of identity.
    pub kind: LotKind,
    /// Human-readable label.
    pub label: String,
    /// Site currently holding the lot.
    pub site_id: String,
    /// Location within the site.
    pub location_id: String,
    /// Devices that observed the lot (sorted, unique).
    pub device_ids: Vec<String>,
    /// Custody window.
    pub window: TimeWindow,
    /// Ledger entries that mention the lot.
    pub ledger_entries: Vec<LedgerLink>,
    /// Quantity represented by this identity.
    pub quantity: u64,
    /// Unit of measure (`kg`, `case`, `L`, …).
    pub uom: String,
    /// When the identity was registered.
    pub created_est: i64,
    /// When it last changed.
    pub updated_est: i64,
    /// Monotonic revision.
    pub revision: u64,
}

impl LotRecord {
    /// Ledger entry ids in stable order.
    pub fn ledger_entry_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .ledger_entries
            .iter()
            .map(|link| link.entry_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

/// Everything needed to register a new lot identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LotDraft {
    /// Lot or batch identifier.
    pub lot_id: String,
    /// Tenant owning the identity.
    pub tenant: String,
    /// Kind of identity.
    pub kind: LotKind,
    /// Human-readable label.
    pub label: String,
    /// Site holding the lot.
    pub site_id: String,
    /// Location within the site.
    pub location_id: String,
    /// Devices that observed the lot.
    pub device_ids: Vec<String>,
    /// Custody window.
    pub window: TimeWindow,
    /// Ledger links.
    pub ledger_entries: Vec<LedgerLink>,
    /// Quantity.
    pub quantity: u64,
    /// Unit of measure.
    pub uom: String,
    /// Registration time.
    pub created_est: i64,
}

impl LotDraft {
    /// Start a draft; the label defaults to the lot id.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lot_id: impl Into<String>,
        tenant: impl Into<String>,
        kind: LotKind,
        site_id: impl Into<String>,
        location_id: impl Into<String>,
        quantity: u64,
        uom: impl Into<String>,
        created_est: i64,
    ) -> Self {
        let lot_id = lot_id.into();
        Self {
            label: lot_id.clone(),
            lot_id,
            tenant: tenant.into(),
            kind,
            site_id: site_id.into(),
            location_id: location_id.into(),
            device_ids: Vec::new(),
            window: TimeWindow::open(created_est),
            ledger_entries: Vec::new(),
            quantity,
            uom: uom.into(),
            created_est,
        }
    }

    /// Override the label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Add a device link.
    pub fn with_device(mut self, device_id: impl Into<String>) -> Self {
        self.device_ids.push(device_id.into());
        self
    }

    /// Add a ledger link.
    pub fn with_ledger(mut self, entry_id: impl Into<String>, kind: LedgerKind) -> Self {
        self.ledger_entries.push(LedgerLink::new(entry_id, kind));
        self
    }

    /// Replace the custody window.
    pub fn with_window(mut self, window: TimeWindow) -> Self {
        self.window = window;
        self
    }
}

// ---------------------------------------------------------------------------
// Lineage
// ---------------------------------------------------------------------------

/// How a child lot relates to its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// The child is a portion of the parent.
    Split,
    /// The child combines several parents.
    Merge,
    /// The child is the parent in a new container or location.
    Repack,
    /// The child aggregates the parents (pallet of cases, tote of units).
    Aggregate,
}

impl EdgeKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Split => "split",
            EdgeKind::Merge => "merge",
            EdgeKind::Repack => "repack",
            EdgeKind::Aggregate => "aggregate",
        }
    }

    /// Parse the stable string form.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "split" => Some(EdgeKind::Split),
            "merge" => Some(EdgeKind::Merge),
            "repack" => Some(EdgeKind::Repack),
            "aggregate" => Some(EdgeKind::Aggregate),
            _ => None,
        }
    }

    /// All kinds in a stable order.
    pub fn all() -> [EdgeKind; 4] {
        [
            EdgeKind::Split,
            EdgeKind::Merge,
            EdgeKind::Repack,
            EdgeKind::Aggregate,
        ]
    }

    /// Whether the relationship consumes the parent's quantity.
    fn consumes_parent(self) -> bool {
        matches!(self, EdgeKind::Split | EdgeKind::Repack)
    }
}

/// One edge of the lineage graph. The child is downstream of the parent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LotEdge {
    /// Upstream lot.
    pub parent_id: String,
    /// Downstream lot.
    pub child_id: String,
    /// Relationship kind.
    pub kind: EdgeKind,
    /// Operation that created the edge, when one did.
    pub operation_id: Option<String>,
    /// When the edge was recorded.
    pub created_est: i64,
}

/// One node of a forward or backward trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceNode {
    /// Lot id.
    pub lot_id: String,
    /// Distance from the query root (0 is the root).
    pub depth: usize,
    /// Edge kind that led here (`None` for the root).
    pub via: Option<EdgeKind>,
    /// Immediate upstream/downstream neighbour on the path.
    pub parent: Option<String>,
    /// Full root-to-node path.
    pub path: Vec<String>,
    /// Site, when the identity exists.
    pub site_id: Option<String>,
    /// Location, when the identity exists.
    pub location_id: Option<String>,
    /// Quantity, when the identity exists.
    pub quantity: u64,
    /// `true` when the edge names a lot with no identity record.
    pub missing: bool,
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Kind of derived-lineage operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    /// One lot into several.
    Split,
    /// Several lots into one.
    Merge,
    /// One lot into one, new container.
    Repack,
}

impl OpKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            OpKind::Split => "split",
            OpKind::Merge => "merge",
            OpKind::Repack => "repack",
        }
    }

    /// Parse the stable string form.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "split" => Some(OpKind::Split),
            "merge" => Some(OpKind::Merge),
            "repack" => Some(OpKind::Repack),
            _ => None,
        }
    }

    /// The edge kind the operation writes.
    pub fn edge_kind(self) -> EdgeKind {
        match self {
            OpKind::Split => EdgeKind::Split,
            OpKind::Merge => EdgeKind::Merge,
            OpKind::Repack => EdgeKind::Repack,
        }
    }
}

/// One created (or replayed) lineage operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LotOperation {
    /// Caller-supplied idempotency key.
    pub operation_id: String,
    /// Operation kind.
    pub kind: OpKind,
    /// Upstream lots.
    pub inputs: Vec<String>,
    /// Downstream lots.
    pub outputs: Vec<String>,
    /// When it was applied.
    pub at_est: i64,
    /// SHA-256 of the canonical request.
    pub request_digest: String,
}

/// What an operation call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationOutcome {
    /// The operation ran now and created `created` lots.
    Applied {
        /// Committed operation.
        operation: LotOperation,
        /// Lot ids the operation created.
        created: Vec<String>,
    },
    /// The same operation id and request were already committed.
    Replayed(LotOperation),
}

impl OperationOutcome {
    /// The operation, applied or replayed.
    pub fn operation(&self) -> &LotOperation {
        match self {
            OperationOutcome::Applied { operation, .. } => operation,
            OperationOutcome::Replayed(operation) => operation,
        }
    }

    /// Whether this call was a replay of an earlier commit.
    pub fn replayed(&self) -> bool {
        matches!(self, OperationOutcome::Replayed(_))
    }

    /// Lot ids created by this call (empty on replay).
    pub fn created(&self) -> &[String] {
        match self {
            OperationOutcome::Applied { created, .. } => created,
            OperationOutcome::Replayed(_) => &[],
        }
    }
}

/// One output of a split/merge/repack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildSpec {
    /// New lot id.
    pub lot_id: String,
    /// Human label; defaults to the lot id.
    pub label: String,
    /// Quantity the child represents.
    pub quantity: u64,
    /// Site; defaults to the parent's.
    pub site_id: Option<String>,
    /// Location; defaults to the parent's.
    pub location_id: Option<String>,
}

impl ChildSpec {
    /// Build a child spec; label defaults to the id and location to the parent's.
    pub fn new(lot_id: impl Into<String>, quantity: u64) -> Self {
        let lot_id = lot_id.into();
        Self {
            label: lot_id.clone(),
            lot_id,
            quantity,
            site_id: None,
            location_id: None,
        }
    }

    /// Move the child to a site/location.
    pub fn at(mut self, site_id: impl Into<String>, location_id: impl Into<String>) -> Self {
        self.site_id = Some(site_id.into());
        self.location_id = Some(location_id.into());
        self
    }
}

/// One lot into several.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRequest {
    /// Idempotency key.
    pub operation_id: String,
    /// Lot being split.
    pub parent_id: String,
    /// Derived lots.
    pub children: Vec<ChildSpec>,
    /// When the split happened.
    pub at_est: i64,
}

/// Several lots into one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeRequest {
    /// Idempotency key.
    pub operation_id: String,
    /// Lots being merged.
    pub parent_ids: Vec<String>,
    /// Derived lot.
    pub child: ChildSpec,
    /// When the merge happened.
    pub at_est: i64,
}

/// One lot into one, in a new container or location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepackRequest {
    /// Idempotency key.
    pub operation_id: String,
    /// Lot being repacked.
    pub parent_id: String,
    /// Derived lot.
    pub child: ChildSpec,
    /// When the repack happened.
    pub at_est: i64,
}

// ---------------------------------------------------------------------------
// Queries and reports
// ---------------------------------------------------------------------------

/// Filter for [`LotRegistry::query`], [`LotRegistry::export_json`] and
/// [`LotRegistry::export_csv`]. Every field is optional and combined with AND.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LotQuery {
    /// Tenant.
    pub tenant: Option<String>,
    /// Site.
    pub site_id: Option<String>,
    /// Location.
    pub location_id: Option<String>,
    /// Kind of identity.
    pub kind: Option<LotKind>,
    /// Lot linked to this device.
    pub device_id: Option<String>,
    /// Lot linked to this ledger entry id.
    pub ledger_entry: Option<String>,
    /// Only lots whose custody window starts at or after this time.
    pub start_after_est: Option<i64>,
    /// Only lots whose custody window ends at or before this time.
    pub end_before_est: Option<i64>,
    /// Maximum number of lots returned.
    pub limit: Option<usize>,
}

impl LotQuery {
    /// An unfiltered query.
    pub fn all() -> Self {
        Self::default()
    }

    /// Restrict to one tenant.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Restrict to one site.
    pub fn site(mut self, site_id: impl Into<String>) -> Self {
        self.site_id = Some(site_id.into());
        self
    }

    /// Restrict to one device.
    pub fn device(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    /// Restrict to lots linked to one ledger entry.
    pub fn ledger_entry(mut self, entry_id: impl Into<String>) -> Self {
        self.ledger_entry = Some(entry_id.into());
        self
    }

    /// Restrict to one identity kind.
    pub fn kind(mut self, kind: LotKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Cap the result count.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    fn matches(&self, lot: &LotRecord) -> bool {
        if let Some(tenant) = &self.tenant {
            if &lot.tenant != tenant {
                return false;
            }
        }
        if let Some(site) = &self.site_id {
            if &lot.site_id != site {
                return false;
            }
        }
        if let Some(location) = &self.location_id {
            if &lot.location_id != location {
                return false;
            }
        }
        if let Some(kind) = self.kind {
            if lot.kind != kind {
                return false;
            }
        }
        if let Some(device) = &self.device_id {
            if !lot.device_ids.iter().any(|id| id == device) {
                return false;
            }
        }
        if let Some(entry) = &self.ledger_entry {
            if !lot
                .ledger_entries
                .iter()
                .any(|link| &link.entry_id == entry)
            {
                return false;
            }
        }
        if let Some(start) = self.start_after_est {
            if lot.window.start_est < start {
                return false;
            }
        }
        if let Some(end) = self.end_before_est {
            if lot.window.end_est.is_none_or(|actual| actual > end) {
                return false;
            }
        }
        true
    }
}

/// Request for a recall query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecallRequest {
    /// Lot the recall starts from.
    pub lot_id: String,
    /// Depth limit; defaults to [`MAX_TRACE_DEPTH`].
    pub max_depth: Option<usize>,
}

impl RecallRequest {
    /// Recall everything derived from `lot_id`.
    pub fn new(lot_id: impl Into<String>) -> Self {
        Self {
            lot_id: lot_id.into(),
            max_depth: None,
        }
    }

    /// Bound the walk depth.
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = Some(max_depth);
        self
    }
}

/// One lot affected by a recall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedLot {
    /// Lot id.
    pub lot_id: String,
    /// Distance from the recalled lot (0 is the recalled lot itself).
    pub depth: usize,
    /// Edge kind that led here.
    pub via: Option<EdgeKind>,
    /// Root-to-lot path.
    pub path: Vec<String>,
    /// Site, when the identity exists.
    pub site_id: Option<String>,
    /// Location, when the identity exists.
    pub location_id: Option<String>,
    /// Quantity, when the identity exists.
    pub quantity: u64,
    /// `true` when the identity record is missing.
    pub missing: bool,
    /// Latest recorded disposition, when one exists.
    pub disposition: Option<DispositionLink>,
}

/// Every affected lot at one physical location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedLocation {
    /// Site.
    pub site_id: String,
    /// Location within the site.
    pub location_id: String,
    /// Lots held there (sorted).
    pub lot_ids: Vec<String>,
}

/// The answer to a recall query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallReport {
    /// Lot the recall started from.
    pub origin_lot: String,
    /// When the report was generated.
    pub generated_est: i64,
    /// Every affected lot, breadth-first.
    pub affected: Vec<AffectedLot>,
    /// Every location holding an affected lot, sorted by site then location.
    pub locations: Vec<AffectedLocation>,
    /// Union of the ledger entry ids of every affected lot.
    pub ledger_entries: Vec<String>,
    /// Lots named by an edge but with no identity record.
    pub missing_links: Vec<String>,
    /// `true` when the walk hit the depth or node limit.
    pub truncated: bool,
}

impl RecallReport {
    /// Affected lot ids, in report order.
    pub fn lot_ids(&self) -> Vec<String> {
        self.affected.iter().map(|lot| lot.lot_id.clone()).collect()
    }
}

/// The answer to a disposition (backward) query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispositionReport {
    /// Lot the query started from.
    pub lot_id: String,
    /// When the report was generated.
    pub generated_est: i64,
    /// Every upstream lot, breadth-first.
    pub source_lots: Vec<TraceNode>,
    /// Every location holding an upstream lot, sorted by site then location.
    pub locations: Vec<AffectedLocation>,
    /// Dispositions recorded against the lot or any upstream lot, newest first.
    pub dispositions: Vec<DispositionLink>,
    /// Union of the ledger entry ids of the lot and its upstream lots.
    pub ledger_entries: Vec<String>,
    /// Lots named by an edge but with no identity record.
    pub missing_links: Vec<String>,
    /// `true` when the walk hit the depth or node limit.
    pub truncated: bool,
}

/// Canonical, digest-covered export of a lot trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LotTraceExport {
    /// Schema identifier.
    pub schema: String,
    /// When the export was generated.
    pub generated_est: i64,
    /// Lots matching the query, sorted by id.
    pub lots: Vec<LotRecord>,
    /// Edges touching a selected lot, sorted.
    pub edges: Vec<LotEdge>,
    /// Operations touching a selected lot, sorted by id.
    pub operations: Vec<LotOperation>,
    /// SHA-256 over the content (not including this field).
    pub digest: String,
}

impl LotTraceExport {
    /// Recompute the digest from the current content.
    pub fn compute_digest(&self) -> String {
        #[derive(Serialize)]
        struct Body<'a> {
            schema: &'a str,
            lots: &'a [LotRecord],
            edges: &'a [LotEdge],
            operations: &'a [LotOperation],
        }
        digest_json(
            CONTEXT_LOT_EXPORT,
            &Body {
                schema: &self.schema,
                lots: &self.lots,
                edges: &self.edges,
                operations: &self.operations,
            },
        )
    }

    /// Whether `digest` matches the current content.
    pub fn digest_valid(&self) -> bool {
        self.digest == self.compute_digest()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a traceability call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LotError {
    /// The underlying store failed.
    Store(String),
    /// No lot with that id exists.
    NotFound(String),
    /// A lot id is already registered with different content.
    AlreadyExists(String),
    /// An idempotency key was reused with a different request, or a link
    /// conflicts with the recorded one.
    Conflict(String),
    /// The edge would close a cycle. `path` runs from the child to the parent
    /// and repeats the child to show the closed loop.
    CycleDetected {
        /// The offending edge's parent.
        parent_id: String,
        /// The offending edge's child.
        child_id: String,
        /// Existing path from child back to parent, plus the child again.
        path: Vec<String>,
    },
    /// The request is malformed or internally inconsistent.
    InvalidRequest(String),
    /// Quantities do not balance.
    QuantityMismatch {
        /// Quantity the operation expected.
        expected: u64,
        /// Quantity the request supplied.
        actual: u64,
    },
    /// A query exceeded [`MAX_TRACE_DEPTH`] or [`MAX_TRACE_NODES`] before it
    /// could be answered.
    TraceTooLarge(String),
    /// The lineage ledger append failed (CC-14). The lot or operation was
    /// already committed; replaying the same request repairs the missing entry.
    Ledger(String),
}

impl std::fmt::Display for LotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LotError::Store(detail) => write!(f, "lot store: {detail}"),
            LotError::NotFound(id) => write!(f, "lot {id} not found"),
            LotError::AlreadyExists(id) => write!(f, "lot {id} already exists"),
            LotError::Conflict(detail) => write!(f, "lot conflict: {detail}"),
            LotError::CycleDetected {
                parent_id,
                child_id,
                path,
            } => write!(
                f,
                "edge {parent_id} -> {child_id} would close a cycle: {}",
                path.join(" -> ")
            ),
            LotError::InvalidRequest(detail) => write!(f, "invalid request: {detail}"),
            LotError::QuantityMismatch { expected, actual } => write!(
                f,
                "quantity does not balance: expected {expected}, got {actual}"
            ),
            LotError::TraceTooLarge(detail) => write!(f, "trace too large: {detail}"),
            LotError::Ledger(detail) => write!(f, "lineage ledger: {detail}"),
        }
    }
}

impl std::error::Error for LotError {}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// The persisted lot traceability registry.
///
/// One registry owns one SQLite database (the gateway's `primary.db` in
/// production). All methods are synchronous; the caller supplies the clock.
#[derive(Debug)]
pub struct LotRegistry {
    store: LotStore,
    ledger: Option<Arc<LedgerSink>>,
}

impl LotRegistry {
    /// Open (or create) the registry database at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, LotError> {
        Ok(Self {
            store: LotStore::open(path)?,
            ledger: None,
        })
    }

    /// Open an in-memory registry (tests and ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, LotError> {
        Ok(Self {
            store: LotStore::open_in_memory()?,
            ledger: None,
        })
    }

    /// Append every registration and lineage operation to `ledger` (CC-14).
    ///
    /// Share one [`LedgerSink`] with the excursion workflow so both write a
    /// single chain. Entry ids are derived from the lot or operation the event
    /// records, so a replayed operation appends nothing new.
    pub fn with_ledger(mut self, ledger: Arc<LedgerSink>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// The attached lineage ledger sink, when there is one.
    pub fn ledger(&self) -> Option<&LedgerSink> {
        self.ledger.as_deref()
    }

    // -----------------------------------------------------------------------
    // Identities
    // -----------------------------------------------------------------------

    /// Register a lot identity.
    ///
    /// Re-registering an identical identity returns the stored record unchanged.
    /// Re-registering the same id with different content is refused, so an
    /// identity can never change meaning under a caller's feet.
    pub fn register(&self, draft: LotDraft) -> Result<LotRecord, LotError> {
        validate_draft(&draft)?;
        if let Some(existing) = self.store.load_lot(&draft.lot_id)? {
            let candidate = draft.into_record(1);
            if same_identity(&existing, &candidate) {
                self.record_registered(&existing)?;
                return Ok(existing);
            }
            return Err(LotError::AlreadyExists(existing.lot_id));
        }
        let record = draft.into_record(1);
        self.store.insert_lot(&record)?;
        self.record_registered(&record)?;
        Ok(record)
    }

    /// Load one lot identity.
    pub fn get(&self, lot_id: &str) -> Result<LotRecord, LotError> {
        self.store
            .load_lot(lot_id)?
            .ok_or_else(|| LotError::NotFound(lot_id.to_string()))
    }

    /// Whether an identity record exists.
    pub fn contains(&self, lot_id: &str) -> Result<bool, LotError> {
        Ok(self.store.load_lot(lot_id)?.is_some())
    }

    /// Move a lot to a new site/location.
    pub fn relocate(
        &self,
        lot_id: &str,
        site_id: &str,
        location_id: &str,
        now_est: i64,
    ) -> Result<LotRecord, LotError> {
        if site_id.trim().is_empty() || location_id.trim().is_empty() {
            return Err(LotError::InvalidRequest(
                "site_id and location_id must be non-empty".to_string(),
            ));
        }
        let mut lot = self.get(lot_id)?;
        lot.site_id = site_id.to_string();
        lot.location_id = location_id.to_string();
        self.bump(&mut lot, now_est)?;
        Ok(lot)
    }

    /// Link a device to a lot (idempotent).
    pub fn link_device(
        &self,
        lot_id: &str,
        device_id: &str,
        now_est: i64,
    ) -> Result<LotRecord, LotError> {
        if device_id.trim().is_empty() {
            return Err(LotError::InvalidRequest(
                "device_id must be non-empty".to_string(),
            ));
        }
        let mut lot = self.get(lot_id)?;
        if lot.device_ids.iter().any(|id| id == device_id) {
            return Ok(lot);
        }
        if lot.device_ids.len() >= MAX_LOT_LINKS {
            return Err(LotError::InvalidRequest(format!(
                "lot {lot_id} already carries {MAX_LOT_LINKS} device links"
            )));
        }
        lot.device_ids.push(device_id.to_string());
        lot.device_ids.sort();
        lot.device_ids.dedup();
        self.bump(&mut lot, now_est)?;
        Ok(lot)
    }

    /// Link a ledger entry to a lot (idempotent).
    pub fn link_ledger(
        &self,
        lot_id: &str,
        link: LedgerLink,
        now_est: i64,
    ) -> Result<LotRecord, LotError> {
        if link.entry_id.trim().is_empty() {
            return Err(LotError::InvalidRequest(
                "ledger entry id must be non-empty".to_string(),
            ));
        }
        let mut lot = self.get(lot_id)?;
        if lot.ledger_entries.contains(&link) {
            return Ok(lot);
        }
        if lot.ledger_entries.len() >= MAX_LOT_LINKS {
            return Err(LotError::InvalidRequest(format!(
                "lot {lot_id} already carries {MAX_LOT_LINKS} ledger links"
            )));
        }
        lot.ledger_entries.push(link);
        lot.ledger_entries.sort_by(|a, b| {
            a.entry_id
                .cmp(&b.entry_id)
                .then_with(|| a.kind.cmp(&b.kind))
        });
        self.bump(&mut lot, now_est)?;
        Ok(lot)
    }

    /// Close a lot's custody window at `now_est` (idempotent for an already
    /// closed window at or before that time).
    pub fn close_window(&self, lot_id: &str, now_est: i64) -> Result<LotRecord, LotError> {
        let mut lot = self.get(lot_id)?;
        if lot.window.end_est.is_some_and(|end| end <= now_est) {
            return Ok(lot);
        }
        if now_est < lot.window.start_est {
            return Err(LotError::InvalidRequest(
                "window cannot close before it opens".to_string(),
            ));
        }
        lot.window.end_est = Some(now_est);
        self.bump(&mut lot, now_est)?;
        Ok(lot)
    }

    fn bump(&self, lot: &mut LotRecord, now_est: i64) -> Result<(), LotError> {
        lot.revision += 1;
        lot.updated_est = now_est;
        self.store.update_lot(lot)
    }

    // -----------------------------------------------------------------------
    // Dispositions
    // -----------------------------------------------------------------------

    /// Attach a recall/disposition decision to a lot.
    ///
    /// Replaying the identical decision is a no-op; a different decision under
    /// the same record id is refused.
    pub fn attach_disposition(
        &self,
        lot_id: &str,
        link: DispositionLink,
        _now_est: i64,
    ) -> Result<DispositionLink, LotError> {
        if link.record_id.trim().is_empty() || link.disposition.trim().is_empty() {
            return Err(LotError::InvalidRequest(
                "disposition record_id and disposition must be non-empty".to_string(),
            ));
        }
        self.get(lot_id)?;
        if let Some((disposition, reason, decided_est)) =
            self.store.load_disposition(lot_id, &link.record_id)?
        {
            if disposition == link.disposition
                && reason == link.reason
                && decided_est == link.decided_est
            {
                return Ok(link);
            }
            return Err(LotError::Conflict(format!(
                "disposition {} for lot {lot_id} was recorded as {disposition:?}",
                link.record_id
            )));
        }
        self.store.attach_disposition(
            lot_id,
            &link.record_id,
            &link.disposition,
            &link.reason,
            link.decided_est,
        )?;
        Ok(link)
    }

    /// Bridge a CC-11 excursion record into this lot's disposition history.
    ///
    /// This is the only path that produces a disposition from the excursion
    /// workflow: the record's own `lot_id`, decision, reason and decision time
    /// are copied, so a recall cites the record an operator signed rather than a
    /// link assembled by the caller. Only a *final* record is accepted (resolved
    /// or closed), which means the decision behind the link is a signed
    /// resolution; a record still under quarantine is refused.
    ///
    /// Bridging the same record twice is a no-op, and a record whose `lot_id`
    /// names an unregistered lot is refused with [`LotError::NotFound`] rather
    /// than inventing an identity.
    pub fn link_excursion(
        &self,
        record: &ExcursionRecord,
        now_est: i64,
    ) -> Result<DispositionLink, LotError> {
        let lot_id = record.lot_id.as_deref().ok_or_else(|| {
            LotError::InvalidRequest(format!(
                "excursion record {} names no lot",
                record.record_id
            ))
        })?;
        if !matches!(
            record.state,
            ExcursionState::Resolved | ExcursionState::Closed
        ) {
            return Err(LotError::InvalidRequest(format!(
                "excursion record {} is {} and carries no final disposition",
                record.record_id,
                record.state.as_str()
            )));
        }
        let disposition = record.disposition.as_ref().ok_or_else(|| {
            LotError::InvalidRequest(format!(
                "excursion record {} carries no disposition",
                record.record_id
            ))
        })?;
        let link = DispositionLink {
            record_id: record.record_id.clone(),
            disposition: disposition.disposition.as_str().to_string(),
            reason: disposition.reason.clone(),
            decided_est: disposition.decided_est,
        };
        self.attach_disposition(lot_id, link.clone(), now_est)?;
        Ok(link)
    }

    /// Dispositions recorded against one lot, newest first.
    pub fn dispositions(&self, lot_id: &str) -> Result<Vec<DispositionLink>, LotError> {
        Ok(self
            .store
            .dispositions_of(lot_id)?
            .into_iter()
            .map(
                |(record_id, disposition, reason, decided_est)| DispositionLink {
                    record_id,
                    disposition,
                    reason,
                    decided_est,
                },
            )
            .collect())
    }

    // -----------------------------------------------------------------------
    // Graph writes
    // -----------------------------------------------------------------------

    /// Record one lineage edge after checking it cannot close a cycle.
    ///
    /// Both endpoints need not exist yet: an edge may arrive before the identity
    /// record it names, which is what [`RecallReport::missing_links`] reports.
    /// Re-adding an identical edge is a no-op.
    pub fn add_edge(
        &self,
        parent_id: &str,
        child_id: &str,
        kind: EdgeKind,
        now_est: i64,
    ) -> Result<LotEdge, LotError> {
        if parent_id.trim().is_empty() || child_id.trim().is_empty() {
            return Err(LotError::InvalidRequest(
                "edge endpoints must be non-empty".to_string(),
            ));
        }
        if parent_id == child_id {
            return Err(LotError::CycleDetected {
                parent_id: parent_id.to_string(),
                child_id: child_id.to_string(),
                path: vec![parent_id.to_string(), child_id.to_string()],
            });
        }
        if let Some(path) = self.path_from(child_id, parent_id, MAX_TRACE_DEPTH)? {
            let mut path = path;
            path.push(child_id.to_string());
            return Err(LotError::CycleDetected {
                parent_id: parent_id.to_string(),
                child_id: child_id.to_string(),
                path,
            });
        }
        let edge = LotEdge {
            parent_id: parent_id.to_string(),
            child_id: child_id.to_string(),
            kind,
            operation_id: None,
            created_est: now_est,
        };
        self.store.insert_edge(&edge)?;
        Ok(edge)
    }

    /// Every edge, ordered deterministically.
    pub fn edges(&self) -> Result<Vec<LotEdge>, LotError> {
        self.store.all_edges()
    }

    /// Whether the stored graph contains a cycle.
    ///
    /// [`Self::add_edge`] refuses cycles, so this only fails for data written by
    /// something else (an import, a hand-edited database).
    pub fn check_acyclic(&self) -> Result<(), LotError> {
        let edges = self.store.all_edges()?;
        let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut nodes: BTreeSet<String> = BTreeSet::new();
        for edge in &edges {
            adjacency
                .entry(edge.parent_id.clone())
                .or_default()
                .push(edge.child_id.clone());
            nodes.insert(edge.parent_id.clone());
            nodes.insert(edge.child_id.clone());
        }
        let mut done: BTreeSet<String> = BTreeSet::new();
        let mut active: Vec<String> = Vec::new();
        for node in nodes {
            if done.contains(&node) {
                continue;
            }
            self.dfs_acyclic(&node, &adjacency, &mut active, &mut done)?;
        }
        Ok(())
    }

    fn dfs_acyclic(
        &self,
        node: &str,
        adjacency: &BTreeMap<String, Vec<String>>,
        active: &mut Vec<String>,
        done: &mut BTreeSet<String>,
    ) -> Result<(), LotError> {
        if let Some(position) = active.iter().position(|id| id == node) {
            let mut path = active[position..].to_vec();
            path.push(node.to_string());
            return Err(LotError::CycleDetected {
                parent_id: path[path.len() - 2].clone(),
                child_id: node.to_string(),
                path,
            });
        }
        if done.contains(node) {
            return Ok(());
        }
        active.push(node.to_string());
        if let Some(children) = adjacency.get(node) {
            for child in children {
                self.dfs_acyclic(child, adjacency, active, done)?;
            }
        }
        active.pop();
        done.insert(node.to_string());
        Ok(())
    }

    /// Breadth-first path from `from` to `to` along downstream edges, if one
    /// exists.
    fn path_from(
        &self,
        from: &str,
        to: &str,
        max_depth: usize,
    ) -> Result<Option<Vec<String>>, LotError> {
        if from == to {
            return Ok(Some(vec![from.to_string()]));
        }
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut previous: BTreeMap<String, String> = BTreeMap::new();
        queue.push_back((from.to_string(), 0));
        seen.insert(from.to_string());
        while let Some((id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            for edge in self.store.edges_from(&id)? {
                if !seen.insert(edge.child_id.clone()) {
                    continue;
                }
                previous.insert(edge.child_id.clone(), id.clone());
                if edge.child_id == to {
                    let mut path = vec![to.to_string()];
                    let mut cursor = to.to_string();
                    while let Some(parent) = previous.get(&cursor) {
                        path.push(parent.clone());
                        cursor = parent.clone();
                    }
                    path.reverse();
                    return Ok(Some(path));
                }
                queue.push_back((edge.child_id, depth + 1));
            }
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Operations
    // -----------------------------------------------------------------------

    /// Split one lot into several.
    ///
    /// Children must be new ids, must sum to the parent's quantity, and the
    /// parent must not already have been consumed by a split or repack.
    pub fn split(&self, request: SplitRequest) -> Result<OperationOutcome, LotError> {
        let digest = digest_json(CONTEXT_LOT_OPERATION, &request);
        if let Some(outcome) = self.replay(&request.operation_id, OpKind::Split, &digest)? {
            // Replaying still attempts the append, so a crash between the commit
            // and the ledger write is repaired rather than lost.
            if let OperationOutcome::Replayed(operation) = &outcome {
                self.record_operation(operation)?;
            }
            return Ok(outcome);
        }
        validate_operation_id(&request.operation_id)?;
        if request.children.is_empty() {
            return Err(LotError::InvalidRequest(
                "split needs at least one child".to_string(),
            ));
        }
        if request.children.len() > MAX_OPERATION_CHILDREN {
            return Err(LotError::InvalidRequest(format!(
                "split is limited to {MAX_OPERATION_CHILDREN} children"
            )));
        }
        let parent = self.get(&request.parent_id)?;
        self.ensure_consumable(&parent)?;

        let total: u64 = request.children.iter().map(|child| child.quantity).sum();
        if total != parent.quantity {
            return Err(LotError::QuantityMismatch {
                expected: parent.quantity,
                actual: total,
            });
        }
        let created = self.build_children(&parent, &request.children, request.at_est)?;
        let operation = LotOperation {
            operation_id: request.operation_id,
            kind: OpKind::Split,
            inputs: vec![parent.lot_id.clone()],
            outputs: created.iter().map(|lot| lot.lot_id.clone()).collect(),
            at_est: request.at_est,
            request_digest: digest,
        };
        let edges: Vec<LotEdge> = created
            .iter()
            .map(|child| LotEdge {
                parent_id: parent.lot_id.clone(),
                child_id: child.lot_id.clone(),
                kind: EdgeKind::Split,
                operation_id: Some(operation.operation_id.clone()),
                created_est: request.at_est,
            })
            .collect();
        let mut closed_parent = parent.clone();
        closed_parent.window.end_est = Some(request.at_est);
        closed_parent.updated_est = request.at_est;
        closed_parent.revision += 1;

        self.store.commit_operation(
            &operation,
            &created,
            std::slice::from_ref(&closed_parent),
            &edges,
        )?;
        self.record_operation(&operation)?;
        Ok(OperationOutcome::Applied {
            created: operation.outputs.clone(),
            operation,
        })
    }

    /// Merge several lots into one.
    ///
    /// The child must be a new id and must equal the sum of the parents'
    /// quantities; no parent may already have been consumed.
    pub fn merge(&self, request: MergeRequest) -> Result<OperationOutcome, LotError> {
        let digest = digest_json(CONTEXT_LOT_OPERATION, &request);
        if let Some(outcome) = self.replay(&request.operation_id, OpKind::Merge, &digest)? {
            if let OperationOutcome::Replayed(operation) = &outcome {
                self.record_operation(operation)?;
            }
            return Ok(outcome);
        }
        validate_operation_id(&request.operation_id)?;
        if request.parent_ids.is_empty() {
            return Err(LotError::InvalidRequest(
                "merge needs at least one parent".to_string(),
            ));
        }
        if request.parent_ids.len() > MAX_OPERATION_CHILDREN {
            return Err(LotError::InvalidRequest(format!(
                "merge is limited to {MAX_OPERATION_CHILDREN} parents"
            )));
        }
        let mut parents = Vec::with_capacity(request.parent_ids.len());
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for id in &request.parent_ids {
            if !seen.insert(id.as_str()) {
                return Err(LotError::InvalidRequest(format!("merge names {id} twice")));
            }
            let parent = self.get(id)?;
            self.ensure_consumable(&parent)?;
            parents.push(parent);
        }
        let expected: u64 = parents.iter().map(|lot| lot.quantity).sum();
        if request.child.quantity != expected {
            return Err(LotError::QuantityMismatch {
                expected,
                actual: request.child.quantity,
            });
        }
        let created = self.build_children(
            &parents[0],
            std::slice::from_ref(&request.child),
            request.at_est,
        )?;
        let child = &created[0];
        let operation = LotOperation {
            operation_id: request.operation_id,
            kind: OpKind::Merge,
            inputs: parents.iter().map(|lot| lot.lot_id.clone()).collect(),
            outputs: vec![child.lot_id.clone()],
            at_est: request.at_est,
            request_digest: digest,
        };
        let edges: Vec<LotEdge> = parents
            .iter()
            .map(|parent| LotEdge {
                parent_id: parent.lot_id.clone(),
                child_id: child.lot_id.clone(),
                kind: EdgeKind::Merge,
                operation_id: Some(operation.operation_id.clone()),
                created_est: request.at_est,
            })
            .collect();
        let updated: Vec<LotRecord> = parents
            .iter()
            .map(|parent| {
                let mut closed = parent.clone();
                closed.window.end_est = Some(request.at_est);
                closed.updated_est = request.at_est;
                closed.revision += 1;
                closed
            })
            .collect();

        self.store
            .commit_operation(&operation, &created, &updated, &edges)?;
        self.record_operation(&operation)?;
        Ok(OperationOutcome::Applied {
            created: operation.outputs.clone(),
            operation,
        })
    }

    /// Repack one lot into one, keeping the quantity.
    pub fn repack(&self, request: RepackRequest) -> Result<OperationOutcome, LotError> {
        let digest = digest_json(CONTEXT_LOT_OPERATION, &request);
        if let Some(outcome) = self.replay(&request.operation_id, OpKind::Repack, &digest)? {
            if let OperationOutcome::Replayed(operation) = &outcome {
                self.record_operation(operation)?;
            }
            return Ok(outcome);
        }
        validate_operation_id(&request.operation_id)?;
        let parent = self.get(&request.parent_id)?;
        self.ensure_consumable(&parent)?;
        if request.child.quantity != parent.quantity {
            return Err(LotError::QuantityMismatch {
                expected: parent.quantity,
                actual: request.child.quantity,
            });
        }
        let created = self.build_children(
            &parent,
            std::slice::from_ref(&request.child),
            request.at_est,
        )?;
        let child = &created[0];
        let operation = LotOperation {
            operation_id: request.operation_id,
            kind: OpKind::Repack,
            inputs: vec![parent.lot_id.clone()],
            outputs: vec![child.lot_id.clone()],
            at_est: request.at_est,
            request_digest: digest,
        };
        let edges = vec![LotEdge {
            parent_id: parent.lot_id.clone(),
            child_id: child.lot_id.clone(),
            kind: EdgeKind::Repack,
            operation_id: Some(operation.operation_id.clone()),
            created_est: request.at_est,
        }];
        let mut closed_parent = parent.clone();
        closed_parent.window.end_est = Some(request.at_est);
        closed_parent.updated_est = request.at_est;
        closed_parent.revision += 1;

        self.store.commit_operation(
            &operation,
            &created,
            std::slice::from_ref(&closed_parent),
            &edges,
        )?;
        self.record_operation(&operation)?;
        Ok(OperationOutcome::Applied {
            created: operation.outputs.clone(),
            operation,
        })
    }

    /// Look up one committed operation.
    pub fn operation(&self, operation_id: &str) -> Result<LotOperation, LotError> {
        self.store
            .load_operation(operation_id)?
            .ok_or_else(|| LotError::NotFound(format!("operation {operation_id}")))
    }

    /// Every committed operation, oldest first.
    pub fn operations(&self) -> Result<Vec<LotOperation>, LotError> {
        self.store.all_operations()
    }

    fn replay(
        &self,
        operation_id: &str,
        kind: OpKind,
        digest: &str,
    ) -> Result<Option<OperationOutcome>, LotError> {
        let Some(existing) = self.store.load_operation(operation_id)? else {
            return Ok(None);
        };
        if existing.kind != kind || existing.request_digest != digest {
            return Err(LotError::Conflict(format!(
                "operation {operation_id} was already committed with a different request"
            )));
        }
        Ok(Some(OperationOutcome::Replayed(existing)))
    }

    // -----------------------------------------------------------------------
    // Ledger (CC-14)
    // -----------------------------------------------------------------------

    /// Append the registration of `record` to the attached ledger.
    ///
    /// The entry id is derived from the lot id, so re-registering an identical
    /// identity appends nothing.
    fn record_registered(&self, record: &LotRecord) -> Result<(), LotError> {
        let Some(sink) = self.ledger.as_ref() else {
            return Ok(());
        };
        let mut request = AppendRequest::new(
            format!("lot-registered:{}", record.lot_id),
            sink.actor_did().to_string(),
            EVENT_LOT_REGISTERED,
            serde_json::json!({
                "lot_id": record.lot_id,
                "tenant": record.tenant,
                "kind": record.kind,
                "label": record.label,
                "site_id": record.site_id,
                "location_id": record.location_id,
                "quantity": record.quantity,
                "uom": record.uom,
                "device_ids": record.device_ids,
                "created_est": record.created_est,
            }),
            record.created_est,
        )
        .with_lot(record.lot_id.clone());
        if let Some(device) = record.device_ids.first() {
            request = request.with_device(device.clone());
        }
        sink.append(request).map_err(ledger_error)?;
        Ok(())
    }

    /// Append a committed split/merge/repack to the attached ledger.
    ///
    /// The entry id is the caller's `operation_id`, so replaying the request is
    /// a duplicate rather than a second row. The payload is derived from the
    /// stored operation, which is what makes the replayed payload identical.
    fn record_operation(&self, operation: &LotOperation) -> Result<(), LotError> {
        let Some(sink) = self.ledger.as_ref() else {
            return Ok(());
        };
        let event_type = match operation.kind {
            OpKind::Split => EVENT_LOT_SPLIT,
            OpKind::Merge => EVENT_LOT_MERGED,
            OpKind::Repack => EVENT_LOT_REPACKED,
        };
        // A merge names several inputs and one output, so the produced lot is the
        // one a trace of the chain will reach; splits and repacks hang off the
        // lot they consume.
        let anchor = match operation.kind {
            OpKind::Merge => operation.outputs.first(),
            OpKind::Split | OpKind::Repack => operation.inputs.first(),
        };
        let mut request = AppendRequest::new(
            format!("lot-op:{}", operation.operation_id),
            sink.actor_did().to_string(),
            event_type,
            serde_json::json!({
                "operation_id": operation.operation_id,
                "kind": operation.kind,
                "inputs": operation.inputs,
                "outputs": operation.outputs,
                "at_est": operation.at_est,
                "request_digest": operation.request_digest,
            }),
            operation.at_est,
        );
        if let Some(lot_id) = anchor {
            request = request.with_lot(lot_id.clone());
        }
        sink.append(request).map_err(ledger_error)?;
        Ok(())
    }

    /// Refuse to derive from a lot that was already fully consumed.
    fn ensure_consumable(&self, lot: &LotRecord) -> Result<(), LotError> {
        let consuming = self
            .store
            .edges_from(&lot.lot_id)?
            .into_iter()
            .find(|edge| edge.kind.consumes_parent());
        if let Some(edge) = consuming {
            return Err(LotError::InvalidRequest(format!(
                "lot {} was already consumed by operation {} into {}",
                lot.lot_id,
                edge.operation_id.as_deref().unwrap_or("(unknown)"),
                edge.child_id
            )));
        }
        Ok(())
    }

    fn build_children(
        &self,
        parent: &LotRecord,
        specs: &[ChildSpec],
        at_est: i64,
    ) -> Result<Vec<LotRecord>, LotError> {
        let mut created = Vec::with_capacity(specs.len());
        let mut ids: BTreeSet<&str> = BTreeSet::new();
        for spec in specs {
            if spec.lot_id.trim().is_empty() {
                return Err(LotError::InvalidRequest(
                    "child lot id must be non-empty".to_string(),
                ));
            }
            if !ids.insert(spec.lot_id.as_str()) {
                return Err(LotError::InvalidRequest(format!(
                    "child lot {} is listed twice",
                    spec.lot_id
                )));
            }
            if spec.quantity == 0 {
                return Err(LotError::InvalidRequest(format!(
                    "child lot {} has zero quantity",
                    spec.lot_id
                )));
            }
            if self.store.load_lot(&spec.lot_id)?.is_some() {
                return Err(LotError::AlreadyExists(spec.lot_id.clone()));
            }
            created.push(LotRecord {
                lot_id: spec.lot_id.clone(),
                tenant: parent.tenant.clone(),
                kind: LotKind::Repack,
                label: if spec.label.trim().is_empty() {
                    spec.lot_id.clone()
                } else {
                    spec.label.clone()
                },
                site_id: spec
                    .site_id
                    .clone()
                    .unwrap_or_else(|| parent.site_id.clone()),
                location_id: spec
                    .location_id
                    .clone()
                    .unwrap_or_else(|| parent.location_id.clone()),
                device_ids: parent.device_ids.clone(),
                window: TimeWindow::open(at_est),
                ledger_entries: Vec::new(),
                quantity: spec.quantity,
                uom: parent.uom.clone(),
                created_est: at_est,
                updated_est: at_est,
                revision: 1,
            });
        }
        Ok(created)
    }

    // -----------------------------------------------------------------------
    // Traversal and reports
    // -----------------------------------------------------------------------

    /// Everything derived from `lot_id`, breadth-first, excluding the root.
    pub fn forward_trace(&self, lot_id: &str) -> Result<Vec<TraceNode>, LotError> {
        Ok(self
            .walk(lot_id, Direction::Forward, MAX_TRACE_DEPTH)?
            .nodes)
    }

    /// Everything `lot_id` was derived from, breadth-first, excluding the root.
    pub fn backward_trace(&self, lot_id: &str) -> Result<Vec<TraceNode>, LotError> {
        Ok(self
            .walk(lot_id, Direction::Backward, MAX_TRACE_DEPTH)?
            .nodes)
    }

    /// Recall query: every lot and location affected by `request.lot_id`.
    pub fn recall(&self, request: &RecallRequest, now_est: i64) -> Result<RecallReport, LotError> {
        if request.lot_id.trim().is_empty() {
            return Err(LotError::InvalidRequest(
                "recall needs a lot id".to_string(),
            ));
        }
        let max_depth = request
            .max_depth
            .unwrap_or(MAX_TRACE_DEPTH)
            .min(MAX_TRACE_DEPTH);
        let walk = self.walk(&request.lot_id, Direction::Forward, max_depth)?;

        let root = self.store.load_lot(&request.lot_id)?;
        let mut affected = vec![root_node(&request.lot_id, &root)];
        affected.extend(walk.nodes.iter().map(node_to_affected));

        for entry in &mut affected {
            if !entry.missing {
                let latest = self.store.dispositions_of(&entry.lot_id)?;
                entry.disposition =
                    latest
                        .first()
                        .map(
                            |(record_id, disposition, reason, decided_est)| DispositionLink {
                                record_id: record_id.clone(),
                                disposition: disposition.clone(),
                                reason: reason.clone(),
                                decided_est: *decided_est,
                            },
                        );
            }
        }

        Ok(RecallReport {
            origin_lot: request.lot_id.clone(),
            generated_est: now_est,
            locations: group_locations(
                affected
                    .iter()
                    .filter_map(|lot| {
                        Some((
                            lot.site_id.clone()?,
                            lot.location_id.clone()?,
                            lot.lot_id.clone(),
                        ))
                    })
                    .collect(),
            ),
            ledger_entries: ledger_union(
                affected
                    .iter()
                    .filter(|lot| !lot.missing)
                    .filter_map(|lot| self.store.load_lot(&lot.lot_id).ok().flatten()),
            ),
            missing_links: missing_ids(&affected),
            affected,
            truncated: walk.truncated,
        })
    }

    /// Disposition query: every upstream lot plus the decisions recorded about
    /// them.
    pub fn disposition_report(
        &self,
        lot_id: &str,
        now_est: i64,
    ) -> Result<DispositionReport, LotError> {
        if lot_id.trim().is_empty() {
            return Err(LotError::InvalidRequest(
                "disposition query needs a lot id".to_string(),
            ));
        }
        let root = self.get(lot_id)?;
        let walk = self.walk(lot_id, Direction::Backward, MAX_TRACE_DEPTH)?;

        let mut ids: Vec<String> = walk.nodes.iter().map(|node| node.lot_id.clone()).collect();
        ids.push(root.lot_id.clone());

        let mut dispositions = Vec::new();
        let mut lots = Vec::new();
        for id in &ids {
            if !self.contains(id)? {
                continue;
            }
            let lot = self.get(id)?;
            for (record_id, disposition, reason, decided_est) in self.store.dispositions_of(id)? {
                dispositions.push(DispositionLink {
                    record_id,
                    disposition,
                    reason,
                    decided_est,
                });
            }
            lots.push(lot);
        }
        dispositions.sort_by(|a, b| {
            b.decided_est
                .cmp(&a.decided_est)
                .then_with(|| a.record_id.cmp(&b.record_id))
        });

        let mut locations_input: Vec<(String, String, String)> = Vec::new();
        for lot in &self.store.all_lots()? {
            if ids.iter().any(|id| id == &lot.lot_id) {
                locations_input.push((
                    lot.site_id.clone(),
                    lot.location_id.clone(),
                    lot.lot_id.clone(),
                ));
            }
        }

        Ok(DispositionReport {
            lot_id: lot_id.to_string(),
            generated_est: now_est,
            locations: group_locations(locations_input),
            ledger_entries: ledger_union(lots.into_iter()),
            missing_links: walk
                .nodes
                .iter()
                .filter(|node| node.missing)
                .map(|node| node.lot_id.clone())
                .collect(),
            source_lots: walk.nodes,
            dispositions,
            truncated: walk.truncated,
        })
    }

    // -----------------------------------------------------------------------
    // Queries and export
    // -----------------------------------------------------------------------

    /// Filtered lot identities, oldest custody window first.
    pub fn query(&self, query: &LotQuery) -> Result<Vec<LotRecord>, LotError> {
        let mut lots = self
            .store
            .list_lots(query.tenant.as_deref())?
            .into_iter()
            .filter(|lot| query.matches(lot))
            .collect::<Vec<_>>();
        lots.sort_by(|a, b| {
            a.window
                .start_est
                .cmp(&b.window.start_est)
                .then_with(|| a.lot_id.cmp(&b.lot_id))
        });
        if let Some(limit) = query.limit {
            lots.truncate(limit);
        }
        Ok(lots)
    }

    /// Build the canonical export for `query`.
    ///
    /// The selected lots, every edge touching one of them, and every operation
    /// naming one of them are included; the digest covers that content only, so
    /// two exports of unchanged state agree regardless of `now_est`.
    pub fn export(&self, query: &LotQuery, now_est: i64) -> Result<LotTraceExport, LotError> {
        self.check_acyclic()?;
        let mut lots = self.query(query)?;
        lots.sort_by(|a, b| a.lot_id.cmp(&b.lot_id));
        let selected: BTreeSet<String> = lots.iter().map(|lot| lot.lot_id.clone()).collect();

        let mut edges: Vec<LotEdge> = self
            .store
            .all_edges()?
            .into_iter()
            .filter(|edge| selected.contains(&edge.parent_id) || selected.contains(&edge.child_id))
            .collect();
        edges.sort_by(|a, b| {
            a.parent_id
                .cmp(&b.parent_id)
                .then_with(|| a.child_id.cmp(&b.child_id))
                .then_with(|| a.kind.cmp(&b.kind))
        });

        let mut operations: Vec<LotOperation> = self
            .store
            .all_operations()?
            .into_iter()
            .filter(|operation| {
                operation
                    .inputs
                    .iter()
                    .chain(operation.outputs.iter())
                    .any(|id| selected.contains(id))
            })
            .collect();
        operations.sort_by(|a, b| a.operation_id.cmp(&b.operation_id));

        let mut export = LotTraceExport {
            schema: LOT_EXPORT_SCHEMA.to_string(),
            generated_est: now_est,
            lots,
            edges,
            operations,
            digest: String::new(),
        };
        export.digest = export.compute_digest();
        Ok(export)
    }

    /// Canonical JSON export (compact, digest-covered).
    pub fn export_json(&self, query: &LotQuery, now_est: i64) -> Result<String, LotError> {
        let export = self.export(query, now_est)?;
        serde_json::to_string(&export).map_err(|error| LotError::Store(error.to_string()))
    }

    /// CSV export: one row per selected lot, with its direct parent ids.
    pub fn export_csv(&self, query: &LotQuery) -> Result<String, LotError> {
        let mut lots = self.query(query)?;
        lots.sort_by(|a, b| a.lot_id.cmp(&b.lot_id));
        let mut out = String::from(
            "lot_id,kind,label,tenant,site_id,location_id,quantity,uom,\
             window_start_est,window_end_est,parent_ids,parents,devices,ledger_entries\n",
        );
        for lot in &lots {
            let parents = self.store.edges_to(&lot.lot_id)?;
            let mut parent_ids: Vec<String> = parents.iter().map(|e| e.parent_id.clone()).collect();
            parent_ids.sort();
            parent_ids.dedup();
            let parents_render: Vec<String> = parents
                .iter()
                .map(|edge| format!("{}:{}", edge.parent_id, edge.kind.as_str()))
                .collect();
            let devices = lot.device_ids.join(";");
            let ledger: Vec<String> = lot
                .ledger_entries
                .iter()
                .map(|link| format!("{}:{}", link.kind.as_str(), link.entry_id))
                .collect();
            let row = [
                lot.lot_id.clone(),
                lot.kind.as_str().to_string(),
                lot.label.clone(),
                lot.tenant.clone(),
                lot.site_id.clone(),
                lot.location_id.clone(),
                lot.quantity.to_string(),
                lot.uom.clone(),
                lot.window.start_est.to_string(),
                lot.window
                    .end_est
                    .map(|end| end.to_string())
                    .unwrap_or_default(),
                parent_ids.join(";"),
                parents_render.join(";"),
                devices,
                ledger.join(";"),
            ];
            out.push_str(
                &row.iter()
                    .map(|field| csv_field(field))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            out.push('\n');
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Traversal internals
    // -----------------------------------------------------------------------

    fn walk(&self, start: &str, direction: Direction, max_depth: usize) -> Result<Walk, LotError> {
        let mut queue: VecDeque<Pending> = VecDeque::new();
        let mut visited: BTreeSet<String> = BTreeSet::new();
        visited.insert(start.to_string());
        queue.push_back(Pending {
            id: start.to_string(),
            depth: 0,
            path: vec![start.to_string()],
        });
        let mut nodes = Vec::new();
        let mut truncated = false;

        while let Some(Pending { id, depth, path }) = queue.pop_front() {
            let edges = match direction {
                Direction::Forward => self.store.edges_from(&id)?,
                Direction::Backward => self.store.edges_to(&id)?,
            };
            for edge in edges {
                let next = match direction {
                    Direction::Forward => edge.child_id.clone(),
                    Direction::Backward => edge.parent_id.clone(),
                };
                // A visited set makes a cycle in imported data a dead end rather
                // than an infinite loop.
                if !visited.insert(next.clone()) {
                    continue;
                }
                if depth + 1 > max_depth {
                    truncated = true;
                    continue;
                }
                if nodes.len() >= MAX_TRACE_NODES {
                    truncated = true;
                    break;
                }
                let lot = self.store.load_lot(&next)?;
                let mut next_path = path.clone();
                next_path.push(next.clone());
                nodes.push(TraceNode {
                    lot_id: next.clone(),
                    depth: depth + 1,
                    via: Some(edge.kind),
                    parent: Some(id.clone()),
                    path: next_path.clone(),
                    site_id: lot.as_ref().map(|lot| lot.site_id.clone()),
                    location_id: lot.as_ref().map(|lot| lot.location_id.clone()),
                    quantity: lot.as_ref().map(|lot| lot.quantity).unwrap_or(0),
                    missing: lot.is_none(),
                });
                queue.push_back(Pending {
                    id: next,
                    depth: depth + 1,
                    path: next_path,
                });
            }
            if truncated && nodes.len() >= MAX_TRACE_NODES {
                break;
            }
        }
        Ok(Walk { nodes, truncated })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Forward,
    Backward,
}

#[derive(Debug)]
struct Walk {
    nodes: Vec<TraceNode>,
    truncated: bool,
}

/// One queued node of a breadth-first trace.
struct Pending {
    id: String,
    depth: usize,
    path: Vec<String>,
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

impl LotDraft {
    fn into_record(self, revision: u64) -> LotRecord {
        LotRecord {
            lot_id: self.lot_id,
            tenant: self.tenant,
            kind: self.kind,
            label: self.label,
            site_id: self.site_id,
            location_id: self.location_id,
            device_ids: self.device_ids,
            window: self.window,
            ledger_entries: self.ledger_entries,
            quantity: self.quantity,
            uom: self.uom,
            created_est: self.created_est,
            updated_est: self.created_est,
            revision,
        }
    }
}

fn ledger_error(error: crate::lineage_ledger::LedgerError) -> LotError {
    LotError::Ledger(error.to_string())
}

fn validate_draft(draft: &LotDraft) -> Result<(), LotError> {
    if draft.lot_id.trim().is_empty() {
        return Err(LotError::InvalidRequest(
            "lot_id must be non-empty".to_string(),
        ));
    }
    if draft.tenant.trim().is_empty() {
        return Err(LotError::InvalidRequest(
            "tenant must be non-empty".to_string(),
        ));
    }
    if draft.site_id.trim().is_empty() || draft.location_id.trim().is_empty() {
        return Err(LotError::InvalidRequest(
            "site_id and location_id must be non-empty".to_string(),
        ));
    }
    if draft.uom.trim().is_empty() {
        return Err(LotError::InvalidRequest(
            "uom must be non-empty".to_string(),
        ));
    }
    if !draft.window.is_valid() {
        return Err(LotError::InvalidRequest(
            "time window ends before it starts".to_string(),
        ));
    }
    if draft.device_ids.iter().any(|id| id.trim().is_empty()) {
        return Err(LotError::InvalidRequest(
            "device link id must be non-empty".to_string(),
        ));
    }
    if draft
        .ledger_entries
        .iter()
        .any(|link| link.entry_id.trim().is_empty())
    {
        return Err(LotError::InvalidRequest(
            "ledger entry id must be non-empty".to_string(),
        ));
    }
    if draft.device_ids.len() > MAX_LOT_LINKS || draft.ledger_entries.len() > MAX_LOT_LINKS {
        return Err(LotError::InvalidRequest(format!(
            "a lot carries at most {MAX_LOT_LINKS} device and ledger links"
        )));
    }
    Ok(())
}

fn validate_operation_id(operation_id: &str) -> Result<(), LotError> {
    if operation_id.trim().is_empty() {
        return Err(LotError::InvalidRequest(
            "operation_id must be non-empty".to_string(),
        ));
    }
    Ok(())
}

/// Compare everything except the bookkeeping columns.
fn same_identity(a: &LotRecord, b: &LotRecord) -> bool {
    a.lot_id == b.lot_id
        && a.tenant == b.tenant
        && a.kind == b.kind
        && a.label == b.label
        && a.site_id == b.site_id
        && a.location_id == b.location_id
        && a.device_ids == b.device_ids
        && a.window == b.window
        && a.ledger_entries == b.ledger_entries
        && a.quantity == b.quantity
        && a.uom == b.uom
        && a.created_est == b.created_est
}

fn digest_json(context: &str, value: &impl Serialize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(context.as_bytes());
    hasher.update([0]);
    hasher.update(serde_json::to_vec(value).unwrap_or_default());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn root_node(lot_id: &str, lot: &Option<LotRecord>) -> AffectedLot {
    AffectedLot {
        lot_id: lot_id.to_string(),
        depth: 0,
        via: None,
        path: vec![lot_id.to_string()],
        site_id: lot.as_ref().map(|lot| lot.site_id.clone()),
        location_id: lot.as_ref().map(|lot| lot.location_id.clone()),
        quantity: lot.as_ref().map(|lot| lot.quantity).unwrap_or(0),
        missing: lot.is_none(),
        disposition: None,
    }
}

fn node_to_affected(node: &TraceNode) -> AffectedLot {
    AffectedLot {
        lot_id: node.lot_id.clone(),
        depth: node.depth,
        via: node.via,
        path: node.path.clone(),
        site_id: node.site_id.clone(),
        location_id: node.location_id.clone(),
        quantity: node.quantity,
        missing: node.missing,
        disposition: None,
    }
}

fn missing_ids(affected: &[AffectedLot]) -> Vec<String> {
    let mut ids: Vec<String> = affected
        .iter()
        .filter(|lot| lot.missing)
        .map(|lot| lot.lot_id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn group_locations(entries: Vec<(String, String, String)>) -> Vec<AffectedLocation> {
    let mut grouped: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for (site_id, location_id, lot_id) in entries {
        grouped
            .entry((site_id, location_id))
            .or_default()
            .push(lot_id);
    }
    grouped
        .into_iter()
        .map(|((site_id, location_id), mut lot_ids)| {
            lot_ids.sort();
            lot_ids.dedup();
            AffectedLocation {
                site_id,
                location_id,
                lot_ids,
            }
        })
        .collect()
}

fn ledger_union(lots: impl Iterator<Item = LotRecord>) -> Vec<String> {
    let mut ids: Vec<String> = lots.flat_map(|lot| lot.ledger_entry_ids()).collect();
    ids.sort();
    ids.dedup();
    ids
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
