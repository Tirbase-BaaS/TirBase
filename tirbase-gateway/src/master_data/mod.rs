// SPDX-License-Identifier: AGPL-3.0-only

//! Master data service (CC-15).
//!
//! Sites, locations, storage zones, trade items, parties, lots, devices and
//! carriers, stored as **versioned records with effective dates**. A record is
//! never overwritten: a change appends the next version and closes the previous
//! version's half-open effective range `[from, to)` at the new start. Every
//! create and revision is also written to an append-only audit history with the
//! actor, the reason and the before/after content digests.
//!
//! # Why effective dates
//!
//! A cold-chain event is interpreted against the master data that was in force
//! *when it happened*, not against today's values. [`MasterData::resolve`] (and
//! the `resolve_lot` / `resolve_excursion` bridges to CC-12 and CC-11) resolves
//! each reference at the event's own timestamp, so revising a site's name or
//! suspending a carrier cannot rewrite what a historical event means.
//!
//! # Validation
//!
//! - Identifiers: internal ids match `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`; GLNs are
//!   13 digits with a GS1 check digit, GTINs 14 digits with a check digit.
//! - Units: quantities use a documented [`QuantityUnit`]; storage-zone bands must
//!   be [`FixedPointValue`]s in the registry's degree-Celsius unit (`unit_id = 1`,
//!   exponent -1) with `min < max`.
//! - Hierarchies: a location's parent must exist, be in the same site, not be
//!   retired, and must not create a cycle or exceed [`MAX_LOCATION_DEPTH`].
//! - Status: [`LifecycleStatus`] transitions are checked; `Retired` is terminal
//!   and cannot be referenced by new records.
//!
//! # Exports
//!
//! [`MasterData::export_json`] is the canonical, digested query export;
//! [`MasterData::export_csv`] is the flat reporting export; and
//! [`MasterData::export_epcis`] builds an EPCIS 2.0 vocabulary document
//! (`BizLocation` or `ReadPoint`) so captured events can cite SGLNs that the
//! document defines.

pub mod epcis;
pub mod store;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::excursion::ExcursionRecord;
use crate::lot::LotRecord;
use crate::master_data::epcis::{EpcisVocabulary, EpcisVocabularyDocument};
use crate::master_data::store::MasterDataStore;
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

/// Domain-separation context for the export digest.
pub const CONTEXT_MASTER_EXPORT: &str = "TirBase/v1/MasterDataExport";

/// Domain-separation context for a version's content digest.
pub const CONTEXT_MASTER_VERSION: &str = "TirBase/v1/MasterDataVersion";

/// Longest accepted internal identifier.
pub const MAX_ID_LEN: usize = 64;

/// Deepest location hierarchy below a site root.
pub const MAX_LOCATION_DEPTH: usize = 8;

/// Most records one query or export returns.
pub const MAX_QUERY_RESULTS: usize = 500;

/// Longest accepted human-readable name.
pub const MAX_NAME_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// Kind of master-data record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// A physical site (plant, warehouse, store, vehicle depot).
    Site,
    /// A location inside a site, optionally nested.
    Location,
    /// A temperature-controlled zone inside a location.
    StorageZone,
    /// A trade item (GTIN) that can be stored.
    TradeItem,
    /// An organisation: operator, owner, manufacturer, laboratory, carrier.
    Party,
    /// A lot or batch identity with its item, site and quantity.
    Lot,
    /// A device or asset, with its calibration record.
    Device,
    /// A transport carrier.
    Carrier,
}

impl EntityKind {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            EntityKind::Site => "site",
            EntityKind::Location => "location",
            EntityKind::StorageZone => "storage_zone",
            EntityKind::TradeItem => "trade_item",
            EntityKind::Party => "party",
            EntityKind::Lot => "lot",
            EntityKind::Device => "device",
            EntityKind::Carrier => "carrier",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, MasterDataError> {
        match value {
            "site" => Ok(EntityKind::Site),
            "location" => Ok(EntityKind::Location),
            "storage_zone" => Ok(EntityKind::StorageZone),
            "trade_item" => Ok(EntityKind::TradeItem),
            "party" => Ok(EntityKind::Party),
            "lot" => Ok(EntityKind::Lot),
            "device" => Ok(EntityKind::Device),
            "carrier" => Ok(EntityKind::Carrier),
            other => Err(MasterDataError::Invalid {
                field: "kind".to_string(),
                detail: format!("unknown master data kind {other:?}"),
            }),
        }
    }

    /// Every kind in a stable order.
    pub fn all() -> [EntityKind; 8] {
        [
            EntityKind::Site,
            EntityKind::Location,
            EntityKind::StorageZone,
            EntityKind::TradeItem,
            EntityKind::Party,
            EntityKind::Lot,
            EntityKind::Device,
            EntityKind::Carrier,
        ]
    }
}

/// Lifecycle status of a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatus {
    /// Being prepared; not yet usable by new events.
    Draft,
    /// In use.
    Active,
    /// Temporarily out of use; may return to `Active`.
    Suspended,
    /// Permanently out of use; terminal.
    Retired,
}

impl LifecycleStatus {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleStatus::Draft => "draft",
            LifecycleStatus::Active => "active",
            LifecycleStatus::Suspended => "suspended",
            LifecycleStatus::Retired => "retired",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, MasterDataError> {
        match value {
            "draft" => Ok(LifecycleStatus::Draft),
            "active" => Ok(LifecycleStatus::Active),
            "suspended" => Ok(LifecycleStatus::Suspended),
            "retired" => Ok(LifecycleStatus::Retired),
            other => Err(MasterDataError::Invalid {
                field: "status".to_string(),
                detail: format!("unknown lifecycle status {other:?}"),
            }),
        }
    }

    /// Whether `next` is a legal successor of `self`. `Retired` is terminal.
    pub fn can_transition_to(self, next: LifecycleStatus) -> bool {
        use LifecycleStatus::{Active, Draft, Retired, Suspended};
        matches!(
            (self, next),
            (Draft, Draft | Active | Retired)
                | (Active, Active | Suspended | Retired)
                | (Suspended, Suspended | Active | Retired)
                | (Retired, Retired)
        )
    }

    /// Whether new records may reference a record in this status.
    pub fn is_referenceable(self) -> bool {
        !matches!(self, LifecycleStatus::Retired)
    }
}

/// Kind of location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationKind {
    /// The site root itself.
    SiteRoot,
    /// A yard or apron.
    Yard,
    /// A loading dock.
    Dock,
    /// A cold room.
    ColdRoom,
    /// A storage zone (freezer, ambient, quarantine).
    Zone,
    /// An aisle.
    Aisle,
    /// A shelf or rack position.
    Shelf,
    /// A staging area.
    Staging,
    /// A vehicle or container.
    Vehicle,
}

/// Role a party plays in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartyRole {
    /// Runs the site.
    Operator,
    /// Owns the goods.
    Owner,
    /// Manufactures the trade item.
    Manufacturer,
    /// Distributes the goods.
    Distributor,
    /// Moves the goods.
    Carrier,
    /// Performs calibration or testing.
    Laboratory,
    /// Receives the goods.
    Customer,
}

/// How a carrier moves goods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Road.
    Road,
    /// Rail.
    Rail,
    /// Sea.
    Sea,
    /// Air.
    Air,
    /// Several modes under one contract.
    Multimodal,
}

/// A quantity unit, as used for lot and trade-item quantities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum QuantityUnit {
    /// Kilograms.
    #[serde(rename = "kg")]
    Kilogram,
    /// Grams.
    #[serde(rename = "g")]
    Gram,
    /// Litres.
    #[serde(rename = "L")]
    Litre,
    /// Millilitres.
    #[serde(rename = "mL")]
    Millilitre,
    /// Individual units.
    #[serde(rename = "each")]
    Each,
    /// Cases.
    #[serde(rename = "case")]
    Case,
    /// Pallets.
    #[serde(rename = "pallet")]
    Pallet,
}

impl QuantityUnit {
    /// Stable wire code.
    pub fn as_str(self) -> &'static str {
        match self {
            QuantityUnit::Kilogram => "kg",
            QuantityUnit::Gram => "g",
            QuantityUnit::Litre => "L",
            QuantityUnit::Millilitre => "mL",
            QuantityUnit::Each => "each",
            QuantityUnit::Case => "case",
            QuantityUnit::Pallet => "pallet",
        }
    }

    /// Parse a wire code; unknown units are refused rather than guessed.
    pub fn parse(value: &str) -> Result<Self, MasterDataError> {
        match value.trim() {
            "kg" => Ok(QuantityUnit::Kilogram),
            "g" => Ok(QuantityUnit::Gram),
            "L" | "l" => Ok(QuantityUnit::Litre),
            "mL" | "ml" => Ok(QuantityUnit::Millilitre),
            "each" | "EA" => Ok(QuantityUnit::Each),
            "case" | "CS" => Ok(QuantityUnit::Case),
            "pallet" | "PLT" => Ok(QuantityUnit::Pallet),
            other => Err(MasterDataError::UnknownUnit {
                value: other.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Attribute payloads
// ---------------------------------------------------------------------------

/// Site attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteAttributes {
    /// Human-readable name.
    pub name: String,
    /// GS1 Global Location Number (13 digits with check digit).
    pub gln: String,
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// Party that operates the site (the custodian of goods held there).
    pub operator_party_id: Option<String>,
}

/// Location attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationAttributes {
    /// Owning site id.
    pub site_id: String,
    /// Parent location id, for nested hierarchies.
    pub parent_location_id: Option<String>,
    /// Human-readable name.
    pub name: String,
    /// Structural kind.
    pub kind: LocationKind,
    /// GS1 SGLN extension, when the location is addressable in EPCIS.
    pub gln: Option<String>,
}

/// Storage-zone attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageZoneAttributes {
    /// Owning site id.
    pub site_id: String,
    /// Physical location the zone sits in.
    pub location_id: String,
    /// Human-readable name.
    pub name: String,
    /// Storage class used by the pack/policy layer, e.g. `2-8C`.
    pub storage_class: String,
    /// Inclusive lower band edge, in deci-degrees Celsius.
    pub min_temp_c: FixedPointValue,
    /// Inclusive upper band edge, in deci-degrees Celsius.
    pub max_temp_c: FixedPointValue,
}

/// Trade-item attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TradeItemAttributes {
    /// GS1 GTIN (14 digits with check digit).
    pub gtin: String,
    /// Human-readable name.
    pub name: String,
    /// Quantity unit lots of this item are measured in.
    pub uom: QuantityUnit,
    /// Net content per unit, in `uom`.
    pub net_content: Option<u64>,
    /// Party that owns the brand.
    pub brand_owner_party_id: Option<String>,
}

/// Party attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyAttributes {
    /// Legal or trading name.
    pub name: String,
    /// GS1 Global Location Number.
    pub gln: String,
    /// Role in the chain.
    pub role: PartyRole,
}

/// Lot attributes: the master-data view of a CC-12 lot identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LotAttributes {
    /// Trade item the lot consists of.
    pub trade_item_id: String,
    /// Site holding the lot.
    pub site_id: String,
    /// Location holding the lot.
    pub location_id: String,
    /// Quantity represented.
    pub quantity: u64,
    /// Unit the quantity is expressed in; must match the trade item's.
    pub uom: QuantityUnit,
    /// CC-12 lot kind, when mirrored from the lot registry.
    pub lot_kind: Option<String>,
}

/// Device/asset attributes, including its calibration record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAttributes {
    /// Site the device is installed at.
    pub site_id: String,
    /// Location the device is installed at.
    pub location_id: String,
    /// Asset identifier used by the maintenance system.
    pub asset_id: String,
    /// Device class, e.g. `temperature-sensor`.
    pub device_class: String,
    /// Calibration record, when the asset is calibrated.
    pub calibration: Option<CalibrationAttributes>,
}

/// One calibration record for an asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationAttributes {
    /// When the asset was last calibrated.
    pub calibrated_est: i64,
    /// Interval until the next calibration is due.
    pub interval_secs: u64,
    /// Calibration certificate identifier.
    pub certificate_id: String,
    /// Laboratory that performed the calibration.
    pub laboratory_party_id: Option<String>,
}

/// Carrier attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarrierAttributes {
    /// Trading name.
    pub name: String,
    /// SCAC or other carrier code.
    pub carrier_code: String,
    /// GS1 Global Location Number, when the carrier has one.
    pub gln: Option<String>,
    /// Primary transport mode.
    pub mode: TransportMode,
}

/// Typed attributes of one master-data version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MasterAttributes {
    /// Site.
    Site(SiteAttributes),
    /// Location.
    Location(LocationAttributes),
    /// Storage zone.
    StorageZone(StorageZoneAttributes),
    /// Trade item.
    TradeItem(TradeItemAttributes),
    /// Party.
    Party(PartyAttributes),
    /// Lot.
    Lot(LotAttributes),
    /// Device.
    Device(DeviceAttributes),
    /// Carrier.
    Carrier(CarrierAttributes),
}

impl MasterAttributes {
    /// Kind this payload belongs to.
    pub fn kind(&self) -> EntityKind {
        match self {
            MasterAttributes::Site(_) => EntityKind::Site,
            MasterAttributes::Location(_) => EntityKind::Location,
            MasterAttributes::StorageZone(_) => EntityKind::StorageZone,
            MasterAttributes::TradeItem(_) => EntityKind::TradeItem,
            MasterAttributes::Party(_) => EntityKind::Party,
            MasterAttributes::Lot(_) => EntityKind::Lot,
            MasterAttributes::Device(_) => EntityKind::Device,
            MasterAttributes::Carrier(_) => EntityKind::Carrier,
        }
    }

    /// Human-readable name, for queries, exports and EPCIS attributes.
    pub fn name(&self) -> &str {
        match self {
            MasterAttributes::Site(attributes) => &attributes.name,
            MasterAttributes::Location(attributes) => &attributes.name,
            MasterAttributes::StorageZone(attributes) => &attributes.name,
            MasterAttributes::TradeItem(attributes) => &attributes.name,
            MasterAttributes::Party(attributes) => &attributes.name,
            MasterAttributes::Lot(attributes) => &attributes.trade_item_id,
            MasterAttributes::Device(attributes) => &attributes.asset_id,
            MasterAttributes::Carrier(attributes) => &attributes.name,
        }
    }

    /// GS1 identifier carried by the record, when it has one.
    pub fn gs1_id(&self) -> Option<&str> {
        match self {
            MasterAttributes::Site(attributes) => Some(&attributes.gln),
            MasterAttributes::Location(attributes) => attributes.gln.as_deref(),
            MasterAttributes::TradeItem(attributes) => Some(&attributes.gtin),
            MasterAttributes::Party(attributes) => Some(&attributes.gln),
            MasterAttributes::Carrier(attributes) => attributes.gln.as_deref(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Versions, drafts and audit
// ---------------------------------------------------------------------------

/// One immutable version of a master-data record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterVersion {
    /// Record kind.
    pub kind: EntityKind,
    /// Record identifier.
    pub id: String,
    /// Version number, starting at 1.
    pub version: u32,
    /// Inclusive start of the effective range.
    pub effective_from_est: i64,
    /// Exclusive end of the effective range, `None` while newest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_to_est: Option<i64>,
    /// Lifecycle status.
    pub status: LifecycleStatus,
    /// Parent location, for locations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Owning site, for site-scoped records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
    /// Typed content.
    pub attributes: MasterAttributes,
    /// Content digest, stable across re-puts of the same content.
    pub digest: String,
    /// Actor that wrote this version.
    pub actor_did: String,
    /// When this version row was written.
    pub created_est: i64,
}

impl MasterVersion {
    /// Whether `at_est` falls inside this version's effective range.
    pub fn is_effective_at(&self, at_est: i64) -> bool {
        at_est >= self.effective_from_est && self.effective_to_est.is_none_or(|end| at_est < end)
    }
}

/// A request to create or revise a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterDraft {
    /// Record kind; must match the payload.
    pub kind: EntityKind,
    /// Record identifier.
    pub id: String,
    /// When this version takes effect.
    pub effective_from_est: i64,
    /// Lifecycle status of this version.
    pub status: LifecycleStatus,
    /// Parent location, for locations.
    pub parent_id: Option<String>,
    /// Owning site, for site-scoped records.
    pub site_id: Option<String>,
    /// Typed content.
    pub attributes: MasterAttributes,
    /// Actor making the change.
    pub actor_did: String,
    /// Why the change was made (recorded in the audit history).
    pub reason: String,
}

impl MasterDraft {
    /// Start a draft for `attributes`.
    pub fn new(
        id: impl Into<String>,
        effective_from_est: i64,
        status: LifecycleStatus,
        attributes: MasterAttributes,
        actor_did: impl Into<String>,
    ) -> Self {
        Self {
            kind: attributes.kind(),
            id: id.into(),
            effective_from_est,
            status,
            parent_id: None,
            site_id: None,
            attributes,
            actor_did: actor_did.into(),
            reason: String::new(),
        }
    }

    /// Set the parent location and mirror it as the site scope.
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Set the owning site.
    pub fn with_site(mut self, site_id: impl Into<String>) -> Self {
        self.site_id = Some(site_id.into());
        self
    }

    /// Record why the change was made.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
}

/// What an audit row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// The record's first version.
    Created,
    /// A new version superseded the previous one.
    Revised,
}

impl AuditAction {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditAction::Created => "created",
            AuditAction::Revised => "revised",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Result<Self, MasterDataError> {
        match value {
            "created" => Ok(AuditAction::Created),
            "revised" => Ok(AuditAction::Revised),
            other => Err(MasterDataError::Invalid {
                field: "action".to_string(),
                detail: format!("unknown audit action {other:?}"),
            }),
        }
    }
}

/// One audit row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence.
    pub seq: i64,
    /// Record kind.
    pub kind: EntityKind,
    /// Record identifier.
    pub id: String,
    /// Version the action produced.
    pub version: u32,
    /// Action.
    pub action: AuditAction,
    /// Actor that made the change.
    pub actor_did: String,
    /// When the change was recorded.
    pub at_est: i64,
    /// Content digest of the produced version.
    pub digest: String,
    /// Reason recorded with the change.
    pub reason: String,
    /// Extra detail (previous digest, status transition, effective range).
    pub detail: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Queries, exports and resolution
// ---------------------------------------------------------------------------

/// Filter for [`MasterData::query`] and the exports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MasterQuery {
    /// Kinds to include; empty means every kind.
    pub kinds: Vec<EntityKind>,
    /// Only records scoped to this site.
    pub site_id: Option<String>,
    /// Only records in this status.
    pub status: Option<LifecycleStatus>,
    /// Case-insensitive substring over id, name and GS1 identifier.
    pub text: Option<String>,
    /// Result cap; clamped to [`MAX_QUERY_RESULTS`].
    pub limit: Option<usize>,
}

/// Canonical, digested export of a query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterExport {
    /// Schema identifier.
    pub schema: String,
    /// When the export was taken.
    pub at_est: i64,
    /// Records in force at that instant.
    pub entries: Vec<MasterVersion>,
    /// SHA-256 over [`CONTEXT_MASTER_EXPORT`] and the canonical entries.
    pub digest: String,
}

impl MasterExport {
    /// Canonical JSON, with the digest first so it is easy to check by hand.
    pub fn to_json(&self) -> Result<String, MasterDataError> {
        serde_json::to_string(self)
            .map_err(|error| MasterDataError::Store(format!("encode export: {error}")))
    }
}

/// References a cold-chain event carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventRefs {
    /// Site the event happened at.
    pub site_id: Option<String>,
    /// Location the event happened at.
    pub location_id: Option<String>,
    /// Device that observed the event.
    pub device_id: Option<String>,
    /// Trade item involved.
    pub trade_item_id: Option<String>,
    /// Party acting or owning.
    pub party_id: Option<String>,
    /// Carrier moving the goods.
    pub carrier_id: Option<String>,
    /// Lot involved; its master-data record supplies the trade item.
    pub lot_id: Option<String>,
}

impl EventRefs {
    /// References for a CC-12 lot record.
    pub fn for_lot(lot: &LotRecord) -> Self {
        Self {
            site_id: Some(lot.site_id.clone()),
            location_id: Some(lot.location_id.clone()),
            lot_id: Some(lot.lot_id.clone()),
            ..Self::default()
        }
    }

    /// References for a CC-11 excursion record: its site, the observing device
    /// (which supplies the location) and its lot (which supplies the item).
    pub fn for_excursion(record: &ExcursionRecord) -> Self {
        Self {
            site_id: Some(record.site_id.clone()),
            device_id: Some(record.device_id.clone()),
            lot_id: record.lot_id.clone(),
            ..Self::default()
        }
    }
}

/// Master data resolved for one event, as of the event's own time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventResolution {
    /// The instant the references were resolved at.
    pub at_est: i64,
    /// Site, when resolvable.
    pub site: Option<MasterVersion>,
    /// Location, when resolvable.
    pub location: Option<MasterVersion>,
    /// Trade item, when resolvable.
    pub trade_item: Option<MasterVersion>,
    /// Party, when resolvable.
    pub party: Option<MasterVersion>,
    /// Device, when resolvable.
    pub device: Option<MasterVersion>,
    /// Carrier, when resolvable.
    pub carrier: Option<MasterVersion>,
    /// Lot, when resolvable.
    pub lot: Option<MasterVersion>,
    /// References that resolved to nothing, as `kind:id`.
    pub missing: Vec<String>,
    /// Store failures that prevented resolution; never silently treated as
    /// "missing".
    pub errors: Vec<String>,
}

impl EventResolution {
    fn new(at_est: i64) -> Self {
        Self {
            at_est,
            site: None,
            location: None,
            trade_item: None,
            party: None,
            device: None,
            carrier: None,
            lot: None,
            missing: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Whether the site, location, trade item and party all resolved.
    pub fn complete(&self) -> bool {
        self.missing.is_empty()
            && self.errors.is_empty()
            && self.site.is_some()
            && self.location.is_some()
            && self.trade_item.is_some()
            && self.party.is_some()
    }

    /// Names of the resolved site, location, item and party.
    pub fn names(&self) -> Vec<String> {
        [&self.site, &self.location, &self.trade_item, &self.party]
            .into_iter()
            .flatten()
            .map(|version| version.attributes.name().to_string())
            .collect()
    }

    /// Error unless every reference resolved.
    pub fn require_complete(&self) -> Result<(), MasterDataError> {
        if let Some(error) = self.errors.first() {
            return Err(MasterDataError::Store(error.clone()));
        }
        if self.complete() {
            return Ok(());
        }
        let mut missing = self.missing.clone();
        for (label, present) in [
            ("site", self.site.is_some()),
            ("location", self.location.is_some()),
            ("trade_item", self.trade_item.is_some()),
            ("party", self.party.is_some()),
        ] {
            if !present && !missing.iter().any(|entry| entry.ends_with(label)) {
                missing.push(label.to_string());
            }
        }
        Err(MasterDataError::Unresolved { missing })
    }
}

/// Calibration state of an asset at an instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationStatus {
    /// The asset carries no calibration record.
    NotRequired,
    /// Calibration is current.
    Valid {
        /// When the next calibration falls due.
        due_est: i64,
    },
    /// Calibration is still current but due soon.
    DueSoon {
        /// When the next calibration falls due.
        due_est: i64,
    },
    /// Calibration has lapsed.
    Expired {
        /// When calibration fell due.
        due_est: i64,
    },
}

impl CalibrationStatus {
    /// Whether measurements taken now may be trusted.
    pub fn is_usable(self) -> bool {
        matches!(
            self,
            CalibrationStatus::NotRequired | CalibrationStatus::Valid { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Master-data failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterDataError {
    /// The store failed.
    Store(String),
    /// No such record.
    NotFound {
        /// Kind.
        kind: String,
        /// Identifier.
        id: String,
    },
    /// The record exists but no version covers the requested instant.
    NotEffective {
        /// Kind.
        kind: String,
        /// Identifier.
        id: String,
        /// Requested instant.
        at_est: i64,
    },
    /// A field is malformed.
    Invalid {
        /// Field path.
        field: String,
        /// What is wrong with it.
        detail: String,
    },
    /// A GS1 identifier is malformed or its check digit does not match.
    InvalidIdentifier {
        /// Field path.
        field: String,
        /// Rejected value.
        value: String,
    },
    /// A quantity unit is not one of the documented units.
    UnknownUnit {
        /// Rejected unit.
        value: String,
    },
    /// The parent/child hierarchy is invalid.
    Hierarchy {
        /// What is wrong with it.
        detail: String,
    },
    /// A lifecycle transition is not allowed.
    IllegalStatusTransition {
        /// Previous status.
        from: String,
        /// Requested status.
        to: String,
    },
    /// The effective date is not usable.
    EffectiveDate {
        /// What is wrong with it.
        detail: String,
    },
    /// A revision reused an id with a payload of a different kind.
    Conflict(String),
    /// References did not resolve.
    Unresolved {
        /// Unresolved references.
        missing: Vec<String>,
    },
}

impl MasterDataError {
    /// The offending field, when the error is about one.
    pub fn field(&self) -> Option<&str> {
        match self {
            MasterDataError::Invalid { field, .. }
            | MasterDataError::InvalidIdentifier { field, .. } => Some(field),
            _ => None,
        }
    }
}

impl std::fmt::Display for MasterDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MasterDataError::Store(detail) => write!(f, "master data store: {detail}"),
            MasterDataError::NotFound { kind, id } => write!(f, "{kind} {id} not found"),
            MasterDataError::NotEffective { kind, id, at_est } => {
                write!(f, "{kind} {id} has no version effective at {at_est}")
            }
            MasterDataError::Invalid { field, detail } => write!(f, "invalid {field}: {detail}"),
            MasterDataError::InvalidIdentifier { field, value } => {
                write!(f, "invalid {field}: {value:?}")
            }
            MasterDataError::UnknownUnit { value } => write!(f, "unknown unit {value:?}"),
            MasterDataError::Hierarchy { detail } => write!(f, "hierarchy: {detail}"),
            MasterDataError::IllegalStatusTransition { from, to } => {
                write!(f, "status cannot move from {from} to {to}")
            }
            MasterDataError::EffectiveDate { detail } => write!(f, "effective date: {detail}"),
            MasterDataError::Conflict(detail) => write!(f, "master data conflict: {detail}"),
            MasterDataError::Unresolved { missing } => {
                write!(f, "unresolved master data: {}", missing.join(", "))
            }
        }
    }
}

impl std::error::Error for MasterDataError {}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// The master data service.
///
/// One service owns one SQLite database (the gateway's `primary.db` in
/// production). All methods are synchronous; the caller supplies the clock.
#[derive(Debug)]
pub struct MasterData {
    store: MasterDataStore,
}

impl MasterData {
    /// Open (or create) the service database at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, MasterDataError> {
        Ok(Self {
            store: MasterDataStore::open(path)?,
        })
    }

    /// Open an in-memory service (tests and ephemeral deployments).
    pub fn open_in_memory() -> Result<Self, MasterDataError> {
        Ok(Self {
            store: MasterDataStore::open_in_memory()?,
        })
    }

    // -----------------------------------------------------------------------
    // Writes
    // -----------------------------------------------------------------------

    /// Create the first version of a record, or append the next version.
    ///
    /// Re-putting the identical content (same digest, same status) returns the
    /// newest version unchanged and writes no audit row, so a retried change is
    /// idempotent. Otherwise the previous version's effective range is closed at
    /// the new start and a new version is inserted: historical versions are never
    /// rewritten.
    pub fn put(&self, draft: MasterDraft) -> Result<MasterVersion, MasterDataError> {
        let mut draft = draft;
        validate_id("id", &draft.id)?;
        // Every site-scoped record carries its site, so a site-scoped query finds
        // the site itself as well as what belongs to it.
        if draft.site_id.is_none() {
            draft.site_id = implicit_site(&draft);
        }
        if draft.actor_did.trim().is_empty() {
            return Err(MasterDataError::Invalid {
                field: "actor_did".to_string(),
                detail: "must be non-empty".to_string(),
            });
        }
        if draft.kind != draft.attributes.kind() {
            return Err(MasterDataError::Conflict(format!(
                "draft kind {} does not match a {} payload",
                draft.kind.as_str(),
                draft.attributes.kind().as_str()
            )));
        }
        if draft.reason.len() > MAX_NAME_LEN {
            return Err(MasterDataError::Invalid {
                field: "reason".to_string(),
                detail: format!("must be at most {MAX_NAME_LEN} characters"),
            });
        }
        validate_attributes(&draft)?;

        let digest = version_digest(&draft)?;
        let latest = self.store.latest(draft.kind, &draft.id)?;

        let (version, action) = match latest.as_ref() {
            None => (1, AuditAction::Created),
            Some(previous) => {
                if previous.digest == digest && previous.status == draft.status {
                    return Ok(previous.clone());
                }
                if draft.effective_from_est <= previous.effective_from_est {
                    return Err(MasterDataError::EffectiveDate {
                        detail: format!(
                            "revision must take effect after version {} ({}), got {}",
                            previous.version, previous.effective_from_est, draft.effective_from_est
                        ),
                    });
                }
                if !previous.status.can_transition_to(draft.status) {
                    return Err(MasterDataError::IllegalStatusTransition {
                        from: previous.status.as_str().to_string(),
                        to: draft.status.as_str().to_string(),
                    });
                }
                (previous.version + 1, AuditAction::Revised)
            }
        };

        // Referential integrity is checked against the state in force when this
        // version takes effect, so a record may reference a parent that is itself
        // being introduced at the same instant but not one that has not started.
        self.check_references(&draft)?;

        let version = MasterVersion {
            kind: draft.kind,
            id: draft.id.clone(),
            version,
            effective_from_est: draft.effective_from_est,
            effective_to_est: None,
            status: draft.status,
            parent_id: draft.parent_id.clone(),
            site_id: draft.site_id.clone(),
            attributes: draft.attributes.clone(),
            digest: digest.clone(),
            actor_did: draft.actor_did.clone(),
            created_est: draft.effective_from_est,
        };
        if let Some(previous) = latest.as_ref() {
            self.store.close_version(
                previous.kind,
                &previous.id,
                previous.version,
                draft.effective_from_est,
            )?;
        }
        self.store.insert_version(&version)?;
        self.store.append_audit(&AuditEntry {
            seq: 0,
            kind: version.kind,
            id: version.id.clone(),
            version: version.version,
            action,
            actor_did: version.actor_did.clone(),
            at_est: draft.effective_from_est,
            digest: version.digest.clone(),
            reason: draft.reason.clone(),
            detail: serde_json::json!({
                "previous_version": latest.as_ref().map(|previous| previous.version),
                "previous_digest": latest.as_ref().map(|previous| previous.digest.clone()),
                "previous_status": latest.as_ref().map(|previous| previous.status.as_str()),
                "status": version.status.as_str(),
                "effective_from_est": version.effective_from_est,
                "previous_effective_to_est": latest.as_ref().and_then(|previous| previous.effective_to_est),
                "reason": draft.reason,
            }),
        })?;
        Ok(version)
    }

    /// Mirror a CC-12 lot identity into master data.
    ///
    /// The lot keeps its own registry; this records the master-data view (item,
    /// site, location, quantity, unit) so cold-chain events about the lot can
    /// resolve their item and party.
    pub fn link_lot(
        &self,
        lot: &LotRecord,
        trade_item_id: impl Into<String>,
        effective_from_est: i64,
        actor_did: impl Into<String>,
    ) -> Result<MasterVersion, MasterDataError> {
        let uom = QuantityUnit::parse(&lot.uom)?;
        let draft = MasterDraft::new(
            lot.lot_id.clone(),
            effective_from_est,
            LifecycleStatus::Active,
            MasterAttributes::Lot(LotAttributes {
                trade_item_id: trade_item_id.into(),
                site_id: lot.site_id.clone(),
                location_id: lot.location_id.clone(),
                quantity: lot.quantity,
                uom,
                lot_kind: Some(lot_kind_name(lot.kind)),
            }),
            actor_did,
        )
        .with_site(lot.site_id.clone())
        .with_reason("mirrored from the lot registry");
        self.put(draft)
    }

    /// Move a record to `Retired` at `at_est`.
    pub fn retire(
        &self,
        kind: EntityKind,
        id: &str,
        at_est: i64,
        actor_did: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<MasterVersion, MasterDataError> {
        let current = self.latest(kind, id)?;
        let mut draft = MasterDraft::new(
            current.id.clone(),
            at_est,
            LifecycleStatus::Retired,
            current.attributes.clone(),
            actor_did,
        )
        .with_reason(reason);
        draft.parent_id = current.parent_id.clone();
        draft.site_id = current.site_id.clone();
        self.put(draft)
    }

    // -----------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------

    /// The version in force at `at_est`.
    pub fn get(
        &self,
        kind: EntityKind,
        id: &str,
        at_est: i64,
    ) -> Result<MasterVersion, MasterDataError> {
        match self.store.at(kind, id, at_est)? {
            Some(version) => Ok(version),
            None => {
                if self.store.latest(kind, id)?.is_some() {
                    Err(MasterDataError::NotEffective {
                        kind: kind.as_str().to_string(),
                        id: id.to_string(),
                        at_est,
                    })
                } else {
                    Err(MasterDataError::NotFound {
                        kind: kind.as_str().to_string(),
                        id: id.to_string(),
                    })
                }
            }
        }
    }

    /// The newest version, whatever its effective range.
    pub fn latest(&self, kind: EntityKind, id: &str) -> Result<MasterVersion, MasterDataError> {
        self.store
            .latest(kind, id)?
            .ok_or_else(|| MasterDataError::NotFound {
                kind: kind.as_str().to_string(),
                id: id.to_string(),
            })
    }

    /// Every version, oldest first.
    pub fn versions(
        &self,
        kind: EntityKind,
        id: &str,
    ) -> Result<Vec<MasterVersion>, MasterDataError> {
        let versions = self.store.versions(kind, id)?;
        if versions.is_empty() {
            return Err(MasterDataError::NotFound {
                kind: kind.as_str().to_string(),
                id: id.to_string(),
            });
        }
        Ok(versions)
    }

    /// Audit history, oldest first.
    pub fn history(&self, kind: EntityKind, id: &str) -> Result<Vec<AuditEntry>, MasterDataError> {
        self.store.audit(kind, id)
    }

    /// Records in force at `at_est`, filtered by `query`.
    pub fn query(
        &self,
        query: &MasterQuery,
        at_est: i64,
    ) -> Result<Vec<MasterVersion>, MasterDataError> {
        let limit = query
            .limit
            .unwrap_or(MAX_QUERY_RESULTS)
            .min(MAX_QUERY_RESULTS);
        let needle = query.text.as_ref().map(|text| text.to_lowercase());
        let mut results = Vec::new();
        for version in self.store.all_at(at_est)? {
            if !query.kinds.is_empty() && !query.kinds.contains(&version.kind) {
                continue;
            }
            if let Some(site) = query.site_id.as_ref() {
                if version.site_id.as_deref() != Some(site.as_str()) {
                    continue;
                }
            }
            if let Some(status) = query.status {
                if version.status != status {
                    continue;
                }
            }
            if let Some(needle) = needle.as_ref() {
                let haystack = format!(
                    "{} {} {}",
                    version.id,
                    version.attributes.name(),
                    version.attributes.gs1_id().unwrap_or_default()
                )
                .to_lowercase();
                if !haystack.contains(needle.as_str()) {
                    continue;
                }
            }
            results.push(version);
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Exports
    // -----------------------------------------------------------------------

    /// Canonical JSON export of a query, with a digest over its entries.
    pub fn export_json(
        &self,
        query: &MasterQuery,
        at_est: i64,
    ) -> Result<MasterExport, MasterDataError> {
        let entries = self.query(query, at_est)?;
        let digest = export_digest(&entries)?;
        Ok(MasterExport {
            schema: CONTEXT_MASTER_EXPORT.to_string(),
            at_est,
            entries,
            digest,
        })
    }

    /// Flat CSV export of a query, for reporting.
    ///
    /// Columns: `kind,id,version,status,site_id,parent_id,name,gs1,uom,effective_from_est,effective_to_est,digest`.
    pub fn export_csv(&self, query: &MasterQuery, at_est: i64) -> Result<String, MasterDataError> {
        let entries = self.query(query, at_est)?;
        let mut out = String::from(
            "kind,id,version,status,site_id,parent_id,name,gs1,uom,effective_from_est,\
             effective_to_est,digest\n",
        );
        for version in entries {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                csv_field(version.kind.as_str()),
                csv_field(&version.id),
                version.version,
                csv_field(version.status.as_str()),
                csv_field(version.site_id.as_deref().unwrap_or_default()),
                csv_field(version.parent_id.as_deref().unwrap_or_default()),
                csv_field(version.attributes.name()),
                csv_field(version.attributes.gs1_id().unwrap_or_default()),
                csv_field(uom_of(&version.attributes).unwrap_or_default()),
                version.effective_from_est,
                version
                    .effective_to_est
                    .map(|end| end.to_string())
                    .unwrap_or_default(),
                csv_field(&version.digest),
            ));
        }
        Ok(out)
    }

    /// EPCIS 2.0 vocabulary document for the sites, locations and zones in force
    /// at `at_est`.
    ///
    /// Only records carrying a GS1 identifier can be expressed as SGLNs; the
    /// document reports how many were skipped for that reason rather than
    /// inventing identifiers.
    pub fn export_epcis(
        &self,
        vocabulary: EpcisVocabulary,
        at_est: i64,
        creation_est: i64,
    ) -> Result<EpcisVocabularyDocument, MasterDataError> {
        let query = MasterQuery {
            kinds: match vocabulary {
                EpcisVocabulary::BizLocation => vec![
                    EntityKind::Site,
                    EntityKind::Location,
                    EntityKind::StorageZone,
                ],
                EpcisVocabulary::ReadPoint => vec![EntityKind::Location, EntityKind::StorageZone],
            },
            ..MasterQuery::default()
        };
        let entries = self.query(&query, at_est)?;
        Ok(epcis::build(vocabulary, &entries, creation_est))
    }

    // -----------------------------------------------------------------------
    // Resolution
    // -----------------------------------------------------------------------

    /// Resolve an event's references against the master data in force at
    /// `at_est`.
    ///
    /// A reference that resolves to nothing is reported in
    /// [`EventResolution::missing`]; a store failure is reported in `errors`
    /// rather than being mistaken for missing data.
    pub fn resolve(&self, refs: &EventRefs, at_est: i64) -> EventResolution {
        let mut resolution = EventResolution::new(at_est);

        resolution.site = self.resolve_one(
            EntityKind::Site,
            refs.site_id.as_deref(),
            at_est,
            &mut resolution,
        );
        resolution.device = self.resolve_one(
            EntityKind::Device,
            refs.device_id.as_deref(),
            at_est,
            &mut resolution,
        );
        resolution.lot = self.resolve_one(
            EntityKind::Lot,
            refs.lot_id.as_deref(),
            at_est,
            &mut resolution,
        );
        resolution.carrier = self.resolve_one(
            EntityKind::Carrier,
            refs.carrier_id.as_deref(),
            at_est,
            &mut resolution,
        );

        // A device knows where it is installed; use that when the event itself
        // names no location.
        let device_location =
            resolution
                .device
                .as_ref()
                .and_then(|device| match &device.attributes {
                    MasterAttributes::Device(attributes) => Some(attributes.location_id.clone()),
                    _ => None,
                });
        let location_id = refs.location_id.clone().or(device_location);
        resolution.location = self.resolve_one(
            EntityKind::Location,
            location_id.as_deref(),
            at_est,
            &mut resolution,
        );

        // A lot knows which trade item it holds; use that when the event names no
        // item.
        let lot_item = resolution
            .lot
            .as_ref()
            .and_then(|lot| match &lot.attributes {
                MasterAttributes::Lot(attributes) => Some(attributes.trade_item_id.clone()),
                _ => None,
            });
        let trade_item_id = refs.trade_item_id.clone().or(lot_item);
        resolution.trade_item = self.resolve_one(
            EntityKind::TradeItem,
            trade_item_id.as_deref(),
            at_est,
            &mut resolution,
        );

        // A site knows which party operates it; that is the party a
        // site-scoped event is attributable to when it names none of its own.
        let site_operator = resolution
            .site
            .as_ref()
            .and_then(|site| match &site.attributes {
                MasterAttributes::Site(attributes) => attributes.operator_party_id.clone(),
                _ => None,
            });
        let party_id = refs.party_id.clone().or(site_operator);
        resolution.party = self.resolve_one(
            EntityKind::Party,
            party_id.as_deref(),
            at_est,
            &mut resolution,
        );

        resolution
    }

    /// Resolve a CC-12 lot identity: its site and location directly, its trade
    /// item and party through master data.
    pub fn resolve_lot(&self, lot: &LotRecord, at_est: i64) -> EventResolution {
        self.resolve(&EventRefs::for_lot(lot), at_est)
    }

    /// Resolve a CC-11 excursion record: its site directly, its location through
    /// the observing device, its item and party through the lot and site.
    pub fn resolve_excursion(&self, record: &ExcursionRecord, at_est: i64) -> EventResolution {
        self.resolve(&EventRefs::for_excursion(record), at_est)
    }

    /// Calibration state of a device at `at_est`.
    pub fn calibration_status(
        &self,
        device_id: &str,
        at_est: i64,
    ) -> Result<CalibrationStatus, MasterDataError> {
        let device = self.get(EntityKind::Device, device_id, at_est)?;
        let MasterAttributes::Device(attributes) = device.attributes else {
            return Err(MasterDataError::Conflict(format!(
                "device {device_id} does not carry device attributes"
            )));
        };
        let Some(calibration) = attributes.calibration else {
            return Ok(CalibrationStatus::NotRequired);
        };
        let due_est = calibration
            .calibrated_est
            .saturating_add(i64::try_from(calibration.interval_secs).unwrap_or(i64::MAX));
        let warning_window = (due_est - calibration.calibrated_est) / 10;
        if at_est >= due_est {
            Ok(CalibrationStatus::Expired { due_est })
        } else if at_est >= due_est - warning_window {
            Ok(CalibrationStatus::DueSoon { due_est })
        } else {
            Ok(CalibrationStatus::Valid { due_est })
        }
    }

    /// Whether a lot's item, site and location are all in force at `at_est`.
    pub fn validate_lot(&self, lot: &LotRecord, at_est: i64) -> Result<(), MasterDataError> {
        self.resolve_lot(lot, at_est).require_complete()
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn resolve_one(
        &self,
        kind: EntityKind,
        id: Option<&str>,
        at_est: i64,
        resolution: &mut EventResolution,
    ) -> Option<MasterVersion> {
        let id = id?;
        match self.store.at(kind, id, at_est) {
            Ok(Some(version)) => Some(version),
            Ok(None) => {
                resolution.missing.push(format!("{}:{id}", kind.as_str()));
                None
            }
            Err(MasterDataError::Store(detail)) => {
                resolution
                    .errors
                    .push(format!("{}:{id}: {detail}", kind.as_str()));
                None
            }
            Err(error) => {
                resolution.errors.push(error.to_string());
                None
            }
        }
    }

    fn check_references(&self, draft: &MasterDraft) -> Result<(), MasterDataError> {
        let at = draft.effective_from_est;
        match &draft.attributes {
            MasterAttributes::Site(attributes) => {
                validate_name("name", &attributes.name)?;
                validate_gln("gln", &attributes.gln)?;
                validate_country(&attributes.country)?;
                if let Some(party) = attributes.operator_party_id.as_ref() {
                    self.require_reference(EntityKind::Party, party, at, "operator_party_id")?;
                }
            }
            MasterAttributes::Location(attributes) => {
                validate_name("name", &attributes.name)?;
                self.require_reference(EntityKind::Site, &attributes.site_id, at, "site_id")?;
                if let Some(gln) = attributes.gln.as_ref() {
                    validate_gln("gln", gln)?;
                }
                let parent = attributes
                    .parent_location_id
                    .as_deref()
                    .or(draft.parent_id.as_deref());
                if let Some(parent) = parent {
                    if parent == draft.id {
                        return Err(MasterDataError::Hierarchy {
                            detail: format!("location {} cannot be its own parent", draft.id),
                        });
                    }
                    let parent_version = self.require_reference(
                        EntityKind::Location,
                        parent,
                        at,
                        "parent_location_id",
                    )?;
                    let parent_site = match &parent_version.attributes {
                        MasterAttributes::Location(parent_attributes) => &parent_attributes.site_id,
                        _ => {
                            return Err(MasterDataError::Hierarchy {
                                detail: format!("{parent} is not a location"),
                            })
                        }
                    };
                    if *parent_site != attributes.site_id {
                        return Err(MasterDataError::Hierarchy {
                            detail: format!(
                                "parent {parent} belongs to site {parent_site}, not {}",
                                attributes.site_id
                            ),
                        });
                    }
                    self.check_depth_cycle(&draft.id, parent, at)?;
                }
                // A location belongs to exactly the site its payload names.
                if draft
                    .site_id
                    .as_deref()
                    .is_some_and(|site| site != attributes.site_id)
                {
                    return Err(MasterDataError::Hierarchy {
                        detail: format!(
                            "location site scope {site} does not match its owning site {}",
                            attributes.site_id,
                            site = draft.site_id.as_deref().unwrap_or_default()
                        ),
                    });
                }
            }
            MasterAttributes::StorageZone(attributes) => {
                validate_name("name", &attributes.name)?;
                if attributes.storage_class.trim().is_empty() {
                    return Err(MasterDataError::Invalid {
                        field: "storage_class".to_string(),
                        detail: "must be non-empty".to_string(),
                    });
                }
                validate_temperature("min_temp_c", &attributes.min_temp_c)?;
                validate_temperature("max_temp_c", &attributes.max_temp_c)?;
                if attributes.min_temp_c.mantissa >= attributes.max_temp_c.mantissa {
                    return Err(MasterDataError::Invalid {
                        field: "min_temp_c".to_string(),
                        detail: "must be below max_temp_c".to_string(),
                    });
                }
                self.require_reference(EntityKind::Site, &attributes.site_id, at, "site_id")?;
                let location = self.require_reference(
                    EntityKind::Location,
                    &attributes.location_id,
                    at,
                    "location_id",
                )?;
                if let MasterAttributes::Location(location_attributes) = &location.attributes {
                    if location_attributes.site_id != attributes.site_id {
                        return Err(MasterDataError::Hierarchy {
                            detail: format!(
                                "location {} belongs to site {}, not {}",
                                attributes.location_id,
                                location_attributes.site_id,
                                attributes.site_id
                            ),
                        });
                    }
                }
            }
            MasterAttributes::TradeItem(attributes) => {
                validate_name("name", &attributes.name)?;
                validate_gtin("gtin", &attributes.gtin)?;
                if attributes.net_content == Some(0) {
                    return Err(MasterDataError::Invalid {
                        field: "net_content".to_string(),
                        detail: "must be positive".to_string(),
                    });
                }
                if let Some(party) = attributes.brand_owner_party_id.as_ref() {
                    self.require_reference(EntityKind::Party, party, at, "brand_owner_party_id")?;
                }
            }
            MasterAttributes::Party(attributes) => {
                validate_name("name", &attributes.name)?;
                validate_gln("gln", &attributes.gln)?;
            }
            MasterAttributes::Lot(attributes) => {
                if attributes.quantity == 0 {
                    return Err(MasterDataError::Invalid {
                        field: "quantity".to_string(),
                        detail: "must be positive".to_string(),
                    });
                }
                self.require_reference(EntityKind::Site, &attributes.site_id, at, "site_id")?;
                let location = self.require_reference(
                    EntityKind::Location,
                    &attributes.location_id,
                    at,
                    "location_id",
                )?;
                let item = self.require_reference(
                    EntityKind::TradeItem,
                    &attributes.trade_item_id,
                    at,
                    "trade_item_id",
                )?;
                match &item.attributes {
                    MasterAttributes::TradeItem(item_attributes) => {
                        if item_attributes.uom != attributes.uom {
                            return Err(MasterDataError::Invalid {
                                field: "uom".to_string(),
                                detail: format!(
                                    "lot unit {} does not match trade item unit {}",
                                    attributes.uom.as_str(),
                                    item_attributes.uom.as_str()
                                ),
                            });
                        }
                    }
                    _ => {
                        return Err(MasterDataError::Hierarchy {
                            detail: format!("{} is not a trade item", attributes.trade_item_id),
                        })
                    }
                }
                if let MasterAttributes::Location(location_attributes) = &location.attributes {
                    if location_attributes.site_id != attributes.site_id {
                        return Err(MasterDataError::Hierarchy {
                            detail: format!(
                                "location {} belongs to site {}, not {}",
                                attributes.location_id,
                                location_attributes.site_id,
                                attributes.site_id
                            ),
                        });
                    }
                }
            }
            MasterAttributes::Device(attributes) => {
                if attributes.asset_id.trim().is_empty() {
                    return Err(MasterDataError::Invalid {
                        field: "asset_id".to_string(),
                        detail: "must be non-empty".to_string(),
                    });
                }
                if attributes.device_class.trim().is_empty() {
                    return Err(MasterDataError::Invalid {
                        field: "device_class".to_string(),
                        detail: "must be non-empty".to_string(),
                    });
                }
                self.require_reference(EntityKind::Site, &attributes.site_id, at, "site_id")?;
                let location = self.require_reference(
                    EntityKind::Location,
                    &attributes.location_id,
                    at,
                    "location_id",
                )?;
                if let MasterAttributes::Location(location_attributes) = &location.attributes {
                    if location_attributes.site_id != attributes.site_id {
                        return Err(MasterDataError::Hierarchy {
                            detail: format!(
                                "location {} belongs to site {}, not {}",
                                attributes.location_id,
                                location_attributes.site_id,
                                attributes.site_id
                            ),
                        });
                    }
                }
                if let Some(calibration) = attributes.calibration.as_ref() {
                    if calibration.interval_secs == 0 {
                        return Err(MasterDataError::Invalid {
                            field: "calibration.interval_secs".to_string(),
                            detail: "must be positive".to_string(),
                        });
                    }
                    if calibration.calibrated_est > at {
                        return Err(MasterDataError::Invalid {
                            field: "calibration.calibrated_est".to_string(),
                            detail: "cannot be after the record takes effect".to_string(),
                        });
                    }
                    if calibration.certificate_id.trim().is_empty() {
                        return Err(MasterDataError::Invalid {
                            field: "calibration.certificate_id".to_string(),
                            detail: "must be non-empty".to_string(),
                        });
                    }
                    if let Some(lab) = calibration.laboratory_party_id.as_ref() {
                        let party = self.require_reference(
                            EntityKind::Party,
                            lab,
                            at,
                            "calibration.laboratory_party_id",
                        )?;
                        if let MasterAttributes::Party(party_attributes) = &party.attributes {
                            if party_attributes.role != PartyRole::Laboratory {
                                return Err(MasterDataError::Invalid {
                                    field: "calibration.laboratory_party_id".to_string(),
                                    detail: format!("party {lab} is not a laboratory"),
                                });
                            }
                        }
                    }
                }
            }
            MasterAttributes::Carrier(attributes) => {
                validate_name("name", &attributes.name)?;
                if attributes.carrier_code.trim().is_empty() {
                    return Err(MasterDataError::Invalid {
                        field: "carrier_code".to_string(),
                        detail: "must be non-empty".to_string(),
                    });
                }
                if let Some(gln) = attributes.gln.as_ref() {
                    validate_gln("gln", gln)?;
                }
            }
        }
        Ok(())
    }

    fn require_reference(
        &self,
        kind: EntityKind,
        id: &str,
        at_est: i64,
        field: &str,
    ) -> Result<MasterVersion, MasterDataError> {
        match self.store.at(kind, id, at_est)? {
            Some(version) => {
                if !version.status.is_referenceable() {
                    return Err(MasterDataError::Hierarchy {
                        detail: format!(
                            "{field} references {} {id}, which is {} at {at_est}",
                            kind.as_str(),
                            version.status.as_str()
                        ),
                    });
                }
                Ok(version)
            }
            None => {
                if self.store.latest(kind, id)?.is_some() {
                    Err(MasterDataError::NotEffective {
                        kind: kind.as_str().to_string(),
                        id: id.to_string(),
                        at_est,
                    })
                } else {
                    Err(MasterDataError::Hierarchy {
                        detail: format!("{field} references unknown {} {id}", kind.as_str()),
                    })
                }
            }
        }
    }

    fn check_depth_cycle(
        &self,
        id: &str,
        parent_id: &str,
        at_est: i64,
    ) -> Result<(), MasterDataError> {
        let mut cursor = Some(parent_id.to_string());
        let mut depth = 0usize;
        let mut seen: Vec<String> = vec![id.to_string()];
        while let Some(current) = cursor {
            if seen.iter().any(|entry| entry == &current) {
                return Err(MasterDataError::Hierarchy {
                    detail: format!(
                        "parent chain from {parent_id} closes a cycle at {current} (path: {})",
                        seen.join(" -> ")
                    ),
                });
            }
            seen.push(current.clone());
            depth += 1;
            if depth > MAX_LOCATION_DEPTH {
                return Err(MasterDataError::Hierarchy {
                    detail: format!("location nesting exceeds {MAX_LOCATION_DEPTH} levels"),
                });
            }
            match self.store.at(EntityKind::Location, &current, at_est)? {
                Some(version) => match &version.attributes {
                    MasterAttributes::Location(attributes) => {
                        cursor = attributes.parent_location_id.clone();
                    }
                    _ => cursor = None,
                },
                None => cursor = None,
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_id(field: &str, value: &str) -> Result<(), MasterDataError> {
    if value.is_empty() || value.len() > MAX_ID_LEN {
        return Err(MasterDataError::Invalid {
            field: field.to_string(),
            detail: format!("must be 1..={MAX_ID_LEN} characters"),
        });
    }
    let mut characters = value.chars();
    let first = characters.next().expect("non-empty");
    if !first.is_ascii_alphanumeric()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:-".contains(character))
    {
        return Err(MasterDataError::InvalidIdentifier {
            field: field.to_string(),
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_name(field: &str, value: &str) -> Result<(), MasterDataError> {
    if value.trim().is_empty() || value.len() > MAX_NAME_LEN {
        return Err(MasterDataError::Invalid {
            field: field.to_string(),
            detail: format!("must be 1..={MAX_NAME_LEN} characters"),
        });
    }
    Ok(())
}

fn validate_country(value: &str) -> Result<(), MasterDataError> {
    if value.len() != 2
        || !value
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(MasterDataError::Invalid {
            field: "country".to_string(),
            detail: "must be an ISO 3166-1 alpha-2 code".to_string(),
        });
    }
    Ok(())
}

fn validate_gln(field: &str, value: &str) -> Result<(), MasterDataError> {
    validate_gs1(field, value, 13)
}

fn validate_gtin(field: &str, value: &str) -> Result<(), MasterDataError> {
    validate_gs1(field, value, 14)
}

fn validate_gs1(field: &str, value: &str, length: usize) -> Result<(), MasterDataError> {
    let invalid = || MasterDataError::InvalidIdentifier {
        field: field.to_string(),
        value: value.to_string(),
    };
    if value.len() != length || !value.chars().all(|character| character.is_ascii_digit()) {
        return Err(invalid());
    }
    let (body, check) = value.split_at(length - 1);
    let check = check.parse::<u32>().map_err(|_| invalid())?;
    let mut sum = 0u32;
    for (index, character) in body.chars().rev().enumerate() {
        let digit = character.to_digit(10).ok_or_else(invalid)?;
        sum += if index % 2 == 0 { digit * 3 } else { digit };
    }
    let expected = (10 - sum % 10) % 10;
    if expected != check {
        return Err(invalid());
    }
    Ok(())
}

fn validate_temperature(field: &str, value: &FixedPointValue) -> Result<(), MasterDataError> {
    if value.unit_id != UNIT_DEG_C {
        return Err(MasterDataError::Invalid {
            field: field.to_string(),
            detail: format!(
                "must be in degC (unit_id {UNIT_DEG_C}), got {}",
                value.unit_id
            ),
        });
    }
    if value.exponent != -1 {
        return Err(MasterDataError::Invalid {
            field: field.to_string(),
            detail: "must be in deci-degrees (exponent -1)".to_string(),
        });
    }
    Ok(())
}

fn validate_attributes(draft: &MasterDraft) -> Result<(), MasterDataError> {
    match &draft.attributes {
        MasterAttributes::Site(attributes) => {
            validate_name("name", &attributes.name)?;
            validate_gln("gln", &attributes.gln)?;
            validate_country(&attributes.country)
        }
        MasterAttributes::Location(attributes) => {
            validate_name("name", &attributes.name)?;
            validate_id("site_id", &attributes.site_id)?;
            if let Some(parent) = attributes.parent_location_id.as_ref() {
                validate_id("parent_location_id", parent)?;
            }
            if let Some(gln) = attributes.gln.as_ref() {
                validate_gln("gln", gln)?;
            }
            Ok(())
        }
        MasterAttributes::StorageZone(attributes) => {
            validate_temperature("min_temp_c", &attributes.min_temp_c)?;
            validate_temperature("max_temp_c", &attributes.max_temp_c)
        }
        MasterAttributes::TradeItem(attributes) => validate_gtin("gtin", &attributes.gtin),
        MasterAttributes::Party(attributes) => validate_gln("gln", &attributes.gln),
        MasterAttributes::Lot(_) => Ok(()),
        MasterAttributes::Device(_) | MasterAttributes::Carrier(_) => Ok(()),
    }
}

/// The site a draft belongs to, when the payload implies one.
fn implicit_site(draft: &MasterDraft) -> Option<String> {
    match &draft.attributes {
        MasterAttributes::Site(_) => Some(draft.id.clone()),
        MasterAttributes::Location(attributes) => Some(attributes.site_id.clone()),
        MasterAttributes::StorageZone(attributes) => Some(attributes.site_id.clone()),
        MasterAttributes::Lot(attributes) => Some(attributes.site_id.clone()),
        MasterAttributes::Device(attributes) => Some(attributes.site_id.clone()),
        MasterAttributes::TradeItem(_)
        | MasterAttributes::Party(_)
        | MasterAttributes::Carrier(_) => None,
    }
}

fn version_digest(draft: &MasterDraft) -> Result<String, MasterDataError> {
    let canonical = serde_json::json!({
        "kind": draft.kind,
        "id": draft.id,
        "status": draft.status,
        "parent_id": draft.parent_id,
        "site_id": draft.site_id,
        "attributes": draft.attributes,
    });
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| MasterDataError::Store(format!("encode version: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_MASTER_VERSION.as_bytes());
    hasher.update([0u8]);
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn export_digest(entries: &[MasterVersion]) -> Result<String, MasterDataError> {
    let bytes = serde_json::to_vec(entries)
        .map_err(|error| MasterDataError::Store(format!("encode export entries: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_MASTER_EXPORT.as_bytes());
    hasher.update([0u8]);
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn csv_field(value: &str) -> String {
    if value.contains(['"', ',', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn uom_of(attributes: &MasterAttributes) -> Option<&'static str> {
    match attributes {
        MasterAttributes::TradeItem(item) => Some(item.uom.as_str()),
        MasterAttributes::Lot(lot) => Some(lot.uom.as_str()),
        _ => None,
    }
}

fn lot_kind_name(kind: crate::lot::LotKind) -> String {
    match kind {
        crate::lot::LotKind::Lot => "lot",
        crate::lot::LotKind::Batch => "batch",
        crate::lot::LotKind::Repack => "repack",
    }
    .to_string()
}
