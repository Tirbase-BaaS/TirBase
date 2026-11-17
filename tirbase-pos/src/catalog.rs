// SPDX-License-Identifier: AGPL-3.0-only

//! POS-04 — immutable catalog, price-book and tax-table versions.
//!
//! POS-01 deliberately stores a line item's unit price and tax rate as values.
//! A closed check therefore keeps its original money even if a menu price or a
//! tax rate later changes. POS-04 adds the provenance around those values:
//!
//! - [`CatalogVersion`] lists sellable items, modifiers, menu links and recipe
//!   links.
//! - [`PriceBookVersion`] maps catalog items and modifiers to money in one
//!   currency.
//! - [`TaxTableVersion`] maps a jurisdiction and product applicability to a
//!   tax rate.
//! - [`VersionPin`] names the three versions an order used.
//!
//! Versions are immutable once published. A price or tax change is a new
//! version with its own [`EffectiveWindow`]; old versions remain available so a
//! historical order can be explained. Publishing a version whose window
//! overlaps an existing version in the same scope is rejected.
//!
//! An order can be opened with [`crate::Order::open_pinned`], and a
//! [`PricedCatalog`] snapshot can turn a catalog item plus the pinned price book
//! and tax table into an ordinary POS-01 [`LineItem`]. The line item carries the
//! resolved price and rate as values, so closing the check seals them.
//!
//! A rollback does not mutate an old version. It publishes a new version that
//! reuses the target version's content and records
//! [`VersionAuditEventKind::RolledBack`] with the replacement, the version it
//! reverted to, the reason, actor and time.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::audit::Timestamp;
use crate::error::PosError;
use crate::ids::{
    validate_identifier, CatalogItemId, CatalogVersionId, EmployeeId, JurisdictionId, MenuId,
    ModifierId, PriceBookVersionId, RecipeComponentId, TaxTableVersionId,
};
use crate::line_item::{LineItem, Modifier};
use crate::money::{Currency, Money, Quantity, Rate};

/// A half-open effective interval: `[from, until)`.
///
/// `until: None` means no scheduled end. Adjacent windows such as
/// `[0, 10)` and `[10, 20)` do not overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EffectiveWindow {
    from: Timestamp,
    until: Option<Timestamp>,
}

impl EffectiveWindow {
    /// Construct a non-empty window. `until` must be strictly after `from`.
    pub fn new(from: Timestamp, until: Option<Timestamp>) -> Result<Self, PosError> {
        if let Some(until) = until {
            if until <= from {
                return Err(PosError::InvalidEffectiveWindow);
            }
        }
        Ok(Self { from, until })
    }

    /// The inclusive start.
    pub fn from(self) -> Timestamp {
        self.from
    }

    /// The exclusive end, or `None` when open-ended.
    pub fn until(self) -> Option<Timestamp> {
        self.until
    }

    /// Whether the window contains `at`.
    pub fn contains(self, at: Timestamp) -> bool {
        self.from <= at && self.until.is_none_or(|until| at < until)
    }

    /// Whether two windows share any instant.
    pub fn overlaps(self, other: Self) -> bool {
        let self_before_other_ends = other.until.is_none_or(|until| self.from < until);
        let other_before_self_ends = self.until.is_none_or(|until| other.from < until);
        self_before_other_ends && other_before_self_ends
    }
}

/// A menu link on a catalog item.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MenuLink {
    menu_id: MenuId,
}

impl MenuLink {
    /// Link an item to a menu.
    pub fn new(menu_id: MenuId) -> Self {
        Self { menu_id }
    }

    /// The linked menu.
    pub fn menu_id(&self) -> &MenuId {
        &self.menu_id
    }
}

/// A recipe component linked to a catalog item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipeLink {
    component_id: RecipeComponentId,
    quantity: Quantity,
}

impl RecipeLink {
    /// Link a recipe component with the quantity consumed by one sale.
    pub fn new(component_id: RecipeComponentId, quantity: Quantity) -> Self {
        Self {
            component_id,
            quantity,
        }
    }

    /// The external recipe component.
    pub fn component_id(&self) -> &RecipeComponentId {
        &self.component_id
    }

    /// The per-sale quantity.
    pub fn quantity(&self) -> Quantity {
        self.quantity
    }
}

/// A sellable item in a catalog version.
///
/// The item has no price and no tax rate; those belong to the price-book and
/// tax-table versions so the same catalog can be used in several jurisdictions
/// and currencies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogItem {
    id: CatalogItemId,
    name: String,
    sku: Option<String>,
    category: Option<String>,
    menu_links: Vec<MenuLink>,
    modifier_ids: Vec<ModifierId>,
    recipe_links: Vec<RecipeLink>,
}

impl CatalogItem {
    /// Construct an item with no SKU, category or links.
    pub fn new(id: CatalogItemId, name: impl Into<String>) -> Result<Self, PosError> {
        let name = name.into();
        validate_identifier(&name, "catalog item name")?;
        Ok(Self {
            id,
            name,
            sku: None,
            category: None,
            menu_links: Vec::new(),
            modifier_ids: Vec::new(),
            recipe_links: Vec::new(),
        })
    }

    /// Attach a stock-keeping reference.
    pub fn with_sku(mut self, sku: impl Into<String>) -> Result<Self, PosError> {
        let sku = sku.into();
        validate_identifier(&sku, "catalog item sku")?;
        self.sku = Some(sku);
        Ok(self)
    }

    /// Attach a product category used by tax applicability.
    pub fn with_category(mut self, category: impl Into<String>) -> Result<Self, PosError> {
        let category = category.into();
        validate_identifier(&category, "catalog category")?;
        self.category = Some(category);
        Ok(self)
    }

    /// Link the item into a menu. Repeating the same menu is ignored.
    pub fn with_menu(mut self, menu_id: MenuId) -> Self {
        if !self.menu_links.iter().any(|link| link.menu_id == menu_id) {
            self.menu_links.push(MenuLink::new(menu_id));
        }
        self
    }

    /// Link a modifier offered for this item. The modifier must exist in the
    /// same catalog version.
    pub fn with_modifier(mut self, modifier_id: ModifierId) -> Self {
        if !self.modifier_ids.contains(&modifier_id) {
            self.modifier_ids.push(modifier_id);
        }
        self
    }

    /// Link a recipe component.
    pub fn with_recipe_link(mut self, link: RecipeLink) -> Self {
        self.recipe_links.push(link);
        self
    }

    /// The catalog item identifier.
    pub fn id(&self) -> &CatalogItemId {
        &self.id
    }

    /// The display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The optional SKU.
    pub fn sku(&self) -> Option<&str> {
        self.sku.as_deref()
    }

    /// The optional category.
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    /// Menu links in insertion order.
    pub fn menu_links(&self) -> &[MenuLink] {
        &self.menu_links
    }

    /// Modifier links in insertion order.
    pub fn modifier_ids(&self) -> &[ModifierId] {
        &self.modifier_ids
    }

    /// Recipe links in insertion order.
    pub fn recipe_links(&self) -> &[RecipeLink] {
        &self.recipe_links
    }
}

/// A modifier definition in a catalog version. Its price delta lives in the
/// price-book version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogModifier {
    id: ModifierId,
    name: String,
}

impl CatalogModifier {
    /// Construct a modifier definition.
    pub fn new(id: ModifierId, name: impl Into<String>) -> Result<Self, PosError> {
        let name = name.into();
        validate_identifier(&name, "modifier name")?;
        Ok(Self { id, name })
    }

    /// The modifier identifier.
    pub fn id(&self) -> &ModifierId {
        &self.id
    }

    /// The display name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// An immutable catalog version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogVersion {
    id: CatalogVersionId,
    effective: EffectiveWindow,
    items: BTreeMap<CatalogItemId, CatalogItem>,
    modifiers: BTreeMap<ModifierId, CatalogModifier>,
}

impl CatalogVersion {
    /// Build a catalog version, rejecting duplicate item or modifier ids and
    /// item-to-modifier links that do not resolve inside the version.
    pub fn new(
        id: CatalogVersionId,
        effective: EffectiveWindow,
        items: Vec<CatalogItem>,
        modifiers: Vec<CatalogModifier>,
    ) -> Result<Self, PosError> {
        let mut item_map = BTreeMap::new();
        for item in items {
            let item_id = item.id.clone();
            if item_map.insert(item_id.clone(), item).is_some() {
                return Err(PosError::DuplicateCatalogEntry(item_id.to_string()));
            }
        }
        let mut modifier_map = BTreeMap::new();
        for modifier in modifiers {
            let modifier_id = modifier.id.clone();
            if modifier_map.insert(modifier_id.clone(), modifier).is_some() {
                return Err(PosError::DuplicateCatalogEntry(modifier_id.to_string()));
            }
        }
        for item in item_map.values() {
            for modifier_id in &item.modifier_ids {
                if !modifier_map.contains_key(modifier_id) {
                    return Err(PosError::UnknownCatalogModifier(modifier_id.clone()));
                }
            }
        }
        Ok(Self {
            id,
            effective,
            items: item_map,
            modifiers: modifier_map,
        })
    }

    fn reissued(&self, id: CatalogVersionId, effective: EffectiveWindow) -> Self {
        Self {
            id,
            effective,
            items: self.items.clone(),
            modifiers: self.modifiers.clone(),
        }
    }

    /// The version identifier.
    pub fn id(&self) -> &CatalogVersionId {
        &self.id
    }

    /// The effective window.
    pub fn effective(&self) -> EffectiveWindow {
        self.effective
    }

    /// Look up an item.
    pub fn item(&self, id: &CatalogItemId) -> Option<&CatalogItem> {
        self.items.get(id)
    }

    /// Look up a modifier definition.
    pub fn modifier(&self, id: &ModifierId) -> Option<&CatalogModifier> {
        self.modifiers.get(id)
    }

    /// Items in identifier order.
    pub fn items(&self) -> impl Iterator<Item = &CatalogItem> {
        self.items.values()
    }

    /// Modifier definitions in identifier order.
    pub fn modifiers(&self) -> impl Iterator<Item = &CatalogModifier> {
        self.modifiers.values()
    }
}

/// An immutable price-book version. Every price in one version uses the same
/// currency, which must match the check being priced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriceBookVersion {
    id: PriceBookVersionId,
    effective: EffectiveWindow,
    currency: Currency,
    item_prices: BTreeMap<CatalogItemId, Money>,
    modifier_deltas: BTreeMap<ModifierId, Money>,
}

impl PriceBookVersion {
    /// Build a price-book version. Item prices must be non-negative; modifier
    /// deltas may be negative (a reduction); all money must match `currency`.
    pub fn new(
        id: PriceBookVersionId,
        effective: EffectiveWindow,
        currency: Currency,
        item_prices: BTreeMap<CatalogItemId, Money>,
        modifier_deltas: BTreeMap<ModifierId, Money>,
    ) -> Result<Self, PosError> {
        for price in item_prices.values() {
            if price.currency() != currency {
                return Err(PosError::CurrencyMismatch);
            }
            if price.is_negative() {
                return Err(PosError::NegativeAmount);
            }
        }
        for delta in modifier_deltas.values() {
            if delta.currency() != currency {
                return Err(PosError::CurrencyMismatch);
            }
        }
        Ok(Self {
            id,
            effective,
            currency,
            item_prices,
            modifier_deltas,
        })
    }

    fn reissued(&self, id: PriceBookVersionId, effective: EffectiveWindow) -> Self {
        Self {
            id,
            effective,
            currency: self.currency,
            item_prices: self.item_prices.clone(),
            modifier_deltas: self.modifier_deltas.clone(),
        }
    }

    /// The version identifier.
    pub fn id(&self) -> &PriceBookVersionId {
        &self.id
    }

    /// The effective window.
    pub fn effective(&self) -> EffectiveWindow {
        self.effective
    }

    /// The price currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// The price of one item, if present.
    pub fn item_price(&self, id: &CatalogItemId) -> Option<Money> {
        self.item_prices.get(id).copied()
    }

    /// The price delta of one modifier, if present.
    pub fn modifier_delta(&self, id: &ModifierId) -> Option<Money> {
        self.modifier_deltas.get(id).copied()
    }

    /// Item prices in identifier order.
    pub fn prices(&self) -> impl Iterator<Item = (&CatalogItemId, Money)> {
        self.item_prices.iter().map(|(id, price)| (id, *price))
    }

    /// Modifier deltas in identifier order.
    pub fn modifier_deltas(&self) -> impl Iterator<Item = (&ModifierId, Money)> {
        self.modifier_deltas.iter().map(|(id, delta)| (id, *delta))
    }
}

/// Which products a tax rule applies to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaxApplicability {
    /// Every item in the tax table's jurisdiction.
    All,
    /// Items whose catalog category equals this value.
    Category(String),
    /// One exact catalog item.
    Item(CatalogItemId),
}

/// One tax rate and its product applicability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxRule {
    applicability: TaxApplicability,
    rate: Rate,
}

impl TaxRule {
    /// Construct a tax rule. A category applicability must be a valid label.
    pub fn new(applicability: TaxApplicability, rate: Rate) -> Result<Self, PosError> {
        if let TaxApplicability::Category(category) = &applicability {
            validate_identifier(category, "tax category")?;
        }
        Ok(Self {
            applicability,
            rate,
        })
    }

    /// What the rule applies to.
    pub fn applicability(&self) -> &TaxApplicability {
        &self.applicability
    }

    /// The tax rate.
    pub fn rate(&self) -> Rate {
        self.rate
    }
}

/// An immutable tax-table version for one jurisdiction.
///
/// Applicability precedence is: exact item, then category, then all items. A
/// version may contain all three; a duplicate applicability is rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxTableVersion {
    id: TaxTableVersionId,
    effective: EffectiveWindow,
    jurisdiction: JurisdictionId,
    rules: Vec<TaxRule>,
}

impl TaxTableVersion {
    /// Build a tax-table version, rejecting duplicate applicability rules.
    pub fn new(
        id: TaxTableVersionId,
        effective: EffectiveWindow,
        jurisdiction: JurisdictionId,
        rules: Vec<TaxRule>,
    ) -> Result<Self, PosError> {
        let mut seen = BTreeSet::new();
        for rule in &rules {
            if !seen.insert(rule.applicability.clone()) {
                return Err(PosError::AmbiguousTaxRule);
            }
        }
        Ok(Self {
            id,
            effective,
            jurisdiction,
            rules,
        })
    }

    fn reissued(&self, id: TaxTableVersionId, effective: EffectiveWindow) -> Self {
        Self {
            id,
            effective,
            jurisdiction: self.jurisdiction.clone(),
            rules: self.rules.clone(),
        }
    }

    /// The version identifier.
    pub fn id(&self) -> &TaxTableVersionId {
        &self.id
    }

    /// The effective window.
    pub fn effective(&self) -> EffectiveWindow {
        self.effective
    }

    /// The jurisdiction this table belongs to.
    pub fn jurisdiction(&self) -> &JurisdictionId {
        &self.jurisdiction
    }

    /// Rules in insertion order.
    pub fn rules(&self) -> &[TaxRule] {
        &self.rules
    }

    /// Resolve the tax rate for an item using item, category, then all-items
    /// precedence.
    pub fn rate_for(&self, item: &CatalogItem) -> Option<Rate> {
        if let Some(rule) = self.rules.iter().find(|rule| {
            matches!(
                &rule.applicability,
                TaxApplicability::Item(id) if id == item.id()
            )
        }) {
            return Some(rule.rate);
        }
        if let Some(category) = item.category() {
            if let Some(rule) = self.rules.iter().find(|rule| {
                matches!(
                    &rule.applicability,
                    TaxApplicability::Category(value) if value == category
                )
            }) {
                return Some(rule.rate);
            }
        }
        self.rules
            .iter()
            .find(|rule| matches!(rule.applicability, TaxApplicability::All))
            .map(|rule| rule.rate)
    }
}

/// A typed reference to one version, used by the audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionRef {
    /// A catalog version.
    Catalog(CatalogVersionId),
    /// A price-book version.
    PriceBook(PriceBookVersionId),
    /// A tax-table version.
    TaxTable(TaxTableVersionId),
}

impl fmt::Display for VersionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionRef::Catalog(id) => write!(f, "catalog/{id}"),
            VersionRef::PriceBook(id) => write!(f, "price-book/{id}"),
            VersionRef::TaxTable(id) => write!(f, "tax-table/{id}"),
        }
    }
}

/// What happened to a version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionAuditEventKind {
    /// A new version was published.
    Published { version: VersionRef },
    /// A new version was published with an older version's content.
    RolledBack {
        replacement: VersionRef,
        reverted_to: VersionRef,
        reason: String,
    },
}

/// One audit entry in a [`VersionStore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionAuditEvent {
    /// Dense sequence starting at 1.
    pub sequence: u64,
    /// Caller-supplied time.
    pub at: Timestamp,
    /// Operator who published or rolled back the version.
    pub actor: EmployeeId,
    /// What happened.
    pub kind: VersionAuditEventKind,
}

/// The versions an order used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionPin {
    catalog: CatalogVersionId,
    price_book: PriceBookVersionId,
    tax_table: TaxTableVersionId,
}

impl VersionPin {
    /// Construct a pin from three exact version identifiers.
    pub fn new(
        catalog: CatalogVersionId,
        price_book: PriceBookVersionId,
        tax_table: TaxTableVersionId,
    ) -> Self {
        Self {
            catalog,
            price_book,
            tax_table,
        }
    }

    /// The pinned catalog version.
    pub fn catalog(&self) -> &CatalogVersionId {
        &self.catalog
    }

    /// The pinned price-book version.
    pub fn price_book(&self) -> &PriceBookVersionId {
        &self.price_book
    }

    /// The pinned tax-table version.
    pub fn tax_table(&self) -> &TaxTableVersionId {
        &self.tax_table
    }
}

/// A coherent snapshot of the three pinned versions, ready to price a line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PricedCatalog {
    catalog: CatalogVersion,
    price_book: PriceBookVersion,
    tax_table: TaxTableVersion,
}

impl PricedCatalog {
    fn new(
        catalog: CatalogVersion,
        price_book: PriceBookVersion,
        tax_table: TaxTableVersion,
    ) -> Self {
        Self {
            catalog,
            price_book,
            tax_table,
        }
    }

    /// The pinned catalog.
    pub fn catalog(&self) -> &CatalogVersion {
        &self.catalog
    }

    /// The pinned price book.
    pub fn price_book(&self) -> &PriceBookVersion {
        &self.price_book
    }

    /// The pinned tax table.
    pub fn tax_table(&self) -> &TaxTableVersion {
        &self.tax_table
    }

    /// Build an ordinary POS-01 line item from the pinned versions.
    ///
    /// `modifier_ids` is explicit; the item's default modifier links are
    /// metadata and are not silently added. The resolved item price, modifier
    /// deltas and tax rate are copied into the returned [`LineItem`], which is
    /// what makes a later version change unable to alter the line.
    pub fn line_item(
        &self,
        line_id: crate::ids::LineItemId,
        item_id: &CatalogItemId,
        quantity: Quantity,
        modifier_ids: &[ModifierId],
    ) -> Result<LineItem, PosError> {
        let item = self
            .catalog
            .item(item_id)
            .ok_or_else(|| PosError::UnknownCatalogItem(item_id.clone()))?;
        let unit_price = self
            .price_book
            .item_price(item_id)
            .ok_or_else(|| PosError::MissingPrice(item_id.clone()))?;
        let mut line = LineItem::new(line_id, item.name(), quantity, unit_price)?;
        if let Some(sku) = item.sku() {
            line = line.with_sku(sku)?;
        }
        for modifier_id in modifier_ids {
            if !item.modifier_ids().contains(modifier_id) {
                return Err(PosError::ModifierNotApplicable {
                    item: item_id.clone(),
                    modifier: modifier_id.clone(),
                });
            }
            let modifier = self
                .catalog
                .modifier(modifier_id)
                .ok_or_else(|| PosError::UnknownCatalogModifier(modifier_id.clone()))?;
            let delta = self
                .price_book
                .modifier_delta(modifier_id)
                .ok_or_else(|| PosError::MissingModifierPrice(modifier_id.clone()))?;
            line = line.with_modifier(Modifier::new(modifier.name(), delta)?)?;
        }
        if let Some(rate) = self.tax_table.rate_for(item) {
            line = line.with_tax_rate(rate);
        }
        Ok(line)
    }
}

/// A store of immutable versions plus their publication and rollback audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionStore {
    catalogs: Vec<CatalogVersion>,
    price_books: Vec<PriceBookVersion>,
    tax_tables: Vec<TaxTableVersion>,
    audit: Vec<VersionAuditEvent>,
    next_sequence: u64,
}

impl Default for VersionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionStore {
    /// An empty version store.
    pub fn new() -> Self {
        Self {
            catalogs: Vec::new(),
            price_books: Vec::new(),
            tax_tables: Vec::new(),
            audit: Vec::new(),
            next_sequence: 1,
        }
    }

    /// Publish a catalog version. Its window must not overlap any existing
    /// catalog version.
    pub fn publish_catalog(
        &mut self,
        version: CatalogVersion,
        actor: EmployeeId,
        at: Timestamp,
    ) -> Result<(), PosError> {
        let version_ref = VersionRef::Catalog(version.id.clone());
        self.insert_catalog(version)?;
        self.record(
            actor,
            at,
            VersionAuditEventKind::Published {
                version: version_ref,
            },
        );
        Ok(())
    }

    /// Publish a price-book version. Its window must not overlap an existing
    /// price book for the same currency.
    pub fn publish_price_book(
        &mut self,
        version: PriceBookVersion,
        actor: EmployeeId,
        at: Timestamp,
    ) -> Result<(), PosError> {
        let version_ref = VersionRef::PriceBook(version.id.clone());
        self.insert_price_book(version)?;
        self.record(
            actor,
            at,
            VersionAuditEventKind::Published {
                version: version_ref,
            },
        );
        Ok(())
    }

    /// Publish a tax-table version. Its window must not overlap an existing tax
    /// table for the same jurisdiction.
    pub fn publish_tax_table(
        &mut self,
        version: TaxTableVersion,
        actor: EmployeeId,
        at: Timestamp,
    ) -> Result<(), PosError> {
        let version_ref = VersionRef::TaxTable(version.id.clone());
        self.insert_tax_table(version)?;
        self.record(
            actor,
            at,
            VersionAuditEventKind::Published {
                version: version_ref,
            },
        );
        Ok(())
    }

    /// Reissue an old catalog's content under a new id and effective window,
    /// recording an auditable rollback.
    pub fn rollback_catalog(
        &mut self,
        replacement_id: CatalogVersionId,
        reverted_to: &CatalogVersionId,
        effective: EffectiveWindow,
        reason: impl Into<String>,
        actor: EmployeeId,
        at: Timestamp,
    ) -> Result<(), PosError> {
        let reason = validated_reason(reason)?;
        let target = self
            .catalog(reverted_to)
            .ok_or_else(|| PosError::VersionNotFound(reverted_to.to_string()))?
            .clone();
        let replacement = target.reissued(replacement_id, effective);
        let replacement_ref = VersionRef::Catalog(replacement.id.clone());
        self.insert_catalog(replacement)?;
        self.record(
            actor,
            at,
            VersionAuditEventKind::RolledBack {
                replacement: replacement_ref,
                reverted_to: VersionRef::Catalog(reverted_to.clone()),
                reason,
            },
        );
        Ok(())
    }

    /// Reissue an old price book's content under a new id and effective window,
    /// recording an auditable rollback.
    pub fn rollback_price_book(
        &mut self,
        replacement_id: PriceBookVersionId,
        reverted_to: &PriceBookVersionId,
        effective: EffectiveWindow,
        reason: impl Into<String>,
        actor: EmployeeId,
        at: Timestamp,
    ) -> Result<(), PosError> {
        let reason = validated_reason(reason)?;
        let target = self
            .price_book(reverted_to)
            .ok_or_else(|| PosError::VersionNotFound(reverted_to.to_string()))?
            .clone();
        let replacement = target.reissued(replacement_id, effective);
        let replacement_ref = VersionRef::PriceBook(replacement.id.clone());
        self.insert_price_book(replacement)?;
        self.record(
            actor,
            at,
            VersionAuditEventKind::RolledBack {
                replacement: replacement_ref,
                reverted_to: VersionRef::PriceBook(reverted_to.clone()),
                reason,
            },
        );
        Ok(())
    }

    /// Reissue an old tax table's content under a new id and effective window,
    /// recording an auditable rollback.
    pub fn rollback_tax_table(
        &mut self,
        replacement_id: TaxTableVersionId,
        reverted_to: &TaxTableVersionId,
        effective: EffectiveWindow,
        reason: impl Into<String>,
        actor: EmployeeId,
        at: Timestamp,
    ) -> Result<(), PosError> {
        let reason = validated_reason(reason)?;
        let target = self
            .tax_table(reverted_to)
            .ok_or_else(|| PosError::VersionNotFound(reverted_to.to_string()))?
            .clone();
        let replacement = target.reissued(replacement_id, effective);
        let replacement_ref = VersionRef::TaxTable(replacement.id.clone());
        self.insert_tax_table(replacement)?;
        self.record(
            actor,
            at,
            VersionAuditEventKind::RolledBack {
                replacement: replacement_ref,
                reverted_to: VersionRef::TaxTable(reverted_to.clone()),
                reason,
            },
        );
        Ok(())
    }

    /// Look up a catalog version by id.
    pub fn catalog(&self, id: &CatalogVersionId) -> Option<&CatalogVersion> {
        self.catalogs.iter().find(|version| &version.id == id)
    }

    /// Look up a price-book version by id.
    pub fn price_book(&self, id: &PriceBookVersionId) -> Option<&PriceBookVersion> {
        self.price_books.iter().find(|version| &version.id == id)
    }

    /// Look up a tax-table version by id.
    pub fn tax_table(&self, id: &TaxTableVersionId) -> Option<&TaxTableVersion> {
        self.tax_tables.iter().find(|version| &version.id == id)
    }

    /// Catalog versions in publication order.
    pub fn catalogs(&self) -> impl Iterator<Item = &CatalogVersion> {
        self.catalogs.iter()
    }

    /// Price-book versions in publication order.
    pub fn price_books(&self) -> impl Iterator<Item = &PriceBookVersion> {
        self.price_books.iter()
    }

    /// Tax-table versions in publication order.
    pub fn tax_tables(&self) -> impl Iterator<Item = &TaxTableVersion> {
        self.tax_tables.iter()
    }

    /// The effective catalog at `at`.
    pub fn effective_catalog(&self, at: Timestamp) -> Result<&CatalogVersion, PosError> {
        self.catalogs
            .iter()
            .find(|version| version.effective.contains(at))
            .ok_or(PosError::NoEffectiveVersion("catalog"))
    }

    /// The effective price book for `currency` at `at`.
    pub fn effective_price_book(
        &self,
        currency: Currency,
        at: Timestamp,
    ) -> Result<&PriceBookVersion, PosError> {
        self.price_books
            .iter()
            .find(|version| version.currency == currency && version.effective.contains(at))
            .ok_or(PosError::NoEffectiveVersion("price book"))
    }

    /// The effective tax table for `jurisdiction` at `at`.
    pub fn effective_tax_table(
        &self,
        jurisdiction: &JurisdictionId,
        at: Timestamp,
    ) -> Result<&TaxTableVersion, PosError> {
        self.tax_tables
            .iter()
            .find(|version| &version.jurisdiction == jurisdiction && version.effective.contains(at))
            .ok_or(PosError::NoEffectiveVersion("tax table"))
    }

    /// Pin the catalog, price book and tax table effective at `at`.
    pub fn pin_at(
        &self,
        at: Timestamp,
        currency: Currency,
        jurisdiction: &JurisdictionId,
    ) -> Result<VersionPin, PosError> {
        let catalog = self.effective_catalog(at)?;
        let price_book = self.effective_price_book(currency, at)?;
        let tax_table = self.effective_tax_table(jurisdiction, at)?;
        Ok(VersionPin::new(
            catalog.id.clone(),
            price_book.id.clone(),
            tax_table.id.clone(),
        ))
    }

    /// Load the exact versions named by a pin.
    pub fn snapshot(&self, pin: &VersionPin) -> Result<PricedCatalog, PosError> {
        let catalog = self
            .catalog(&pin.catalog)
            .ok_or_else(|| PosError::VersionNotFound(pin.catalog.to_string()))?
            .clone();
        let price_book = self
            .price_book(&pin.price_book)
            .ok_or_else(|| PosError::VersionNotFound(pin.price_book.to_string()))?
            .clone();
        let tax_table = self
            .tax_table(&pin.tax_table)
            .ok_or_else(|| PosError::VersionNotFound(pin.tax_table.to_string()))?
            .clone();
        Ok(PricedCatalog::new(catalog, price_book, tax_table))
    }

    /// Publication and rollback events in sequence order.
    pub fn audit_events(&self) -> &[VersionAuditEvent] {
        &self.audit
    }

    fn insert_catalog(&mut self, version: CatalogVersion) -> Result<(), PosError> {
        if self.catalog(&version.id).is_some() {
            return Err(PosError::VersionAlreadyExists(version.id.to_string()));
        }
        if let Some(existing) = self
            .catalogs
            .iter()
            .find(|existing| existing.effective.overlaps(version.effective))
        {
            return Err(PosError::OverlappingEffectiveWindow {
                existing: existing.id.to_string(),
            });
        }
        self.catalogs.push(version);
        Ok(())
    }

    fn insert_price_book(&mut self, version: PriceBookVersion) -> Result<(), PosError> {
        if self.price_book(&version.id).is_some() {
            return Err(PosError::VersionAlreadyExists(version.id.to_string()));
        }
        if let Some(existing) = self.price_books.iter().find(|existing| {
            existing.currency == version.currency && existing.effective.overlaps(version.effective)
        }) {
            return Err(PosError::OverlappingEffectiveWindow {
                existing: existing.id.to_string(),
            });
        }
        self.price_books.push(version);
        Ok(())
    }

    fn insert_tax_table(&mut self, version: TaxTableVersion) -> Result<(), PosError> {
        if self.tax_table(&version.id).is_some() {
            return Err(PosError::VersionAlreadyExists(version.id.to_string()));
        }
        if let Some(existing) = self.tax_tables.iter().find(|existing| {
            existing.jurisdiction == version.jurisdiction
                && existing.effective.overlaps(version.effective)
        }) {
            return Err(PosError::OverlappingEffectiveWindow {
                existing: existing.id.to_string(),
            });
        }
        self.tax_tables.push(version);
        Ok(())
    }

    fn record(&mut self, actor: EmployeeId, at: Timestamp, kind: VersionAuditEventKind) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.audit.push(VersionAuditEvent {
            sequence,
            at,
            actor,
            kind,
        });
    }
}

fn validated_reason(reason: impl Into<String>) -> Result<String, PosError> {
    let reason = reason.into();
    if reason.trim().is_empty() {
        return Err(PosError::MissingReason);
    }
    validate_identifier(&reason, "rollback reason")?;
    Ok(reason)
}
