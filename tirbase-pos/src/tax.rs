// SPDX-License-Identifier: AGPL-3.0-only

//! POS-10 — tax calculation, inclusive/exclusive pricing and applicability.
//!
//! This module deliberately contains no jurisdiction default. A deployment
//! supplies a [`TaxProfile`] built from its own published rates, currency,
//! rounding rule and product classifications. The profile is data; the
//! arithmetic is the same for every jurisdiction.
//!
//! ## Calculation model
//!
//! A profile has an ordered list of [`TaxComponent`]s. A non-compounding
//! component is charged on the net amount. A compounding component is charged
//! on the net amount plus every tax already calculated, so the common
//! "GST then QST on GST" case is expressible without a special case. A
//! non-compounding component may not follow a compounding one: that ordering
//! would make the result depend on an arbitrary grouping and is rejected.
//!
//! For [`TaxPricing::Exclusive`] the input amount is the net; for
//! [`TaxPricing::Inclusive`] it is the gross, and the engine extracts the net
//! by reversing the same component order. In both directions every division
//! uses the profile's [`RoundingMode`]. Inclusive extraction can leave a
//! one-minor-unit difference after per-component rounding; the difference is
//! reported in [`TaxBreakdown::rounding_adjustment`] and applied to the final
//! component so `net + tax == gross` exactly.
//!
//! [`TaxTreatment::ZeroRated`] and [`TaxTreatment::Exempt`] are distinct states
//! in the result even though both collect zero tax. Neither is allowed to fall
//! back to the standard components.

use crate::catalog::{CatalogItem, TaxApplicability};
use crate::error::PosError;
use crate::ids::{validate_identifier, JurisdictionId};
use crate::money::{Currency, Money, Rate, RATE_SCALE};
use crate::rounding::{div_round, RoundingMode};

/// Maximum number of components in one tax profile.
pub const MAX_TAX_COMPONENTS: usize = 8;

/// How a profile's amounts are quoted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaxPricing {
    /// The input is net; tax is added to produce the gross.
    Exclusive,
    /// The input is gross; tax is extracted to produce the net.
    Inclusive,
}

/// How a product is treated for tax.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaxTreatment {
    /// The profile's standard components apply.
    Standard,
    /// Taxable supply at a zero rate; the rate rows are retained at zero.
    ZeroRated,
    /// Outside the scope of tax; no tax is collected.
    Exempt,
}

impl TaxTreatment {
    /// `true` when the standard components must be charged.
    pub fn is_taxable(self) -> bool {
        matches!(self, TaxTreatment::Standard)
    }

    /// Stable label for logs and receipts.
    pub fn label(self) -> &'static str {
        match self {
            TaxTreatment::Standard => "standard",
            TaxTreatment::ZeroRated => "zero-rated",
            TaxTreatment::Exempt => "exempt",
        }
    }
}

/// One tax charged by a jurisdiction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxComponent {
    id: String,
    rate: Rate,
    compounding: bool,
}

impl TaxComponent {
    /// Construct a component. `compounding` charges this component on the net
    /// plus all earlier taxes.
    pub fn new(id: impl Into<String>, rate: Rate, compounding: bool) -> Result<Self, TaxError> {
        let id = id.into();
        validate_identifier(&id, "tax component id").map_err(|_| TaxError::InvalidComponentId)?;
        Ok(Self {
            id,
            rate,
            compounding,
        })
    }

    /// The component label, such as `VAT` or `QST`.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The component rate.
    pub fn rate(&self) -> Rate {
        self.rate
    }

    /// `true` when this component compounds on earlier taxes.
    pub fn is_compounding(&self) -> bool {
        self.compounding
    }
}

/// One calculated tax component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxComponentAmount {
    /// The component label.
    pub id: String,
    /// The rate applied.
    pub rate: Rate,
    /// `true` when the component compounded on earlier taxes.
    pub compounding: bool,
    /// The base this component was charged on.
    pub taxable_base: Money,
    /// The tax collected for this component.
    pub tax: Money,
}

/// The result of one tax calculation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxBreakdown {
    /// The treatment used.
    pub treatment: TaxTreatment,
    /// Whether the input was inclusive or exclusive.
    pub pricing: TaxPricing,
    /// Net amount, excluding tax.
    pub net: Money,
    /// Total tax across all components.
    pub tax: Money,
    /// Gross amount, including tax.
    pub gross: Money,
    /// One row per profile component, in profile order.
    pub components: Vec<TaxComponentAmount>,
    /// A minor-unit correction applied to the final component so that
    /// `net + tax == gross` after inclusive extraction.
    pub rounding_adjustment: Money,
}

/// A product classification within a jurisdiction profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxClassification {
    applicability: TaxApplicability,
    treatment: TaxTreatment,
}

impl TaxClassification {
    /// Classify an item, category or every product.
    pub fn new(applicability: TaxApplicability, treatment: TaxTreatment) -> Result<Self, TaxError> {
        if let TaxApplicability::Category(category) = &applicability {
            validate_identifier(category, "tax category")
                .map_err(|_| TaxError::InvalidClassification)?;
        }
        Ok(Self {
            applicability,
            treatment,
        })
    }

    /// What the classification applies to.
    pub fn applicability(&self) -> &TaxApplicability {
        &self.applicability
    }

    /// The treatment for matching products.
    pub fn treatment(&self) -> TaxTreatment {
        self.treatment
    }
}

/// The calculation engine for one pricing convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxEngine {
    pricing: TaxPricing,
    rounding: RoundingMode,
    components: Vec<TaxComponent>,
}

impl TaxEngine {
    /// Build an engine, rejecting duplicate ids, too many components and a
    /// non-compounding component after a compounding one.
    pub fn new(
        pricing: TaxPricing,
        rounding: RoundingMode,
        components: Vec<TaxComponent>,
    ) -> Result<Self, TaxError> {
        if components.len() > MAX_TAX_COMPONENTS {
            return Err(TaxError::TooManyComponents {
                components: components.len(),
                limit: MAX_TAX_COMPONENTS,
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut compounded = false;
        for component in &components {
            if !seen.insert(component.id.clone()) {
                return Err(TaxError::DuplicateComponent(component.id.clone()));
            }
            if compound_order_is_invalid(compounded, component.compounding) {
                return Err(TaxError::NonCompoundingAfterCompound(component.id.clone()));
            }
            compounded |= component.compounding;
        }
        Ok(Self {
            pricing,
            rounding,
            components,
        })
    }

    /// The profile's pricing convention.
    pub fn pricing(&self) -> TaxPricing {
        self.pricing
    }

    /// The profile's rounding mode.
    pub fn rounding(&self) -> RoundingMode {
        self.rounding
    }

    /// The profile's components.
    pub fn components(&self) -> &[TaxComponent] {
        &self.components
    }

    /// Calculate tax for an amount.
    ///
    /// For exclusive pricing `amount` is net; for inclusive pricing it is
    /// gross. Negative amounts (a return) are calculated with the same signs.
    pub fn calculate(
        &self,
        amount: Money,
        treatment: TaxTreatment,
    ) -> Result<TaxBreakdown, TaxError> {
        if !treatment.is_taxable() {
            return self.zero_breakdown(amount, treatment);
        }

        match self.pricing {
            TaxPricing::Exclusive => {
                let rows = self.forward(amount, amount.currency())?;
                let tax = sum_tax(&rows, amount.currency())?;
                let gross = amount.checked_add(tax).map_err(TaxError::from)?;
                Ok(TaxBreakdown {
                    treatment,
                    pricing: self.pricing,
                    net: amount,
                    tax,
                    gross,
                    components: rows,
                    rounding_adjustment: Money::zero(amount.currency()),
                })
            }
            TaxPricing::Inclusive => {
                let net = self.extract_net(amount)?;
                let mut rows = self.forward(net, amount.currency())?;
                let calculated = sum_tax(&rows, amount.currency())?;
                let residual = amount
                    .checked_sub(net)
                    .and_then(|value| value.checked_sub(calculated))
                    .map_err(TaxError::from)?;
                if !residual.is_zero() {
                    if let Some(last) = rows.last_mut() {
                        last.tax = last.tax.checked_add(residual).map_err(TaxError::from)?;
                    }
                }
                let tax = amount.checked_sub(net).map_err(TaxError::from)?;
                Ok(TaxBreakdown {
                    treatment,
                    pricing: self.pricing,
                    net,
                    tax,
                    gross: amount,
                    components: rows,
                    rounding_adjustment: residual,
                })
            }
        }
    }

    fn zero_breakdown(
        &self,
        amount: Money,
        treatment: TaxTreatment,
    ) -> Result<TaxBreakdown, TaxError> {
        let zero = Money::zero(amount.currency());
        let rows = self
            .components
            .iter()
            .map(|component| TaxComponentAmount {
                id: component.id.clone(),
                rate: component.rate,
                compounding: component.compounding,
                taxable_base: zero,
                tax: zero,
            })
            .collect();
        Ok(TaxBreakdown {
            treatment,
            pricing: self.pricing,
            net: amount,
            tax: zero,
            gross: amount,
            components: rows,
            rounding_adjustment: zero,
        })
    }

    fn forward(&self, net: Money, currency: Currency) -> Result<Vec<TaxComponentAmount>, TaxError> {
        let mut rows: Vec<TaxComponentAmount> = Vec::with_capacity(self.components.len());
        let mut prior_tax = Money::zero(currency);
        for component in &self.components {
            let base = if component.compounding {
                net.checked_add(prior_tax).map_err(TaxError::from)?
            } else {
                net
            };
            let tax = base.mul_rate(component.rate, self.rounding)?;
            prior_tax = prior_tax.checked_add(tax).map_err(TaxError::from)?;
            rows.push(TaxComponentAmount {
                id: component.id.clone(),
                rate: component.rate,
                compounding: component.compounding,
                taxable_base: base,
                tax,
            });
        }
        Ok(rows)
    }

    /// Reverse the forward calculation to recover the net from a gross.
    fn extract_net(&self, gross: Money) -> Result<Money, TaxError> {
        let currency = gross.currency();
        let mut value = gross;
        for component in self.components.iter().rev() {
            if component.compounding {
                value = divide_by_rate(value, component.rate, self.rounding)?;
            }
        }
        let non_compounding: i128 = self
            .components
            .iter()
            .filter(|component| !component.compounding)
            .map(|component| i128::from(component.rate.ppm()))
            .sum();
        let denominator = RATE_SCALE + non_compounding;
        let numerator = i128::from(value.minor()) * RATE_SCALE;
        let net = div_round(numerator, denominator, self.rounding)?;
        Ok(Money::new(currency, net))
    }
}

/// A jurisdiction profile: currency, calculation engine and product classes.
///
/// The profile is a value object. It does not mutate and does not claim that
/// its rates are legally current; a deployment is responsible for loading
/// published rates and effective dates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxProfile {
    jurisdiction: JurisdictionId,
    currency: Currency,
    engine: TaxEngine,
    classifications: Vec<TaxClassification>,
}

impl TaxProfile {
    /// Build a profile. Product classifications must not repeat an
    /// applicability, so resolution is unambiguous.
    pub fn new(
        jurisdiction: JurisdictionId,
        currency: Currency,
        engine: TaxEngine,
        classifications: Vec<TaxClassification>,
    ) -> Result<Self, TaxError> {
        let mut seen = std::collections::BTreeSet::new();
        for classification in &classifications {
            if !seen.insert(classification.applicability.clone()) {
                return Err(TaxError::DuplicateClassification);
            }
        }
        Ok(Self {
            jurisdiction,
            currency,
            engine,
            classifications,
        })
    }

    /// The jurisdiction this profile belongs to.
    pub fn jurisdiction(&self) -> &JurisdictionId {
        &self.jurisdiction
    }

    /// The profile currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// The calculation engine.
    pub fn engine(&self) -> &TaxEngine {
        &self.engine
    }

    /// Resolve a product's treatment using item, category, then all-products
    /// precedence. A product with no matching classification is `Standard`.
    pub fn treatment_for(&self, item: &CatalogItem) -> TaxTreatment {
        if let Some(classification) = self.classifications.iter().find(|classification| {
            matches!(
                &classification.applicability,
                TaxApplicability::Item(id) if id == item.id()
            )
        }) {
            return classification.treatment;
        }
        if let Some(category) = item.category() {
            if let Some(classification) = self.classifications.iter().find(|classification| {
                matches!(
                    &classification.applicability,
                    TaxApplicability::Category(value) if value == category
                )
            }) {
                return classification.treatment;
            }
        }
        self.classifications
            .iter()
            .find(|classification| matches!(classification.applicability, TaxApplicability::All))
            .map(|classification| classification.treatment)
            .unwrap_or(TaxTreatment::Standard)
    }

    /// Calculate tax for a catalog item. The amount currency must be the
    /// profile currency.
    pub fn calculate_for_item(
        &self,
        amount: Money,
        item: &CatalogItem,
    ) -> Result<TaxBreakdown, TaxError> {
        if amount.currency() != self.currency {
            return Err(TaxError::CurrencyMismatch);
        }
        self.engine.calculate(amount, self.treatment_for(item))
    }
}

fn compound_order_is_invalid(seen_compound: bool, compounding: bool) -> bool {
    seen_compound && !compounding
}

fn sum_tax(rows: &[TaxComponentAmount], currency: Currency) -> Result<Money, TaxError> {
    let mut total = Money::zero(currency);
    for row in rows {
        total = total.checked_add(row.tax).map_err(TaxError::from)?;
    }
    Ok(total)
}

fn divide_by_rate(value: Money, rate: Rate, rounding: RoundingMode) -> Result<Money, TaxError> {
    let denominator = RATE_SCALE + i128::from(rate.ppm());
    let numerator = i128::from(value.minor()) * RATE_SCALE;
    let net = div_round(numerator, denominator, rounding)?;
    Ok(Money::new(value.currency(), net))
}

/// A rejected tax configuration or calculation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaxError {
    /// A component id was empty, too long or contained control characters.
    InvalidComponentId,
    /// Two components used the same id.
    DuplicateComponent(String),
    /// The profile has more than [`MAX_TAX_COMPONENTS`].
    TooManyComponents {
        /// The supplied count.
        components: usize,
        /// The supported limit.
        limit: usize,
    },
    /// A non-compounding component followed a compounding one.
    NonCompoundingAfterCompound(String),
    /// A classification category was invalid.
    InvalidClassification,
    /// Two classifications used the same applicability.
    DuplicateClassification,
    /// The amount and profile use different currencies.
    CurrencyMismatch,
    /// A monetary intermediate overflowed.
    ArithmeticOverflow,
}

impl TaxError {
    /// Stable reason code for logs and policy.
    pub fn code(&self) -> &'static str {
        match self {
            TaxError::InvalidComponentId => "tax.invalid_component_id",
            TaxError::DuplicateComponent(_) => "tax.duplicate_component",
            TaxError::TooManyComponents { .. } => "tax.too_many_components",
            TaxError::NonCompoundingAfterCompound(_) => "tax.compound_order",
            TaxError::InvalidClassification => "tax.invalid_classification",
            TaxError::DuplicateClassification => "tax.duplicate_classification",
            TaxError::CurrencyMismatch => "tax.currency_mismatch",
            TaxError::ArithmeticOverflow => "tax.arithmetic_overflow",
        }
    }
}

impl From<PosError> for TaxError {
    fn from(value: PosError) -> Self {
        match value {
            PosError::ArithmeticOverflow | PosError::InvalidDivisor => TaxError::ArithmeticOverflow,
            _ => TaxError::ArithmeticOverflow,
        }
    }
}

impl std::fmt::Display for TaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaxError::InvalidComponentId => f.write_str("invalid tax component id"),
            TaxError::DuplicateComponent(id) => write!(f, "duplicate tax component: {id}"),
            TaxError::TooManyComponents { components, limit } => {
                write!(
                    f,
                    "tax profile has {components} components; limit is {limit}"
                )
            }
            TaxError::NonCompoundingAfterCompound(id) => {
                write!(
                    f,
                    "non-compounding component {id} follows a compounding one"
                )
            }
            TaxError::InvalidClassification => f.write_str("invalid tax classification"),
            TaxError::DuplicateClassification => {
                f.write_str("duplicate tax classification applicability")
            }
            TaxError::CurrencyMismatch => f.write_str("tax currency mismatch"),
            TaxError::ArithmeticOverflow => f.write_str("tax arithmetic overflow"),
        }
    }
}

impl std::error::Error for TaxError {}
