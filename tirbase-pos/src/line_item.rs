// SPDX-License-Identifier: AGPL-3.0-only

//! Line items, modifiers, discounts, tax lines and their exact arithmetic.
//!
//! # Calculation order
//!
//! For one line item, with the check's rounding mode:
//!
//! 1. `effective unit price = unit price + Σ modifier price deltas` (exact,
//!    modifiers must share the unit price currency, result must be non-negative).
//! 2. `base = round(quantity × effective unit price)`.
//! 3. `discount = amount`, or `round(base × rate)` for a percentage discount.
//! 4. `taxable base = base − discount`.
//! 5. `tax = round(taxable base × rate)`, absent a tax rate it is zero.
//! 6. `line total = taxable base + tax`.
//!
//! Every step is integer arithmetic on minor units. A check's `subtotal`,
//! `discount_total` and `tax_total` are the exact sums of the per-line values;
//! no group-level re-rounding happens. Taxes are reported grouped by rate into
//! [`TaxLine`] records whose amounts are the sums of the per-line tax values.

use crate::error::PosError;
use crate::ids::{validate_identifier, LineItemId};
use crate::money::{Money, Quantity, Rate};
use crate::rounding::RoundingMode;

/// A price adjustment attached to a line item, applied per unit of quantity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Modifier {
    label: String,
    price_delta: Money,
}

impl Modifier {
    /// Construct a modifier. `price_delta` may be negative (a reduction) or
    /// positive (an add-on); currency compatibility is checked when it is
    /// attached to a line item.
    pub fn new(label: impl Into<String>, price_delta: Money) -> Result<Self, PosError> {
        let label = label.into();
        validate_identifier(&label, "modifier label")?;
        Ok(Self { label, price_delta })
    }

    /// The modifier label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The per-unit price delta.
    pub fn price_delta(&self) -> Money {
        self.price_delta
    }
}

/// How a line discount is expressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscountKind {
    /// An exact amount off the line base.
    Amount(Money),
    /// A percentage off the line base.
    Percent(Rate),
}

/// A labelled line discount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discount {
    label: String,
    kind: DiscountKind,
}

impl Discount {
    /// A fixed-amount discount. The amount must not be negative; whether it
    /// exceeds the line base is checked when totals are computed.
    pub fn amount(label: impl Into<String>, amount: Money) -> Result<Self, PosError> {
        if amount.is_negative() {
            return Err(PosError::NegativeAmount);
        }
        let label = label.into();
        validate_identifier(&label, "discount label")?;
        Ok(Self {
            label,
            kind: DiscountKind::Amount(amount),
        })
    }

    /// A percentage discount, expressed in parts per million.
    pub fn percent(label: impl Into<String>, rate: Rate) -> Result<Self, PosError> {
        let label = label.into();
        validate_identifier(&label, "discount label")?;
        Ok(Self {
            label,
            kind: DiscountKind::Percent(rate),
        })
    }

    /// The discount label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The discount kind.
    pub fn kind(&self) -> DiscountKind {
        self.kind
    }
}

/// The computed monetary value of one line item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineTotals {
    /// The line item this total belongs to.
    pub line_item_id: LineItemId,
    /// The quantity used for the calculation.
    pub quantity: Quantity,
    /// `unit price + Σ modifiers`.
    pub effective_unit_price: Money,
    /// `round(quantity × effective unit price)`.
    pub base: Money,
    /// The discount applied to the base.
    pub discount: Money,
    /// `base − discount`.
    pub taxable_base: Money,
    /// The tax on `taxable_base` (zero when the line has no tax rate).
    pub tax: Money,
    /// The rate used for the tax, when present.
    pub tax_rate: Option<Rate>,
    /// `taxable_base + tax`.
    pub total: Money,
}

/// Tax collected at one rate.
///
/// `taxable_base` and `tax` are exact sums of the per-line values at this rate.
/// A check has one tax line per distinct rate, in ascending rate order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaxLine {
    /// The rate.
    pub rate: Rate,
    /// The sum of taxable bases at this rate.
    pub taxable_base: Money,
    /// The sum of per-line tax at this rate.
    pub tax: Money,
}

/// One sold item on a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineItem {
    id: LineItemId,
    name: String,
    sku: Option<String>,
    quantity: Quantity,
    unit_price: Money,
    modifiers: Vec<Modifier>,
    discount: Option<Discount>,
    tax_rate: Option<Rate>,
}

impl LineItem {
    /// Construct a line item with no modifiers, discount or tax.
    pub fn new(
        id: LineItemId,
        name: impl Into<String>,
        quantity: Quantity,
        unit_price: Money,
    ) -> Result<Self, PosError> {
        let name = name.into();
        validate_identifier(&name, "line item name")?;
        Ok(Self {
            id,
            name,
            sku: None,
            quantity,
            unit_price,
            modifiers: Vec::new(),
            discount: None,
            tax_rate: None,
        })
    }

    /// Attach an optional stock-keeping reference.
    pub fn with_sku(mut self, sku: impl Into<String>) -> Result<Self, PosError> {
        let sku = sku.into();
        validate_identifier(&sku, "line item sku")?;
        self.sku = Some(sku);
        Ok(self)
    }

    /// Attach a modifier. The modifier currency must match the unit price and
    /// the resulting effective unit price must not be negative.
    pub fn with_modifier(mut self, modifier: Modifier) -> Result<Self, PosError> {
        if modifier.price_delta().currency() != self.unit_price.currency() {
            return Err(PosError::CurrencyMismatch);
        }
        self.modifiers.push(modifier);
        self.effective_unit_price()?;
        Ok(self)
    }

    /// Attach a line discount. Amount discounts must share the unit price
    /// currency.
    pub fn with_discount(mut self, discount: Discount) -> Result<Self, PosError> {
        if let DiscountKind::Amount(amount) = discount.kind() {
            if amount.currency() != self.unit_price.currency() {
                return Err(PosError::CurrencyMismatch);
            }
        }
        self.discount = Some(discount);
        Ok(self)
    }

    /// Attach a tax rate.
    pub fn with_tax_rate(mut self, rate: Rate) -> Self {
        self.tax_rate = Some(rate);
        self
    }

    /// The line item identifier.
    pub fn id(&self) -> &LineItemId {
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

    /// The quantity.
    pub fn quantity(&self) -> Quantity {
        self.quantity
    }

    /// The catalogue unit price before modifiers.
    pub fn unit_price(&self) -> Money {
        self.unit_price
    }

    /// The attached modifiers.
    pub fn modifiers(&self) -> &[Modifier] {
        &self.modifiers
    }

    /// The optional discount.
    pub fn discount(&self) -> Option<&Discount> {
        self.discount.as_ref()
    }

    /// The optional tax rate.
    pub fn tax_rate(&self) -> Option<Rate> {
        self.tax_rate
    }

    /// `unit price + Σ modifier deltas`, rejecting a negative result.
    pub fn effective_unit_price(&self) -> Result<Money, PosError> {
        let mut price = self.unit_price;
        for modifier in &self.modifiers {
            price = price.checked_add(modifier.price_delta())?;
        }
        if price.is_negative() {
            return Err(PosError::NegativeEffectiveUnitPrice);
        }
        Ok(price)
    }

    /// Compute this line's exact monetary contribution under `mode`.
    pub fn compute(&self, mode: RoundingMode) -> Result<LineTotals, PosError> {
        let effective_unit_price = self.effective_unit_price()?;
        let base = effective_unit_price.mul_quantity(self.quantity, mode)?;

        let discount = match self.discount.as_ref().map(Discount::kind) {
            None => Money::zero(base.currency()),
            Some(DiscountKind::Amount(amount)) => amount,
            Some(DiscountKind::Percent(rate)) => base.mul_rate(rate, mode)?,
        };
        if discount.is_negative() {
            return Err(PosError::NegativeAmount);
        }
        if discount.minor() > base.minor() {
            return Err(PosError::DiscountExceedsBase);
        }

        let taxable_base = base.checked_sub(discount)?;
        let tax = match self.tax_rate {
            Some(rate) => taxable_base.mul_rate(rate, mode)?,
            None => Money::zero(base.currency()),
        };
        let total = taxable_base.checked_add(tax)?;

        Ok(LineTotals {
            line_item_id: self.id.clone(),
            quantity: self.quantity,
            effective_unit_price,
            base,
            discount,
            taxable_base,
            tax,
            tax_rate: self.tax_rate,
            total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::money::Currency;

    fn usd(minor: i64) -> Money {
        Money::new(Currency::from_code("USD").unwrap(), minor)
    }

    fn line(qty_thousandths: i64, unit_minor: i64) -> LineItem {
        LineItem::new(
            LineItemId::new("line-1").unwrap(),
            "Coffee",
            Quantity::from_thousandths(qty_thousandths).unwrap(),
            usd(unit_minor),
        )
        .unwrap()
    }

    #[test]
    fn modifiers_change_the_effective_unit_price() {
        let item = line(2_000, 500)
            .with_modifier(Modifier::new("Oat milk", usd(75)).unwrap())
            .unwrap()
            .with_modifier(Modifier::new("No lid", usd(-25)).unwrap())
            .unwrap();
        assert_eq!(item.effective_unit_price().unwrap(), usd(550));
        assert_eq!(
            item.compute(RoundingMode::HalfAwayFromZero).unwrap().base,
            usd(1_100)
        );
    }

    #[test]
    fn modifiers_that_make_a_price_negative_are_rejected() {
        let err = line(1_000, 50)
            .with_modifier(Modifier::new("Too much", usd(-51)).unwrap())
            .unwrap_err();
        assert_eq!(err, PosError::NegativeEffectiveUnitPrice);
    }

    #[test]
    fn percent_discount_rounds_then_tax_applies_to_the_discounted_base() {
        // 3 units at 0.99 = 2.97; 10% discount = 0.297 → 0.30; taxable 2.67;
        // 8.875% tax = 0.2369625 → 0.24; line total 2.91.
        let rate = Rate::from_ppm(88_750).unwrap();
        let item = line(3_000, 99)
            .with_discount(Discount::percent("Member", Rate::from_percent(10).unwrap()).unwrap())
            .unwrap()
            .with_tax_rate(rate);
        let totals = item.compute(RoundingMode::HalfAwayFromZero).unwrap();
        assert_eq!(totals.base, usd(297));
        assert_eq!(totals.discount, usd(30));
        assert_eq!(totals.taxable_base, usd(267));
        assert_eq!(totals.tax, usd(24));
        assert_eq!(totals.total, usd(291));
    }

    #[test]
    fn amount_discount_above_the_base_is_rejected() {
        let item = line(1_000, 100)
            .with_discount(Discount::amount("Coupon", usd(101)).unwrap())
            .unwrap();
        assert_eq!(
            item.compute(RoundingMode::HalfEven),
            Err(PosError::DiscountExceedsBase)
        );
    }

    #[test]
    fn discount_currency_must_match_the_unit_price() {
        let eur = Money::new(Currency::from_code("EUR").unwrap(), 10);
        let err = line(1_000, 100)
            .with_discount(Discount::amount("Coupon", eur).unwrap())
            .unwrap_err();
        assert_eq!(err, PosError::CurrencyMismatch);
    }

    #[test]
    fn negative_discount_amounts_are_rejected_at_construction() {
        assert_eq!(
            Discount::amount("Refund?", usd(-1)).unwrap_err(),
            PosError::NegativeAmount
        );
    }

    #[test]
    fn fractional_quantity_rounding_can_differ_by_mode() {
        // 1.005 units at 1.00 USD = 100.5 minor units.
        let item = line(1_005, 100);
        let half_up = item.compute(RoundingMode::HalfAwayFromZero).unwrap();
        let half_even = item.compute(RoundingMode::HalfEven).unwrap();
        let toward_zero = item.compute(RoundingMode::TowardZero).unwrap();
        assert_eq!(half_up.base, usd(101));
        // 100 is even, so banker's rounding leaves the half at 100.
        assert_eq!(half_even.base, usd(100));
        assert_eq!(toward_zero.base, usd(100));
    }
}
