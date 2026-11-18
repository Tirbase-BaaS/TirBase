// SPDX-License-Identifier: Apache-2.0

//! POS invoice input and its mapping onto the EN 16931 semantic model.
//!
//! The input is the shape a POS register holds after POS-10: a numbered,
//! time-stamped sale or refund, with integer quantities, minor-unit prices, a VAT
//! category and rate per line, optional line and document discounts, and the
//! payment that settled it. The mapping is total and deterministic:
//!
//! - quantities become thousandths, never floats;
//! - a document discount is apportioned across the VAT groups it applies to with
//!   largest-remainder rounding, so the breakdown still adds up to the document
//!   total;
//! - a refund becomes a credit note (type 381) that names the invoice it corrects;
//! - dates come from the register's epoch seconds in UTC, with no time-zone lookup.
//!
//! ```no_run
//! use tirbase_en16931::pos::PosInvoiceFile;
//!
//! let file = PosInvoiceFile::from_json(r#"{"invoices": []}"#)?;
//! assert!(file.invoices.is_empty());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use serde::{Deserialize, Serialize};

use crate::model::{
    Address, AllowanceCharge, Date, DocumentType, Invoice, InvoiceLine, Party, PaymentMeans,
    VatCategory,
};

/// A file of POS invoices, as the batch exporter reads it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PosInvoiceFile {
    /// Invoices, in export order.
    pub invoices: Vec<PosInvoice>,
}

impl PosInvoiceFile {
    /// Parse and structurally check a batch file.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let file: Self =
            serde_json::from_str(text).map_err(|error| format!("cannot parse batch: {error}"))?;
        if file.invoices.is_empty() {
            return Err("the batch contains no invoices".to_string());
        }
        Ok(file)
    }
}

/// VAT category as the register names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PosVatCategory {
    /// Standard rate.
    Standard,
    /// Zero rate.
    Zero,
    /// Exempt.
    Exempt,
    /// Reverse charge.
    ReverseCharge,
    /// Intra-community supply.
    IntraCommunity,
    /// Export.
    Export,
    /// Outside the scope of VAT.
    OutsideScope,
}

impl PosVatCategory {
    /// The EN 16931 category.
    pub fn to_model(self) -> VatCategory {
        match self {
            PosVatCategory::Standard => VatCategory::Standard,
            PosVatCategory::Zero => VatCategory::Zero,
            PosVatCategory::Exempt => VatCategory::Exempt,
            PosVatCategory::ReverseCharge => VatCategory::ReverseCharge,
            PosVatCategory::IntraCommunity => VatCategory::IntraCommunity,
            PosVatCategory::Export => VatCategory::Export,
            PosVatCategory::OutsideScope => VatCategory::OutsideScope,
        }
    }
}

/// A party as the register holds it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PosParty {
    /// Registered name.
    pub name: String,
    /// Trading name.
    #[serde(default)]
    pub trading_name: Option<String>,
    /// VAT identifier with its country prefix.
    #[serde(default)]
    pub vat_id: Option<String>,
    /// Legal registration identifier.
    #[serde(default)]
    pub legal_id: Option<String>,
    /// Scheme of the legal identifier.
    #[serde(default)]
    pub legal_scheme: Option<String>,
    /// Street and number.
    pub line1: String,
    /// Additional address line.
    #[serde(default)]
    pub line2: Option<String>,
    /// City.
    pub city: String,
    /// Postal code.
    pub postcode: String,
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// Electronic address.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Scheme of the electronic address.
    #[serde(default)]
    pub endpoint_scheme: Option<String>,
}

/// One register line.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PosLine {
    /// Register line identifier; the 1-based position when absent.
    #[serde(default)]
    pub id: Option<String>,
    /// Item description.
    pub description: String,
    /// Whole quantity.
    pub quantity: u32,
    /// Unit price in minor units, tax-exclusive.
    pub unit_price_minor: i64,
    /// VAT category.
    pub vat_category: PosVatCategory,
    /// VAT rate in basis points.
    #[serde(default)]
    pub vat_rate_bp: u32,
    /// UN/ECE Recommendation 20 unit code.
    #[serde(default)]
    pub unit_code: Option<String>,
    /// Line discount in minor units.
    #[serde(default)]
    pub discount_minor: Option<i64>,
}

/// A register invoice or refund.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PosInvoice {
    /// Tenant the sale belongs to (batch grouping only; never serialized).
    pub tenant: String,
    /// Document number.
    pub number: String,
    /// Issue instant, epoch seconds.
    pub issued_est: i64,
    /// Payment due instant, epoch seconds.
    #[serde(default)]
    pub due_est: Option<i64>,
    /// ISO 4217 currency.
    pub currency: String,
    /// Seller.
    pub seller: PosParty,
    /// Buyer.
    pub buyer: PosParty,
    /// Lines.
    pub lines: Vec<PosLine>,
    /// Document-level discount in minor units.
    #[serde(default)]
    pub document_discount_minor: i64,
    /// Amount already paid.
    #[serde(default)]
    pub prepaid_minor: i64,
    /// Rounding applied to the payable amount; may be negative.
    #[serde(default)]
    pub rounding_minor: i64,
    /// UN/ECE 4461 payment means code.
    #[serde(default)]
    pub payment_code: Option<String>,
    /// Payment instruction.
    #[serde(default)]
    pub payment_instruction: Option<String>,
    /// Payment reference.
    #[serde(default)]
    pub payment_reference: Option<String>,
    /// Buyer reference (order or cost centre).
    #[serde(default)]
    pub buyer_reference: Option<String>,
    /// Free-text note.
    #[serde(default)]
    pub note: Option<String>,
    /// Invoice this document corrects; its presence makes the document a credit
    /// note.
    #[serde(default)]
    pub refund_of: Option<String>,
}

impl PosInvoice {
    /// Whether this is a refund (credit note).
    pub fn is_refund(&self) -> bool {
        self.refund_of.is_some()
    }

    /// Map the register invoice onto the EN 16931 model.
    ///
    /// Returns every problem it found rather than the first, so a batch export can
    /// report a complete list for one document.
    pub fn to_invoice(&self) -> Result<Invoice, Vec<String>> {
        let mut problems = Vec::new();
        let issue_date = Date::from_unix_seconds(self.issued_est);
        let due_date = self.due_est.map(Date::from_unix_seconds);

        let seller = party(&self.seller, "seller", &mut problems);
        let buyer = party(&self.buyer, "buyer", &mut problems);

        if self.lines.is_empty() {
            problems.push(format!("{}: the invoice has no lines", self.number));
        }

        let mut lines = Vec::new();
        for (index, line) in self.lines.iter().enumerate() {
            if line.quantity == 0 {
                problems.push(format!(
                    "{}:{}: the quantity must be greater than zero",
                    self.number,
                    index + 1
                ));
                continue;
            }
            if line.unit_price_minor < 0 {
                problems.push(format!(
                    "{}:{}: the unit price must not be negative",
                    self.number,
                    index + 1
                ));
                continue;
            }
            let category = line.vat_category.to_model();
            if !category.is_taxed() && line.vat_rate_bp != 0 {
                problems.push(format!(
                    "{}:{}: category {} must carry a zero rate",
                    self.number,
                    index + 1,
                    category.code()
                ));
                continue;
            }
            let quantity_milli = i64::from(line.quantity) * 1_000;
            let id = line.id.clone().unwrap_or_else(|| (index + 1).to_string());
            let unit_code = line.unit_code.clone().unwrap_or_else(|| "C62".to_string());
            let built = InvoiceLine::new(
                &id,
                &line.description,
                quantity_milli,
                &unit_code,
                line.unit_price_minor,
                category,
                line.vat_rate_bp,
            );
            match built {
                Ok(line_model) => {
                    let discount = line.discount_minor.unwrap_or(0);
                    if discount < 0 || discount > line_model.gross_minor() {
                        problems.push(format!(
                            "{}:{}: the discount must be between zero and the line amount",
                            self.number,
                            index + 1
                        ));
                        continue;
                    }
                    lines.push(if discount > 0 {
                        line_model.with_allowance(discount, "Line discount")
                    } else {
                        line_model
                    });
                }
                Err(detail) => problems.push(format!("{}:{index}: {detail}", self.number)),
            }
        }

        let mut allowances = Vec::new();
        if self.document_discount_minor < 0 {
            problems.push(format!(
                "{}: the document discount must not be negative",
                self.number
            ));
        } else if self.document_discount_minor > 0 {
            let line_total: i64 = lines.iter().map(InvoiceLine::net_minor).sum();
            if self.document_discount_minor > line_total {
                problems.push(format!(
                    "{}: the document discount exceeds the line total",
                    self.number
                ));
            } else {
                allowances =
                    apportioned_discounts(&lines, self.document_discount_minor, &mut problems);
            }
        }

        let payment_means = match &self.payment_code {
            Some(code) => match PaymentMeans::new(code, self.payment_instruction.as_deref()) {
                Ok(means) => Some(means),
                Err(detail) => {
                    problems.push(format!("{}: {detail}", self.number));
                    None
                }
            },
            None => None,
        };

        let (seller, buyer) = match (seller, buyer) {
            (Some(seller), Some(buyer)) => (seller, buyer),
            _ => {
                return Err(problems);
            }
        };

        let invoice = Invoice {
            number: self.number.trim().to_string(),
            issue_date,
            due_date,
            document_type: if self.is_refund() {
                DocumentType::CreditNote
            } else {
                DocumentType::Invoice
            },
            currency: self.currency.trim().to_uppercase(),
            seller,
            buyer,
            lines,
            allowances,
            charges: Vec::new(),
            prepaid_minor: self.prepaid_minor,
            rounding_minor: self.rounding_minor,
            payment_means,
            payment_reference: self.payment_reference.clone(),
            buyer_reference: self.buyer_reference.clone(),
            note: self.note.clone(),
            preceding_invoices: self.refund_of.iter().cloned().collect(),
        };

        for issue in invoice.validate() {
            problems.push(format!(
                "{}: {} ({})",
                self.number, issue.message, issue.rule
            ));
        }
        if problems.is_empty() {
            Ok(invoice)
        } else {
            Err(problems)
        }
    }
}

fn party(source: &PosParty, role: &str, problems: &mut Vec<String>) -> Option<Party> {
    let address = match Address::new(
        &source.line1,
        source.line2.as_deref(),
        &source.city,
        &source.postcode,
        &source.country,
    ) {
        Ok(address) => address,
        Err(detail) => {
            problems.push(format!("{role}: {detail}"));
            return None;
        }
    };
    let mut party = match Party::new(&source.name, address) {
        Ok(party) => party,
        Err(detail) => {
            problems.push(format!("{role}: {detail}"));
            return None;
        }
    };
    if let Some(trading_name) = &source.trading_name {
        party = party.with_trading_name(trading_name);
    }
    if let Some(vat_id) = &source.vat_id {
        party = party.with_vat_id(vat_id);
    }
    if let (Some(id), Some(scheme)) = (&source.legal_id, &source.legal_scheme) {
        party = party.with_legal_id(id, scheme);
    }
    if let (Some(endpoint), Some(scheme)) = (&source.endpoint, &source.endpoint_scheme) {
        party.endpoint = Some((endpoint.clone(), scheme.clone()));
    }
    Some(party)
}

/// Split a document discount across the VAT groups it applies to.
///
/// Largest-remainder apportionment: every group gets its proportional share
/// floored, then the remaining minor units go to the groups with the largest
/// fractional part (ties to the earlier group, which is the category/rate order).
/// The shares always add up to `total_minor`, so the VAT breakdown stays balanced.
fn apportioned_discounts(
    lines: &[InvoiceLine],
    total_minor: i64,
    problems: &mut Vec<String>,
) -> Vec<AllowanceCharge> {
    let mut groups: std::collections::BTreeMap<(VatCategory, u32), i64> =
        std::collections::BTreeMap::new();
    for line in lines {
        *groups
            .entry((line.vat_category, line.vat_rate_bp))
            .or_insert(0) += line.net_minor();
    }
    let base: i64 = groups.values().sum();
    if base <= 0 {
        problems.push("the document discount has no positive base".to_string());
        return Vec::new();
    }
    let weights: Vec<((VatCategory, u32), i64)> = groups.into_iter().collect();
    let shares = apportion(total_minor, &weights, base);
    let mut allowances = Vec::new();
    for (index, ((category, rate_bp), _weight)) in weights.iter().enumerate() {
        let share = shares[index];
        if share <= 0 {
            continue;
        }
        match AllowanceCharge::new("Document discount", share, *category, *rate_bp) {
            Ok(allowance) => allowances.push(allowance),
            Err(detail) => problems.push(detail),
        }
    }
    allowances
}

/// Largest-remainder apportionment of `total` over `weights`.
fn apportion(total: i64, weights: &[((VatCategory, u32), i64)], base: i64) -> Vec<i64> {
    let mut shares: Vec<i64> = Vec::with_capacity(weights.len());
    let mut remainders: Vec<(i128, usize)> = Vec::with_capacity(weights.len());
    let mut assigned = 0i64;
    for (index, (_key, weight)) in weights.iter().enumerate() {
        let numerator = i128::from(total) * i128::from(*weight);
        let denominator = i128::from(base);
        let floor = numerator / denominator;
        let remainder = numerator % denominator;
        let share = i64::try_from(floor).unwrap_or(i64::MAX);
        shares.push(share);
        assigned = assigned.saturating_add(share);
        remainders.push((remainder, index));
    }
    remainders.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let mut leftover = total.saturating_sub(assigned);
    for (_, index) in remainders {
        if leftover <= 0 {
            break;
        }
        shares[index] = shares[index].saturating_add(1);
        leftover -= 1;
    }
    shares
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(name: &str, country: &str) -> PosParty {
        PosParty {
            name: name.to_string(),
            trading_name: None,
            vat_id: Some("ESA12345674".to_string()),
            legal_id: None,
            legal_scheme: None,
            line1: "Calle Mayor 1".to_string(),
            line2: None,
            city: "Madrid".to_string(),
            postcode: "28013".to_string(),
            country: country.to_string(),
            endpoint: None,
            endpoint_scheme: None,
        }
    }

    fn invoice() -> PosInvoice {
        PosInvoice {
            tenant: "acme".to_string(),
            number: "INV-1".to_string(),
            issued_est: 1_767_225_600,
            due_est: None,
            currency: "eur".to_string(),
            seller: party("Acme", "ES"),
            buyer: party("Customer", "ES"),
            lines: vec![
                PosLine {
                    id: None,
                    description: "Espresso".to_string(),
                    quantity: 2,
                    unit_price_minor: 250,
                    vat_category: PosVatCategory::Standard,
                    vat_rate_bp: 2_100,
                    unit_code: None,
                    discount_minor: None,
                },
                PosLine {
                    id: None,
                    description: "Bread".to_string(),
                    quantity: 1,
                    unit_price_minor: 120,
                    vat_category: PosVatCategory::Zero,
                    vat_rate_bp: 0,
                    unit_code: None,
                    discount_minor: None,
                },
            ],
            document_discount_minor: 0,
            prepaid_minor: 0,
            rounding_minor: 0,
            payment_code: Some("30".to_string()),
            payment_instruction: None,
            payment_reference: None,
            buyer_reference: None,
            note: None,
            refund_of: None,
        }
    }

    #[test]
    fn a_sale_maps_onto_the_model() {
        let invoice = invoice().to_invoice().expect("mapped");
        assert_eq!(invoice.issue_date.to_iso(), "2026-01-01");
        assert_eq!(invoice.currency, "EUR");
        assert_eq!(invoice.document_type, DocumentType::Invoice);
        assert_eq!(invoice.lines.len(), 2);
        assert_eq!(invoice.lines[0].id, "1");
        assert_eq!(invoice.lines[1].id, "2");
        assert_eq!(invoice.tax_exclusive_minor(), 620);
        assert_eq!(invoice.tax_total_minor(), 105);
    }

    #[test]
    fn a_document_discount_is_apportioned_and_still_balances() {
        let mut source = invoice();
        source.document_discount_minor = 100;
        let mapped = source.to_invoice().expect("mapped");
        let discount: i64 = mapped
            .allowances
            .iter()
            .map(|entry| entry.amount_minor)
            .sum();
        assert_eq!(discount, 100);
        let groups = mapped.breakdown();
        let line_total: i64 = groups.iter().map(|group| group.taxable_minor).sum();
        assert_eq!(line_total, mapped.tax_exclusive_minor());
        assert_eq!(mapped.tax_exclusive_minor(), 520);
        assert_eq!(mapped.allowances.len(), 2);
    }

    #[test]
    fn a_refund_becomes_a_credit_note_that_names_its_invoice() {
        let mut source = invoice();
        source.refund_of = Some("INV-1".to_string());
        let mapped = source.to_invoice().expect("mapped");
        assert_eq!(mapped.document_type, DocumentType::CreditNote);
        assert_eq!(mapped.preceding_invoices, vec!["INV-1".to_string()]);
        assert_eq!(mapped.document_type.code(), "381");
    }

    #[test]
    fn bad_input_is_reported_in_full() {
        let mut source = invoice();
        source.lines[0].quantity = 0;
        source.lines[1].vat_rate_bp = 1_000;
        source.document_discount_minor = 100_000;
        let problems = source.to_invoice().expect_err("refused");
        assert!(problems.iter().any(|problem| problem.contains("quantity")));
        assert!(problems.iter().any(|problem| problem.contains("zero rate")));
        assert!(problems
            .iter()
            .any(|problem| problem.contains("discount exceeds")));
    }
}
