// SPDX-License-Identifier: Apache-2.0

//! The EN 16931 semantic model, restricted to what a POS invoice needs.
//!
//! Amounts are integer minor units, quantities are integer thousandths and
//! percentages are integer basis points, so every figure the serializers emit is
//! derived by integer arithmetic with one half-up rounding step per derived
//! value. The model validates itself ([`Invoice::validate`]) before a serializer
//! touches it.
//!
//! Term identifiers in the doc comments (`BT-…`, `BR-…`) refer to EN 16931.

use std::collections::BTreeMap;

use crate::round_half_up;

/// Longest document number accepted.
pub const MAX_NUMBER_LEN: usize = 64;

/// Longest free-text field accepted.
pub const MAX_TEXT_LEN: usize = 240;

/// A calendar date without a time zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    /// Year.
    pub year: i32,
    /// Month, 1–12.
    pub month: u8,
    /// Day, 1–31.
    pub day: u8,
}

impl Date {
    /// Build a date, checking that it exists.
    pub fn new(year: i32, month: u8, day: u8) -> Result<Self, String> {
        let candidate = Self { year, month, day };
        if !candidate.is_valid() {
            return Err(format!(
                "{year:04}-{month:02}-{day:02} is not a calendar date"
            ));
        }
        Ok(candidate)
    }

    /// The UTC date of an epoch second.
    ///
    /// Uses the civil-from-days algorithm, so no time-zone database and no clock
    /// is consulted: the instant is the caller's and the result is a pure
    /// function of it.
    pub fn from_unix_seconds(seconds: i64) -> Self {
        let days = seconds.div_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        Self { year, month, day }
    }

    /// Whether the date exists.
    pub fn is_valid(&self) -> bool {
        if !(1..=12).contains(&self.month) || self.day == 0 || self.year < 1 {
            return false;
        }
        self.day <= days_in_month(self.year, self.month)
    }

    /// `YYYY-MM-DD` (UBL form).
    pub fn to_iso(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// `YYYYMMDD` (CII `format="102"` form).
    pub fn to_compact(self) -> String {
        format!("{:04}{:02}{:02}", self.year, self.month, self.day)
    }
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (
        i32::try_from(year).unwrap_or(i32::MAX),
        u8::try_from(m).unwrap_or(1),
        u8::try_from(d).unwrap_or(1),
    )
}

/// Invoice or credit note (BT-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentType {
    /// Commercial invoice, UN/CEFACT 380.
    Invoice,
    /// Credit note, UN/CEFACT 381.
    CreditNote,
}

impl DocumentType {
    /// UN/CEFACT 1001 document type code.
    pub fn code(self) -> &'static str {
        match self {
            DocumentType::Invoice => "380",
            DocumentType::CreditNote => "381",
        }
    }
}

/// EN 16931 VAT category code (BT-118 / BT-151).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VatCategory {
    /// Standard rated (`S`).
    Standard,
    /// Zero rated (`Z`).
    Zero,
    /// Exempt (`E`).
    Exempt,
    /// Reverse charge (`AE`).
    ReverseCharge,
    /// Intra-community supply (`K`).
    IntraCommunity,
    /// Export outside the EU (`G`).
    Export,
    /// Not subject to VAT (`O`).
    OutsideScope,
}

impl VatCategory {
    /// EN 16931 category code.
    pub fn code(self) -> &'static str {
        match self {
            VatCategory::Standard => "S",
            VatCategory::Zero => "Z",
            VatCategory::Exempt => "E",
            VatCategory::ReverseCharge => "AE",
            VatCategory::IntraCommunity => "K",
            VatCategory::Export => "G",
            VatCategory::OutsideScope => "O",
        }
    }

    /// Whether the category carries tax at its rate.
    ///
    /// Only a standard-rated line is taxed. Zero-rated, exempt, reverse-charge,
    /// intra-community and export supplies all carry a zero rate, and the model
    /// refuses a non-zero rate on them.
    pub fn is_taxed(self) -> bool {
        matches!(self, VatCategory::Standard)
    }

    /// Every category, in code order.
    pub fn all() -> [VatCategory; 7] {
        [
            VatCategory::Standard,
            VatCategory::Zero,
            VatCategory::Exempt,
            VatCategory::ReverseCharge,
            VatCategory::IntraCommunity,
            VatCategory::Export,
            VatCategory::OutsideScope,
        ]
    }
}

/// A postal address (BT-35…BT-41, BT-50…BT-55).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Street and number (BT-35/BT-50).
    pub line1: String,
    /// Additional address line.
    pub line2: Option<String>,
    /// City (BT-37/BT-52).
    pub city: String,
    /// Postal code (BT-38/BT-53).
    pub postcode: String,
    /// ISO 3166-1 alpha-2 country code (BT-40/BT-55).
    pub country: String,
}

impl Address {
    /// Build an address, checking the country code shape.
    pub fn new(
        line1: &str,
        line2: Option<&str>,
        city: &str,
        postcode: &str,
        country: &str,
    ) -> Result<Self, String> {
        let address = Self {
            line1: line1.trim().to_string(),
            line2: line2.map(|value| value.trim().to_string()),
            city: city.trim().to_string(),
            postcode: postcode.trim().to_string(),
            country: country.trim().to_uppercase(),
        };
        address.validate()?;
        Ok(address)
    }

    /// Check the mandatory fields and the country code.
    pub fn validate(&self) -> Result<(), String> {
        if self.line1.is_empty() || self.city.is_empty() || self.postcode.is_empty() {
            return Err("an address needs a street, a city and a postal code".to_string());
        }
        if self.country.len() != 2 || !self.country.chars().all(|c| c.is_ascii_uppercase()) {
            return Err(format!(
                "country {:?} must be two upper-case ISO 3166-1 letters",
                self.country
            ));
        }
        Ok(())
    }
}

/// A seller or buyer party (BG-4, BG-7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Party {
    /// Registered name (BT-27/BT-44).
    pub name: String,
    /// Trading name (BT-28/BT-45).
    pub trading_name: Option<String>,
    /// VAT identifier including the country prefix (BT-31/BT-48), when the party
    /// is VAT registered.
    pub vat_id: Option<String>,
    /// Legal registration identifier and its scheme (BT-30/BT-47).
    pub legal_id: Option<(String, String)>,
    /// Postal address.
    pub address: Address,
    /// Electronic address and its scheme (BT-34/BT-49), when known.
    pub endpoint: Option<(String, String)>,
}

impl Party {
    /// Build a party from its mandatory fields.
    pub fn new(name: &str, address: Address) -> Result<Self, String> {
        let party = Self {
            name: name.trim().to_string(),
            trading_name: None,
            vat_id: None,
            legal_id: None,
            address,
            endpoint: None,
        };
        party.validate()?;
        Ok(party)
    }

    /// Attach a VAT identifier.
    pub fn with_vat_id(mut self, vat_id: &str) -> Self {
        self.vat_id = Some(vat_id.trim().to_uppercase());
        self
    }

    /// Attach a legal registration identifier and scheme.
    pub fn with_legal_id(mut self, id: &str, scheme: &str) -> Self {
        self.legal_id = Some((id.trim().to_string(), scheme.trim().to_string()));
        self
    }

    /// Attach a trading name.
    pub fn with_trading_name(mut self, name: &str) -> Self {
        self.trading_name = Some(name.trim().to_string());
        self
    }

    /// Check the mandatory fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("a party needs a registered name".to_string());
        }
        if self.name.chars().count() > MAX_TEXT_LEN {
            return Err(format!(
                "a party name must be at most {MAX_TEXT_LEN} characters"
            ));
        }
        self.address.validate()
    }
}

/// One invoice line (BG-25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceLine {
    /// Line identifier (BT-126).
    pub id: String,
    /// Item name (BT-153).
    pub name: String,
    /// Item description (BT-154).
    pub description: Option<String>,
    /// Billed quantity in thousandths (BT-129).
    pub quantity_milli: i64,
    /// UN/ECE Recommendation 20 unit code (BT-130).
    pub unit_code: String,
    /// Net unit price in minor units (BT-146).
    pub unit_price_minor: i64,
    /// VAT category (BT-151).
    pub vat_category: VatCategory,
    /// VAT rate in basis points (BT-152); 2100 is 21 %.
    pub vat_rate_bp: u32,
    /// Line-level allowance in minor units, already included in the net amount.
    pub allowance_minor: i64,
    /// Why the line allowance was given.
    pub allowance_reason: Option<String>,
}

impl InvoiceLine {
    /// Build a line with no allowance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        name: &str,
        quantity_milli: i64,
        unit_code: &str,
        unit_price_minor: i64,
        vat_category: VatCategory,
        vat_rate_bp: u32,
    ) -> Result<Self, String> {
        let line = Self {
            id: id.trim().to_string(),
            name: name.trim().to_string(),
            description: None,
            quantity_milli,
            unit_code: unit_code.trim().to_string(),
            unit_price_minor,
            vat_category,
            vat_rate_bp,
            allowance_minor: 0,
            allowance_reason: None,
        };
        line.validate()?;
        Ok(line)
    }

    /// Attach a line-level allowance.
    pub fn with_allowance(mut self, minor: i64, reason: &str) -> Self {
        self.allowance_minor = minor;
        self.allowance_reason = Some(reason.trim().to_string());
        self
    }

    /// Attach a description.
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.trim().to_string());
        self
    }

    /// Quantity times unit price, before the allowance (BT-131 includes it).
    pub fn gross_minor(&self) -> i64 {
        round_half_up(
            i128::from(self.quantity_milli) * i128::from(self.unit_price_minor),
            1_000,
        )
    }

    /// Line net amount (BT-131).
    pub fn net_minor(&self) -> i64 {
        self.gross_minor().saturating_sub(self.allowance_minor)
    }

    /// Check the line invariants.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("a line needs an identifier".to_string());
        }
        if self.name.trim().is_empty() {
            return Err("a line needs an item name".to_string());
        }
        if self.quantity_milli <= 0 {
            return Err(format!("line {:?} needs a positive quantity", self.id));
        }
        if self.unit_price_minor < 0 {
            return Err(format!(
                "line {:?} must not have a negative unit price",
                self.id
            ));
        }
        if self.allowance_minor < 0 || self.allowance_minor > self.gross_minor() {
            return Err(format!(
                "line {:?} allowance must be between zero and the line gross amount",
                self.id
            ));
        }
        if self.unit_code.is_empty() {
            return Err(format!("line {:?} needs a unit code", self.id));
        }
        if !self.vat_rate_bp_is_plausible() {
            return Err(format!("line {:?} has a VAT rate above 100 %", self.id));
        }
        Ok(())
    }

    fn vat_rate_bp_is_plausible(&self) -> bool {
        self.vat_rate_bp <= 10_000
    }
}

/// A document-level allowance or charge (BG-20, BG-21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowanceCharge {
    /// Why it was given or charged.
    pub reason: String,
    /// Amount in minor units.
    pub amount_minor: i64,
    /// Percentage in basis points, when the reason is a rate.
    pub percent_bp: Option<u32>,
    /// Base amount in minor units, when the reason is a rate.
    pub base_minor: Option<i64>,
    /// VAT category the adjustment belongs to.
    pub vat_category: VatCategory,
    /// VAT rate in basis points for that category.
    pub vat_rate_bp: u32,
}

impl AllowanceCharge {
    /// Build an allowance or charge.
    pub fn new(
        reason: &str,
        amount_minor: i64,
        vat_category: VatCategory,
        vat_rate_bp: u32,
    ) -> Result<Self, String> {
        if reason.trim().is_empty() {
            return Err("an allowance or charge needs a reason".to_string());
        }
        if amount_minor <= 0 {
            return Err("an allowance or charge needs a positive amount".to_string());
        }
        Ok(Self {
            reason: reason.trim().to_string(),
            amount_minor,
            percent_bp: None,
            base_minor: None,
            vat_category,
            vat_rate_bp,
        })
    }

    /// Attach the percentage and base the amount was derived from.
    pub fn with_percent(mut self, percent_bp: u32, base_minor: i64) -> Self {
        self.percent_bp = Some(percent_bp);
        self.base_minor = Some(base_minor);
        self
    }
}

/// How the invoice is paid (BG-16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentMeans {
    /// UN/ECE 4461 payment means code (for example `30` credit transfer, `10`
    /// cash, `68` online payment service).
    pub code: String,
    /// Free-text instruction.
    pub instruction: Option<String>,
}

impl PaymentMeans {
    /// Build payment means from a UN/ECE 4461 code.
    pub fn new(code: &str, instruction: Option<&str>) -> Result<Self, String> {
        let code = code.trim();
        if code.len() != 2 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("payment means code {code:?} must be two digits"));
        }
        Ok(Self {
            code: code.to_string(),
            instruction: instruction.map(|value| value.trim().to_string()),
        })
    }
}

/// One VAT breakdown group (BG-23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VatBreakdown {
    /// Category code (BT-118).
    pub vat_category: VatCategory,
    /// Rate in basis points (BT-119).
    pub vat_rate_bp: u32,
    /// Taxable base in minor units (BT-116).
    pub taxable_minor: i64,
    /// Tax amount in minor units (BT-117).
    pub tax_minor: i64,
}

/// Every total the serializers emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totals {
    /// Sum of line net amounts (BT-106).
    pub line_total_minor: i64,
    /// Sum of document allowances (BT-107).
    pub allowance_total_minor: i64,
    /// Sum of document charges (BT-108).
    pub charge_total_minor: i64,
    /// Total without VAT (BT-109).
    pub tax_exclusive_minor: i64,
    /// Total VAT (BT-110).
    pub tax_total_minor: i64,
    /// Total with VAT (BT-112).
    pub tax_inclusive_minor: i64,
    /// Prepaid amount (BT-113).
    pub prepaid_minor: i64,
    /// Rounding (BT-114).
    pub rounding_minor: i64,
    /// Amount due for payment (BT-115).
    pub payable_minor: i64,
    /// VAT breakdown per category and rate.
    pub breakdown: Vec<VatBreakdown>,
}

/// An EN 16931 invoice or credit note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    /// Document number (BT-1).
    pub number: String,
    /// Issue date (BT-2).
    pub issue_date: Date,
    /// Payment due date (BT-9).
    pub due_date: Option<Date>,
    /// Invoice or credit note.
    pub document_type: DocumentType,
    /// Invoice currency (BT-5), ISO 4217.
    pub currency: String,
    /// Seller (BG-4).
    pub seller: Party,
    /// Buyer (BG-7).
    pub buyer: Party,
    /// Lines (BG-25).
    pub lines: Vec<InvoiceLine>,
    /// Document-level allowances (BG-20).
    pub allowances: Vec<AllowanceCharge>,
    /// Document-level charges (BG-21).
    pub charges: Vec<AllowanceCharge>,
    /// Prepaid amount (BT-113).
    pub prepaid_minor: i64,
    /// Rounding amount (BT-114), which may be negative.
    pub rounding_minor: i64,
    /// Payment means (BG-16).
    pub payment_means: Option<PaymentMeans>,
    /// Payment reference (BT-83).
    pub payment_reference: Option<String>,
    /// Buyer reference (BT-10).
    pub buyer_reference: Option<String>,
    /// Free-text note (BT-22).
    pub note: Option<String>,
    /// Preceding invoice references (BT-25), required for a credit note.
    pub preceding_invoices: Vec<String>,
}

impl Invoice {
    /// Sum of line net amounts (BT-106).
    pub fn line_total_minor(&self) -> i64 {
        self.lines.iter().map(InvoiceLine::net_minor).sum()
    }

    /// Sum of document allowances (BT-107).
    pub fn allowance_total_minor(&self) -> i64 {
        self.allowances.iter().map(|entry| entry.amount_minor).sum()
    }

    /// Sum of document charges (BT-108).
    pub fn charge_total_minor(&self) -> i64 {
        self.charges.iter().map(|entry| entry.amount_minor).sum()
    }

    /// Total without VAT (BT-109) = BT-106 − BT-107 + BT-108.
    pub fn tax_exclusive_minor(&self) -> i64 {
        self.line_total_minor() - self.allowance_total_minor() + self.charge_total_minor()
    }

    /// VAT breakdown per category and rate, in category-then-rate order.
    pub fn breakdown(&self) -> Vec<VatBreakdown> {
        let mut groups: BTreeMap<(VatCategory, u32), i64> = BTreeMap::new();
        for line in &self.lines {
            *groups
                .entry((line.vat_category, line.vat_rate_bp))
                .or_insert(0) += line.net_minor();
        }
        for allowance in &self.allowances {
            *groups
                .entry((allowance.vat_category, allowance.vat_rate_bp))
                .or_insert(0) -= allowance.amount_minor;
        }
        for charge in &self.charges {
            *groups
                .entry((charge.vat_category, charge.vat_rate_bp))
                .or_insert(0) += charge.amount_minor;
        }
        groups
            .into_iter()
            .map(|((vat_category, vat_rate_bp), taxable_minor)| {
                let tax_minor = if vat_category.is_taxed() {
                    round_half_up(i128::from(taxable_minor) * i128::from(vat_rate_bp), 10_000)
                } else {
                    0
                };
                VatBreakdown {
                    vat_category,
                    vat_rate_bp,
                    taxable_minor,
                    tax_minor,
                }
            })
            .collect()
    }

    /// Total VAT (BT-110).
    pub fn tax_total_minor(&self) -> i64 {
        self.breakdown().iter().map(|group| group.tax_minor).sum()
    }

    /// Total with VAT (BT-112) = BT-109 + BT-110.
    pub fn tax_inclusive_minor(&self) -> i64 {
        self.tax_exclusive_minor() + self.tax_total_minor()
    }

    /// Amount due for payment (BT-115) = BT-112 − BT-113 + BT-114.
    pub fn payable_minor(&self) -> i64 {
        self.tax_inclusive_minor() - self.prepaid_minor + self.rounding_minor
    }

    /// Every total, computed once.
    pub fn totals(&self) -> Totals {
        Totals {
            line_total_minor: self.line_total_minor(),
            allowance_total_minor: self.allowance_total_minor(),
            charge_total_minor: self.charge_total_minor(),
            tax_exclusive_minor: self.tax_exclusive_minor(),
            tax_total_minor: self.tax_total_minor(),
            tax_inclusive_minor: self.tax_inclusive_minor(),
            prepaid_minor: self.prepaid_minor,
            rounding_minor: self.rounding_minor,
            payable_minor: self.payable_minor(),
            breakdown: self.breakdown(),
        }
    }

    /// Check every model invariant the serializers and the business rules rely on.
    pub fn validate(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        if self.number.trim().is_empty() || self.number.chars().count() > MAX_NUMBER_LEN {
            issues.push(ValidationIssue::error(
                "BR-02",
                "invoice number",
                format!("the document number must be 1..={MAX_NUMBER_LEN} characters"),
            ));
        }
        if !self.issue_date.is_valid() {
            issues.push(ValidationIssue::error(
                "BR-03",
                "issue date",
                "the issue date is not a calendar date",
            ));
        }
        if let Some(due) = self.due_date {
            if due < self.issue_date {
                issues.push(ValidationIssue::error(
                    "MODEL-DUE-01",
                    "due date",
                    "the payment due date is before the issue date",
                ));
            }
        }
        if !is_currency(&self.currency) {
            issues.push(ValidationIssue::error(
                "BR-05",
                "currency",
                format!("{:?} is not an ISO 4217 code", self.currency),
            ));
        }
        if let Err(detail) = self.seller.validate() {
            issues.push(ValidationIssue::error("BR-06", "seller", detail));
        }
        if let Err(detail) = self.buyer.validate() {
            issues.push(ValidationIssue::error("BR-07", "buyer", detail));
        }
        if self.lines.is_empty() {
            issues.push(ValidationIssue::error(
                "BR-16",
                "lines",
                "an invoice needs at least one line",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for line in &self.lines {
            if let Err(detail) = line.validate() {
                issues.push(ValidationIssue::error("BR-25", "line", detail));
            }
            if !ids.insert(line.id.as_str()) {
                issues.push(ValidationIssue::error(
                    "BR-21",
                    "line",
                    format!("duplicate line identifier {:?}", line.id),
                ));
            }
        }
        if self.prepaid_minor < 0 {
            issues.push(ValidationIssue::error(
                "MODEL-PREPAID-01",
                "prepaid amount",
                "the prepaid amount must not be negative",
            ));
        }
        for allowance in self.allowances.iter().chain(self.charges.iter()) {
            if allowance.amount_minor <= 0 {
                issues.push(ValidationIssue::error(
                    "BR-31",
                    "allowance or charge",
                    "an allowance or charge needs a positive amount",
                ));
            }
            if !allowance.vat_category.is_taxed() && allowance.vat_rate_bp != 0 {
                issues.push(ValidationIssue::error(
                    "MODEL-VAT-01",
                    "allowance or charge",
                    format!(
                        "category {} must carry a zero rate",
                        allowance.vat_category.code()
                    ),
                ));
            }
        }
        if self.document_type == DocumentType::CreditNote && self.preceding_invoices.is_empty() {
            issues.push(ValidationIssue::error(
                "BR-55",
                "preceding invoice",
                "a credit note must reference the invoice it corrects",
            ));
        }
        if self.tax_exclusive_minor() < 0 {
            issues.push(ValidationIssue::error(
                "MODEL-TOTAL-01",
                "totals",
                "the total without VAT is negative",
            ));
        }
        if self.payable_minor() < 0 {
            issues.push(ValidationIssue::error(
                "MODEL-TOTAL-02",
                "totals",
                "the amount due for payment is negative",
            ));
        }
        issues
    }
}

/// Whether `code` looks like an ISO 4217 currency.
pub fn is_currency(code: &str) -> bool {
    code.len() == 3 && code.chars().all(|character| character.is_ascii_uppercase())
}

/// One validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Rule identifier, following the EN 16931 numbering where one applies.
    pub rule: String,
    /// Where the problem is.
    pub path: String,
    /// What is wrong.
    pub message: String,
    /// Whether it makes the document invalid.
    pub fatal: bool,
}

impl ValidationIssue {
    /// A finding that makes the document invalid.
    pub fn error(rule: &str, path: &str, message: impl Into<String>) -> Self {
        Self {
            rule: rule.to_string(),
            path: path.to_string(),
            message: message.into(),
            fatal: true,
        }
    }

    /// A finding worth reporting that does not invalidate the document.
    pub fn warning(rule: &str, path: &str, message: impl Into<String>) -> Self {
        Self {
            rule: rule.to_string(),
            path: path.to_string(),
            message: message.into(),
            fatal: false,
        }
    }
}

/// Format minor units as an EN 16931 amount (`1234` → `"12.34"`).
pub fn format_money(minor: i64) -> String {
    let sign = if minor < 0 { "-" } else { "" };
    let magnitude = minor.unsigned_abs();
    format!("{sign}{}.{:02}", magnitude / 100, magnitude % 100)
}

/// Format basis points as an EN 16931 percentage (`2100` → `"21.00"`).
pub fn format_percent(basis_points: u32) -> String {
    format!("{}.{:02}", basis_points / 100, basis_points % 100)
}

/// Format a quantity in thousandths, trimming trailing zeros.
pub fn format_quantity(quantity_milli: i64) -> String {
    let whole = quantity_milli / 1_000;
    let fraction = (quantity_milli % 1_000).unsigned_abs();
    if fraction == 0 {
        return whole.to_string();
    }
    let mut text = format!("{whole}.{fraction:03}");
    while text.ends_with('0') {
        text.pop();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> Address {
        Address::new("Calle Mayor 1", None, "Madrid", "28013", "es").expect("address")
    }

    #[test]
    fn dates_convert_from_epoch_and_round_trip() {
        assert_eq!(
            Date::from_unix_seconds(0),
            Date {
                year: 1970,
                month: 1,
                day: 1
            }
        );
        assert_eq!(
            Date::from_unix_seconds(1_767_225_600),
            Date {
                year: 2026,
                month: 1,
                day: 1
            }
        );
        assert_eq!(
            Date::from_unix_seconds(1_767_225_599),
            Date {
                year: 2025,
                month: 12,
                day: 31
            }
        );
        let date = Date::new(2024, 2, 29).expect("leap day");
        assert_eq!(date.to_iso(), "2024-02-29");
        assert_eq!(date.to_compact(), "20240229");
        assert!(Date::new(2025, 2, 29).is_err());
        assert!(Date::from_unix_seconds(-1) < Date::from_unix_seconds(0));
    }

    #[test]
    fn totals_and_breakdown_are_derived_from_integers() {
        let invoice = Invoice {
            number: "INV-1".to_string(),
            issue_date: Date::new(2026, 1, 31).expect("date"),
            due_date: None,
            document_type: DocumentType::Invoice,
            currency: "EUR".to_string(),
            seller: Party::new("Acme", address()).expect("party"),
            buyer: Party::new("Customer", address()).expect("party"),
            lines: vec![
                InvoiceLine::new(
                    "1",
                    "Espresso",
                    2_000,
                    "C62",
                    250,
                    VatCategory::Standard,
                    2_100,
                )
                .expect("line"),
                InvoiceLine::new("2", "Bread", 1_000, "C62", 120, VatCategory::Zero, 0)
                    .expect("line"),
            ],
            allowances: vec![
                AllowanceCharge::new("Loyalty", 50, VatCategory::Standard, 2_100)
                    .expect("discount"),
            ],
            charges: Vec::new(),
            prepaid_minor: 0,
            rounding_minor: 0,
            payment_means: None,
            payment_reference: None,
            buyer_reference: None,
            note: None,
            preceding_invoices: Vec::new(),
        };
        let totals = invoice.totals();
        assert_eq!(totals.line_total_minor, 620);
        assert_eq!(totals.allowance_total_minor, 50);
        assert_eq!(totals.tax_exclusive_minor, 570);
        assert_eq!(totals.breakdown.len(), 2);
        // 4.50 at 21 % is 0.945 → 0.95 half-up.
        assert_eq!(totals.tax_total_minor, 95);
        assert_eq!(totals.tax_inclusive_minor, 665);
        assert_eq!(totals.payable_minor, 665);
        assert!(invoice.validate().is_empty());
    }

    #[test]
    fn formatting_is_fixed_point() {
        assert_eq!(format_money(1_234), "12.34");
        assert_eq!(format_money(-5), "-0.05");
        assert_eq!(format_money(0), "0.00");
        assert_eq!(format_percent(2_100), "21.00");
        assert_eq!(format_percent(750), "7.50");
        assert_eq!(format_quantity(2_000), "2");
        assert_eq!(format_quantity(1_500), "1.5");
        assert_eq!(format_quantity(1_234), "1.234");
    }

    #[test]
    fn model_validation_catches_negative_and_missing_input() {
        let mut invoice = Invoice {
            number: String::new(),
            issue_date: Date::new(2026, 1, 31).expect("date"),
            due_date: Some(Date::new(2026, 1, 1).expect("date")),
            document_type: DocumentType::CreditNote,
            currency: "eur".to_string(),
            seller: Party::new("Acme", address()).expect("party"),
            buyer: Party::new("Customer", address()).expect("party"),
            lines: Vec::new(),
            allowances: Vec::new(),
            charges: Vec::new(),
            prepaid_minor: 0,
            rounding_minor: 0,
            payment_means: None,
            payment_reference: None,
            buyer_reference: None,
            note: None,
            preceding_invoices: Vec::new(),
        };
        let rules: Vec<String> = invoice
            .validate()
            .into_iter()
            .map(|issue| issue.rule)
            .collect();
        for expected in ["BR-02", "BR-05", "BR-16", "BR-55"] {
            assert!(rules.contains(&expected.to_string()), "missing {expected}");
        }
        invoice.prepaid_minor = -1;
        assert!(invoice
            .validate()
            .iter()
            .any(|issue| issue.rule == "MODEL-PREPAID-01"));
    }
}
