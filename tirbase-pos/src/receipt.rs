// SPDX-License-Identifier: AGPL-3.0-only

//! POS-10 — receipt document, legal fields, reprints and delivery hooks.
//!
//! A [`ReceiptDocument`] is a validated, immutable description of one sale
//! receipt. Rendering produces a [`RenderedReceipt`] with a localized plain-text
//! body. Reprints carry the same [`InvoiceNumber`] as the original, explicitly
//! set [`ReceiptCopy::Reprint`], a positive reprint count and a visible marker;
//! rendering never allocates a new invoice number.
//!
//! [`ReceiptOutput`] is the print/email boundary. The crate does not open a
//! printer, send mail or claim to have done so: a deployment implements the
//! trait with its own transport. The trait shape keeps a failed delivery
//! visible to the caller instead of pretending the receipt was sent.
//!
//! ## Prototype posture
//!
//! The fields are the fields a legal receipt normally needs, but filling them
//! does not make a document fiscally valid. There is no certification,
//! jurisdiction-specific mandatory layout, fiscal signature or archival claim
//! in this module. The renderer adds no legal statement it cannot support.

use crate::audit::Timestamp;
use crate::localization::{Locale, ReceiptLabel};
use crate::money::Money;
use crate::numbering::InvoiceNumber;
use crate::tax::{TaxBreakdown, TaxTreatment};

/// Maximum item lines in one receipt.
pub const MAX_RECEIPT_ITEM_LINES: usize = 200;
/// Maximum address lines for a merchant.
pub const MAX_MERCHANT_ADDRESS_LINES: usize = 4;
/// Character width used by the plain-text renderer.
pub const RECEIPT_DOCUMENT_WIDTH: usize = 32;

/// Seller identity printed on the receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Merchant {
    legal_name: String,
    address: Vec<String>,
    tax_registration: String,
}

impl Merchant {
    /// Construct a merchant. The legal name, at least one address line and the
    /// tax registration are required.
    pub fn new(
        legal_name: impl Into<String>,
        address: Vec<String>,
        tax_registration: impl Into<String>,
    ) -> Result<Self, ReceiptError> {
        let legal_name = legal_name.into();
        validate_text(&legal_name, 128).map_err(|_| ReceiptError::InvalidMerchantName)?;
        if address.is_empty() || address.len() > MAX_MERCHANT_ADDRESS_LINES {
            return Err(ReceiptError::InvalidMerchantAddress);
        }
        for line in &address {
            validate_text(line, 128).map_err(|_| ReceiptError::InvalidMerchantAddress)?;
        }
        let tax_registration = tax_registration.into();
        validate_text(&tax_registration, 64).map_err(|_| ReceiptError::InvalidTaxRegistration)?;
        Ok(Self {
            legal_name,
            address,
            tax_registration,
        })
    }

    /// Registered legal name.
    pub fn legal_name(&self) -> &str {
        &self.legal_name
    }

    /// Address lines, in print order.
    pub fn address(&self) -> &[String] {
        &self.address
    }

    /// Tax registration identifier.
    pub fn tax_registration(&self) -> &str {
        &self.tax_registration
    }
}

/// One printed sale line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptItemLine {
    description: String,
    quantity_thousandths: i64,
    unit_price: Money,
    amount: Money,
}

impl ReceiptItemLine {
    /// Construct a line. `quantity_thousandths` uses the same thousandths scale
    /// as [`crate::money::Quantity`]. `amount` is the amount printed for the
    /// line; `unit_price` is retained as a legal reference.
    pub fn new(
        description: impl Into<String>,
        quantity_thousandths: i64,
        unit_price: Money,
        amount: Money,
    ) -> Result<Self, ReceiptError> {
        let description = description.into();
        validate_text(&description, 128).map_err(|_| ReceiptError::InvalidItemDescription)?;
        if quantity_thousandths <= 0 {
            return Err(ReceiptError::InvalidQuantity);
        }
        if unit_price.currency() != amount.currency() {
            return Err(ReceiptError::CurrencyMismatch);
        }
        if unit_price.is_negative() || amount.is_negative() {
            return Err(ReceiptError::InvalidAmount);
        }
        Ok(Self {
            description,
            quantity_thousandths,
            unit_price,
            amount,
        })
    }

    /// Item or service description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Quantity in thousandths.
    pub fn quantity_thousandths(&self) -> i64 {
        self.quantity_thousandths
    }

    /// Unit price reference.
    pub fn unit_price(&self) -> Money {
        self.unit_price
    }

    /// Printed line amount.
    pub fn amount(&self) -> Money {
        self.amount
    }
}

/// Receipt totals. `total` and `change` are derived, not caller-supplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptTotals {
    subtotal: Money,
    discount: Money,
    tax: Money,
    tip: Money,
    total: Money,
    paid: Money,
    change: Money,
}

impl ReceiptTotals {
    /// Derive totals and change:
    /// `total = subtotal - discount + tax + tip`, `change = paid - total`.
    pub fn new(
        subtotal: Money,
        discount: Money,
        tax: Money,
        tip: Money,
        paid: Money,
    ) -> Result<Self, ReceiptError> {
        let currency = subtotal.currency();
        for amount in [discount, tax, tip, paid] {
            if amount.currency() != currency {
                return Err(ReceiptError::CurrencyMismatch);
            }
        }
        if subtotal.is_negative()
            || discount.is_negative()
            || tax.is_negative()
            || tip.is_negative()
        {
            return Err(ReceiptError::InvalidAmount);
        }
        if discount > subtotal {
            return Err(ReceiptError::DiscountExceedsSubtotal);
        }
        let total = subtotal
            .checked_sub(discount)
            .and_then(|value| value.checked_add(tax))
            .and_then(|value| value.checked_add(tip))
            .map_err(ReceiptError::from)?;
        if paid < total {
            return Err(ReceiptError::PaidLessThanTotal);
        }
        let change = paid.checked_sub(total).map_err(ReceiptError::from)?;
        Ok(Self {
            subtotal,
            discount,
            tax,
            tip,
            total,
            paid,
            change,
        })
    }

    /// Net merchandise subtotal.
    pub fn subtotal(&self) -> Money {
        self.subtotal
    }

    /// Discount total.
    pub fn discount(&self) -> Money {
        self.discount
    }

    /// Tax total.
    pub fn tax(&self) -> Money {
        self.tax
    }

    /// Tip total.
    pub fn tip(&self) -> Money {
        self.tip
    }

    /// Derived grand total.
    pub fn total(&self) -> Money {
        self.total
    }

    /// Amount tendered.
    pub fn paid(&self) -> Money {
        self.paid
    }

    /// Derived change.
    pub fn change(&self) -> Money {
        self.change
    }

    /// Currency shared by every amount.
    pub fn currency(&self) -> crate::money::Currency {
        self.subtotal.currency()
    }
}

/// Original or reprint marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReceiptCopy {
    /// First issue of this invoice number.
    Original,
    /// A later copy of the same invoice number.
    Reprint,
}

/// One tender line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptPayment {
    method: String,
    amount: Money,
}

impl ReceiptPayment {
    /// Construct a payment line.
    pub fn new(method: impl Into<String>, amount: Money) -> Result<Self, ReceiptError> {
        let method = method.into();
        validate_text(&method, 32).map_err(|_| ReceiptError::InvalidPaymentMethod)?;
        if amount.is_negative() || amount.is_zero() {
            return Err(ReceiptError::InvalidAmount);
        }
        Ok(Self { method, amount })
    }

    /// Payment method, such as `Cash` or `Visa`.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Tendered amount.
    pub fn amount(&self) -> Money {
        self.amount
    }
}

/// A validated receipt before rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptDocument {
    merchant: Merchant,
    invoice: InvoiceNumber,
    issued_at: Timestamp,
    reference: Option<(String, String, String)>,
    lines: Vec<ReceiptItemLine>,
    totals: ReceiptTotals,
    tax: TaxBreakdown,
    payments: Vec<ReceiptPayment>,
    footer: Option<String>,
    copy: ReceiptCopy,
    reprint_count: u64,
}

impl ReceiptDocument {
    /// Construct an original receipt. The tax breakdown must agree with the
    /// totals and use the same currency.
    pub fn new(
        merchant: Merchant,
        invoice: InvoiceNumber,
        issued_at: Timestamp,
        totals: ReceiptTotals,
        tax: TaxBreakdown,
    ) -> Result<Self, ReceiptError> {
        if tax.net.currency() != totals.currency() || tax.tax.currency() != totals.currency() {
            return Err(ReceiptError::CurrencyMismatch);
        }
        let net_after_discount = totals
            .subtotal
            .checked_sub(totals.discount)
            .map_err(ReceiptError::from)?;
        if tax.net != net_after_discount || tax.tax != totals.tax {
            return Err(ReceiptError::TaxMismatch);
        }
        Ok(Self {
            merchant,
            invoice,
            issued_at,
            reference: None,
            lines: Vec::new(),
            totals,
            tax,
            payments: Vec::new(),
            footer: None,
            copy: ReceiptCopy::Original,
            reprint_count: 0,
        })
    }

    /// Attach the terminal, operator and transaction reference.
    pub fn with_reference(
        mut self,
        terminal: impl Into<String>,
        operator: impl Into<String>,
        reference: impl Into<String>,
    ) -> Result<Self, ReceiptError> {
        let terminal = terminal.into();
        let operator = operator.into();
        let reference = reference.into();
        validate_text(&terminal, 64).map_err(|_| ReceiptError::InvalidReference)?;
        validate_text(&operator, 64).map_err(|_| ReceiptError::InvalidReference)?;
        validate_text(&reference, 64).map_err(|_| ReceiptError::InvalidReference)?;
        self.reference = Some((terminal, operator, reference));
        Ok(self)
    }

    /// Append one item line.
    pub fn with_line(mut self, line: ReceiptItemLine) -> Result<Self, ReceiptError> {
        if self.lines.len() >= MAX_RECEIPT_ITEM_LINES {
            return Err(ReceiptError::TooManyLines);
        }
        if line.amount.currency() != self.totals.currency() {
            return Err(ReceiptError::CurrencyMismatch);
        }
        self.lines.push(line);
        Ok(self)
    }

    /// Append one tender line.
    pub fn with_payment(mut self, payment: ReceiptPayment) -> Result<Self, ReceiptError> {
        if payment.amount.currency() != self.totals.currency() {
            return Err(ReceiptError::CurrencyMismatch);
        }
        self.payments.push(payment);
        Ok(self)
    }

    /// Add a footer notice. The text is wrapped by the renderer; newlines are
    /// rejected so a caller cannot inject arbitrary layout.
    pub fn with_footer(mut self, footer: impl Into<String>) -> Result<Self, ReceiptError> {
        let footer = footer.into();
        validate_text(&footer, 256).map_err(|_| ReceiptError::InvalidFooter)?;
        self.footer = Some(footer);
        Ok(self)
    }

    /// Mark this document as a reprint of the same invoice number.
    pub fn as_reprint(mut self, reprint_count: u64) -> Result<Self, ReceiptError> {
        if reprint_count == 0 {
            return Err(ReceiptError::InvalidReprintCount);
        }
        self.copy = ReceiptCopy::Reprint;
        self.reprint_count = reprint_count;
        Ok(self)
    }

    /// The invoice number this document describes.
    pub fn invoice(&self) -> &InvoiceNumber {
        &self.invoice
    }

    /// Issue time.
    pub fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// Original or reprint.
    pub fn copy(&self) -> ReceiptCopy {
        self.copy
    }

    /// Reprint count; zero for an original.
    pub fn reprint_count(&self) -> u64 {
        self.reprint_count
    }

    /// Seller identity.
    pub fn merchant(&self) -> &Merchant {
        &self.merchant
    }

    /// Item lines.
    pub fn lines(&self) -> &[ReceiptItemLine] {
        &self.lines
    }

    /// Totals.
    pub fn totals(&self) -> &ReceiptTotals {
        &self.totals
    }

    /// Tax breakdown.
    pub fn tax(&self) -> &TaxBreakdown {
        &self.tax
    }

    /// Payment lines.
    pub fn payments(&self) -> &[ReceiptPayment] {
        &self.payments
    }

    /// Validate the assembled document.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.lines.is_empty() {
            return Err(ReceiptError::NoLines);
        }
        if self.reference.is_none() {
            return Err(ReceiptError::InvalidReference);
        }
        if self.payments.is_empty() {
            return Err(ReceiptError::NoPayments);
        }
        let paid = Money::checked_sum(
            self.totals.currency(),
            self.payments.iter().map(ReceiptPayment::amount),
        )
        .map_err(ReceiptError::from)?;
        if paid != self.totals.paid {
            return Err(ReceiptError::PaymentMismatch);
        }
        if self.copy == ReceiptCopy::Reprint && self.reprint_count == 0 {
            return Err(ReceiptError::InvalidReprintCount);
        }
        if self.copy == ReceiptCopy::Original && self.reprint_count != 0 {
            return Err(ReceiptError::InvalidReprintCount);
        }
        let net_after_discount = self
            .totals
            .subtotal
            .checked_sub(self.totals.discount)
            .map_err(ReceiptError::from)?;
        if self.tax.tax != self.totals.tax || self.tax.net != net_after_discount {
            return Err(ReceiptError::TaxMismatch);
        }
        Ok(())
    }

    /// Validate and render a localized plain-text receipt.
    pub fn render(&self, locale: &Locale) -> Result<RenderedReceipt, ReceiptError> {
        self.validate()?;
        let mut out = Vec::new();
        if self.copy == ReceiptCopy::Reprint {
            out.push(format!(
                "*** {} #{} ***",
                locale.label(ReceiptLabel::Reprint),
                self.reprint_count
            ));
        }
        out.push(self.merchant.legal_name.clone());
        out.extend(self.merchant.address.iter().cloned());
        out.push(format!(
            "{}: {}",
            locale.label(ReceiptLabel::TaxId),
            self.merchant.tax_registration
        ));
        out.push(String::new());
        out.push(format!(
            "{}: {}",
            locale.label(ReceiptLabel::Invoice),
            self.invoice
        ));
        out.push(format!(
            "{}: {}",
            locale.label(ReceiptLabel::Date),
            locale
                .format_datetime(self.issued_at)
                .map_err(|_| ReceiptError::InvalidTimestamp)?
        ));
        if let Some((terminal, operator, reference)) = &self.reference {
            out.push(format!(
                "{}: {terminal}",
                locale.label(ReceiptLabel::Terminal)
            ));
            out.push(format!(
                "{}: {operator}",
                locale.label(ReceiptLabel::Operator)
            ));
            out.push(format!(
                "{}: {reference}",
                locale.label(ReceiptLabel::Reference)
            ));
        }
        out.push(separator());

        for line in &self.lines {
            let left = format!(
                "{} x {}",
                locale.format_quantity(line.quantity_thousandths),
                line.description
            );
            push_amount(&mut out, &left, &locale.format_money(line.amount));
        }

        out.push(separator());
        push_amount(
            &mut out,
            locale.label(ReceiptLabel::Subtotal),
            &locale.format_money(self.totals.subtotal),
        );
        if !self.totals.discount.is_zero() {
            push_amount(
                &mut out,
                locale.label(ReceiptLabel::Discount),
                &locale.format_money(self.totals.discount),
            );
        }
        self.render_tax(locale, &mut out);
        if !self.totals.tip.is_zero() {
            push_amount(
                &mut out,
                locale.label(ReceiptLabel::Tip),
                &locale.format_money(self.totals.tip),
            );
        }
        push_amount(
            &mut out,
            locale.label(ReceiptLabel::Total),
            &locale.format_money(self.totals.total),
        );
        for payment in &self.payments {
            let left = format!("{} {}", locale.label(ReceiptLabel::Payment), payment.method);
            push_amount(&mut out, &left, &locale.format_money(payment.amount));
        }
        push_amount(
            &mut out,
            locale.label(ReceiptLabel::Paid),
            &locale.format_money(self.totals.paid),
        );
        push_amount(
            &mut out,
            locale.label(ReceiptLabel::Change),
            &locale.format_money(self.totals.change),
        );

        if let Some(footer) = &self.footer {
            out.push(String::new());
            for line in wrap(footer, RECEIPT_DOCUMENT_WIDTH) {
                out.push(line);
            }
        }

        Ok(RenderedReceipt {
            lines: out,
            invoice: self.invoice.clone(),
            copy: self.copy,
            reprint_count: self.reprint_count,
        })
    }

    /// Render and deliver to the print hook.
    pub fn print(
        &self,
        locale: &Locale,
        output: &mut impl ReceiptOutput,
    ) -> Result<RenderedReceipt, ReceiptError> {
        let rendered = self.render(locale)?;
        output.print(&rendered)?;
        Ok(rendered)
    }

    /// Render and deliver to the email hook. The address is validated before
    /// rendering, so an invalid address fails without producing a document.
    pub fn email(
        &self,
        locale: &Locale,
        to: &EmailAddress,
        output: &mut impl ReceiptOutput,
    ) -> Result<RenderedReceipt, ReceiptError> {
        let rendered = self.render(locale)?;
        output.email(&rendered, to)?;
        Ok(rendered)
    }

    fn render_tax(&self, locale: &Locale, out: &mut Vec<String>) {
        if self.tax.treatment != TaxTreatment::Standard {
            let label = format!(
                "{} ({})",
                locale.label(ReceiptLabel::Tax),
                self.tax.treatment.label()
            );
            push_amount(out, &label, &locale.format_money(self.tax.tax));
            return;
        }
        for component in &self.tax.components {
            let label = format!(
                "{} {} {}",
                locale.label(ReceiptLabel::Tax),
                component.id,
                locale.format_rate(component.rate)
            );
            push_amount(out, &label, &locale.format_money(component.tax));
        }
        if self.tax.components.is_empty() && !self.tax.tax.is_zero() {
            push_amount(
                out,
                locale.label(ReceiptLabel::Tax),
                &locale.format_money(self.tax.tax),
            );
        }
    }
}

/// A rendered receipt, independent of delivery channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedReceipt {
    lines: Vec<String>,
    invoice: InvoiceNumber,
    copy: ReceiptCopy,
    reprint_count: u64,
}

impl RenderedReceipt {
    /// Rendered text lines.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Whole document joined with `\n`.
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// The invoice number this receipt describes.
    pub fn invoice(&self) -> &InvoiceNumber {
        &self.invoice
    }

    /// Original or reprint.
    pub fn copy(&self) -> ReceiptCopy {
        self.copy
    }

    /// `true` when the visible reprint marker is present.
    pub fn is_reprint(&self) -> bool {
        self.copy == ReceiptCopy::Reprint && self.reprint_count > 0
    }

    /// Reprint count.
    pub fn reprint_count(&self) -> u64 {
        self.reprint_count
    }
}

/// Print and email delivery hooks.
///
/// Implementations own their transport and may return
/// [`ReceiptError::DeliveryFailed`] when it fails. Returning `Ok` means the
/// transport accepted the document; this crate makes no stronger guarantee.
pub trait ReceiptOutput {
    /// Deliver to a printer or print queue.
    fn print(&mut self, receipt: &RenderedReceipt) -> Result<(), ReceiptError>;

    /// Deliver to an email transport.
    fn email(&mut self, receipt: &RenderedReceipt, to: &EmailAddress) -> Result<(), ReceiptError>;
}

/// A syntactically validated email address for the email hook.
///
/// This checks shape only: one `@`, a non-empty local part and a dotted domain.
/// It does not verify deliverability and does not normalize the address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Parse `value`.
    pub fn new(value: impl Into<String>) -> Result<Self, ReceiptError> {
        let value = value.into();
        if value.len() > 254
            || value.chars().any(|character| {
                character.is_whitespace() || character.is_control() || character == ','
            })
        {
            return Err(ReceiptError::InvalidEmail);
        }
        let mut parts = value.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        if local.is_empty() || domain.is_empty() || parts.next().is_some() {
            return Err(ReceiptError::InvalidEmail);
        }
        if local.len() > 64
            || !domain.contains('.')
            || domain.starts_with('.')
            || domain.ends_with('.')
        {
            return Err(ReceiptError::InvalidEmail);
        }
        Ok(Self(value))
    }

    /// The address text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn validate_text(value: &str, max: usize) -> Result<(), ()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(());
    }
    Ok(())
}

fn separator() -> String {
    "-".repeat(RECEIPT_DOCUMENT_WIDTH)
}

fn push_amount(out: &mut Vec<String>, left: &str, right: &str) {
    let left_width = left.chars().count();
    let right_width = right.chars().count();
    if left_width + right_width < RECEIPT_DOCUMENT_WIDTH {
        let pad = RECEIPT_DOCUMENT_WIDTH - left_width - right_width;
        out.push(format!("{left}{}{right}", " ".repeat(pad)));
    } else {
        out.push(left.to_string());
        let pad = RECEIPT_DOCUMENT_WIDTH.saturating_sub(right_width);
        out.push(format!("{}{right}", " ".repeat(pad)));
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if !current.is_empty() && current.chars().count() + 1 + word_len > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        if word_len > width {
            // Split an overlong token rather than letting it exceed the width.
            for character in word.chars() {
                if current.chars().count() == width {
                    lines.push(std::mem::take(&mut current));
                }
                current.push(character);
            }
        } else {
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// A rejected receipt field or delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptError {
    /// The merchant legal name was empty or unsafe.
    InvalidMerchantName,
    /// The merchant address was missing, too long or had too many lines.
    InvalidMerchantAddress,
    /// The tax registration was empty or unsafe.
    InvalidTaxRegistration,
    /// The terminal, operator or transaction reference was invalid.
    InvalidReference,
    /// An item description was invalid.
    InvalidItemDescription,
    /// A line quantity was zero or negative.
    InvalidQuantity,
    /// A monetary amount was negative, zero where tender is required, or
    /// otherwise invalid.
    InvalidAmount,
    /// The document had no item lines.
    NoLines,
    /// The document exceeded [`MAX_RECEIPT_ITEM_LINES`].
    TooManyLines,
    /// Amounts used more than one currency.
    CurrencyMismatch,
    /// The discount exceeded the subtotal.
    DiscountExceedsSubtotal,
    /// Tendered amount was less than the total.
    PaidLessThanTotal,
    /// The tax breakdown did not match the totals.
    TaxMismatch,
    /// A payment method was invalid.
    InvalidPaymentMethod,
    /// The document had no tender lines.
    NoPayments,
    /// Tender lines did not sum to the paid total.
    PaymentMismatch,
    /// The footer was invalid.
    InvalidFooter,
    /// The email address was not syntactically valid.
    InvalidEmail,
    /// A reprint count was zero on a reprint, or non-zero on an original.
    InvalidReprintCount,
    /// The timestamp was outside the supported calendar range.
    InvalidTimestamp,
    /// A monetary intermediate overflowed.
    ArithmeticOverflow,
    /// The output transport rejected the document.
    DeliveryFailed(String),
}

impl ReceiptError {
    /// Stable reason code for logs and policy.
    pub fn code(&self) -> &'static str {
        match self {
            ReceiptError::InvalidMerchantName => "receipt.invalid_merchant_name",
            ReceiptError::InvalidMerchantAddress => "receipt.invalid_merchant_address",
            ReceiptError::InvalidTaxRegistration => "receipt.invalid_tax_registration",
            ReceiptError::InvalidReference => "receipt.invalid_reference",
            ReceiptError::InvalidItemDescription => "receipt.invalid_item_description",
            ReceiptError::InvalidQuantity => "receipt.invalid_quantity",
            ReceiptError::InvalidAmount => "receipt.invalid_amount",
            ReceiptError::NoLines => "receipt.no_lines",
            ReceiptError::TooManyLines => "receipt.too_many_lines",
            ReceiptError::CurrencyMismatch => "receipt.currency_mismatch",
            ReceiptError::DiscountExceedsSubtotal => "receipt.discount_exceeds_subtotal",
            ReceiptError::PaidLessThanTotal => "receipt.paid_less_than_total",
            ReceiptError::TaxMismatch => "receipt.tax_mismatch",
            ReceiptError::InvalidPaymentMethod => "receipt.invalid_payment_method",
            ReceiptError::NoPayments => "receipt.no_payments",
            ReceiptError::PaymentMismatch => "receipt.payment_mismatch",
            ReceiptError::InvalidFooter => "receipt.invalid_footer",
            ReceiptError::InvalidEmail => "receipt.invalid_email",
            ReceiptError::InvalidReprintCount => "receipt.invalid_reprint_count",
            ReceiptError::InvalidTimestamp => "receipt.invalid_timestamp",
            ReceiptError::ArithmeticOverflow => "receipt.arithmetic_overflow",
            ReceiptError::DeliveryFailed(_) => "receipt.delivery_failed",
        }
    }
}

impl From<crate::error::PosError> for ReceiptError {
    fn from(_: crate::error::PosError) -> Self {
        ReceiptError::ArithmeticOverflow
    }
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::InvalidMerchantName => f.write_str("invalid merchant legal name"),
            ReceiptError::InvalidMerchantAddress => f.write_str("invalid merchant address"),
            ReceiptError::InvalidTaxRegistration => f.write_str("invalid tax registration"),
            ReceiptError::InvalidReference => f.write_str("invalid receipt reference"),
            ReceiptError::InvalidItemDescription => f.write_str("invalid item description"),
            ReceiptError::InvalidQuantity => f.write_str("invalid item quantity"),
            ReceiptError::InvalidAmount => f.write_str("invalid receipt amount"),
            ReceiptError::NoLines => f.write_str("receipt has no item lines"),
            ReceiptError::TooManyLines => f.write_str("receipt has too many item lines"),
            ReceiptError::CurrencyMismatch => f.write_str("receipt currency mismatch"),
            ReceiptError::DiscountExceedsSubtotal => f.write_str("discount exceeds subtotal"),
            ReceiptError::PaidLessThanTotal => f.write_str("paid amount is less than total"),
            ReceiptError::TaxMismatch => f.write_str("tax breakdown does not match totals"),
            ReceiptError::InvalidPaymentMethod => f.write_str("invalid payment method"),
            ReceiptError::NoPayments => f.write_str("receipt has no payments"),
            ReceiptError::PaymentMismatch => f.write_str("payments do not sum to paid total"),
            ReceiptError::InvalidFooter => f.write_str("invalid receipt footer"),
            ReceiptError::InvalidEmail => f.write_str("invalid email address"),
            ReceiptError::InvalidReprintCount => f.write_str("invalid reprint count"),
            ReceiptError::InvalidTimestamp => f.write_str("timestamp outside receipt range"),
            ReceiptError::ArithmeticOverflow => f.write_str("receipt arithmetic overflow"),
            ReceiptError::DeliveryFailed(reason) => write!(f, "receipt delivery failed: {reason}"),
        }
    }
}

impl std::error::Error for ReceiptError {}
