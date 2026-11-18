// SPDX-License-Identifier: Apache-2.0

//! EN 16931 e-invoicing adapter for POS data.
//!
//! The crate maps point-of-sale invoice data onto the EN 16931 semantic model,
//! serializes it as UBL 2.1 (Invoice and CreditNote) or UN/CEFACT CII D16B, and
//! validates the result. It is Apache-2.0 and links no first-party crate, so it
//! can be embedded in a closed product.
//!
//! ```no_run
//! use tirbase_en16931::{ubl, validate, Date, DocumentType, Invoice, Party, Address, InvoiceLine, VatCategory};
//!
//! let invoice = Invoice {
//!     number: "INV-1".to_string(),
//!     issue_date: Date::new(2026, 1, 31)?,
//!     due_date: None,
//!     document_type: DocumentType::Invoice,
//!     currency: "EUR".to_string(),
//!     seller: Party::new("Acme", Address::new("Calle Mayor 1", None, "Madrid", "28013", "ES")?)?,
//!     buyer: Party::new("Customer", Address::new("Calle Menor 2", None, "Madrid", "28014", "ES")?)?,
//!     lines: vec![InvoiceLine::new("1", "Espresso", 2_000, "C62", 250, VatCategory::Standard, 2_100)?],
//!     allowances: Vec::new(),
//!     charges: Vec::new(),
//!     prepaid_minor: 0,
//!     rounding_minor: 0,
//!     payment_means: None,
//!     payment_reference: None,
//!     buyer_reference: None,
//!     note: None,
//!     preceding_invoices: Vec::new(),
//! };
//! let xml = ubl::serialize(&invoice);
//! let report = validate::validate_document(&xml, &invoice, validate::Syntax::Ubl);
//! assert!(report.valid, "{:?}", report.issues);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Guarantees
//!
//! - **Deterministic.** Nothing reads the clock, the environment or a locale. The
//!   same invoice serializes to the same bytes on every run and every machine;
//!   every collection is ordered, every decimal is formatted from integers and
//!   every date is computed with integer arithmetic.
//! - **EN 16931 core only.** The crate implements the European semantic standard
//!   and its UBL/CII syntax bindings. It implements **no country profile** and
//!   makes **no national fiscal claim**: no verification URL, no fiscal code, no
//!   qualified signature, no national schema. A national profile is a closed
//!   module implementing [`profiles::CountryProfile`].
//! - **Arithmetic in minor units.** Amounts are integer cents, quantities are
//!   integer thousandths and percentages are integer basis points; every division
//!   is a single half-up rounding step.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod batch;
pub mod cii;
pub mod model;
pub mod pos;
pub mod profiles;
pub mod ubl;
pub mod validate;
pub mod xml;

pub use model::{
    Address, AllowanceCharge, Date, DocumentType, Invoice, InvoiceLine, Party, PaymentMeans,
    Totals, VatBreakdown, VatCategory,
};

/// Specification identifier of the EN 16931 core invoice (BT-24).
pub const SPECIFICATION_ID: &str = "urn:cen.eu:en16931:2017";

/// Crate version from the manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Round a rational numerator/denominator half away from zero.
///
/// The only rounding step in the crate: line amounts, tax per VAT category and
/// any percentage-derived figure all go through it, so an invoice cannot drift
/// by a cent depending on the order operations happen in.
pub fn round_half_up(numerator: i128, denominator: i128) -> i64 {
    debug_assert!(denominator > 0);
    let negative = numerator < 0;
    let magnitude = numerator.unsigned_abs();
    let denominator = denominator.unsigned_abs();
    let quotient = magnitude / denominator;
    let remainder = magnitude % denominator;
    let rounded = if remainder * 2 >= denominator {
        quotient + 1
    } else {
        quotient
    };
    let value = i64::try_from(rounded).unwrap_or(i64::MAX);
    if negative {
        -value
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounding_is_half_up_and_symmetric() {
        assert_eq!(round_half_up(5, 2), 3);
        assert_eq!(round_half_up(4, 2), 2);
        assert_eq!(round_half_up(-5, 2), -3);
        assert_eq!(round_half_up(2_100 * 1_000, 10_000), 210);
        assert_eq!(round_half_up(i128::from(i64::MAX) * 1_000, 1), i64::MAX);
    }
}
