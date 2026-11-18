// SPDX-License-Identifier: Apache-2.0

//! POS integration contracts: payments, accounting, e-invoicing, delivery and tax.
//!
//! This module is part of the Apache-2.0 framework crate, so a closed (vendored
//! or proprietary) POS connector links `tirbase-integrations` and nothing from
//! the AGPL runtime. A connector implements [`contract::PosConnector`]; the
//! framework supplies idempotency-key derivation, request validation, retries,
//! a dead-letter queue, replay, reconciliation hooks, redacted logs, the four
//! mocks and the conformance suite in [`conformance::certify_pos`].
//!
//! ```
//! use tirbase_integrations::pos::contract::{AuthorizeRequest, PosConnector};
//! use tirbase_integrations::pos::mock::MockPaymentTerminal;
//! use tirbase_integrations::pos::{Amount, PaymentMethodToken, PosOutcome};
//!
//! let terminal = MockPaymentTerminal::new("acme-terminal");
//! let token = PaymentMethodToken::new("tok_test_5f2c1a")?;
//! let amount = Amount::new("EUR", 2_500)?;
//! let request = AuthorizeRequest::new(
//!     terminal.name(), "acme", "intent-1", token, amount.clone(), true, 1_700_000_000,
//! );
//! let result = terminal.authorize(&request);
//! assert_eq!(result.outcome, PosOutcome::Accepted);
//! assert_eq!(result.amount, Some(amount));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Invariants
//!
//! - **Amounts are integer minor units.** Every [`Amount`] carries its currency
//!   and a non-negative `i64`; arithmetic refuses to mix currencies and refuses
//!   to go negative, so a silent rounding drift cannot enter the ledger.
//! - **Idempotency keys are derived, never supplied.** [`pos_idempotency_key`]
//!   hashes the connector, the operation kind and the reference, so a retry, a
//!   process restart or a dead-letter replay presents the same key and the
//!   vendor recognises the duplicate instead of charging twice.
//! - **No card data.** [`PaymentMethodToken`] refuses PAN-shaped values, errors
//!   and log details are scrubbed with [`pci::scrub_card_data`], and
//!   [`pci::contains_card_data`] is used by the conformance suite and the test
//!   fixtures so a PAN cannot be committed or logged.
//! - **Deterministic.** Nothing here reads the clock; every instant is supplied
//!   by the caller.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod config;
pub mod conformance;
pub mod contract;
pub mod mock;
pub mod pci;
pub mod reconcile;
pub mod runtime;

pub use config::{ConfigError, ConnectorConfig, RetryConfig, SecretRef, CONFIG_SCHEMA_VERSION};
pub use conformance::{certify_pos, PosCertificationReport, PosCheck};
pub use contract::{
    AuthorizeRequest, CaptureRequest, CreditNote, DeliveryCancel, DeliveryOrder, DeliveryStatus,
    Direction, Invoice, InvoiceLine, JournalEntry, JournalLine, OperationResult, PosCapabilities,
    PosConnector, PosOperation, RefundRequest, TaxQuery, TaxQueryLine, TaxVerify, VoidRequest,
};
pub use mock::{
    MockAccountingApi, MockDeliveryPlatform, MockPaymentTerminal, MockPosVendor, MockTaxAuthority,
    MockTerminalConfig,
};
pub use pci::{contains_card_data, scrub_card_data, PaymentMethodToken};
pub use reconcile::{
    reconcile, Discrepancy, DiscrepancyKind, LocalSettlement, ReconciliationPolicy,
    ReconciliationReport, ReconciliationSource, RemoteSettlement, DEFAULT_RECONCILIATION_SECS,
};
pub use runtime::{
    IntegrityViolation, PosDeadLetter, PosFlushReport, PosMetrics, PosRecord, PosRecordState,
    PosRuntime, PosSubmit,
};

/// Schema version of the operation and configuration documents.
pub const POS_SCHEMA_VERSION: u32 = 1;

/// Domain-separation context for POS idempotency keys.
pub const CONTEXT_POS_IDEMPOTENCY: &str = "TirBase/v1/PosIdempotency";

/// Prefix every POS idempotency key carries.
pub const POS_KEY_PREFIX: &str = "pos-";

/// Longest reference (intent id, invoice number, delivery ref) accepted.
pub const MAX_REFERENCE_LEN: usize = 128;

/// Longest tenant label accepted.
pub const MAX_TENANT_LEN: usize = 64;

/// The five POS integration families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PosFamily {
    /// Card-present and card-not-present capture through a tokenised terminal.
    Payment,
    /// Journal posting to a general ledger or accounting package.
    Accounting,
    /// E-invoicing: issuing compliant invoices and credit notes.
    Einvoicing,
    /// Delivery and courier dispatch.
    Delivery,
    /// Tax rate quotation and verification.
    Tax,
}

impl PosFamily {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            PosFamily::Payment => "payment",
            PosFamily::Accounting => "accounting",
            PosFamily::Einvoicing => "einvoicing",
            PosFamily::Delivery => "delivery",
            PosFamily::Tax => "tax",
        }
    }

    /// Parse a wire name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "payment" => Some(PosFamily::Payment),
            "accounting" => Some(PosFamily::Accounting),
            "einvoicing" => Some(PosFamily::Einvoicing),
            "delivery" => Some(PosFamily::Delivery),
            "tax" => Some(PosFamily::Tax),
            _ => None,
        }
    }

    /// Every family, in report order.
    pub fn all() -> [PosFamily; 5] {
        [
            PosFamily::Payment,
            PosFamily::Accounting,
            PosFamily::Einvoicing,
            PosFamily::Delivery,
            PosFamily::Tax,
        ]
    }
}

/// The kind of operation an idempotency key is derived for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PosOperationKind {
    /// Authorise a payment intent.
    Authorize,
    /// Capture an authorisation.
    Capture,
    /// Void an authorisation.
    Void,
    /// Refund a captured amount.
    Refund,
    /// Post a journal entry.
    PostEntry,
    /// Issue an invoice.
    IssueInvoice,
    /// Issue a credit note.
    CreditNote,
    /// Book a delivery job.
    CreateDelivery,
    /// Cancel a delivery job.
    CancelDelivery,
    /// Query a delivery job.
    DeliveryStatus,
    /// Quote tax.
    QuoteTax,
    /// Verify a tax quote.
    VerifyTax,
}

impl PosOperationKind {
    /// Stable wire name, used in idempotency keys and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            PosOperationKind::Authorize => "authorize",
            PosOperationKind::Capture => "capture",
            PosOperationKind::Void => "void",
            PosOperationKind::Refund => "refund",
            PosOperationKind::PostEntry => "journal-entry",
            PosOperationKind::IssueInvoice => "invoice",
            PosOperationKind::CreditNote => "credit-note",
            PosOperationKind::CreateDelivery => "delivery",
            PosOperationKind::CancelDelivery => "delivery-cancel",
            PosOperationKind::DeliveryStatus => "delivery-status",
            PosOperationKind::QuoteTax => "tax-quote",
            PosOperationKind::VerifyTax => "tax-verify",
        }
    }
}

/// A monetary amount in integer minor units.
///
/// Fields are public so a host can persist and restore a request, which means a
/// forged value is possible; [`PosOperation::validate`] re-checks every amount
/// and the runtime refuses an operation that fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amount {
    /// ISO-4217 code, three upper-case letters.
    pub currency: String,
    /// Non-negative count of minor units.
    pub minor: i64,
}

impl Amount {
    /// Build an amount, refusing a malformed currency or a negative value.
    pub fn new(currency: &str, minor: i64) -> Result<Self, PosError> {
        let currency = currency.trim();
        if currency.len() != 3
            || !currency
                .chars()
                .all(|character| character.is_ascii_uppercase())
        {
            return Err(PosError::InvalidAmount {
                detail: format!("currency {currency:?} must be three upper-case letters"),
            });
        }
        if minor < 0 {
            return Err(PosError::InvalidAmount {
                detail: format!("amount {minor} must not be negative"),
            });
        }
        Ok(Self {
            currency: currency.to_string(),
            minor,
        })
    }

    /// A zero amount in `currency`.
    pub fn zero(currency: &str) -> Result<Self, PosError> {
        Self::new(currency, 0)
    }

    /// Whether the amount is well formed.
    pub fn is_valid(&self) -> bool {
        self.minor >= 0
            && self.currency.len() == 3
            && self
                .currency
                .chars()
                .all(|character| character.is_ascii_uppercase())
    }

    /// Refuse to mix currencies.
    pub fn same_currency(&self, other: &Amount) -> Result<(), PosError> {
        if self.currency != other.currency {
            return Err(PosError::CurrencyMismatch {
                expected: self.currency.clone(),
                got: other.currency.clone(),
                reference: String::new(),
            });
        }
        Ok(())
    }

    /// Add two amounts in the same currency.
    pub fn checked_add(&self, other: &Amount) -> Result<Self, PosError> {
        self.same_currency(other)?;
        let minor = self
            .minor
            .checked_add(other.minor)
            .ok_or_else(|| PosError::InvalidAmount {
                detail: "amount sum overflows".to_string(),
            })?;
        Self::new(&self.currency, minor)
    }

    /// Subtract `other` from `self`, refusing to go below zero.
    pub fn checked_sub(&self, other: &Amount) -> Result<Self, PosError> {
        self.same_currency(other)?;
        let minor = self
            .minor
            .checked_sub(other.minor)
            .filter(|value| *value >= 0)
            .ok_or_else(|| PosError::AmountMismatch {
                reference: String::new(),
                expected_minor: self.minor,
                got_minor: other.minor,
            })?;
        Self::new(&self.currency, minor)
    }

    /// Multiply by a whole factor (quantity, instalments).
    pub fn checked_mul(&self, factor: u32) -> Result<Self, PosError> {
        let minor =
            self.minor
                .checked_mul(i64::from(factor))
                .ok_or_else(|| PosError::InvalidAmount {
                    detail: "amount product overflows".to_string(),
                })?;
        Self::new(&self.currency, minor)
    }

    /// Whether both amounts are the same currency and value.
    pub fn matches(&self, other: &Amount) -> bool {
        self.currency == other.currency && self.minor == other.minor
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let major = self.minor / 100;
        let minor = self.minor % 100;
        write!(f, "{} {major}.{minor:02}", self.currency)
    }
}

/// What an attempt concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PosOutcome {
    /// The vendor accepted and recorded the operation.
    Accepted,
    /// The vendor already had this idempotency key; nothing was recorded twice.
    Replayed,
    /// A transient failure; retry later.
    Retryable,
    /// A permanent failure; retrying would not help.
    Permanent,
}

impl PosOutcome {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            PosOutcome::Accepted => "accepted",
            PosOutcome::Replayed => "replayed",
            PosOutcome::Retryable => "retryable",
            PosOutcome::Permanent => "permanent",
        }
    }

    /// Whether the operation is settled at the vendor.
    pub fn is_settled(self) -> bool {
        matches!(self, PosOutcome::Accepted | PosOutcome::Replayed)
    }

    /// The generic delivery outcome this maps to, for the shared log record.
    pub fn delivery_outcome(self) -> crate::connector::DeliveryOutcome {
        match self {
            PosOutcome::Accepted => crate::connector::DeliveryOutcome::Delivered,
            PosOutcome::Replayed => crate::connector::DeliveryOutcome::Duplicate,
            PosOutcome::Retryable => crate::connector::DeliveryOutcome::Retryable,
            PosOutcome::Permanent => crate::connector::DeliveryOutcome::Permanent,
        }
    }
}

/// Why a POS operation was refused.
///
/// Every variant is safe to log: [`std::fmt::Display`] scrubs card-shaped digit
/// runs and card-named fields before printing, so an error raised while handling
/// a malformed request cannot echo a PAN into a log sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PosError {
    /// A monetary value is malformed.
    InvalidAmount {
        /// What is wrong.
        detail: String,
    },
    /// A settlement amount does not match what was authorised.
    AmountMismatch {
        /// Operation or vendor reference.
        reference: String,
        /// Amount the local ledger expected, in minor units.
        expected_minor: i64,
        /// Amount the operation or vendor reported, in minor units.
        got_minor: i64,
    },
    /// Two amounts are in different currencies.
    CurrencyMismatch {
        /// Currency expected.
        expected: String,
        /// Currency seen.
        got: String,
        /// Operation or vendor reference.
        reference: String,
    },
    /// Card data was supplied where a token belongs.
    CardDataDetected {
        /// Field that carried it.
        field: String,
    },
    /// A request invariant failed.
    Invariant {
        /// Offending field.
        field: String,
        /// Why it is unusable.
        detail: String,
    },
    /// The connector does not implement this family.
    Unsupported {
        /// Family asked for.
        family: PosFamily,
    },
    /// The queue refused a submission because it is full.
    Backpressure {
        /// Operations pending at the time.
        pending: usize,
        /// Configured ceiling.
        limit: usize,
    },
    /// The vendor declined the operation.
    Declined {
        /// Vendor decline code, already token-shaped.
        code: String,
    },
    /// The vendor could not be reached.
    Transport {
        /// Short, secret-free explanation.
        detail: String,
    },
    /// A configuration document is unusable.
    Configuration {
        /// Offending field.
        field: String,
        /// Why it is unusable.
        detail: String,
    },
}

impl PosError {
    /// Whether another attempt could succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(self, PosError::Transport { .. })
    }
}

impl std::fmt::Display for PosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            PosError::InvalidAmount { detail } => format!("invalid amount: {detail}"),
            PosError::AmountMismatch {
                reference,
                expected_minor,
                got_minor,
            } => format!(
                "amount mismatch on {reference:?}: expected {expected_minor} minor units, got {got_minor}"
            ),
            PosError::CurrencyMismatch {
                expected,
                got,
                reference,
            } => format!("currency mismatch on {reference:?}: expected {expected}, got {got}"),
            PosError::CardDataDetected { field } => {
                format!("card data is not accepted in {field:?}; send an opaque token instead")
            }
            PosError::Invariant { field, detail } => format!("invalid {field}: {detail}"),
            PosError::Unsupported { family } => {
                format!("connector does not support the {} family", family.as_str())
            }
            PosError::Backpressure { pending, limit } => {
                format!("queue backpressure: {pending} pending (limit {limit})")
            }
            PosError::Declined { code } => format!("vendor declined the operation ({code})"),
            PosError::Transport { detail } => format!("vendor transport failure: {detail}"),
            PosError::Configuration { field, detail } => {
                format!("invalid connector configuration {field}: {detail}")
            }
        };
        write!(f, "{}", pci::scrub_card_data(&text))
    }
}

impl std::error::Error for PosError {}

/// Derive the idempotency key for one POS operation.
///
/// The key is a function of the connector, the operation kind and the reference
/// only, so a retry, a restart or a dead-letter replay of the same operation
/// presents the vendor the same key.
pub fn pos_idempotency_key(connector: &str, kind: &str, reference: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_POS_IDEMPOTENCY.as_bytes());
    hasher.update(b"\0");
    hasher.update(connector.as_bytes());
    hasher.update(b"\0");
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(reference.as_bytes());
    let digest: String = hasher
        .finalize()
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{POS_KEY_PREFIX}{digest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_integer_and_currency_safe() {
        let euros = Amount::new("EUR", 2_500).expect("valid");
        let more = Amount::new("EUR", 500).expect("valid");
        assert_eq!(euros.checked_add(&more).expect("sum").minor, 3_000);
        assert!(Amount::new("eur", 100).is_err());
        assert!(Amount::new("EURO", 100).is_err());
        assert!(Amount::new("EUR", -1).is_err());
        assert!(matches!(
            euros.checked_add(&Amount::new("USD", 1).expect("valid")),
            Err(PosError::CurrencyMismatch { .. })
        ));
        assert!(matches!(
            more.checked_sub(&euros),
            Err(PosError::AmountMismatch { .. })
        ));
    }

    #[test]
    fn idempotency_keys_are_derived_and_stable() {
        let first = pos_idempotency_key("terminal", "authorize", "intent-1");
        assert_eq!(
            first,
            pos_idempotency_key("terminal", "authorize", "intent-1")
        );
        assert_ne!(
            first,
            pos_idempotency_key("terminal", "capture", "intent-1")
        );
        assert_ne!(first, pos_idempotency_key("other", "authorize", "intent-1"));
        assert!(first.starts_with(POS_KEY_PREFIX));
        assert_eq!(first.len(), POS_KEY_PREFIX.len() + 32);
    }

    #[test]
    fn error_display_never_echoes_card_data() {
        let error = PosError::Transport {
            detail: "declined for 1234 5678 9012 3456".to_string(),
        };
        assert!(!contains_card_data(&error.to_string()));
    }
}
