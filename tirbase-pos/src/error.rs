// SPDX-License-Identifier: AGPL-3.0-only

//! Errors raised by the POS domain model.
//!
//! Every fallible operation returns one of these variants rather than panicking,
//! so a caller (until POS-02 supplies the persistence adapter) can reject a
//! command without partially mutating an order.

use crate::check::CheckStatus;
use crate::ids::{
    CatalogItemId, CheckId, IdempotencyKey, LineItemId, ModifierId, OperationId, OrderId,
    PaymentId, PaymentIntentId, RefundId,
};
use crate::intent::IntentStatus;
use crate::money::Money;

/// A rejected POS operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PosError {
    /// The string is not a supported ISO 4217 alphabetic code.
    UnknownCurrency(String),
    /// Two monetary values carry different currencies.
    CurrencyMismatch,
    /// An `i64` minor-unit or `i128` intermediate overflowed.
    ArithmeticOverflow,
    /// A rounding divisor was zero or negative.
    InvalidDivisor,
    /// A required identifier, name or label was empty or too long.
    InvalidIdentifier(&'static str),
    /// A line quantity was zero or negative.
    InvalidQuantity,
    /// A rate was outside `0 ..= 1_000_000` parts per million.
    InvalidRate,
    /// After modifiers the unit price would be negative.
    NegativeEffectiveUnitPrice,
    /// A discount was larger than the amount it discounts.
    DiscountExceedsBase,
    /// The referenced store is not in the ownership model.
    UnknownStore,
    /// The referenced terminal is not in the ownership model.
    UnknownTerminal,
    /// The referenced employee is not in the ownership model.
    UnknownEmployee,
    /// The referenced customer is not in the ownership model.
    UnknownCustomer,
    /// The terminal belongs to a different store than the ownership record.
    TerminalNotInStore,
    /// The employee belongs to a different store than the ownership record.
    EmployeeNotInStore,
    /// A check with this identifier already exists in the order.
    CheckAlreadyExists(CheckId),
    /// No check with this identifier exists in the order.
    CheckNotFound(CheckId),
    /// A line item with this identifier already exists in the check.
    LineItemAlreadyExists(LineItemId),
    /// No line item with this identifier exists in the check.
    LineItemNotFound(LineItemId),
    /// A payment with this identifier is already linked to the check.
    PaymentAlreadyLinked(PaymentId),
    /// No payment with this identifier is linked to the check.
    PaymentLinkNotFound(PaymentId),
    /// The line item is voided and cannot be moved or split.
    LineItemVoided(LineItemId),
    /// The line item has already been voided.
    LineItemAlreadyVoided(LineItemId),
    /// The payment is voided and cannot be moved or split.
    PaymentVoided(PaymentId),
    /// The payment has already been voided.
    PaymentAlreadyVoided(PaymentId),
    /// A payment allocation exceeded the available amount.
    PaymentAllocationExceeds { requested: Money, available: Money },
    /// A tip allocation exceeded the check's tip.
    TipAllocationExceeds { requested: Money, available: Money },
    /// Splitting would change tax, discount or base amounts at minor-unit
    /// precision; the operation was rejected rather than silently losing money.
    LossySplit,
    /// The same operation identifier was supplied with a different command.
    OperationConflict(OperationId),
    /// The check's state does not permit content changes.
    CheckNotMutable { status: CheckStatus },
    /// The requested state transition is not part of the check state machine.
    InvalidTransition { from: CheckStatus, to: CheckStatus },
    /// Closing or holding a check with no line items is not meaningful.
    EmptyCheck,
    /// Closing requires the check to be fully settled by captured payments.
    CheckNotFullyPaid { amount_due: Money },
    /// A refund was requested on a check with no captured payments.
    NothingToRefund,
    /// A refund exceeded the remaining captured amount.
    RefundExceedsPaid { requested: Money, remaining: Money },
    /// A refund was requested on a check that is not closed/refunded.
    CheckNotClosed { status: CheckStatus },
    /// A refund with this identifier already exists on the check.
    RefundAlreadyRecorded(RefundId),
    /// A monetary amount that must be positive was zero or negative.
    NonPositiveAmount,
    /// A monetary amount that must not be negative was negative.
    NegativeAmount,
    /// The ownership model already contains an entity with this identifier.
    AlreadyRegistered(&'static str),
    /// A void, refund or adjustment was supplied without a reason.
    MissingReason,
    /// The audit sequence cannot grow any further.
    AuditSequenceExhausted,
    /// Source and target checks are the same check.
    SameCheck,
    /// Source and target orders are the same order.
    SameOrder,
    /// The checks cannot be combined because a structural property differs.
    IncompatibleChecks(&'static str),
    /// Moving a check to another store would change sale attribution.
    CrossStoreTransfer,
    /// No order with this identifier exists in the replica.
    UnknownOrder(OrderId),
    /// The two replicas do not share the same genesis (organization/orders).
    IncompatibleReplica,
    /// Orders and ownership must be registered before any operation is applied.
    GenesisLocked,
    /// A book operation's envelope disagrees with the wrapped order command.
    EnvelopeMismatch,
    /// The acting terminal does not belong to the order's store.
    ActorNotInStore,
    /// A merge or move is ambiguous or would discard information.
    AmbiguousMerge(&'static str),
    /// No payment intent with this identifier exists.
    IntentNotFound(PaymentIntentId),
    /// A payment intent with this identifier already exists.
    IntentAlreadyExists(PaymentIntentId),
    /// An idempotency key was reused with a different check, amount,
    /// currency, terminal, operator or tender method.
    IdempotencyKeyConflict(IdempotencyKey),
    /// A capture or refund amount does not match the intent amount.
    IntentAmountMismatch { expected: Money, actual: Money },
    /// The requested intent transition is not part of its state machine.
    InvalidIntentTransition {
        from: IntentStatus,
        to: IntentStatus,
    },
    /// A processor token differs from the token already bound to the intent.
    IntentTokenMismatch(PaymentIntentId),
    /// A processor token was empty, oversized or contained control characters.
    InvalidProcessorToken,
    /// A value that looks like a card number was supplied as a processor token.
    PanLikeProcessorToken,
    /// An effective window is empty or ends before it starts.
    InvalidEffectiveWindow,
    /// A catalog, price-book or tax-table version overlaps an existing version
    /// in the same scope.
    OverlappingEffectiveWindow { existing: String },
    /// No version of the requested kind/scope is effective at the given time.
    NoEffectiveVersion(&'static str),
    /// A referenced version does not exist.
    VersionNotFound(String),
    /// A version with this identifier already exists.
    VersionAlreadyExists(String),
    /// A catalog version contains a duplicate item or modifier identifier.
    DuplicateCatalogEntry(String),
    /// A sellable item is not present in the pinned catalog.
    UnknownCatalogItem(CatalogItemId),
    /// A modifier is not present in the pinned catalog.
    UnknownCatalogModifier(ModifierId),
    /// A modifier exists but is not linked to the item in the pinned catalog.
    ModifierNotApplicable {
        item: CatalogItemId,
        modifier: ModifierId,
    },
    /// The pinned price book has no price for the item.
    MissingPrice(CatalogItemId),
    /// The pinned price book has no price delta for the modifier.
    MissingModifierPrice(ModifierId),
    /// A tax table contains the same applicability rule more than once.
    AmbiguousTaxRule,
    /// The order has no pinned catalog, price-book and tax-table versions.
    OrderNotPinned,
}

impl std::fmt::Display for PosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PosError::UnknownCurrency(code) => write!(f, "unknown ISO 4217 currency: {code}"),
            PosError::CurrencyMismatch => write!(f, "currency mismatch"),
            PosError::ArithmeticOverflow => write!(f, "monetary arithmetic overflow"),
            PosError::InvalidDivisor => write!(f, "invalid rounding divisor"),
            PosError::InvalidIdentifier(what) => write!(f, "invalid {what}"),
            PosError::InvalidQuantity => write!(f, "quantity must be positive"),
            PosError::InvalidRate => write!(f, "rate must be within 0..=1_000_000 ppm"),
            PosError::NegativeEffectiveUnitPrice => {
                write!(f, "modifiers make the effective unit price negative")
            }
            PosError::DiscountExceedsBase => write!(f, "discount exceeds the line base amount"),
            PosError::UnknownStore => write!(f, "unknown store"),
            PosError::UnknownTerminal => write!(f, "unknown terminal"),
            PosError::UnknownEmployee => write!(f, "unknown employee"),
            PosError::UnknownCustomer => write!(f, "unknown customer"),
            PosError::TerminalNotInStore => write!(f, "terminal does not belong to the store"),
            PosError::EmployeeNotInStore => write!(f, "employee does not belong to the store"),
            PosError::CheckAlreadyExists(id) => write!(f, "check already exists: {id}"),
            PosError::CheckNotFound(id) => write!(f, "check not found: {id}"),
            PosError::LineItemAlreadyExists(id) => write!(f, "line item already exists: {id}"),
            PosError::LineItemNotFound(id) => write!(f, "line item not found: {id}"),
            PosError::PaymentAlreadyLinked(id) => write!(f, "payment already linked: {id}"),
            PosError::PaymentLinkNotFound(id) => write!(f, "payment link not found: {id}"),
            PosError::LineItemVoided(id) => write!(f, "line item is voided: {id}"),
            PosError::LineItemAlreadyVoided(id) => write!(f, "line item already voided: {id}"),
            PosError::PaymentVoided(id) => write!(f, "payment is voided: {id}"),
            PosError::PaymentAlreadyVoided(id) => write!(f, "payment already voided: {id}"),
            PosError::PaymentAllocationExceeds {
                requested,
                available,
            } => write!(
                f,
                "payment allocation of {requested} exceeds available {available}"
            ),
            PosError::TipAllocationExceeds {
                requested,
                available,
            } => write!(
                f,
                "tip allocation of {requested} exceeds available {available}"
            ),
            PosError::LossySplit => {
                write!(
                    f,
                    "split rejected: it would change line money at minor-unit precision"
                )
            }
            PosError::OperationConflict(id) => {
                write!(
                    f,
                    "operation {id} was already applied with different content"
                )
            }
            PosError::CheckNotMutable { status } => {
                write!(f, "check is {status}; content is frozen")
            }
            PosError::InvalidTransition { from, to } => {
                write!(f, "cannot transition a check from {from} to {to}")
            }
            PosError::EmptyCheck => write!(f, "check has no line items"),
            PosError::CheckNotFullyPaid { amount_due } => {
                write!(f, "check is not fully paid; {amount_due} remains due")
            }
            PosError::NothingToRefund => write!(f, "check has no captured payments to refund"),
            PosError::RefundExceedsPaid {
                requested,
                remaining,
            } => write!(
                f,
                "refund of {requested} exceeds the remaining refundable {remaining}"
            ),
            PosError::CheckNotClosed { status } => {
                write!(f, "refunds require a closed check; check is {status}")
            }
            PosError::RefundAlreadyRecorded(id) => {
                write!(f, "refund already recorded: {id}")
            }
            PosError::NonPositiveAmount => write!(f, "amount must be positive"),
            PosError::NegativeAmount => write!(f, "amount must not be negative"),
            PosError::AlreadyRegistered(what) => write!(f, "{what} is already registered"),
            PosError::MissingReason => write!(f, "a reason is required"),
            PosError::AuditSequenceExhausted => write!(f, "audit sequence exhausted"),
            PosError::SameCheck => write!(f, "source and target checks are identical"),
            PosError::SameOrder => write!(f, "source and target orders are identical"),
            PosError::IncompatibleChecks(reason) => {
                write!(f, "checks cannot be combined: {reason}")
            }
            PosError::CrossStoreTransfer => {
                write!(f, "a check cannot be transferred to a different store")
            }
            PosError::UnknownOrder(id) => write!(f, "order not found: {id}"),
            PosError::IncompatibleReplica => write!(f, "replicas have different genesis"),
            PosError::GenesisLocked => {
                write!(f, "orders must be registered before applying operations")
            }
            PosError::EnvelopeMismatch => {
                write!(f, "book operation envelope disagrees with its command")
            }
            PosError::ActorNotInStore => {
                write!(f, "acting terminal does not belong to the order's store")
            }
            PosError::AmbiguousMerge(reason) => write!(f, "ambiguous merge: {reason}"),
            PosError::IntentNotFound(id) => write!(f, "payment intent not found: {id}"),
            PosError::IntentAlreadyExists(id) => write!(f, "payment intent already exists: {id}"),
            PosError::IdempotencyKeyConflict(key) => write!(
                f,
                "idempotency key {key} was already used for a different request"
            ),
            PosError::IntentAmountMismatch { expected, actual } => write!(
                f,
                "payment intent amount mismatch: expected {expected}, got {actual}"
            ),
            PosError::InvalidIntentTransition { from, to } => {
                write!(f, "cannot transition a payment intent from {from} to {to}")
            }
            PosError::IntentTokenMismatch(id) => {
                write!(f, "processor token does not match payment intent {id}")
            }
            PosError::InvalidProcessorToken => {
                write!(f, "processor token is empty, oversized or invalid")
            }
            PosError::PanLikeProcessorToken => write!(
                f,
                "processor token looks like a card number; only opaque tokens are accepted"
            ),
            PosError::InvalidEffectiveWindow => {
                write!(
                    f,
                    "effective window must be non-empty and end after it starts"
                )
            }
            PosError::OverlappingEffectiveWindow { existing } => {
                write!(f, "effective window overlaps existing version {existing}")
            }
            PosError::NoEffectiveVersion(what) => {
                write!(f, "no effective {what} version at the requested time")
            }
            PosError::VersionNotFound(id) => write!(f, "version not found: {id}"),
            PosError::VersionAlreadyExists(id) => write!(f, "version already exists: {id}"),
            PosError::DuplicateCatalogEntry(id) => {
                write!(f, "catalog version contains duplicate entry: {id}")
            }
            PosError::UnknownCatalogItem(id) => write!(f, "catalog item not found: {id}"),
            PosError::UnknownCatalogModifier(id) => write!(f, "catalog modifier not found: {id}"),
            PosError::ModifierNotApplicable { item, modifier } => write!(
                f,
                "modifier {modifier} is not linked to catalog item {item}"
            ),
            PosError::MissingPrice(id) => write!(f, "price book has no price for item: {id}"),
            PosError::MissingModifierPrice(id) => {
                write!(f, "price book has no price delta for modifier: {id}")
            }
            PosError::AmbiguousTaxRule => {
                write!(f, "tax table contains duplicate applicability rules")
            }
            PosError::OrderNotPinned => {
                write!(f, "order has no pinned catalog/price-book/tax versions")
            }
        }
    }
}

impl std::error::Error for PosError {}
