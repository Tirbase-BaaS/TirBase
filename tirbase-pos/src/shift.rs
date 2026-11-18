// SPDX-License-Identifier: AGPL-3.0-only

//! POS-11 — shifts, drawers, cash operations, variance and X/Z reports.
//!
//! A [`Shift`] is one operator session on one terminal. It owns the drawer: an
//! opening float, the operator's cash movements, the drawer counts and the
//! settled checks rung during the session. Closing produces a Z report and
//! seals the shift; an X report is a read-only snapshot that closes nothing.
//!
//! # Cash model
//!
//! Expected drawer cash is derived, never entered:
//!
//! ```text
//! expected = opening_float
//!          + cash_in − cash_out − safe_drops − cash_refunds
//!          + cash_sales
//! ```
//!
//! `cash_sales`, `cash_refunds` and the report totals come from settled checks
//! ([`SaleRecord`]); the drawer effects of `cash_in`, `cash_out`, `safe_drops`
//! and `cash_refunds` come from explicit [`CashMovement`]s. A movement never
//! carries a sale, and a sale never carries a movement: recording the same
//! check twice is a replay, so a sale cannot add cash to the drawer twice.
//!
//! # Variance and attribution
//!
//! A [`DrawerCount`] compares counted cash with the expected cash at that
//! moment. The difference is a [`CashVariance`] attributed to the operator who
//! recorded the count. No method in this module accepts that operator from the
//! caller: it is always taken from the authenticated [`StaffSession`], and the
//! same rule applies to movements and to the final count recorded by
//! [`Shift::close`].
//!
//! # Boundaries
//!
//! A [`Shift`] is open exactly once and closes exactly once. After the Z report
//! every mutator returns [`ShiftError::Closed`]; the Z report itself is stored
//! behind an accessor and has no setters, so a closed shift cannot be edited.
//! [`ShiftBook`] additionally allows at most one open shift per terminal, while
//! different terminals keep independent drawers.
//!
//! # Offline
//!
//! Every movement, sale and count carries a caller-supplied identifier and is
//! idempotent. [`Shift::reconcile`] replays an offline event log in the order
//! supplied: an event that is already present with identical content is
//! reported as replayed and changes nothing, so reconnecting cannot duplicate a
//! cash movement. [`ShiftBook::adopt_offline`] registers a shift that was
//! opened on a disconnected terminal and refuses a second open drawer on the
//! same terminal.

use std::collections::BTreeMap;

use crate::audit::Timestamp;
use crate::check::{Check, CheckStatus, PaymentMethod, PaymentStatus};
use crate::error::PosError;
use crate::ids::{
    validate_identifier, CashMovementId, CheckId, DrawerCountId, EmployeeId, ShiftId, StoreId,
    TerminalId,
};
use crate::money::{Currency, Money};
use crate::staff::{Permission, StaffSession};

/// What one cash movement did to the drawer.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum CashMovementKind {
    /// Cash placed in the drawer from outside the sale flow.
    CashIn,
    /// Cash removed from the drawer without a sale or a safe drop.
    CashOut,
    /// Cash removed from the drawer and secured in the safe.
    SafeDrop,
    /// Cash paid out to a customer as a refund; recorded separately because the
    /// POS-01 refund record does not name a tender.
    CashRefund,
}

impl CashMovementKind {
    /// Every kind, in a stable order.
    pub const ALL: [CashMovementKind; 4] = [
        CashMovementKind::CashIn,
        CashMovementKind::CashOut,
        CashMovementKind::SafeDrop,
        CashMovementKind::CashRefund,
    ];

    /// Stable label for logs, reports and policy.
    pub fn as_str(self) -> &'static str {
        match self {
            CashMovementKind::CashIn => "cash_in",
            CashMovementKind::CashOut => "cash_out",
            CashMovementKind::SafeDrop => "safe_drop",
            CashMovementKind::CashRefund => "cash_refund",
        }
    }

    /// The permission an operator needs for this movement.
    pub fn permission(self) -> Permission {
        match self {
            CashMovementKind::CashIn => Permission::CashIn,
            CashMovementKind::CashOut => Permission::CashOut,
            CashMovementKind::SafeDrop => Permission::SafeDrop,
            CashMovementKind::CashRefund => Permission::Refund,
        }
    }

    /// `true` when the movement takes cash out of the drawer.
    pub fn is_outflow(self) -> bool {
        !matches!(self, CashMovementKind::CashIn)
    }
}

impl std::fmt::Display for CashMovementKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One operator cash movement on a drawer.
///
/// `amount` is the positive magnitude of the movement; [`CashMovementKind`]
/// decides the sign of its effect on expected cash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashMovement {
    id: CashMovementId,
    kind: CashMovementKind,
    amount: Money,
    at: Timestamp,
    by: EmployeeId,
    note: Option<String>,
}

impl CashMovement {
    /// The caller-supplied idempotent identifier.
    pub fn id(&self) -> &CashMovementId {
        &self.id
    }

    /// What the movement did.
    pub fn kind(&self) -> CashMovementKind {
        self.kind
    }

    /// The positive amount moved.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The caller-supplied time.
    pub fn at(&self) -> Timestamp {
        self.at
    }

    /// The authenticated operator who recorded the movement.
    pub fn by(&self) -> &EmployeeId {
        &self.by
    }

    /// The optional note.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }
}

/// One drawer count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrawerCount {
    id: DrawerCountId,
    counted: Money,
    at: Timestamp,
    by: EmployeeId,
    note: Option<String>,
}

impl DrawerCount {
    /// The caller-supplied idempotent identifier.
    pub fn id(&self) -> &DrawerCountId {
        &self.id
    }

    /// The total cash the operator counted.
    pub fn counted(&self) -> Money {
        self.counted
    }

    /// The caller-supplied time.
    pub fn at(&self) -> Timestamp {
        self.at
    }

    /// The authenticated operator who counted the drawer.
    pub fn by(&self) -> &EmployeeId {
        &self.by
    }

    /// The optional note.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }
}

/// Counted cash compared with the cash the ledger expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashVariance {
    /// The count this variance belongs to.
    pub count_id: DrawerCountId,
    /// Expected cash at the moment of the count.
    pub expected: Money,
    /// Cash the operator counted.
    pub counted: Money,
    /// `counted − expected`; negative is short, positive is over.
    pub variance: Money,
    /// The operator who counted the drawer.
    pub operator: EmployeeId,
    /// When the count was recorded.
    pub at: Timestamp,
}

impl CashVariance {
    /// `true` when the drawer was short.
    pub fn is_short(&self) -> bool {
        self.variance.is_negative()
    }

    /// `true` when the drawer was over.
    pub fn is_over(&self) -> bool {
        self.variance.is_positive()
    }

    /// `true` when counted cash matched the ledger exactly.
    pub fn is_balanced(&self) -> bool {
        self.variance.is_zero()
    }
}

/// The settled-check figures one shift aggregates.
///
/// A sale is built from a closed POS-01 [`Check`] with
/// [`SaleRecord::from_check`], so its totals, tax, discount, tip, void and
/// refund figures are the frozen ones the check already carries.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SaleRecord {
    check_id: CheckId,
    currency: Currency,
    subtotal: Money,
    discount_total: Money,
    tax_total: Money,
    tip: Money,
    grand_total: Money,
    cash_paid: Money,
    card_paid: Money,
    other_paid: Money,
    refunded_total: Money,
    voided_payment_amount: Money,
    voided_lines: u64,
    voided_payments: u64,
}

impl SaleRecord {
    /// Build the report record for a settled check.
    ///
    /// The check must be `Closed` or `Refunded`; an open, held, voided or
    /// merged check is not a sale. Captured payments are split by tender,
    /// voided lines and payments are counted, and every amount is the exact
    /// integer minor-unit value the check holds.
    pub fn from_check(check: &Check) -> Result<Self, ShiftError> {
        if !matches!(check.status(), CheckStatus::Closed | CheckStatus::Refunded) {
            return Err(ShiftError::SaleNotSettled(check.status()));
        }
        let totals = check.totals()?;
        let zero = Money::zero(totals.currency);
        let mut cash_paid = zero;
        let mut card_paid = zero;
        let mut other_paid = zero;
        let mut voided_payment_amount = zero;
        for payment in check.payments() {
            match payment.status() {
                PaymentStatus::Captured => match payment.method() {
                    PaymentMethod::Cash => cash_paid = cash_paid.checked_add(payment.amount())?,
                    PaymentMethod::Card => card_paid = card_paid.checked_add(payment.amount())?,
                    PaymentMethod::Voucher | PaymentMethod::Other => {
                        other_paid = other_paid.checked_add(payment.amount())?
                    }
                },
                PaymentStatus::Voided => {
                    voided_payment_amount = voided_payment_amount.checked_add(payment.amount())?
                }
                PaymentStatus::Authorized => {}
            }
        }
        let record = Self {
            check_id: check.id().clone(),
            currency: totals.currency,
            subtotal: totals.subtotal,
            discount_total: totals.discount_total,
            tax_total: totals.tax_total,
            tip: totals.tip,
            grand_total: totals.grand_total,
            cash_paid,
            card_paid,
            other_paid,
            refunded_total: totals.refunded_total,
            voided_payment_amount,
            voided_lines: check.voided_lines().count() as u64,
            voided_payments: check.voided_payments().count() as u64,
        };
        record.validate()?;
        Ok(record)
    }

    /// Check that a record is internally consistent.
    ///
    /// [`Shift::reconcile`] calls this on every decoded offline sale, so a
    /// transport cannot inject an amount that does not add up.
    pub fn validate(&self) -> Result<(), ShiftError> {
        let amounts = [
            self.subtotal,
            self.discount_total,
            self.tax_total,
            self.tip,
            self.grand_total,
            self.cash_paid,
            self.card_paid,
            self.other_paid,
            self.refunded_total,
            self.voided_payment_amount,
        ];
        if amounts
            .iter()
            .any(|amount| amount.currency() != self.currency)
        {
            return Err(ShiftError::InvalidSale(
                "every sale amount must use the sale currency",
            ));
        }
        if amounts.iter().any(|amount| amount.is_negative()) {
            return Err(ShiftError::InvalidSale("sale amounts must not be negative"));
        }
        let derived = self
            .subtotal
            .checked_sub(self.discount_total)?
            .checked_add(self.tax_total)?
            .checked_add(self.tip)?;
        if derived != self.grand_total {
            return Err(ShiftError::InvalidSale(
                "grand total does not match subtotal, discount, tax and tip",
            ));
        }
        Ok(())
    }

    /// The check this sale came from.
    pub fn check_id(&self) -> &CheckId {
        &self.check_id
    }

    /// The sale currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// Sum of line base amounts.
    pub fn subtotal(&self) -> Money {
        self.subtotal
    }

    /// Sum of line discounts.
    pub fn discount_total(&self) -> Money {
        self.discount_total
    }

    /// Sum of line tax amounts.
    pub fn tax_total(&self) -> Money {
        self.tax_total
    }

    /// The check tip.
    pub fn tip(&self) -> Money {
        self.tip
    }

    /// `subtotal − discount_total + tax_total + tip`.
    pub fn grand_total(&self) -> Money {
        self.grand_total
    }

    /// Captured cash tendered.
    pub fn cash_paid(&self) -> Money {
        self.cash_paid
    }

    /// Captured card tendered.
    pub fn card_paid(&self) -> Money {
        self.card_paid
    }

    /// Captured voucher and other tendered.
    pub fn other_paid(&self) -> Money {
        self.other_paid
    }

    /// Refunds recorded against the check.
    pub fn refunded_total(&self) -> Money {
        self.refunded_total
    }

    /// Amounts on payments that were voided.
    pub fn voided_payment_amount(&self) -> Money {
        self.voided_payment_amount
    }

    /// Number of voided line items.
    pub fn voided_lines(&self) -> u64 {
        self.voided_lines
    }

    /// Number of voided payments.
    pub fn voided_payments(&self) -> u64 {
        self.voided_payments
    }
}

/// Aggregated shift figures shared by the X and Z reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShiftTotals {
    /// The drawer currency, fixed by the opening float.
    pub currency: Currency,
    /// Cash the drawer opened with.
    pub opening_float: Money,
    /// Cash placed in the drawer by an operator.
    pub cash_in: Money,
    /// Cash removed from the drawer by an operator.
    pub cash_out: Money,
    /// Cash moved to the safe.
    pub safe_drops: Money,
    /// Cash refunded to customers.
    pub cash_refunds: Money,
    /// Captured cash tendered on settled checks.
    pub cash_sales: Money,
    /// Captured card tendered on settled checks.
    pub card_sales: Money,
    /// Captured voucher and other tendered on settled checks.
    pub other_sales: Money,
    /// Sum of line base amounts over settled checks.
    pub subtotal: Money,
    /// Sum of line discounts over settled checks.
    pub discount_total: Money,
    /// Sum of line taxes over settled checks.
    pub tax_total: Money,
    /// Sum of tips over settled checks.
    pub tip: Money,
    /// Sum of grand totals over settled checks.
    pub grand_total: Money,
    /// Refunds recorded against settled checks.
    pub refunded_total: Money,
    /// Amounts on voided payments.
    pub voided_payment_amount: Money,
    /// Number of voided line items.
    pub voided_lines: u64,
    /// Number of voided payments.
    pub voided_payments: u64,
    /// Number of settled checks.
    pub sale_count: u64,
}

impl ShiftTotals {
    /// Cash the drawer should hold right now.
    pub fn expected_cash(&self) -> Result<Money, PosError> {
        self.opening_float
            .checked_add(self.cash_in)?
            .checked_sub(self.cash_out)?
            .checked_sub(self.safe_drops)?
            .checked_sub(self.cash_refunds)?
            .checked_add(self.cash_sales)
    }

    /// Everything customers tendered, whatever the method.
    pub fn tendered_total(&self) -> Result<Money, PosError> {
        self.cash_sales
            .checked_add(self.card_sales)?
            .checked_add(self.other_sales)
    }
}

/// Which report was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReportKind {
    /// A mid-shift snapshot that leaves the shift open.
    X,
    /// The closing report that seals the shift.
    Z,
}

impl ReportKind {
    /// Stable label for logs and policy.
    pub fn as_str(self) -> &'static str {
        match self {
            ReportKind::X => "x",
            ReportKind::Z => "z",
        }
    }
}

impl std::fmt::Display for ReportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An immutable X or Z report.
///
/// Every field is a snapshot taken when the report was built. There is no
/// setter, and a Z report is additionally backed by a closed [`Shift`], so the
/// report and the shift cannot drift apart after closing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShiftReport {
    kind: ReportKind,
    shift_id: ShiftId,
    store_id: StoreId,
    terminal_id: TerminalId,
    currency: Currency,
    opened_by: EmployeeId,
    opened_at: Timestamp,
    closed_by: Option<EmployeeId>,
    closed_at: Option<Timestamp>,
    generated_at: Timestamp,
    totals: ShiftTotals,
    expected_cash: Money,
    variances: Vec<CashVariance>,
    counts: Vec<DrawerCount>,
    movements: Vec<CashMovement>,
}

impl ShiftReport {
    /// `X` or `Z`.
    pub fn kind(&self) -> ReportKind {
        self.kind
    }

    /// The shift this report covers.
    pub fn shift_id(&self) -> &ShiftId {
        &self.shift_id
    }

    /// The shift's store.
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// The shift's terminal.
    pub fn terminal_id(&self) -> &TerminalId {
        &self.terminal_id
    }

    /// The drawer currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// Who opened the shift.
    pub fn opened_by(&self) -> &EmployeeId {
        &self.opened_by
    }

    /// When the shift opened.
    pub fn opened_at(&self) -> Timestamp {
        self.opened_at
    }

    /// Who closed the shift, absent on an X report.
    pub fn closed_by(&self) -> Option<&EmployeeId> {
        self.closed_by.as_ref()
    }

    /// When the shift closed, absent on an X report.
    pub fn closed_at(&self) -> Option<Timestamp> {
        self.closed_at
    }

    /// When this report was generated.
    pub fn generated_at(&self) -> Timestamp {
        self.generated_at
    }

    /// The aggregated totals.
    pub fn totals(&self) -> &ShiftTotals {
        &self.totals
    }

    /// Cash the drawer should have held at generation time.
    pub fn expected_cash(&self) -> Money {
        self.expected_cash
    }

    /// Every variance recorded so far, in count order.
    pub fn variances(&self) -> &[CashVariance] {
        &self.variances
    }

    /// The closing variance, which is the last count on a Z report.
    pub fn final_variance(&self) -> Option<&CashVariance> {
        self.variances.last()
    }

    /// Every drawer count, in recording order.
    pub fn counts(&self) -> &[DrawerCount] {
        &self.counts
    }

    /// Every cash movement, in recording order.
    pub fn movements(&self) -> &[CashMovement] {
        &self.movements
    }

    /// `true` for the closing Z report.
    pub fn is_final(&self) -> bool {
        self.kind == ReportKind::Z
    }
}

/// Whether a shift operation changed state or was an idempotent replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShiftChange {
    /// The operation ran and changed the shift.
    Applied,
    /// The identifier was already present with identical content.
    Replayed,
}

impl ShiftChange {
    /// `true` when the operation changed state.
    pub fn is_applied(self) -> bool {
        matches!(self, ShiftChange::Applied)
    }
}

/// Why a shift operation was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShiftError {
    /// The shift is closed; every mutation is refused.
    Closed,
    /// No shift with this identifier exists.
    UnknownShift(ShiftId),
    /// A shift with this identifier already exists.
    DuplicateShift(ShiftId),
    /// The terminal already has an open drawer.
    DrawerAlreadyOpen(TerminalId),
    /// The session belongs to a different store.
    StoreMismatch,
    /// The session belongs to a different terminal.
    TerminalMismatch,
    /// The amount uses a different currency than the drawer.
    CurrencyMismatch,
    /// The session lacks the required permission.
    NotPermitted(Permission),
    /// A movement amount was zero or negative.
    NonPositiveAmount,
    /// Counted cash or the opening float was negative.
    NegativeAmount,
    /// The event is earlier than the shift's opening time.
    TimeBeforeOpen,
    /// A note was empty, oversized or control-bearing.
    InvalidNote,
    /// The movement identifier was reused with different content.
    MovementConflict(CashMovementId),
    /// The check identifier was reused with different content.
    SaleConflict(CheckId),
    /// The count identifier was reused with different content.
    CountConflict(DrawerCountId),
    /// Only a closed or refunded check is a sale.
    SaleNotSettled(CheckStatus),
    /// A sale record is internally inconsistent.
    InvalidSale(&'static str),
    /// Money arithmetic failed.
    Pos(PosError),
}

impl ShiftError {
    /// Stable reason code for logs and policy.
    pub fn code(&self) -> &'static str {
        match self {
            ShiftError::Closed => "shift.closed",
            ShiftError::UnknownShift(_) => "shift.unknown_shift",
            ShiftError::DuplicateShift(_) => "shift.duplicate_shift",
            ShiftError::DrawerAlreadyOpen(_) => "shift.drawer_open",
            ShiftError::StoreMismatch => "shift.store_mismatch",
            ShiftError::TerminalMismatch => "shift.terminal_mismatch",
            ShiftError::CurrencyMismatch => "shift.currency_mismatch",
            ShiftError::NotPermitted(_) => "shift.not_permitted",
            ShiftError::NonPositiveAmount => "shift.non_positive_amount",
            ShiftError::NegativeAmount => "shift.negative_amount",
            ShiftError::TimeBeforeOpen => "shift.time_before_open",
            ShiftError::InvalidNote => "shift.invalid_note",
            ShiftError::MovementConflict(_) => "shift.movement_conflict",
            ShiftError::SaleConflict(_) => "shift.sale_conflict",
            ShiftError::CountConflict(_) => "shift.count_conflict",
            ShiftError::SaleNotSettled(_) => "shift.sale_not_settled",
            ShiftError::InvalidSale(_) => "shift.invalid_sale",
            ShiftError::Pos(_) => "shift.pos",
        }
    }
}

impl std::fmt::Display for ShiftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShiftError::Closed => f.write_str("shift is closed"),
            ShiftError::UnknownShift(id) => write!(f, "unknown shift: {id}"),
            ShiftError::DuplicateShift(id) => write!(f, "duplicate shift: {id}"),
            ShiftError::DrawerAlreadyOpen(terminal) => {
                write!(f, "terminal {terminal} already has an open drawer")
            }
            ShiftError::StoreMismatch => f.write_str("session and shift are in different stores"),
            ShiftError::TerminalMismatch => {
                f.write_str("session and shift are on different terminals")
            }
            ShiftError::CurrencyMismatch => {
                f.write_str("amount currency does not match the drawer")
            }
            ShiftError::NotPermitted(permission) => write!(f, "permission denied: {permission}"),
            ShiftError::NonPositiveAmount => f.write_str("amount must be positive"),
            ShiftError::NegativeAmount => f.write_str("amount must not be negative"),
            ShiftError::TimeBeforeOpen => f.write_str("event precedes the shift opening"),
            ShiftError::InvalidNote => f.write_str("invalid note"),
            ShiftError::MovementConflict(id) => {
                write!(
                    f,
                    "cash movement {id} was already recorded with different content"
                )
            }
            ShiftError::SaleConflict(id) => {
                write!(f, "sale {id} was already recorded with different content")
            }
            ShiftError::CountConflict(id) => {
                write!(
                    f,
                    "drawer count {id} was already recorded with different content"
                )
            }
            ShiftError::SaleNotSettled(status) => {
                write!(f, "a {status} check is not a settled sale")
            }
            ShiftError::InvalidSale(reason) => write!(f, "invalid sale: {reason}"),
            ShiftError::Pos(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ShiftError {}

impl From<PosError> for ShiftError {
    fn from(error: PosError) -> Self {
        ShiftError::Pos(error)
    }
}

/// The parameters of a new shift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShiftSpec {
    id: ShiftId,
    store_id: StoreId,
    terminal_id: TerminalId,
    opening_float: Money,
    opened_at: Timestamp,
}

impl ShiftSpec {
    /// Describe a shift. Scope and amount are validated by [`Shift::open`].
    pub fn new(
        id: ShiftId,
        store_id: StoreId,
        terminal_id: TerminalId,
        opening_float: Money,
        opened_at: Timestamp,
    ) -> Self {
        Self {
            id,
            store_id,
            terminal_id,
            opening_float,
            opened_at,
        }
    }
}

/// One replayable offline event.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShiftEvent {
    /// The operator who performed the event offline.
    pub actor: EmployeeId,
    /// What happened.
    pub body: ShiftEventBody,
}

/// The body of a [`ShiftEvent`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShiftEventBody {
    /// A cash movement recorded offline.
    CashMovement {
        /// Idempotent movement identifier.
        id: CashMovementId,
        /// What the movement did.
        kind: CashMovementKind,
        /// Positive amount moved.
        amount: Money,
        /// When it happened.
        at: Timestamp,
        /// Optional note.
        note: Option<String>,
    },
    /// A settled check recorded offline, boxed to keep the event small.
    Sale(Box<SaleRecord>),
    /// A drawer count recorded offline.
    DrawerCount {
        /// Idempotent count identifier.
        id: DrawerCountId,
        /// Cash counted.
        counted: Money,
        /// When it was counted.
        at: Timestamp,
        /// Optional note.
        note: Option<String>,
    },
}

impl ShiftEventBody {
    /// A settled-check event.
    pub fn sale(sale: SaleRecord) -> Self {
        Self::Sale(Box::new(sale))
    }

    /// The sale record, when this event is one.
    pub fn as_sale(&self) -> Option<&SaleRecord> {
        match self {
            ShiftEventBody::Sale(sale) => Some(sale),
            _ => None,
        }
    }
}

/// One offline event that could not be applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShiftRejection {
    /// The event as supplied.
    pub event: ShiftEvent,
    /// Why it was rejected.
    pub error: ShiftError,
}

/// The result of reconciling an offline event log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Events that changed the shift.
    pub applied: usize,
    /// Events that were already present with identical content.
    pub replayed: usize,
    /// Events that were refused; each one left the shift unchanged.
    pub rejected: Vec<ShiftRejection>,
}

impl ReconcileReport {
    /// `true` when every event was applied or recognised as a replay.
    pub fn is_clean(&self) -> bool {
        self.rejected.is_empty()
    }
}

/// Internal result of recording a count.
struct CountOutcome {
    change: ShiftChange,
    variance: CashVariance,
}

/// One operator session on one terminal, with its drawer and settled sales.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shift {
    id: ShiftId,
    store_id: StoreId,
    terminal_id: TerminalId,
    opened_by: EmployeeId,
    opened_at: Timestamp,
    opening_float: Money,
    currency: Currency,
    movements: Vec<CashMovement>,
    sales: BTreeMap<CheckId, SaleRecord>,
    counts: Vec<DrawerCount>,
    variances: Vec<CashVariance>,
    closed_by: Option<EmployeeId>,
    closed_at: Option<Timestamp>,
    z_report: Option<ShiftReport>,
}

impl Shift {
    /// Open a shift for the authenticated session.
    ///
    /// The session must hold [`Permission::OpenShift`] and must be scoped to
    /// exactly the store and terminal named in `spec`. An empty or positive
    /// opening float is accepted; a negative one is not.
    pub fn open(session: &StaffSession, spec: ShiftSpec) -> Result<Self, ShiftError> {
        require(session, Permission::OpenShift)?;
        if spec.store_id != *session.store_id() {
            return Err(ShiftError::StoreMismatch);
        }
        if spec.terminal_id != *session.terminal_id() {
            return Err(ShiftError::TerminalMismatch);
        }
        if spec.opening_float.is_negative() {
            return Err(ShiftError::NegativeAmount);
        }
        Ok(Self {
            currency: spec.opening_float.currency(),
            id: spec.id,
            store_id: spec.store_id,
            terminal_id: spec.terminal_id,
            opened_by: session.employee_id().clone(),
            opened_at: spec.opened_at,
            opening_float: spec.opening_float,
            movements: Vec::new(),
            sales: BTreeMap::new(),
            counts: Vec::new(),
            variances: Vec::new(),
            closed_by: None,
            closed_at: None,
            z_report: None,
        })
    }

    /// The shift identifier.
    pub fn id(&self) -> &ShiftId {
        &self.id
    }

    /// The shift's store.
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// The shift's terminal.
    pub fn terminal_id(&self) -> &TerminalId {
        &self.terminal_id
    }

    /// Who opened the shift.
    pub fn opened_by(&self) -> &EmployeeId {
        &self.opened_by
    }

    /// When the shift opened.
    pub fn opened_at(&self) -> Timestamp {
        self.opened_at
    }

    /// The opening float.
    pub fn opening_float(&self) -> Money {
        self.opening_float
    }

    /// The drawer currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// `true` until the Z report closes the shift.
    pub fn is_open(&self) -> bool {
        self.closed_at.is_none()
    }

    /// `true` once the Z report closed the shift.
    pub fn is_closed(&self) -> bool {
        self.closed_at.is_some()
    }

    /// Who closed the shift, if it is closed.
    pub fn closed_by(&self) -> Option<&EmployeeId> {
        self.closed_by.as_ref()
    }

    /// When the shift closed, if it is closed.
    pub fn closed_at(&self) -> Option<Timestamp> {
        self.closed_at
    }

    /// The stored Z report, present only after closing.
    pub fn z_report(&self) -> Option<&ShiftReport> {
        self.z_report.as_ref()
    }

    /// Every cash movement, in recording order.
    pub fn movements(&self) -> &[CashMovement] {
        &self.movements
    }

    /// Every drawer count, in recording order.
    pub fn counts(&self) -> &[DrawerCount] {
        &self.counts
    }

    /// Every variance, in count order.
    pub fn variances(&self) -> &[CashVariance] {
        &self.variances
    }

    /// Every recorded sale.
    pub fn sales(&self) -> impl Iterator<Item = &SaleRecord> {
        self.sales.values()
    }

    /// One recorded sale.
    pub fn sale(&self, check_id: &CheckId) -> Option<&SaleRecord> {
        self.sales.get(check_id)
    }

    /// The current aggregate figures.
    pub fn totals(&self) -> Result<ShiftTotals, ShiftError> {
        let zero = Money::zero(self.currency);
        let mut cash_in = zero;
        let mut cash_out = zero;
        let mut safe_drops = zero;
        let mut cash_refunds = zero;
        for movement in &self.movements {
            let target = match movement.kind {
                CashMovementKind::CashIn => &mut cash_in,
                CashMovementKind::CashOut => &mut cash_out,
                CashMovementKind::SafeDrop => &mut safe_drops,
                CashMovementKind::CashRefund => &mut cash_refunds,
            };
            *target = (*target).checked_add(movement.amount)?;
        }

        let mut cash_sales = zero;
        let mut card_sales = zero;
        let mut other_sales = zero;
        let mut subtotal = zero;
        let mut discount_total = zero;
        let mut tax_total = zero;
        let mut tip = zero;
        let mut grand_total = zero;
        let mut refunded_total = zero;
        let mut voided_payment_amount = zero;
        let mut voided_lines = 0_u64;
        let mut voided_payments = 0_u64;
        for sale in self.sales.values() {
            cash_sales = cash_sales.checked_add(sale.cash_paid)?;
            card_sales = card_sales.checked_add(sale.card_paid)?;
            other_sales = other_sales.checked_add(sale.other_paid)?;
            subtotal = subtotal.checked_add(sale.subtotal)?;
            discount_total = discount_total.checked_add(sale.discount_total)?;
            tax_total = tax_total.checked_add(sale.tax_total)?;
            tip = tip.checked_add(sale.tip)?;
            grand_total = grand_total.checked_add(sale.grand_total)?;
            refunded_total = refunded_total.checked_add(sale.refunded_total)?;
            voided_payment_amount =
                voided_payment_amount.checked_add(sale.voided_payment_amount)?;
            voided_lines = voided_lines
                .checked_add(sale.voided_lines)
                .ok_or(PosError::ArithmeticOverflow)?;
            voided_payments = voided_payments
                .checked_add(sale.voided_payments)
                .ok_or(PosError::ArithmeticOverflow)?;
        }

        Ok(ShiftTotals {
            currency: self.currency,
            opening_float: self.opening_float,
            cash_in,
            cash_out,
            safe_drops,
            cash_refunds,
            cash_sales,
            card_sales,
            other_sales,
            subtotal,
            discount_total,
            tax_total,
            tip,
            grand_total,
            refunded_total,
            voided_payment_amount,
            voided_lines,
            voided_payments,
            sale_count: self.sales.len() as u64,
        })
    }

    /// Cash the drawer should hold right now.
    pub fn expected_cash(&self) -> Result<Money, ShiftError> {
        Ok(self.totals()?.expected_cash()?)
    }

    /// Record cash entering or leaving the drawer.
    ///
    /// The movement is idempotent by `id`: replaying the same identifier with
    /// identical content returns [`ShiftChange::Replayed`], and any other
    /// content is refused.
    pub fn record_movement(
        &mut self,
        session: &StaffSession,
        id: CashMovementId,
        kind: CashMovementKind,
        amount: Money,
        at: Timestamp,
        note: Option<&str>,
    ) -> Result<ShiftChange, ShiftError> {
        require(session, kind.permission())?;
        self.ensure_session(session)?;
        self.apply_movement(session.employee_id().clone(), id, kind, amount, at, note)
    }

    /// Record a settled check on the shift.
    ///
    /// The sale is idempotent by check identifier; recording it again with the
    /// same figures is a replay and never adds cash twice.
    pub fn record_sale(
        &mut self,
        session: &StaffSession,
        sale: SaleRecord,
    ) -> Result<ShiftChange, ShiftError> {
        require(session, Permission::Sell)?;
        self.ensure_session(session)?;
        self.apply_sale(sale)
    }

    /// Count the drawer and return the variance against expected cash.
    ///
    /// The returned variance names the authenticated session's employee as its
    /// operator. Replaying the same count identifier with identical content
    /// returns the original variance unchanged.
    pub fn record_count(
        &mut self,
        session: &StaffSession,
        id: DrawerCountId,
        counted: Money,
        at: Timestamp,
        note: Option<&str>,
    ) -> Result<CashVariance, ShiftError> {
        require(session, Permission::CountDrawer)?;
        self.ensure_session(session)?;
        let outcome = self.apply_count(id, counted, at, note, session.employee_id().clone())?;
        Ok(outcome.variance)
    }

    /// Produce an X report without closing the shift.
    ///
    /// Any employee in the shift's store may read it; the drawer cannot change.
    pub fn x_report(
        &self,
        session: &StaffSession,
        at: Timestamp,
    ) -> Result<ShiftReport, ShiftError> {
        require(session, Permission::ViewXReport)?;
        self.ensure_store(session)?;
        self.ensure_open()?;
        if at < self.opened_at {
            return Err(ShiftError::TimeBeforeOpen);
        }
        self.build_report(ReportKind::X, at, None)
    }

    /// Count the drawer, close the shift and produce the Z report.
    ///
    /// The final count is recorded as the closing operator's action, so the
    /// closing variance is attributed to them. The returned report is also
    /// stored on the shift, and no later call can change it: every mutator
    /// returns [`ShiftError::Closed`] once this succeeds.
    pub fn close(
        &mut self,
        session: &StaffSession,
        final_count_id: DrawerCountId,
        counted: Money,
        at: Timestamp,
        note: Option<&str>,
    ) -> Result<ShiftReport, ShiftError> {
        require(session, Permission::CloseShift)?;
        self.ensure_session(session)?;
        self.ensure_open()?;
        if at < self.opened_at {
            return Err(ShiftError::TimeBeforeOpen);
        }
        let operator = session.employee_id().clone();
        self.apply_count(final_count_id, counted, at, note, operator.clone())?;
        let report = self.build_report(ReportKind::Z, at, Some((operator.clone(), at)))?;
        self.closed_at = Some(at);
        self.closed_by = Some(operator);
        self.z_report = Some(report.clone());
        Ok(report)
    }

    /// Replay an offline event log against this shift.
    ///
    /// Events are applied in the order supplied, because a count's variance
    /// depends on the movements and sales that preceded it. An event already
    /// present with identical content is counted as `replayed` and changes
    /// nothing; a conflicting event is collected in [`ReconcileReport::rejected`]
    /// and leaves the shift untouched.
    pub fn reconcile(
        &mut self,
        session: &StaffSession,
        events: impl IntoIterator<Item = ShiftEvent>,
    ) -> Result<ReconcileReport, ShiftError> {
        require(session, Permission::ReconcileOffline)?;
        self.ensure_session(session)?;
        self.ensure_open()?;

        let mut report = ReconcileReport::default();
        for event in events {
            let actor = event.actor.clone();
            let result = match event.body.clone() {
                ShiftEventBody::CashMovement {
                    id,
                    kind,
                    amount,
                    at,
                    note,
                } => self.apply_movement(actor, id, kind, amount, at, note.as_deref()),
                ShiftEventBody::Sale(sale) => self.apply_sale(*sale),
                ShiftEventBody::DrawerCount {
                    id,
                    counted,
                    at,
                    note,
                } => self
                    .apply_count(id, counted, at, note.as_deref(), actor)
                    .map(|outcome| outcome.change),
            };
            match result {
                Ok(ShiftChange::Applied) => report.applied += 1,
                Ok(ShiftChange::Replayed) => report.replayed += 1,
                Err(error) => report.rejected.push(ShiftRejection { event, error }),
            }
        }
        Ok(report)
    }

    fn ensure_open(&self) -> Result<(), ShiftError> {
        if self.is_closed() {
            Err(ShiftError::Closed)
        } else {
            Ok(())
        }
    }

    fn ensure_store(&self, session: &StaffSession) -> Result<(), ShiftError> {
        if session.store_id() != &self.store_id {
            return Err(ShiftError::StoreMismatch);
        }
        Ok(())
    }

    fn ensure_session(&self, session: &StaffSession) -> Result<(), ShiftError> {
        self.ensure_store(session)?;
        if session.terminal_id() != &self.terminal_id {
            return Err(ShiftError::TerminalMismatch);
        }
        Ok(())
    }

    fn apply_movement(
        &mut self,
        actor: EmployeeId,
        id: CashMovementId,
        kind: CashMovementKind,
        amount: Money,
        at: Timestamp,
        note: Option<&str>,
    ) -> Result<ShiftChange, ShiftError> {
        self.ensure_open()?;
        if at < self.opened_at {
            return Err(ShiftError::TimeBeforeOpen);
        }
        if !amount.is_positive() {
            return Err(ShiftError::NonPositiveAmount);
        }
        if amount.currency() != self.currency {
            return Err(ShiftError::CurrencyMismatch);
        }
        let note = validate_note(note)?;
        if let Some(existing) = self.movements.iter().find(|movement| movement.id == id) {
            let same = existing.kind == kind
                && existing.amount == amount
                && existing.at == at
                && existing.by == actor
                && existing.note == note;
            return if same {
                Ok(ShiftChange::Replayed)
            } else {
                Err(ShiftError::MovementConflict(id))
            };
        }
        self.movements.push(CashMovement {
            id,
            kind,
            amount,
            at,
            by: actor,
            note,
        });
        Ok(ShiftChange::Applied)
    }

    fn apply_sale(&mut self, sale: SaleRecord) -> Result<ShiftChange, ShiftError> {
        self.ensure_open()?;
        sale.validate()?;
        if sale.currency != self.currency {
            return Err(ShiftError::CurrencyMismatch);
        }
        if let Some(existing) = self.sales.get(&sale.check_id) {
            return if *existing == sale {
                Ok(ShiftChange::Replayed)
            } else {
                Err(ShiftError::SaleConflict(sale.check_id.clone()))
            };
        }
        self.sales.insert(sale.check_id.clone(), sale);
        Ok(ShiftChange::Applied)
    }

    fn apply_count(
        &mut self,
        id: DrawerCountId,
        counted: Money,
        at: Timestamp,
        note: Option<&str>,
        actor: EmployeeId,
    ) -> Result<CountOutcome, ShiftError> {
        self.ensure_open()?;
        if at < self.opened_at {
            return Err(ShiftError::TimeBeforeOpen);
        }
        if counted.is_negative() {
            return Err(ShiftError::NegativeAmount);
        }
        if counted.currency() != self.currency {
            return Err(ShiftError::CurrencyMismatch);
        }
        let note = validate_note(note)?;
        if let Some(existing) = self.counts.iter().find(|count| count.id == id) {
            let same = existing.counted == counted
                && existing.at == at
                && existing.by == actor
                && existing.note == note;
            if !same {
                return Err(ShiftError::CountConflict(id));
            }
            let variance = self
                .variances
                .iter()
                .find(|variance| variance.count_id == id)
                .cloned()
                .ok_or(ShiftError::CountConflict(id))?;
            return Ok(CountOutcome {
                change: ShiftChange::Replayed,
                variance,
            });
        }
        let expected = self.expected_cash()?;
        let variance = CashVariance {
            count_id: id.clone(),
            expected,
            counted,
            variance: counted.checked_sub(expected)?,
            operator: actor.clone(),
            at,
        };
        self.counts.push(DrawerCount {
            id,
            counted,
            at,
            by: actor,
            note,
        });
        self.variances.push(variance.clone());
        Ok(CountOutcome {
            change: ShiftChange::Applied,
            variance,
        })
    }

    fn build_report(
        &self,
        kind: ReportKind,
        generated_at: Timestamp,
        closed: Option<(EmployeeId, Timestamp)>,
    ) -> Result<ShiftReport, ShiftError> {
        let totals = self.totals()?;
        let expected_cash = totals.expected_cash()?;
        let (closed_by, closed_at) = match closed {
            Some((by, at)) => (Some(by), Some(at)),
            None => (self.closed_by.clone(), self.closed_at),
        };
        Ok(ShiftReport {
            kind,
            shift_id: self.id.clone(),
            store_id: self.store_id.clone(),
            terminal_id: self.terminal_id.clone(),
            currency: self.currency,
            opened_by: self.opened_by.clone(),
            opened_at: self.opened_at,
            closed_by,
            closed_at,
            generated_at,
            totals,
            expected_cash,
            variances: self.variances.clone(),
            counts: self.counts.clone(),
            movements: self.movements.clone(),
        })
    }
}

/// Every shift in one store or deployment, with one open drawer per terminal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShiftBook {
    shifts: BTreeMap<ShiftId, Shift>,
    open_terminals: BTreeMap<TerminalId, ShiftId>,
}

impl ShiftBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a shift and reserve its terminal.
    ///
    /// Returns [`ShiftError::DrawerAlreadyOpen`] when the terminal already has
    /// an open shift, and [`ShiftError::DuplicateShift`] when the identifier is
    /// already known. Other terminals are unaffected.
    pub fn open(&mut self, session: &StaffSession, spec: ShiftSpec) -> Result<&Shift, ShiftError> {
        if self.shifts.contains_key(&spec.id) {
            return Err(ShiftError::DuplicateShift(spec.id));
        }
        if let Some(open) = self.open_terminals.get(&spec.terminal_id) {
            return Err(ShiftError::DrawerAlreadyOpen(
                self.shifts
                    .get(open)
                    .map(|shift| shift.terminal_id.clone())
                    .unwrap_or_else(|| spec.terminal_id.clone()),
            ));
        }
        let shift = Shift::open(session, spec)?;
        let id = shift.id().clone();
        self.open_terminals
            .insert(shift.terminal_id().clone(), id.clone());
        self.shifts.insert(id.clone(), shift);
        self.shifts.get(&id).ok_or(ShiftError::UnknownShift(id))
    }

    /// Register a shift that was opened on a disconnected terminal.
    ///
    /// A closed offline shift is adopted unchanged; an open one also reserves
    /// its terminal, and a second open drawer on that terminal is refused.
    pub fn adopt_offline(&mut self, shift: Shift) -> Result<(), ShiftError> {
        let id = shift.id().clone();
        if self.shifts.contains_key(&id) {
            return Err(ShiftError::DuplicateShift(id));
        }
        if shift.is_open() {
            if let Some(open) = self.open_terminals.get(&shift.terminal_id) {
                return Err(ShiftError::DrawerAlreadyOpen(open_terminal(
                    &self.shifts,
                    open,
                    &shift.terminal_id,
                )));
            }
            self.open_terminals
                .insert(shift.terminal_id.clone(), id.clone());
        }
        self.shifts.insert(id, shift);
        Ok(())
    }

    /// Look up a shift.
    pub fn shift(&self, id: &ShiftId) -> Option<&Shift> {
        self.shifts.get(id)
    }

    /// Mutate a shift that is already registered.
    ///
    /// Opening is deliberately not reachable from here, so the one-drawer-per-
    /// terminal rule cannot be bypassed.
    pub fn shift_mut(&mut self, id: &ShiftId) -> Option<&mut Shift> {
        self.shifts.get_mut(id)
    }

    /// The open shift on a terminal, if any.
    pub fn open_on(&self, terminal: &TerminalId) -> Option<&Shift> {
        self.open_terminals
            .get(terminal)
            .and_then(|id| self.shifts.get(id))
    }

    /// Every shift, in identifier order.
    pub fn shifts(&self) -> impl Iterator<Item = &Shift> {
        self.shifts.values()
    }

    /// Close a registered shift and release its terminal.
    pub fn close(
        &mut self,
        id: &ShiftId,
        session: &StaffSession,
        final_count_id: DrawerCountId,
        counted: Money,
        at: Timestamp,
        note: Option<&str>,
    ) -> Result<ShiftReport, ShiftError> {
        let shift = self
            .shifts
            .get_mut(id)
            .ok_or_else(|| ShiftError::UnknownShift(id.clone()))?;
        let report = shift.close(session, final_count_id, counted, at, note)?;
        self.open_terminals.remove(shift.terminal_id());
        Ok(report)
    }
}

fn open_terminal(
    shifts: &BTreeMap<ShiftId, Shift>,
    id: &ShiftId,
    fallback: &TerminalId,
) -> TerminalId {
    shifts
        .get(id)
        .map(|shift| shift.terminal_id.clone())
        .unwrap_or_else(|| fallback.clone())
}

fn require(session: &StaffSession, permission: Permission) -> Result<(), ShiftError> {
    if session.can(permission) {
        Ok(())
    } else {
        Err(ShiftError::NotPermitted(permission))
    }
}

fn validate_note(note: Option<&str>) -> Result<Option<String>, ShiftError> {
    match note {
        None => Ok(None),
        Some(text) => {
            validate_identifier(text, "cash note").map_err(|_| ShiftError::InvalidNote)?;
            Ok(Some(text.to_owned()))
        }
    }
}
