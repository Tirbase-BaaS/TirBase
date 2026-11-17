// SPDX-License-Identifier: AGPL-3.0-only

//! POS-05 — refund, discount and void guard, plus M-of-N approval.
//!
//! This module is the authorization layer in front of POS-01 operations. It
//! does not change the order/check state machine; it decides whether a refund,
//! discount or void may proceed, records the security outcome of every denial
//! and issues single-use approvals for overrides.
//!
//! # Caps
//!
//! [`ApprovalGuard`] tracks refunded amounts by operator, terminal, business
//! day and check. A refund is allowed only when every configured cap would still
//! hold after the amount is added. A cap breach is denied with a stable
//! [`DenialCode`] unless the request carries a valid approval.
//!
//! Discount caps are configured separately for line and check scope and for
//! percentage and absolute amount. `StackingPolicy` decides whether a new
//! discount may combine with existing ones:
//!
//! - `Deny`: no existing discount may be present.
//! - `Additive`: percentages and amounts add and the total must fit the caps.
//! - `BestOf`: the new discount must be strictly better than the existing total;
//!   it replaces the existing discounts for cap checking.
//!
//! # Approvals
//!
//! An approval request is bound to its action, check, amount, currency, reason
//! and expiry. An approver must be registered with an F-03
//! [`OperatorRole`] that may approve; the requester cannot approve their own
//! request. Once the configured M signatures are present, the approval is
//! `Ready`. Using it for an operation marks it `Consumed`, so it cannot be
//! replayed.
//!
//! # Security events
//!
//! Every denied operation appends one [`SecurityEvent`] with a stable
//! `DenialCode` and a caller-supplied time. Successful operations do not append
//! a denial event. The sequence is dense and starts at 1.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::audit::Timestamp;
use crate::check::{CheckStatus, PaymentStatus};
use crate::ids::{
    validate_identifier, ApprovalId, CheckId, EmployeeId, LineItemId, PaymentId, TerminalId,
};
use crate::line_item::DiscountKind;
use crate::money::{Currency, Money, Rate};
use crate::rounding::RoundingMode;

/// Milliseconds in one UTC day, used for the refund day bucket.
pub const MILLIS_PER_DAY: i64 = 86_400_000;

/// F-03-compatible operator roles used by the approval matrix.
///
/// The variants intentionally mirror `tirbase-types::OperatorRole` so an
/// adapter can map its authenticated F-03 role into the POS guard without
/// pulling the whole core crate into this domain model. Only `Supervisor`,
/// `Qa` and `Admin` carry the F-03 `Approve` permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperatorRole {
    /// Ordinary operator.
    Operator,
    /// May supervise and approve exceptions.
    Supervisor,
    /// Quality/sign-off role that may approve.
    Qa,
    /// Read/audit role; cannot approve.
    Auditor,
    /// Administrative role that may approve.
    Admin,
    /// Integration principal; cannot approve.
    Integrator,
    /// Emergency role; does not carry the normal Approve permission.
    BreakGlass,
}

impl OperatorRole {
    /// All roles, in stable order.
    pub const ALL: [OperatorRole; 7] = [
        OperatorRole::Operator,
        OperatorRole::Supervisor,
        OperatorRole::Qa,
        OperatorRole::Auditor,
        OperatorRole::Admin,
        OperatorRole::Integrator,
        OperatorRole::BreakGlass,
    ];

    /// Canonical role name.
    pub fn as_str(self) -> &'static str {
        match self {
            OperatorRole::Operator => "operator",
            OperatorRole::Supervisor => "supervisor",
            OperatorRole::Qa => "qa",
            OperatorRole::Auditor => "auditor",
            OperatorRole::Admin => "admin",
            OperatorRole::Integrator => "integrator",
            OperatorRole::BreakGlass => "break-glass",
        }
    }
}

impl fmt::Display for OperatorRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable reason codes for guard denials.
///
/// The string value is the wire/log value; changing it is a compatibility
/// change even if the Rust variant is renamed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenialCode {
    /// Refund would exceed the operator cap.
    RefundOperatorCap,
    /// Refund would exceed the terminal cap.
    RefundTerminalCap,
    /// Refund would exceed the day cap.
    RefundDayCap,
    /// Refund would exceed the check cap.
    RefundCheckCap,
    /// Refund usage arithmetic overflowed.
    RefundUsageOverflow,
    /// Line percentage discount cap exceeded.
    DiscountLinePercentCap,
    /// Line absolute discount cap exceeded.
    DiscountLineAmountCap,
    /// Check percentage discount cap exceeded.
    DiscountCheckPercentCap,
    /// Check absolute discount cap exceeded.
    DiscountCheckAmountCap,
    /// Discount stacking policy rejected the combination.
    DiscountStackingDenied,
    /// Discounts would exceed the base amount.
    DiscountBaseExceeded,
    /// Voiding a captured payment or closed check needs approval.
    VoidApprovalRequired,
    /// Approval request not found.
    ApprovalNotFound,
    /// Approval request id already exists.
    ApprovalAlreadyExists,
    /// Approval has expired.
    ApprovalExpired,
    /// Approval was already consumed by an operation.
    ApprovalAlreadyUsed,
    /// Approval does not have enough distinct approvers yet.
    ApprovalNotReady,
    /// Approval is already ready and accepts no more approvers.
    ApprovalNotPending,
    /// Approval does not match the operation's action/check/amount/reason.
    ApprovalBindingMismatch,
    /// Requester tried to approve their own request.
    ApprovalSelfNotAllowed,
    /// Approver is not registered or their role cannot approve.
    ApprovalRoleDenied,
    /// The same approver signed twice.
    ApprovalDuplicate,
    /// Fewer eligible approvers exist than the required M.
    ApprovalPoolTooSmall,
    /// Expiry is not after the request time.
    ApprovalInvalidExpiry,
    /// Request amount is not positive.
    InvalidAmount,
    /// Request or approval currency differs from the guard currency.
    CurrencyMismatch,
    /// Reason is blank, oversized or contains control characters.
    InvalidReason,
    /// The request target/status combination is invalid.
    InvalidRequest,
    /// Guard configuration is invalid.
    InvalidConfiguration,
}

impl DenialCode {
    /// Stable wire/log string.
    pub fn as_str(self) -> &'static str {
        match self {
            DenialCode::RefundOperatorCap => "refund.cap.operator",
            DenialCode::RefundTerminalCap => "refund.cap.terminal",
            DenialCode::RefundDayCap => "refund.cap.day",
            DenialCode::RefundCheckCap => "refund.cap.check",
            DenialCode::RefundUsageOverflow => "refund.usage_overflow",
            DenialCode::DiscountLinePercentCap => "discount.cap.line.percent",
            DenialCode::DiscountLineAmountCap => "discount.cap.line.amount",
            DenialCode::DiscountCheckPercentCap => "discount.cap.check.percent",
            DenialCode::DiscountCheckAmountCap => "discount.cap.check.amount",
            DenialCode::DiscountStackingDenied => "discount.stacking_denied",
            DenialCode::DiscountBaseExceeded => "discount.base_exceeded",
            DenialCode::VoidApprovalRequired => "void.approval_required",
            DenialCode::ApprovalNotFound => "approval.not_found",
            DenialCode::ApprovalAlreadyExists => "approval.already_exists",
            DenialCode::ApprovalExpired => "approval.expired",
            DenialCode::ApprovalAlreadyUsed => "approval.already_used",
            DenialCode::ApprovalNotReady => "approval.not_ready",
            DenialCode::ApprovalNotPending => "approval.not_pending",
            DenialCode::ApprovalBindingMismatch => "approval.binding_mismatch",
            DenialCode::ApprovalSelfNotAllowed => "approval.self_not_allowed",
            DenialCode::ApprovalRoleDenied => "approval.role_denied",
            DenialCode::ApprovalDuplicate => "approval.duplicate_approver",
            DenialCode::ApprovalPoolTooSmall => "approval.pool_too_small",
            DenialCode::ApprovalInvalidExpiry => "approval.invalid_expiry",
            DenialCode::InvalidAmount => "request.invalid_amount",
            DenialCode::CurrencyMismatch => "request.currency_mismatch",
            DenialCode::InvalidReason => "request.invalid_reason",
            DenialCode::InvalidRequest => "request.invalid",
            DenialCode::InvalidConfiguration => "guard.invalid_configuration",
        }
    }
}

impl fmt::Display for DenialCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A denied guard operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardError {
    code: DenialCode,
    detail: String,
}

impl GuardError {
    fn denial(code: DenialCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn configuration(detail: impl Into<String>) -> Self {
        Self {
            code: DenialCode::InvalidConfiguration,
            detail: detail.into(),
        }
    }

    /// Stable denial reason.
    pub fn code(&self) -> DenialCode {
        self.code
    }

    /// Human-readable detail; do not key policy on this string.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for GuardError {}

/// Which operation a security event concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityAction {
    /// Refund guard.
    Refund,
    /// Discount guard.
    Discount,
    /// Void guard.
    Void,
    /// Approval request/approval/consumption.
    Approval,
}

/// One denial security event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityEvent {
    /// Dense sequence starting at 1.
    pub sequence: u64,
    /// Caller-supplied operation time.
    pub at: Timestamp,
    /// Operator associated with the denied operation, when known.
    pub actor: Option<EmployeeId>,
    /// Terminal associated with the operation, when known.
    pub terminal: Option<TerminalId>,
    /// Check associated with the operation, when known.
    pub check: Option<CheckId>,
    /// Operation family.
    pub action: SecurityAction,
    /// Approval associated with the denial, when applicable.
    pub approval: Option<ApprovalId>,
    /// Stable denial code.
    pub code: DenialCode,
    /// Human-readable detail.
    pub detail: String,
}

/// A UTC day bucket for refund caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BusinessDay(i64);

impl BusinessDay {
    /// Derive the UTC day containing `at`.
    pub const fn from_timestamp(at: Timestamp) -> Self {
        Self(at.millis().div_euclid(MILLIS_PER_DAY))
    }

    /// The day index since the Unix epoch.
    pub const fn index(self) -> i64 {
        self.0
    }
}

impl fmt::Display for BusinessDay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "day:{}", self.0)
    }
}

/// Refund caps, in the guard's currency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundCaps {
    per_operator: Money,
    per_terminal: Money,
    per_day: Money,
    per_check: Money,
}

impl RefundCaps {
    /// Configure all four caps. They must share one currency and be non-negative.
    pub fn new(
        per_operator: Money,
        per_terminal: Money,
        per_day: Money,
        per_check: Money,
    ) -> Result<Self, GuardError> {
        let currency = per_operator.currency();
        let caps = [per_operator, per_terminal, per_day, per_check];
        if caps.iter().any(|cap| cap.currency() != currency) {
            return Err(GuardError::configuration(
                "refund caps must share one currency",
            ));
        }
        if caps.iter().any(|cap| cap.is_negative()) {
            return Err(GuardError::configuration(
                "refund caps must be non-negative",
            ));
        }
        Ok(Self {
            per_operator,
            per_terminal,
            per_day,
            per_check,
        })
    }

    /// The operator cap.
    pub fn per_operator(&self) -> Money {
        self.per_operator
    }

    /// The terminal cap.
    pub fn per_terminal(&self) -> Money {
        self.per_terminal
    }

    /// The UTC-day cap.
    pub fn per_day(&self) -> Money {
        self.per_day
    }

    /// The check cap.
    pub fn per_check(&self) -> Money {
        self.per_check
    }
}

/// One discount cap: a percentage and an absolute amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscountCap {
    percent: Rate,
    amount: Money,
}

impl DiscountCap {
    /// Configure a percentage and absolute cap. The amount must be non-negative.
    pub fn new(percent: Rate, amount: Money) -> Result<Self, GuardError> {
        if amount.is_negative() {
            return Err(GuardError::configuration(
                "discount amount cap must be non-negative",
            ));
        }
        Ok(Self { percent, amount })
    }

    /// The percentage cap.
    pub fn percent(&self) -> Rate {
        self.percent
    }

    /// The absolute cap.
    pub fn amount(&self) -> Money {
        self.amount
    }
}

/// How a new discount may combine with existing discounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackingPolicy {
    /// Reject if any discount already exists.
    Deny,
    /// Add percentages and amounts; the total must fit the caps.
    Additive,
    /// The new discount must be strictly better than the existing total and
    /// replaces it for cap checking.
    BestOf,
}

/// Line and check discount caps plus the stacking rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscountCaps {
    line: DiscountCap,
    check: DiscountCap,
    stacking: StackingPolicy,
}

impl DiscountCaps {
    /// Configure line and check caps. Their absolute caps must share one
    /// currency.
    pub fn new(
        line: DiscountCap,
        check: DiscountCap,
        stacking: StackingPolicy,
    ) -> Result<Self, GuardError> {
        if line.amount().currency() != check.amount().currency() {
            return Err(GuardError::configuration(
                "discount caps must share one currency",
            ));
        }
        Ok(Self {
            line,
            check,
            stacking,
        })
    }

    /// The line cap.
    pub fn line(&self) -> &DiscountCap {
        &self.line
    }

    /// The check cap.
    pub fn check(&self) -> &DiscountCap {
        &self.check
    }

    /// The stacking rule.
    pub fn stacking(&self) -> StackingPolicy {
        self.stacking
    }
}

/// Where a discount applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscountScope {
    /// One line item.
    Line(LineItemId),
    /// The whole check.
    Check,
}

/// A discount authorization request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscountRequest {
    /// Operator applying the discount.
    pub operator: EmployeeId,
    /// Terminal applying the discount.
    pub terminal: TerminalId,
    /// Check being discounted.
    pub check: CheckId,
    /// Line or check scope.
    pub scope: DiscountScope,
    /// Base amount the discount is calculated against.
    pub base: Money,
    /// The requested discount.
    pub discount: DiscountKind,
    /// Discounts already applied to the same base.
    pub existing: Vec<DiscountKind>,
    /// Rounding mode of the check.
    pub rounding: RoundingMode,
    /// Reason; bound into an override approval.
    pub reason: String,
    /// Caller-supplied operation time.
    pub at: Timestamp,
    /// Optional approval for a cap override.
    pub approval: Option<ApprovalId>,
}

impl DiscountRequest {
    /// Construct a discount request without an approval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator: EmployeeId,
        terminal: TerminalId,
        check: CheckId,
        scope: DiscountScope,
        base: Money,
        discount: DiscountKind,
        existing: Vec<DiscountKind>,
        rounding: RoundingMode,
        reason: impl Into<String>,
        at: Timestamp,
    ) -> Self {
        Self {
            operator,
            terminal,
            check,
            scope,
            base,
            discount,
            existing,
            rounding,
            reason: reason.into(),
            at,
            approval: None,
        }
    }

    /// Attach an approval to a cap-override request.
    pub fn with_approval(mut self, approval: ApprovalId) -> Self {
        self.approval = Some(approval);
        self
    }
}

/// A refund authorization request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundRequest {
    /// Operator requesting the refund.
    pub operator: EmployeeId,
    /// Terminal requesting the refund.
    pub terminal: TerminalId,
    /// Check being refunded.
    pub check: CheckId,
    /// Refund amount.
    pub amount: Money,
    /// Reason; bound into an override approval.
    pub reason: String,
    /// Caller-supplied operation time.
    pub at: Timestamp,
    /// Optional approval for a cap override.
    pub approval: Option<ApprovalId>,
}

impl RefundRequest {
    /// Construct a refund request without an approval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator: EmployeeId,
        terminal: TerminalId,
        check: CheckId,
        amount: Money,
        reason: impl Into<String>,
        at: Timestamp,
    ) -> Self {
        Self {
            operator,
            terminal,
            check,
            amount,
            reason: reason.into(),
            at,
            approval: None,
        }
    }

    /// Attach an approval to a cap-override request.
    pub fn with_approval(mut self, approval: ApprovalId) -> Self {
        self.approval = Some(approval);
        self
    }
}

/// The object of a void request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoidTarget {
    /// The whole check.
    Check,
    /// One linked payment.
    Payment(PaymentId),
}

/// A void authorization request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoidRequest {
    /// Operator requesting the void.
    pub operator: EmployeeId,
    /// Terminal requesting the void.
    pub terminal: TerminalId,
    /// Check being voided or containing the payment.
    pub check: CheckId,
    /// Whole check or one payment.
    pub target: VoidTarget,
    /// Amount being voided.
    pub amount: Money,
    /// Reason; bound into the required approval.
    pub reason: String,
    /// Caller-supplied operation time.
    pub at: Timestamp,
    /// Current check status.
    pub check_status: CheckStatus,
    /// Current payment status when the target is a payment.
    pub payment_status: Option<PaymentStatus>,
    /// Optional approval.
    pub approval: Option<ApprovalId>,
}

impl VoidRequest {
    /// Construct a void request without an approval.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator: EmployeeId,
        terminal: TerminalId,
        check: CheckId,
        target: VoidTarget,
        amount: Money,
        reason: impl Into<String>,
        at: Timestamp,
        check_status: CheckStatus,
        payment_status: Option<PaymentStatus>,
    ) -> Self {
        Self {
            operator,
            terminal,
            check,
            target,
            amount,
            reason: reason.into(),
            at,
            check_status,
            payment_status,
            approval: None,
        }
    }

    /// Attach an approval.
    pub fn with_approval(mut self, approval: ApprovalId) -> Self {
        self.approval = Some(approval);
        self
    }
}

/// The operation an approval covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalAction {
    /// Refund one check.
    Refund,
    /// Void one check.
    VoidCheck,
    /// Void one captured payment.
    VoidPayment(PaymentId),
    /// Apply a discount, optionally scoped to one line.
    Discount { line: Option<LineItemId> },
}

/// One approver's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalSignature {
    /// The approver.
    pub approver: EmployeeId,
    /// Their F-03 role at signing time.
    pub role: OperatorRole,
}

/// State of an approval request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// Waiting for more distinct approvers.
    Pending,
    /// M distinct approvers have signed; ready for one use.
    Ready,
    /// Already used by an operation.
    Consumed,
}

/// A stored, single-use approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    id: ApprovalId,
    action: ApprovalAction,
    check: CheckId,
    amount: Money,
    reason: String,
    expires_at: Timestamp,
    requester: EmployeeId,
    terminal: TerminalId,
    required: u8,
    eligible_approvers: BTreeSet<EmployeeId>,
    signatures: Vec<ApprovalSignature>,
    consumed: bool,
}

impl Approval {
    /// The approval id.
    pub fn id(&self) -> &ApprovalId {
        &self.id
    }

    /// The action it covers.
    pub fn action(&self) -> &ApprovalAction {
        &self.action
    }

    /// The bound check.
    pub fn check_id(&self) -> &CheckId {
        &self.check
    }

    /// The bound amount.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The bound amount's currency.
    pub fn currency(&self) -> Currency {
        self.amount.currency()
    }

    /// The bound reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The caller-supplied expiry.
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// The operator who requested it.
    pub fn requester(&self) -> &EmployeeId {
        &self.requester
    }

    /// The terminal that requested it.
    pub fn terminal(&self) -> &TerminalId {
        &self.terminal
    }

    /// How many distinct approvals are required.
    pub fn required(&self) -> u8 {
        self.required
    }

    /// Signatures in arrival order.
    pub fn signatures(&self) -> &[ApprovalSignature] {
        &self.signatures
    }

    /// Current state.
    pub fn status(&self) -> ApprovalStatus {
        if self.consumed {
            ApprovalStatus::Consumed
        } else if self.signatures.len() >= usize::from(self.required) {
            ApprovalStatus::Ready
        } else {
            ApprovalStatus::Pending
        }
    }

    /// `true` when the approval is ready and not consumed.
    pub fn is_ready(&self) -> bool {
        self.status() == ApprovalStatus::Ready
    }
}

/// The stateful refund/discount/void guard and approval registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalGuard {
    currency: Currency,
    refund_caps: RefundCaps,
    discount_caps: DiscountCaps,
    required_approvals: u8,
    approvers: BTreeMap<EmployeeId, OperatorRole>,
    approvals: BTreeMap<ApprovalId, Approval>,
    operator_refunds: BTreeMap<EmployeeId, Money>,
    terminal_refunds: BTreeMap<TerminalId, Money>,
    day_refunds: BTreeMap<BusinessDay, Money>,
    check_refunds: BTreeMap<CheckId, Money>,
    security: Vec<SecurityEvent>,
    next_security_sequence: u64,
}

impl ApprovalGuard {
    /// Construct a guard. The required approval count must be at least 1 and all
    /// caps must use `currency`.
    pub fn new(
        currency: Currency,
        refund_caps: RefundCaps,
        discount_caps: DiscountCaps,
        required_approvals: u8,
    ) -> Result<Self, GuardError> {
        if required_approvals == 0 {
            return Err(GuardError::configuration(
                "at least one approval must be required",
            ));
        }
        if refund_caps.per_operator().currency() != currency
            || refund_caps.per_terminal().currency() != currency
            || refund_caps.per_day().currency() != currency
            || refund_caps.per_check().currency() != currency
        {
            return Err(GuardError::configuration(
                "refund caps do not match the guard currency",
            ));
        }
        if discount_caps.line().amount().currency() != currency
            || discount_caps.check().amount().currency() != currency
        {
            return Err(GuardError::configuration(
                "discount caps do not match the guard currency",
            ));
        }
        Ok(Self {
            currency,
            refund_caps,
            discount_caps,
            required_approvals,
            approvers: BTreeMap::new(),
            approvals: BTreeMap::new(),
            operator_refunds: BTreeMap::new(),
            terminal_refunds: BTreeMap::new(),
            day_refunds: BTreeMap::new(),
            check_refunds: BTreeMap::new(),
            security: Vec::new(),
            next_security_sequence: 1,
        })
    }

    /// Register an approver and their F-03 role. Re-registering updates the role.
    pub fn register_approver(&mut self, approver: EmployeeId, role: OperatorRole) {
        self.approvers.insert(approver, role);
    }

    /// The registered role for an approver, if any.
    pub fn role_of(&self, approver: &EmployeeId) -> Option<OperatorRole> {
        self.approvers.get(approver).copied()
    }

    /// The guard currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// The refund caps.
    pub fn refund_caps(&self) -> &RefundCaps {
        &self.refund_caps
    }

    /// The discount caps.
    pub fn discount_caps(&self) -> &DiscountCaps {
        &self.discount_caps
    }

    /// The required number of distinct approvers.
    pub fn required_approvals(&self) -> u8 {
        self.required_approvals
    }

    /// All denial events in sequence order.
    pub fn security_events(&self) -> &[SecurityEvent] {
        &self.security
    }

    /// Look up an approval.
    pub fn approval(&self, id: &ApprovalId) -> Option<&Approval> {
        self.approvals.get(id)
    }

    /// Approvals in identifier order.
    pub fn approvals(&self) -> impl Iterator<Item = &Approval> {
        self.approvals.values()
    }

    /// How much an operator has refunded through this guard.
    pub fn refunded_by_operator(&self, operator: &EmployeeId) -> Money {
        self.operator_refunds
            .get(operator)
            .copied()
            .unwrap_or(Money::zero(self.currency))
    }

    /// How much a terminal has refunded through this guard.
    pub fn refunded_by_terminal(&self, terminal: &TerminalId) -> Money {
        self.terminal_refunds
            .get(terminal)
            .copied()
            .unwrap_or(Money::zero(self.currency))
    }

    /// How much has been refunded on a UTC day.
    pub fn refunded_on_day(&self, day: BusinessDay) -> Money {
        self.day_refunds
            .get(&day)
            .copied()
            .unwrap_or(Money::zero(self.currency))
    }

    /// How much has been refunded against a check.
    pub fn refunded_on_check(&self, check: &CheckId) -> Money {
        self.check_refunds
            .get(check)
            .copied()
            .unwrap_or(Money::zero(self.currency))
    }

    /// Request an M-of-N approval. The eligible approver set is snapshotted
    /// from the registered approvers with an approving F-03 role.
    #[allow(clippy::too_many_arguments)]
    pub fn request_approval(
        &mut self,
        id: ApprovalId,
        action: ApprovalAction,
        check: CheckId,
        amount: Money,
        reason: impl Into<String>,
        requester: EmployeeId,
        terminal: TerminalId,
        at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<ApprovalId, GuardError> {
        if amount.currency() != self.currency {
            return Err(self.deny(
                at,
                Some(requester),
                Some(terminal),
                Some(check),
                SecurityAction::Approval,
                Some(id),
                DenialCode::CurrencyMismatch,
                "approval amount currency does not match guard",
            ));
        }
        if !amount.is_positive() {
            return Err(self.deny(
                at,
                Some(requester),
                Some(terminal),
                Some(check),
                SecurityAction::Approval,
                Some(id),
                DenialCode::InvalidAmount,
                "approval amount must be positive",
            ));
        }
        let reason = reason.into();
        if !valid_reason(&reason) {
            return Err(self.deny(
                at,
                Some(requester),
                Some(terminal),
                Some(check),
                SecurityAction::Approval,
                Some(id),
                DenialCode::InvalidReason,
                "approval reason is blank, invalid or too long",
            ));
        }
        if expires_at <= at {
            return Err(self.deny(
                at,
                Some(requester),
                Some(terminal),
                Some(check),
                SecurityAction::Approval,
                Some(id),
                DenialCode::ApprovalInvalidExpiry,
                "approval expiry must be after the request time",
            ));
        }
        if self.approvals.contains_key(&id) {
            return Err(self.deny(
                at,
                Some(requester),
                Some(terminal),
                Some(check),
                SecurityAction::Approval,
                Some(id),
                DenialCode::ApprovalAlreadyExists,
                "approval id already exists",
            ));
        }

        let eligible_approvers: BTreeSet<EmployeeId> = self
            .approvers
            .iter()
            .filter(|(id, role)| **id != requester && role_may_approve(**role))
            .map(|(id, _)| id.clone())
            .collect();
        if usize::from(self.required_approvals) > eligible_approvers.len() {
            return Err(self.deny(
                at,
                Some(requester),
                Some(terminal),
                Some(check),
                SecurityAction::Approval,
                Some(id),
                DenialCode::ApprovalPoolTooSmall,
                format!(
                    "{} approvals required but only {} eligible approvers registered",
                    self.required_approvals,
                    eligible_approvers.len()
                ),
            ));
        }

        self.approvals.insert(
            id.clone(),
            Approval {
                id: id.clone(),
                action,
                check,
                amount,
                reason,
                expires_at,
                requester,
                terminal,
                required: self.required_approvals,
                eligible_approvers,
                signatures: Vec::new(),
                consumed: false,
            },
        );
        Ok(id)
    }

    /// Add one approver's signature. The requester cannot sign their own
    /// request, and duplicate signatures are rejected.
    pub fn approve(
        &mut self,
        id: &ApprovalId,
        approver: &EmployeeId,
        at: Timestamp,
    ) -> Result<ApprovalStatus, GuardError> {
        let Some(approval) = self.approvals.get(id).cloned() else {
            return Err(self.deny(
                at,
                Some(approver.clone()),
                None,
                None,
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalNotFound,
                "approval request not found",
            ));
        };
        if approval.status() == ApprovalStatus::Consumed {
            return Err(self.deny(
                at,
                Some(approver.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalAlreadyUsed,
                "approval has already been consumed",
            ));
        }
        if at >= approval.expires_at {
            return Err(self.deny(
                at,
                Some(approver.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalExpired,
                "approval has expired",
            ));
        }
        if approval.status() == ApprovalStatus::Ready {
            return Err(self.deny(
                at,
                Some(approver.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalNotPending,
                "approval already has enough signatures",
            ));
        }
        if &approval.requester == approver {
            return Err(self.deny(
                at,
                Some(approver.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalSelfNotAllowed,
                "a requester cannot approve their own request",
            ));
        }
        let Some(role) = self.approvers.get(approver).copied() else {
            return Err(self.deny(
                at,
                Some(approver.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalRoleDenied,
                "approver is not registered",
            ));
        };
        if !role_may_approve(role) || !approval.eligible_approvers.contains(approver) {
            return Err(self.deny(
                at,
                Some(approver.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalRoleDenied,
                "approver role cannot approve this request",
            ));
        }
        if approval
            .signatures
            .iter()
            .any(|signature| &signature.approver == approver)
        {
            return Err(self.deny(
                at,
                Some(approver.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalDuplicate,
                "approver has already signed",
            ));
        }

        let Some(approval) = self.approvals.get_mut(id) else {
            return Err(self.deny(
                at,
                Some(approver.clone()),
                None,
                None,
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalNotFound,
                "approval request not found",
            ));
        };
        approval.signatures.push(ApprovalSignature {
            approver: approver.clone(),
            role,
        });
        Ok(approval.status())
    }

    /// Authorize a refund against all four caps.
    ///
    /// A cap breach requires an optional approval whose action is `Refund` and
    /// whose check, amount, currency, reason and expiry match. A successful
    /// authorization consumes the approval and records the refunded amount in
    /// every usage bucket.
    pub fn authorize_refund(&mut self, request: &RefundRequest) -> Result<(), GuardError> {
        if !self.valid_amount(request.amount) {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Refund,
                request.approval.clone(),
                if request.amount.currency() != self.currency {
                    DenialCode::CurrencyMismatch
                } else {
                    DenialCode::InvalidAmount
                },
                "refund amount must be positive and in the guard currency",
            ));
        }
        if !valid_reason(&request.reason) {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Refund,
                request.approval.clone(),
                DenialCode::InvalidReason,
                "refund reason is blank, invalid or too long",
            ));
        }

        let day = BusinessDay::from_timestamp(request.at);
        let operator_used = self.refunded_by_operator(&request.operator);
        let terminal_used = self.refunded_by_terminal(&request.terminal);
        let day_used = self.refunded_on_day(day);
        let check_used = self.refunded_on_check(&request.check);

        let Some(operator_total) = checked_total(operator_used, request.amount) else {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Refund,
                request.approval.clone(),
                DenialCode::RefundUsageOverflow,
                "operator refund usage overflowed",
            ));
        };
        let Some(terminal_total) = checked_total(terminal_used, request.amount) else {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Refund,
                request.approval.clone(),
                DenialCode::RefundUsageOverflow,
                "terminal refund usage overflowed",
            ));
        };
        let Some(day_total) = checked_total(day_used, request.amount) else {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Refund,
                request.approval.clone(),
                DenialCode::RefundUsageOverflow,
                "day refund usage overflowed",
            ));
        };
        let Some(check_total) = checked_total(check_used, request.amount) else {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Refund,
                request.approval.clone(),
                DenialCode::RefundUsageOverflow,
                "check refund usage overflowed",
            ));
        };

        let cap_breach = if operator_total > self.refund_caps.per_operator {
            Some((
                DenialCode::RefundOperatorCap,
                format!(
                    "operator cap {} would be exceeded by {}",
                    self.refund_caps.per_operator, operator_total
                ),
            ))
        } else if terminal_total > self.refund_caps.per_terminal {
            Some((
                DenialCode::RefundTerminalCap,
                format!(
                    "terminal cap {} would be exceeded by {}",
                    self.refund_caps.per_terminal, terminal_total
                ),
            ))
        } else if day_total > self.refund_caps.per_day {
            Some((
                DenialCode::RefundDayCap,
                format!(
                    "day cap {} would be exceeded by {}",
                    self.refund_caps.per_day, day_total
                ),
            ))
        } else if check_total > self.refund_caps.per_check {
            Some((
                DenialCode::RefundCheckCap,
                format!(
                    "check cap {} would be exceeded by {}",
                    self.refund_caps.per_check, check_total
                ),
            ))
        } else {
            None
        };

        match (cap_breach, request.approval.as_ref()) {
            (Some((code, detail)), None) => {
                return Err(self.deny(
                    request.at,
                    Some(request.operator.clone()),
                    Some(request.terminal.clone()),
                    Some(request.check.clone()),
                    SecurityAction::Refund,
                    None,
                    code,
                    detail,
                ));
            }
            (_, Some(approval)) => {
                self.consume_approval(
                    approval,
                    &ApprovalAction::Refund,
                    &request.check,
                    request.amount,
                    &request.reason,
                    &request.operator,
                    request.at,
                )?;
            }
            (None, None) => {}
        }

        self.operator_refunds
            .insert(request.operator.clone(), operator_total);
        self.terminal_refunds
            .insert(request.terminal.clone(), terminal_total);
        self.day_refunds.insert(day, day_total);
        self.check_refunds
            .insert(request.check.clone(), check_total);
        Ok(())
    }

    /// Authorize a discount against line/check and percentage/absolute caps,
    /// honoring the configured stacking rule.
    ///
    /// A cap breach requires an optional approval whose action is the matching
    /// `Discount` action, and whose check, discount amount, currency and reason
    /// match. Stacking-policy denials are not overrideable.
    pub fn authorize_discount(&mut self, request: &DiscountRequest) -> Result<(), GuardError> {
        if request.base.currency() != self.currency || request.base.is_negative() {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Discount,
                request.approval.clone(),
                if request.base.currency() != self.currency {
                    DenialCode::CurrencyMismatch
                } else {
                    DenialCode::InvalidAmount
                },
                "discount base must be non-negative and in the guard currency",
            ));
        }
        if !valid_reason(&request.reason) {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Discount,
                request.approval.clone(),
                DenialCode::InvalidReason,
                "discount reason is blank, invalid or too long",
            ));
        }

        if let DiscountKind::Amount(amount) = request.discount {
            if amount.currency() != self.currency {
                return Err(self.deny(
                    request.at,
                    Some(request.operator.clone()),
                    Some(request.terminal.clone()),
                    Some(request.check.clone()),
                    SecurityAction::Discount,
                    request.approval.clone(),
                    DenialCode::CurrencyMismatch,
                    "discount amount currency does not match the guard",
                ));
            }
            if amount.is_negative() {
                return Err(self.deny(
                    request.at,
                    Some(request.operator.clone()),
                    Some(request.terminal.clone()),
                    Some(request.check.clone()),
                    SecurityAction::Discount,
                    request.approval.clone(),
                    DenialCode::InvalidAmount,
                    "discount amount must be non-negative",
                ));
            }
        }
        let Some(requested_amount) = discount_amount(
            &request.discount,
            request.base,
            request.rounding,
            self.currency,
        ) else {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Discount,
                request.approval.clone(),
                DenialCode::InvalidAmount,
                "discount amount must be non-negative and in the guard currency",
            ));
        };
        if requested_amount > request.base {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Discount,
                request.approval.clone(),
                DenialCode::DiscountBaseExceeded,
                "discount exceeds the base amount",
            ));
        }

        let mut existing_percent_ppm = 0_i64;
        let mut existing_amount = Money::zero(self.currency);
        for existing in &request.existing {
            match existing {
                DiscountKind::Amount(amount) => {
                    if amount.currency() != self.currency || amount.is_negative() {
                        return Err(self.deny(
                            request.at,
                            Some(request.operator.clone()),
                            Some(request.terminal.clone()),
                            Some(request.check.clone()),
                            SecurityAction::Discount,
                            request.approval.clone(),
                            DenialCode::CurrencyMismatch,
                            "existing discount amount is invalid",
                        ));
                    }
                    let Some(total) = checked_total(existing_amount, *amount) else {
                        return Err(self.deny(
                            request.at,
                            Some(request.operator.clone()),
                            Some(request.terminal.clone()),
                            Some(request.check.clone()),
                            SecurityAction::Discount,
                            request.approval.clone(),
                            DenialCode::InvalidAmount,
                            "existing discount amount overflowed",
                        ));
                    };
                    existing_amount = total;
                }
                DiscountKind::Percent(rate) => {
                    existing_percent_ppm =
                        existing_percent_ppm.saturating_add(i64::from(rate.ppm()));
                }
            }
        }
        if existing_amount > request.base {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Discount,
                request.approval.clone(),
                DenialCode::DiscountBaseExceeded,
                "existing discounts exceed the base amount",
            ));
        }

        let requested_percent_ppm = match request.discount {
            DiscountKind::Percent(rate) => i64::from(rate.ppm()),
            DiscountKind::Amount(_) => 0,
        };
        let (total_percent_ppm, total_amount) = match self.discount_caps.stacking {
            StackingPolicy::Deny if !request.existing.is_empty() => {
                return Err(self.deny(
                    request.at,
                    Some(request.operator.clone()),
                    Some(request.terminal.clone()),
                    Some(request.check.clone()),
                    SecurityAction::Discount,
                    request.approval.clone(),
                    DenialCode::DiscountStackingDenied,
                    "stacking is disabled and a discount already exists",
                ));
            }
            StackingPolicy::Deny => (requested_percent_ppm, requested_amount),
            StackingPolicy::Additive => {
                let Some(total) = checked_total(existing_amount, requested_amount) else {
                    return Err(self.deny(
                        request.at,
                        Some(request.operator.clone()),
                        Some(request.terminal.clone()),
                        Some(request.check.clone()),
                        SecurityAction::Discount,
                        request.approval.clone(),
                        DenialCode::InvalidAmount,
                        "stacked discount amount overflowed",
                    ));
                };
                (
                    existing_percent_ppm.saturating_add(requested_percent_ppm),
                    total,
                )
            }
            StackingPolicy::BestOf if existing_amount >= requested_amount => {
                return Err(self.deny(
                    request.at,
                    Some(request.operator.clone()),
                    Some(request.terminal.clone()),
                    Some(request.check.clone()),
                    SecurityAction::Discount,
                    request.approval.clone(),
                    DenialCode::DiscountStackingDenied,
                    "new discount is not better than the existing discount",
                ));
            }
            StackingPolicy::BestOf => (requested_percent_ppm, requested_amount),
        };
        if total_amount > request.base {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Discount,
                request.approval.clone(),
                DenialCode::DiscountBaseExceeded,
                "stacked discounts exceed the base amount",
            ));
        }

        let (cap, percent_code, amount_code) = match request.scope {
            DiscountScope::Line(_) => (
                self.discount_caps.line(),
                DenialCode::DiscountLinePercentCap,
                DenialCode::DiscountLineAmountCap,
            ),
            DiscountScope::Check => (
                self.discount_caps.check(),
                DenialCode::DiscountCheckPercentCap,
                DenialCode::DiscountCheckAmountCap,
            ),
        };
        let cap_breach = if total_percent_ppm > i64::from(cap.percent.ppm()) {
            Some((
                percent_code,
                format!("discount percentage cap {} would be exceeded", cap.percent),
            ))
        } else if total_amount > cap.amount {
            Some((
                amount_code,
                format!("discount amount cap {} would be exceeded", cap.amount),
            ))
        } else {
            None
        };

        let line = match &request.scope {
            DiscountScope::Line(line) => Some(line.clone()),
            DiscountScope::Check => None,
        };
        match (cap_breach, request.approval.as_ref()) {
            (Some((code, detail)), None) => {
                return Err(self.deny(
                    request.at,
                    Some(request.operator.clone()),
                    Some(request.terminal.clone()),
                    Some(request.check.clone()),
                    SecurityAction::Discount,
                    None,
                    code,
                    detail,
                ));
            }
            (_, Some(approval)) => {
                self.consume_approval(
                    approval,
                    &ApprovalAction::Discount { line },
                    &request.check,
                    requested_amount,
                    &request.reason,
                    &request.operator,
                    request.at,
                )?;
            }
            (None, None) => {}
        }
        Ok(())
    }

    /// Authorize a void. Voiding a captured payment or a closed check requires a
    /// matching, unconsumed approval; other voids need no approval.
    pub fn authorize_void(&mut self, request: &VoidRequest) -> Result<(), GuardError> {
        if !self.valid_amount(request.amount) {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Void,
                request.approval.clone(),
                if request.amount.currency() != self.currency {
                    DenialCode::CurrencyMismatch
                } else {
                    DenialCode::InvalidAmount
                },
                "void amount must be positive and in the guard currency",
            ));
        }
        if !valid_reason(&request.reason) {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Void,
                request.approval.clone(),
                DenialCode::InvalidReason,
                "void reason is blank, invalid or too long",
            ));
        }
        let (action, requires_approval) = match &request.target {
            VoidTarget::Check => (
                ApprovalAction::VoidCheck,
                request.check_status == CheckStatus::Closed,
            ),
            VoidTarget::Payment(payment) => {
                let Some(status) = request.payment_status else {
                    return Err(self.deny(
                        request.at,
                        Some(request.operator.clone()),
                        Some(request.terminal.clone()),
                        Some(request.check.clone()),
                        SecurityAction::Void,
                        request.approval.clone(),
                        DenialCode::InvalidRequest,
                        "payment target is missing its payment status",
                    ));
                };
                (
                    ApprovalAction::VoidPayment(payment.clone()),
                    status == PaymentStatus::Captured,
                )
            }
        };
        if !requires_approval {
            if let Some(approval) = &request.approval {
                self.consume_approval(
                    approval,
                    &action,
                    &request.check,
                    request.amount,
                    &request.reason,
                    &request.operator,
                    request.at,
                )?;
            }
            return Ok(());
        }
        let Some(approval) = &request.approval else {
            return Err(self.deny(
                request.at,
                Some(request.operator.clone()),
                Some(request.terminal.clone()),
                Some(request.check.clone()),
                SecurityAction::Void,
                None,
                DenialCode::VoidApprovalRequired,
                "void of a captured payment or closed check requires approval",
            ));
        };
        self.consume_approval(
            approval,
            &action,
            &request.check,
            request.amount,
            &request.reason,
            &request.operator,
            request.at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn consume_approval(
        &mut self,
        id: &ApprovalId,
        action: &ApprovalAction,
        check: &CheckId,
        amount: Money,
        reason: &str,
        actor: &EmployeeId,
        at: Timestamp,
    ) -> Result<(), GuardError> {
        let Some(approval) = self.approvals.get(id).cloned() else {
            return Err(self.deny(
                at,
                Some(actor.clone()),
                None,
                Some(check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalNotFound,
                "approval request not found",
            ));
        };
        if approval.status() == ApprovalStatus::Consumed {
            return Err(self.deny(
                at,
                Some(actor.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalAlreadyUsed,
                "approval has already been consumed",
            ));
        }
        if at >= approval.expires_at {
            return Err(self.deny(
                at,
                Some(actor.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalExpired,
                "approval has expired",
            ));
        }
        if approval.status() != ApprovalStatus::Ready {
            return Err(self.deny(
                at,
                Some(actor.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalNotReady,
                "approval does not have enough signatures",
            ));
        }
        if approval.action != *action
            || approval.check != *check
            || approval.amount != amount
            || approval.reason != reason
        {
            return Err(self.deny(
                at,
                Some(actor.clone()),
                Some(approval.terminal.clone()),
                Some(approval.check.clone()),
                SecurityAction::Approval,
                Some(id.clone()),
                DenialCode::ApprovalBindingMismatch,
                "approval does not match this operation",
            ));
        }
        if let Some(approval) = self.approvals.get_mut(id) {
            approval.consumed = true;
        }
        Ok(())
    }

    fn valid_amount(&self, amount: Money) -> bool {
        amount.currency() == self.currency && amount.is_positive()
    }

    #[allow(clippy::too_many_arguments)]
    fn deny(
        &mut self,
        at: Timestamp,
        actor: Option<EmployeeId>,
        terminal: Option<TerminalId>,
        check: Option<CheckId>,
        action: SecurityAction,
        approval: Option<ApprovalId>,
        code: DenialCode,
        detail: impl Into<String>,
    ) -> GuardError {
        let sequence = self.next_security_sequence;
        self.next_security_sequence = self.next_security_sequence.saturating_add(1);
        let detail = detail.into();
        self.security.push(SecurityEvent {
            sequence,
            at,
            actor,
            terminal,
            check,
            action,
            approval,
            code,
            detail: detail.clone(),
        });
        GuardError::denial(code, detail)
    }
}

/// F-03 approval matrix: these roles carry the `Approve` permission.
pub fn role_may_approve(role: OperatorRole) -> bool {
    matches!(
        role,
        OperatorRole::Supervisor | OperatorRole::Qa | OperatorRole::Admin
    )
}

fn valid_reason(reason: &str) -> bool {
    !reason.trim().is_empty() && validate_identifier(reason, "reason").is_ok()
}

fn checked_total(current: Money, amount: Money) -> Option<Money> {
    current.checked_add(amount).ok()
}

fn discount_amount(
    discount: &DiscountKind,
    base: Money,
    rounding: RoundingMode,
    currency: Currency,
) -> Option<Money> {
    match discount {
        DiscountKind::Amount(amount) => {
            if amount.currency() != currency || amount.is_negative() {
                None
            } else {
                Some(*amount)
            }
        }
        DiscountKind::Percent(rate) => base.mul_rate(*rate, rounding).ok(),
    }
}
