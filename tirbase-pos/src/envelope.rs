// SPDX-License-Identifier: AGPL-3.0-only

//! POS-06 — payment envelope and anti-replay.
//!
//! A [`PaymentEnvelope`] is everything a terminal claims about one payment:
//! the check, its total and tip, the amount and currency, the terminal, the
//! operator, the terminal epoch, a caller-supplied nonce, a monotonic counter
//! and an optional approval. The envelope is not a standalone helper: every
//! capture, refund and void executed by [`PaymentDesk`] passes through the
//! same envelope check, and the nonce is only recorded after the intent store
//! accepts the transition.
//!
//! # What the envelope enforces
//!
//! - **Amounts.** `total`, `tip` and `amount` must share the policy currency.
//!   `total` must be positive, `tip` must be non-negative and no larger than
//!   `total`, `amount` must be positive and no larger than `total`, and both
//!   `amount` and `total` must be inside the configured policy limits.
//! - **Actors.** The terminal and operator must exist in the [`Organization`]
//!   and belong to the same store.
//! - **Epoch.** A terminal must have an active epoch, and the envelope must
//!   name exactly that epoch. An epoch can only move forward.
//! - **Replay.** A nonce is globally unique for the desk. Reusing it on another
//!   terminal, epoch, intent, amount or action is rejected as a conflict.
//!   Within one `(terminal, epoch)` a new nonce must carry a counter strictly
//!   greater than the last accepted counter. An identical repeat inside the
//!   bounded replay window returns [`PaymentOutcome::Replayed`] without
//!   executing anything; an older repeat is rejected as
//!   [`EnvelopeCode::ReplayWindowExpired`].
//! - **Intent.** The referenced intent must already exist and its POS-03
//!   binding must equal the envelope's check, amount, currency, terminal,
//!   operator and tender. The first envelope freezes the intent to one
//!   `(payment, epoch)` scope.
//! - **Approval.** A supplied POS-05 approval must be for the same check,
//!   amount, reason, terminal and requester, and the matching action
//!   (`Refund` or `VoidPayment(payment)`). No approval is accepted for a
//!   capture, and none is silently ignored.
//!
//! # Bounded state
//!
//! The desk keeps the last [`EnvelopePolicy::replay_window`] counter positions
//! per terminal epoch for idempotent replay. Nonces themselves are retained in
//! a bounded table; when the table is full a new payment is rejected rather
//! than evicting a nonce and silently allowing a future replay.
//!
//! All times are caller-supplied. The desk reads no clock, opens no socket and
//! stores no card data.

use std::collections::BTreeMap;
use std::fmt;

use crate::audit::Timestamp;
use crate::check::{CheckStatus, PaymentMethod, PaymentStatus};
use crate::error::PosError;
use crate::guard::{
    ApprovalAction, ApprovalGuard, GuardError, RefundRequest, VoidRequest, VoidTarget,
};
use crate::ids::{
    ApprovalId, CheckId, EmployeeId, PaymentId, PaymentIntentId, PaymentNonce, TerminalId,
};
use crate::intent::{
    CreateIntent, CreateOutcome, IntentStatus, PaymentIntent, PaymentIntentStore, ProcessorToken,
    TransitionOutcome,
};
use crate::money::{Currency, Money};
use crate::ownership::Organization;

/// Stable reason codes for envelope and replay denials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvelopeCode {
    /// Envelope configuration is invalid.
    InvalidConfiguration,
    /// `total`, `tip` or `amount` uses a different currency.
    CurrencyMismatch,
    /// `total` is zero or negative.
    InvalidTotal,
    /// `tip` is negative.
    InvalidTip,
    /// `tip` is greater than `total`.
    TipExceedsTotal,
    /// `amount` is zero or negative.
    InvalidAmount,
    /// `amount` is greater than `total`.
    AmountExceedsTotal,
    /// `amount` is above the policy's maximum payment amount.
    AmountOutOfRange,
    /// `total` is above the policy's maximum check total.
    TotalOutOfRange,
    /// The terminal is not registered in the organization.
    UnknownTerminal,
    /// The operator is not registered in the organization.
    UnknownOperator,
    /// The terminal and operator belong to different stores.
    ActorMismatch,
    /// The terminal has no active epoch.
    EpochNotRegistered,
    /// The envelope names an epoch other than the terminal's active epoch.
    EpochMismatch,
    /// The nonce was already used with a different binding.
    NonceReuse,
    /// A new nonce carried a counter that did not advance.
    CounterNotMonotonic,
    /// The nonce is a repeat older than the bounded replay window.
    ReplayWindowExpired,
    /// The bounded nonce table is full; the desk fails closed.
    ReplayCapacityExceeded,
    /// The envelope action does not match the operation.
    ActionMismatch,
    /// The referenced intent is missing or its binding differs.
    IntentMismatch,
    /// The referenced intent is already bound to another payment or epoch.
    IntentScopeMismatch,
    /// The intent lifecycle state does not permit the operation.
    IntentState,
    /// The supplied approval does not match this exact payment.
    ApprovalMismatch,
}

impl EnvelopeCode {
    /// Stable wire/log string.
    pub fn as_str(self) -> &'static str {
        match self {
            EnvelopeCode::InvalidConfiguration => "envelope.invalid_configuration",
            EnvelopeCode::CurrencyMismatch => "envelope.currency_mismatch",
            EnvelopeCode::InvalidTotal => "envelope.invalid_total",
            EnvelopeCode::InvalidTip => "envelope.invalid_tip",
            EnvelopeCode::TipExceedsTotal => "envelope.tip_exceeds_total",
            EnvelopeCode::InvalidAmount => "envelope.invalid_amount",
            EnvelopeCode::AmountExceedsTotal => "envelope.amount_exceeds_total",
            EnvelopeCode::AmountOutOfRange => "envelope.amount_out_of_range",
            EnvelopeCode::TotalOutOfRange => "envelope.total_out_of_range",
            EnvelopeCode::UnknownTerminal => "envelope.unknown_terminal",
            EnvelopeCode::UnknownOperator => "envelope.unknown_operator",
            EnvelopeCode::ActorMismatch => "envelope.actor_mismatch",
            EnvelopeCode::EpochNotRegistered => "envelope.epoch_not_registered",
            EnvelopeCode::EpochMismatch => "envelope.epoch_mismatch",
            EnvelopeCode::NonceReuse => "envelope.nonce_reuse",
            EnvelopeCode::CounterNotMonotonic => "envelope.counter_not_monotonic",
            EnvelopeCode::ReplayWindowExpired => "envelope.replay_window_expired",
            EnvelopeCode::ReplayCapacityExceeded => "envelope.replay_capacity_exceeded",
            EnvelopeCode::ActionMismatch => "envelope.action_mismatch",
            EnvelopeCode::IntentMismatch => "envelope.intent_mismatch",
            EnvelopeCode::IntentScopeMismatch => "envelope.intent_scope_mismatch",
            EnvelopeCode::IntentState => "envelope.intent_state",
            EnvelopeCode::ApprovalMismatch => "envelope.approval_mismatch",
        }
    }
}

impl fmt::Display for EnvelopeCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A denied envelope or replay check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeError {
    code: EnvelopeCode,
    detail: String,
}

impl EnvelopeError {
    fn new(code: EnvelopeCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Stable denial reason.
    pub fn code(&self) -> EnvelopeCode {
        self.code
    }

    /// Human-readable detail; do not key policy on this string.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for EnvelopeError {}

/// A monotonic terminal epoch, such as a shift or boot generation.
///
/// Epochs are caller-supplied. The desk only knows that they advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TerminalEpoch(u64);

impl TerminalEpoch {
    /// Construct an epoch from its caller-supplied value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The epoch value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for TerminalEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "epoch:{}", self.0)
    }
}

/// The operation an envelope authorizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvelopeAction {
    /// Capture an authorized payment intent.
    Capture,
    /// Refund a captured payment intent.
    Refund,
    /// Void a payment intent or its captured payment.
    Void,
}

/// One payment request as presented by a terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentEnvelope {
    payment_id: PaymentId,
    intent_id: PaymentIntentId,
    check_id: CheckId,
    terminal_id: TerminalId,
    epoch: TerminalEpoch,
    operator_id: EmployeeId,
    nonce: PaymentNonce,
    counter: u64,
    method: PaymentMethod,
    total: Money,
    tip: Money,
    amount: Money,
    action: EnvelopeAction,
    reason: String,
    approval: Option<ApprovalId>,
    check_status: CheckStatus,
}

impl PaymentEnvelope {
    /// Construct an envelope. Amounts, actors and replay state are validated by
    /// [`PaymentDesk`] when the operation executes; construction itself is
    /// deliberately infallible so a malformed wire request can be represented
    /// and rejected with a stable code.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        payment_id: PaymentId,
        intent_id: PaymentIntentId,
        check_id: CheckId,
        terminal_id: TerminalId,
        epoch: TerminalEpoch,
        operator_id: EmployeeId,
        nonce: PaymentNonce,
        counter: u64,
        total: Money,
        tip: Money,
        amount: Money,
        method: PaymentMethod,
    ) -> Self {
        Self {
            payment_id,
            intent_id,
            check_id,
            terminal_id,
            epoch,
            operator_id,
            nonce,
            counter,
            method,
            total,
            tip,
            amount,
            action: EnvelopeAction::Capture,
            reason: String::new(),
            approval: None,
            check_status: CheckStatus::Open,
        }
    }

    /// Set the operation and its required reason.
    pub fn with_action(mut self, action: EnvelopeAction, reason: impl Into<String>) -> Self {
        self.action = action;
        self.reason = reason.into();
        self
    }

    /// Replace the total, tip and amount. The envelope check validates them.
    pub fn with_amounts(mut self, total: Money, tip: Money, amount: Money) -> Self {
        self.total = total;
        self.tip = tip;
        self.amount = amount;
        self
    }

    /// Attach a POS-05 approval.
    pub fn with_approval(mut self, approval: ApprovalId) -> Self {
        self.approval = Some(approval);
        self
    }

    /// Attach the current check status (used by the POS-05 void guard).
    pub fn with_check_status(mut self, status: CheckStatus) -> Self {
        self.check_status = status;
        self
    }

    /// The payment link identifier.
    pub fn payment_id(&self) -> &PaymentId {
        &self.payment_id
    }

    /// The referenced POS-03 intent.
    pub fn intent_id(&self) -> &PaymentIntentId {
        &self.intent_id
    }

    /// The check being paid, refunded or voided.
    pub fn check_id(&self) -> &CheckId {
        &self.check_id
    }

    /// The terminal that presented the envelope.
    pub fn terminal_id(&self) -> &TerminalId {
        &self.terminal_id
    }

    /// The terminal epoch.
    pub fn epoch(&self) -> TerminalEpoch {
        self.epoch
    }

    /// The operator presenting the envelope.
    pub fn operator_id(&self) -> &EmployeeId {
        &self.operator_id
    }

    /// The anti-replay nonce.
    pub fn nonce(&self) -> &PaymentNonce {
        &self.nonce
    }

    /// The monotonic counter for this terminal epoch.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The tender method.
    pub fn method(&self) -> PaymentMethod {
        self.method
    }

    /// The check total including tip.
    pub fn total(&self) -> Money {
        self.total
    }

    /// The tip portion of the total.
    pub fn tip(&self) -> Money {
        self.tip
    }

    /// The amount being paid, refunded or voided.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The operation this envelope authorizes.
    pub fn action(&self) -> EnvelopeAction {
        self.action
    }

    /// The reason supplied for a refund or void.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The optional POS-05 approval.
    pub fn approval(&self) -> Option<&ApprovalId> {
        self.approval.as_ref()
    }

    /// The check status supplied by the caller.
    pub fn check_status(&self) -> CheckStatus {
        self.check_status
    }

    fn fingerprint(&self) -> EnvelopeFingerprint {
        EnvelopeFingerprint {
            payment_id: self.payment_id.clone(),
            intent_id: self.intent_id.clone(),
            check_id: self.check_id.clone(),
            terminal_id: self.terminal_id.clone(),
            epoch: self.epoch,
            operator_id: self.operator_id.clone(),
            nonce: self.nonce.clone(),
            counter: self.counter,
            method: self.method,
            total: self.total,
            tip: self.tip,
            amount: self.amount,
            action: self.action,
            reason: self.reason.clone(),
            approval: self.approval.clone(),
            check_status: self.check_status,
        }
    }
}

/// Immutable limits for every envelope handled by a desk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopePolicy {
    currency: Currency,
    max_amount: Money,
    max_total: Money,
    replay_window: u64,
    max_nonce_entries: usize,
}

impl EnvelopePolicy {
    /// Configure the policy. `max_amount` and `max_total` must be positive and
    /// share `currency`; `replay_window` and `max_nonce_entries` must be at
    /// least one.
    pub fn new(
        currency: Currency,
        max_amount: Money,
        max_total: Money,
        replay_window: u64,
        max_nonce_entries: usize,
    ) -> Result<Self, EnvelopeError> {
        if max_amount.currency() != currency || max_total.currency() != currency {
            return Err(EnvelopeError::new(
                EnvelopeCode::InvalidConfiguration,
                "envelope limits must use the policy currency",
            ));
        }
        if !max_amount.is_positive() || !max_total.is_positive() {
            return Err(EnvelopeError::new(
                EnvelopeCode::InvalidConfiguration,
                "envelope limits must be positive",
            ));
        }
        if max_total < max_amount {
            return Err(EnvelopeError::new(
                EnvelopeCode::InvalidConfiguration,
                "maximum total must be at least the maximum amount",
            ));
        }
        if replay_window == 0 || max_nonce_entries == 0 {
            return Err(EnvelopeError::new(
                EnvelopeCode::InvalidConfiguration,
                "replay window and nonce capacity must be at least one",
            ));
        }
        Ok(Self {
            currency,
            max_amount,
            max_total,
            replay_window,
            max_nonce_entries,
        })
    }

    /// The policy currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// The largest permitted payment amount.
    pub fn max_amount(&self) -> Money {
        self.max_amount
    }

    /// The largest permitted check total.
    pub fn max_total(&self) -> Money {
        self.max_total
    }

    /// How many recent counters per terminal epoch are replayable.
    pub fn replay_window(&self) -> u64 {
        self.replay_window
    }

    /// The maximum number of retained nonces.
    pub fn max_nonce_entries(&self) -> usize {
        self.max_nonce_entries
    }
}

/// Result of an envelope-driven operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentOutcome {
    /// The operation executed on the intent store.
    Executed(PaymentIntent),
    /// The identical nonce was seen before; the intent was not touched.
    Replayed(PaymentIntent),
}

impl PaymentOutcome {
    /// The intent snapshot after the operation or replay.
    pub fn intent(&self) -> &PaymentIntent {
        match self {
            PaymentOutcome::Executed(intent) | PaymentOutcome::Replayed(intent) => intent,
        }
    }

    /// `true` when the operation was a replay.
    pub fn is_replayed(&self) -> bool {
        matches!(self, PaymentOutcome::Replayed(_))
    }
}

/// An envelope, guard, or intent-store failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentError {
    /// The envelope or replay check denied the operation.
    Envelope(EnvelopeError),
    /// The POS-05 approval/cap guard denied the operation.
    Guard(GuardError),
    /// The POS-03 intent store rejected the transition.
    Pos(PosError),
}

impl PaymentError {
    /// The envelope denial code, when the failure came from the envelope check.
    pub fn envelope_code(&self) -> Option<EnvelopeCode> {
        match self {
            PaymentError::Envelope(error) => Some(error.code()),
            PaymentError::Guard(_) | PaymentError::Pos(_) => None,
        }
    }
}

impl From<EnvelopeError> for PaymentError {
    fn from(error: EnvelopeError) -> Self {
        PaymentError::Envelope(error)
    }
}

impl From<GuardError> for PaymentError {
    fn from(error: GuardError) -> Self {
        PaymentError::Guard(error)
    }
}

impl From<PosError> for PaymentError {
    fn from(error: PosError) -> Self {
        PaymentError::Pos(error)
    }
}

impl fmt::Display for PaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaymentError::Envelope(error) => error.fmt(f),
            PaymentError::Guard(error) => error.fmt(f),
            PaymentError::Pos(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PaymentError {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EnvelopeFingerprint {
    payment_id: PaymentId,
    intent_id: PaymentIntentId,
    check_id: CheckId,
    terminal_id: TerminalId,
    epoch: TerminalEpoch,
    operator_id: EmployeeId,
    nonce: PaymentNonce,
    counter: u64,
    method: PaymentMethod,
    total: Money,
    tip: Money,
    amount: Money,
    action: EnvelopeAction,
    reason: String,
    approval: Option<ApprovalId>,
    check_status: CheckStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NonceUse {
    fingerprint: EnvelopeFingerprint,
    intent: PaymentIntent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IntentScope {
    payment_id: PaymentId,
    epoch: TerminalEpoch,
}

/// What a successful envelope check produced.
enum Checked {
    /// The intent store must execute the transition.
    Fresh(PaymentIntent),
    /// The nonce was already executed; return the recorded intent.
    Replay(PaymentIntent),
}

/// The production caller of the POS-06 envelope check.
///
/// The desk owns the POS-03 intent store, the POS-05 approval guard and the
/// anti-replay state. There is no public method that bypasses
/// [`PaymentDesk::check`]: capture, refund and void all run the envelope check
/// before they touch the intent store, and a nonce is recorded only after the
/// transition succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentDesk {
    organization: Organization,
    policy: EnvelopePolicy,
    approvals: ApprovalGuard,
    intents: PaymentIntentStore,
    epochs: BTreeMap<TerminalId, TerminalEpoch>,
    last_counters: BTreeMap<(TerminalId, TerminalEpoch), u64>,
    nonces: BTreeMap<PaymentNonce, NonceUse>,
    intent_scopes: BTreeMap<PaymentIntentId, IntentScope>,
}

impl PaymentDesk {
    /// Build a desk. The approval guard must use the policy currency.
    pub fn new(
        organization: Organization,
        policy: EnvelopePolicy,
        approvals: ApprovalGuard,
    ) -> Result<Self, PaymentError> {
        if approvals.currency() != policy.currency() {
            return Err(PaymentError::Envelope(EnvelopeError::new(
                EnvelopeCode::InvalidConfiguration,
                "approval guard currency does not match the envelope policy",
            )));
        }
        Ok(Self {
            organization,
            policy,
            approvals,
            intents: PaymentIntentStore::new(),
            epochs: BTreeMap::new(),
            last_counters: BTreeMap::new(),
            nonces: BTreeMap::new(),
            intent_scopes: BTreeMap::new(),
        })
    }

    /// The ownership registry used for terminal/operator checks.
    pub fn organization(&self) -> &Organization {
        &self.organization
    }

    /// The envelope policy.
    pub fn policy(&self) -> &EnvelopePolicy {
        &self.policy
    }

    /// The POS-05 approval guard.
    pub fn approvals(&self) -> &ApprovalGuard {
        &self.approvals
    }

    /// The POS-05 approval guard, for requesting approvals and registering
    /// approvers before an operation is submitted.
    pub fn approvals_mut(&mut self) -> &mut ApprovalGuard {
        &mut self.approvals
    }

    /// The POS-03 intent store.
    pub fn intents(&self) -> &PaymentIntentStore {
        &self.intents
    }

    /// One intent by identifier.
    pub fn intent(&self, id: &PaymentIntentId) -> Option<&PaymentIntent> {
        self.intents.intent(id)
    }

    /// Activate or advance a terminal's epoch.
    ///
    /// Re-declaring the current epoch is a no-op. Moving backwards or sideways
    /// to an already-passed epoch is rejected so an old envelope cannot be
    /// resubmitted under a recycled epoch.
    pub fn begin_epoch(
        &mut self,
        terminal: &TerminalId,
        epoch: TerminalEpoch,
    ) -> Result<(), EnvelopeError> {
        if self.organization.terminal(terminal).is_none() {
            return Err(EnvelopeError::new(
                EnvelopeCode::UnknownTerminal,
                "terminal is not registered",
            ));
        }
        match self.epochs.get(terminal).copied() {
            Some(current) if epoch < current => Err(EnvelopeError::new(
                EnvelopeCode::EpochMismatch,
                format!("terminal epoch cannot move back from {current} to {epoch}"),
            )),
            Some(current) if epoch == current => Ok(()),
            _ => {
                self.epochs.insert(terminal.clone(), epoch);
                Ok(())
            }
        }
    }

    /// The active epoch for a terminal, if one has been started.
    pub fn epoch_of(&self, terminal: &TerminalId) -> Option<TerminalEpoch> {
        self.epochs.get(terminal).copied()
    }

    /// The last accepted counter for a terminal epoch.
    pub fn last_counter(&self, terminal: &TerminalId, epoch: TerminalEpoch) -> Option<u64> {
        self.last_counters.get(&(terminal.clone(), epoch)).copied()
    }

    /// Number of retained nonces.
    pub fn nonce_count(&self) -> usize {
        self.nonces.len()
    }

    /// Create a POS-03 intent through the desk.
    pub fn create_intent(&mut self, request: CreateIntent) -> Result<CreateOutcome, PaymentError> {
        Ok(self.intents.create(request)?)
    }

    /// Authorize a POS-03 intent through the desk.
    pub fn authorize_intent(
        &mut self,
        id: &PaymentIntentId,
        token: ProcessorToken,
        at: Timestamp,
    ) -> Result<TransitionOutcome, PaymentError> {
        Ok(self.intents.authorize(id, token, at)?)
    }

    /// Capture an authorized intent, guarded by the payment envelope.
    pub fn capture(
        &mut self,
        envelope: &PaymentEnvelope,
        token: ProcessorToken,
        at: Timestamp,
    ) -> Result<PaymentOutcome, PaymentError> {
        let checked = self.check(envelope, EnvelopeAction::Capture)?;
        let intent = match checked {
            Checked::Replay(intent) => return Ok(PaymentOutcome::Replayed(intent)),
            Checked::Fresh(intent) => intent,
        };
        let outcome = self
            .intents
            .capture(intent.id(), envelope.amount, token, at)?;
        let intent = outcome.intent().clone();
        self.record(envelope, intent.clone());
        Ok(PaymentOutcome::Executed(intent))
    }

    /// Refund a captured intent, guarded by the payment envelope and the POS-05
    /// refund guard.
    pub fn refund(
        &mut self,
        envelope: &PaymentEnvelope,
        at: Timestamp,
    ) -> Result<PaymentOutcome, PaymentError> {
        let checked = self.check(envelope, EnvelopeAction::Refund)?;
        let intent = match checked {
            Checked::Replay(intent) => return Ok(PaymentOutcome::Replayed(intent)),
            Checked::Fresh(intent) => intent,
        };
        let mut request = RefundRequest::new(
            envelope.operator_id.clone(),
            envelope.terminal_id.clone(),
            envelope.check_id.clone(),
            envelope.amount,
            envelope.reason.clone(),
            at,
        );
        if let Some(approval) = &envelope.approval {
            request = request.with_approval(approval.clone());
        }
        self.approvals.authorize_refund(&request)?;
        let outcome = self.intents.refund(intent.id(), envelope.amount, at)?;
        let intent = outcome.intent().clone();
        self.record(envelope, intent.clone());
        Ok(PaymentOutcome::Executed(intent))
    }

    /// Void a payment, guarded by the payment envelope and the POS-05 void
    /// guard.
    pub fn void(
        &mut self,
        envelope: &PaymentEnvelope,
        at: Timestamp,
    ) -> Result<PaymentOutcome, PaymentError> {
        let checked = self.check(envelope, EnvelopeAction::Void)?;
        let intent = match checked {
            Checked::Replay(intent) => return Ok(PaymentOutcome::Replayed(intent)),
            Checked::Fresh(intent) => intent,
        };
        let payment_status = match intent.status() {
            IntentStatus::Created | IntentStatus::Authorized => PaymentStatus::Authorized,
            IntentStatus::Captured => PaymentStatus::Captured,
            IntentStatus::Refunded | IntentStatus::Voided => PaymentStatus::Voided,
        };
        let mut request = VoidRequest::new(
            envelope.operator_id.clone(),
            envelope.terminal_id.clone(),
            envelope.check_id.clone(),
            VoidTarget::Payment(envelope.payment_id.clone()),
            envelope.amount,
            envelope.reason.clone(),
            at,
            envelope.check_status,
            Some(payment_status),
        );
        if let Some(approval) = &envelope.approval {
            request = request.with_approval(approval.clone());
        }
        self.approvals.authorize_void(&request)?;
        let outcome = self
            .intents
            .void(intent.id(), envelope.reason.clone(), at)?;
        let intent = outcome.intent().clone();
        self.record(envelope, intent.clone());
        Ok(PaymentOutcome::Executed(intent))
    }

    /// The single envelope check used by every operation.
    fn check(
        &self,
        envelope: &PaymentEnvelope,
        expected: EnvelopeAction,
    ) -> Result<Checked, EnvelopeError> {
        if envelope.action != expected {
            return Err(EnvelopeError::new(
                EnvelopeCode::ActionMismatch,
                format!(
                    "envelope is for {:?}, operation is {:?}",
                    envelope.action, expected
                ),
            ));
        }
        self.check_amounts(envelope)?;
        self.check_actors(envelope)?;
        self.check_epoch(envelope)?;
        self.check_nonce(envelope)?;
        self.check_intent(envelope)?;
        self.check_approval(envelope)?;

        // A replay is accepted before the intent-state check: the first
        // execution has already moved the intent to its terminal state.
        if let Some(use_) = self.nonces.get(envelope.nonce()) {
            return Ok(Checked::Replay(use_.intent.clone()));
        }
        self.check_intent_state(envelope)?;
        self.intents
            .intent(envelope.intent_id())
            .cloned()
            .map(Checked::Fresh)
            .ok_or_else(|| {
                EnvelopeError::new(
                    EnvelopeCode::IntentMismatch,
                    "payment intent does not exist",
                )
            })
    }

    fn check_amounts(&self, envelope: &PaymentEnvelope) -> Result<(), EnvelopeError> {
        let policy = &self.policy;
        if envelope.total.currency() != policy.currency
            || envelope.tip.currency() != policy.currency
            || envelope.amount.currency() != policy.currency
        {
            return Err(EnvelopeError::new(
                EnvelopeCode::CurrencyMismatch,
                "total, tip and amount must use the policy currency",
            ));
        }
        if !envelope.total.is_positive() {
            return Err(EnvelopeError::new(
                EnvelopeCode::InvalidTotal,
                "check total must be positive",
            ));
        }
        if envelope.tip.is_negative() {
            return Err(EnvelopeError::new(
                EnvelopeCode::InvalidTip,
                "tip must not be negative",
            ));
        }
        if envelope.tip > envelope.total {
            return Err(EnvelopeError::new(
                EnvelopeCode::TipExceedsTotal,
                "tip cannot exceed the check total",
            ));
        }
        if !envelope.amount.is_positive() {
            return Err(EnvelopeError::new(
                EnvelopeCode::InvalidAmount,
                "payment amount must be positive",
            ));
        }
        if envelope.amount > envelope.total {
            return Err(EnvelopeError::new(
                EnvelopeCode::AmountExceedsTotal,
                "payment amount cannot exceed the check total",
            ));
        }
        if envelope.amount > policy.max_amount {
            return Err(EnvelopeError::new(
                EnvelopeCode::AmountOutOfRange,
                format!(
                    "payment amount {} exceeds the maximum {}",
                    envelope.amount, policy.max_amount
                ),
            ));
        }
        if envelope.total > policy.max_total {
            return Err(EnvelopeError::new(
                EnvelopeCode::TotalOutOfRange,
                format!(
                    "check total {} exceeds the maximum {}",
                    envelope.total, policy.max_total
                ),
            ));
        }
        Ok(())
    }

    fn check_actors(&self, envelope: &PaymentEnvelope) -> Result<(), EnvelopeError> {
        let terminal = self
            .organization
            .terminal(&envelope.terminal_id)
            .ok_or_else(|| {
                EnvelopeError::new(EnvelopeCode::UnknownTerminal, "terminal is not registered")
            })?;
        let operator = self
            .organization
            .employee(&envelope.operator_id)
            .ok_or_else(|| {
                EnvelopeError::new(EnvelopeCode::UnknownOperator, "operator is not registered")
            })?;
        if terminal.store_id() != operator.store_id() {
            return Err(EnvelopeError::new(
                EnvelopeCode::ActorMismatch,
                "terminal and operator belong to different stores",
            ));
        }
        Ok(())
    }

    fn check_epoch(&self, envelope: &PaymentEnvelope) -> Result<(), EnvelopeError> {
        let Some(current) = self.epochs.get(&envelope.terminal_id).copied() else {
            return Err(EnvelopeError::new(
                EnvelopeCode::EpochNotRegistered,
                "terminal has no active epoch",
            ));
        };
        if envelope.epoch != current {
            return Err(EnvelopeError::new(
                EnvelopeCode::EpochMismatch,
                format!(
                    "envelope epoch {} is not the terminal's active {}",
                    envelope.epoch, current
                ),
            ));
        }
        Ok(())
    }

    fn check_nonce(&self, envelope: &PaymentEnvelope) -> Result<(), EnvelopeError> {
        if let Some(use_) = self.nonces.get(envelope.nonce()) {
            if use_.fingerprint != envelope.fingerprint() {
                return Err(EnvelopeError::new(
                    EnvelopeCode::NonceReuse,
                    "nonce was already used for a different payment",
                ));
            }
            let last = self
                .last_counters
                .get(&(envelope.terminal_id.clone(), envelope.epoch))
                .copied()
                .unwrap_or(envelope.counter);
            if last.saturating_sub(envelope.counter) >= self.policy.replay_window {
                return Err(EnvelopeError::new(
                    EnvelopeCode::ReplayWindowExpired,
                    "nonce is older than the bounded replay window",
                ));
            }
            return Ok(());
        }

        if self.nonces.len() >= self.policy.max_nonce_entries {
            return Err(EnvelopeError::new(
                EnvelopeCode::ReplayCapacityExceeded,
                "nonce table is full; refusing a new payment rather than evicting a nonce",
            ));
        }

        if let Some(last) = self
            .last_counters
            .get(&(envelope.terminal_id.clone(), envelope.epoch))
        {
            if envelope.counter <= *last {
                return Err(EnvelopeError::new(
                    EnvelopeCode::CounterNotMonotonic,
                    format!(
                        "counter {} did not advance past the last accepted {}",
                        envelope.counter, last
                    ),
                ));
            }
        }
        Ok(())
    }

    fn check_intent(&self, envelope: &PaymentEnvelope) -> Result<(), EnvelopeError> {
        let intent = self.intents.intent(&envelope.intent_id).ok_or_else(|| {
            EnvelopeError::new(
                EnvelopeCode::IntentMismatch,
                "payment intent does not exist",
            )
        })?;
        if intent.check_id() != &envelope.check_id
            || intent.amount() != envelope.amount
            || intent.currency() != envelope.amount.currency()
            || intent.terminal_id() != &envelope.terminal_id
            || intent.operator_id() != &envelope.operator_id
            || intent.method() != envelope.method
        {
            return Err(EnvelopeError::new(
                EnvelopeCode::IntentMismatch,
                "intent binding does not match the envelope",
            ));
        }
        if let Some(scope) = self.intent_scopes.get(&envelope.intent_id) {
            if scope.payment_id != envelope.payment_id || scope.epoch != envelope.epoch {
                return Err(EnvelopeError::new(
                    EnvelopeCode::IntentScopeMismatch,
                    "intent is bound to a different payment or epoch",
                ));
            }
        }
        Ok(())
    }

    fn check_intent_state(&self, envelope: &PaymentEnvelope) -> Result<(), EnvelopeError> {
        let Some(intent) = self.intents.intent(&envelope.intent_id) else {
            return Ok(());
        };
        let allowed = match envelope.action {
            EnvelopeAction::Capture => intent.status() == IntentStatus::Authorized,
            EnvelopeAction::Refund => intent.status() == IntentStatus::Captured,
            EnvelopeAction::Void => matches!(
                intent.status(),
                IntentStatus::Created | IntentStatus::Authorized | IntentStatus::Captured
            ),
        };
        if allowed {
            Ok(())
        } else {
            Err(EnvelopeError::new(
                EnvelopeCode::IntentState,
                format!(
                    "intent is {} and cannot be used for {:?}",
                    intent.status(),
                    envelope.action
                ),
            ))
        }
    }

    fn check_approval(&self, envelope: &PaymentEnvelope) -> Result<(), EnvelopeError> {
        let Some(id) = envelope.approval() else {
            return Ok(());
        };
        if envelope.action == EnvelopeAction::Capture {
            return Err(EnvelopeError::new(
                EnvelopeCode::ApprovalMismatch,
                "a capture cannot consume an approval",
            ));
        }
        let Some(approval) = self.approvals.approval(id) else {
            return Err(EnvelopeError::new(
                EnvelopeCode::ApprovalMismatch,
                "approval does not exist",
            ));
        };
        let action_matches = match (envelope.action, approval.action()) {
            (EnvelopeAction::Refund, ApprovalAction::Refund) => true,
            (EnvelopeAction::Void, ApprovalAction::VoidPayment(payment_id)) => {
                payment_id == &envelope.payment_id
            }
            _ => false,
        };
        if !action_matches
            || approval.check_id() != &envelope.check_id
            || approval.amount() != envelope.amount
            || approval.reason() != envelope.reason
            || approval.terminal() != &envelope.terminal_id
            || approval.requester() != &envelope.operator_id
        {
            return Err(EnvelopeError::new(
                EnvelopeCode::ApprovalMismatch,
                "approval is not bound to this exact payment",
            ));
        }
        Ok(())
    }

    fn record(&mut self, envelope: &PaymentEnvelope, intent: PaymentIntent) {
        let scope = (envelope.terminal_id.clone(), envelope.epoch);
        let last = self.last_counters.entry(scope).or_insert(envelope.counter);
        if envelope.counter > *last {
            *last = envelope.counter;
        }
        self.nonces.insert(
            envelope.nonce.clone(),
            NonceUse {
                fingerprint: envelope.fingerprint(),
                intent,
            },
        );
        self.intent_scopes
            .entry(envelope.intent_id.clone())
            .or_insert_with(|| IntentScope {
                payment_id: envelope.payment_id.clone(),
                epoch: envelope.epoch,
            });
    }
}
