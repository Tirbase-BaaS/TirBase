// SPDX-License-Identifier: AGPL-3.0-only

//! POS-03 — idempotent payment intents.
//!
//! A [`PaymentIntent`] is the POS-side record of one request to take money. It
//! deliberately does not talk to a processor: the caller supplies the opaque
//! processor token and reports the processor's state through
//! [`PaymentIntentStore::reconcile`]. That keeps the state machine testable and
//! makes the crash-recovery seam explicit.
//!
//! # State machine
//!
//! ```text
//!              authorize              capture             refund
//!   Created ───────────────► Authorized ──────► Captured ─────────► Refunded
//!      │                         │                 │
//!      └───────── void ──────────┴───── void ──────┴──── void ─────► Voided
//! ```
//!
//! `Refunded` and `Voided` are terminal. A capture cannot happen before an
//! authorization, and a refund cannot happen before a capture. Voiding is
//! allowed before capture and, for a same-day processor reversal, after capture;
//! it is not allowed after a refund.
//!
//! # Idempotency
//!
//! A [`CreateIntent`] carries a caller-supplied [`IdempotencyKey`] and an
//! [`IntentBinding`] containing the check, amount (and therefore currency),
//! terminal, operator and tender method. The first request creates one intent;
//! every identical duplicate returns the original result without adding an
//! intent or a processor charge. Reusing the key with any different binding is
//! rejected with [`PosError::IdempotencyKeyConflict`].
//!
//! Authorization, capture, refund and void are also idempotent: repeating an
//! already-applied request returns [`TransitionOutcome::Replayed`] and does not
//! append another journal event. A capture or refund with a different amount (or
//! currency) is rejected with [`PosError::IntentAmountMismatch`] or
//! [`PosError::CurrencyMismatch`].
//!
//! # Processor data
//!
//! Only [`ProcessorToken`] values are stored. A token is opaque, printable
//! ASCII without whitespace, and a value that looks like a 13–19 digit card
//! number is rejected. There is no PAN, CVV, track-data or expiry field, and the
//! token's `Debug` output is redacted.
//!
//! # Recovery and reconciliation
//!
//! Every applied transition appends an [`IntentEvent`]. [`PaymentIntentStore::recover`]
//! rebuilds a store from that journal, so a process that crashes after
//! authorization can restore the authorized intent. When the processor knows
//! more than the local store (for example the response was lost), feed a
//! [`ProcessorReport`] to [`PaymentIntentStore::reconcile`]; the store advances
//! only when the report proves a valid next state and otherwise leaves the
//! intent for manual reconciliation.

use std::collections::BTreeMap;
use std::fmt;

use crate::audit::Timestamp;
use crate::check::{PaymentMethod, VoidRecord};
use crate::error::PosError;
use crate::ids::{CheckId, EmployeeId, IdempotencyKey, PaymentIntentId, TerminalId};
use crate::money::{Currency, Money};

/// Maximum accepted processor-token length, in bytes.
pub const MAX_PROCESSOR_TOKEN_LEN: usize = 256;

/// Lifecycle of a payment intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntentStatus {
    /// Request recorded; not yet authorized by the processor.
    Created,
    /// Processor authorized the amount; not yet captured.
    Authorized,
    /// Funds captured for the intent amount.
    Captured,
    /// Captured funds fully refunded.
    Refunded,
    /// Request cancelled before or after capture (processor reversal).
    Voided,
}

impl IntentStatus {
    /// `true` when no further transition is permitted.
    pub fn is_terminal(self) -> bool {
        matches!(self, IntentStatus::Refunded | IntentStatus::Voided)
    }

    /// Whether one edge of the intent state machine connects `self` to `to`.
    pub fn can_transition_to(self, to: IntentStatus) -> bool {
        matches!(
            (self, to),
            (IntentStatus::Created, IntentStatus::Authorized)
                | (IntentStatus::Created, IntentStatus::Voided)
                | (IntentStatus::Authorized, IntentStatus::Captured)
                | (IntentStatus::Authorized, IntentStatus::Voided)
                | (IntentStatus::Captured, IntentStatus::Refunded)
                | (IntentStatus::Captured, IntentStatus::Voided)
        )
    }
}

impl fmt::Display for IntentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            IntentStatus::Created => "created",
            IntentStatus::Authorized => "authorized",
            IntentStatus::Captured => "captured",
            IntentStatus::Refunded => "refunded",
            IntentStatus::Voided => "voided",
        };
        f.write_str(label)
    }
}

/// An opaque processor token.
///
/// This type stores no card data. Construction rejects empty, oversized or
/// control-containing values and values that look like a 13–19 digit PAN. The
/// `Debug` implementation redacts the value so a log line cannot leak it.
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessorToken(String);

impl ProcessorToken {
    /// Validate and wrap an opaque processor token.
    pub fn new(value: impl Into<String>) -> Result<Self, PosError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_PROCESSOR_TOKEN_LEN || !value.is_ascii() {
            return Err(PosError::InvalidProcessorToken);
        }
        if looks_like_pan(&value) {
            return Err(PosError::PanLikeProcessorToken);
        }
        if value
            .chars()
            .any(|c| c.is_ascii_control() || c.is_ascii_whitespace())
        {
            return Err(PosError::InvalidProcessorToken);
        }
        Ok(Self(value))
    }

    /// Borrow the opaque token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProcessorToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessorToken(<redacted>)")
    }
}

fn looks_like_pan(value: &str) -> bool {
    let mut digits = 0_usize;
    for character in value.chars() {
        if character.is_ascii_digit() {
            digits += 1;
        } else if character != '-' && character != ' ' {
            return false;
        }
    }
    (13..=19).contains(&digits)
}

/// The request identity an idempotency key is bound to.
///
/// Two requests with the same key but a different check, amount, currency,
/// terminal, operator or tender method are not duplicates; they are a conflict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentBinding {
    check_id: CheckId,
    amount: Money,
    terminal_id: TerminalId,
    operator_id: EmployeeId,
    method: PaymentMethod,
}

impl IntentBinding {
    /// Bind an intent request to its check, money, terminal, operator and tender.
    pub fn new(
        check_id: CheckId,
        amount: Money,
        terminal_id: TerminalId,
        operator_id: EmployeeId,
        method: PaymentMethod,
    ) -> Result<Self, PosError> {
        if !amount.is_positive() {
            return Err(PosError::NonPositiveAmount);
        }
        Ok(Self {
            check_id,
            amount,
            terminal_id,
            operator_id,
            method,
        })
    }

    /// The check this request pays.
    pub fn check_id(&self) -> &CheckId {
        &self.check_id
    }

    /// The exact amount requested.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The amount currency.
    pub fn currency(&self) -> Currency {
        self.amount.currency()
    }

    /// The terminal that made the request.
    pub fn terminal_id(&self) -> &TerminalId {
        &self.terminal_id
    }

    /// The operator who made the request.
    pub fn operator_id(&self) -> &EmployeeId {
        &self.operator_id
    }

    /// The tender method.
    pub fn method(&self) -> PaymentMethod {
        self.method
    }
}

/// A request to create a payment intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateIntent {
    intent_id: PaymentIntentId,
    idempotency_key: IdempotencyKey,
    binding: IntentBinding,
    at: Timestamp,
}

impl CreateIntent {
    /// Construct a create request. The binding is already validated.
    pub fn new(
        intent_id: PaymentIntentId,
        idempotency_key: IdempotencyKey,
        binding: IntentBinding,
        at: Timestamp,
    ) -> Self {
        Self {
            intent_id,
            idempotency_key,
            binding,
            at,
        }
    }

    /// The intent identifier the first request proposes.
    pub fn intent_id(&self) -> &PaymentIntentId {
        &self.intent_id
    }

    /// The idempotency key.
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// The bound request identity.
    pub fn binding(&self) -> &IntentBinding {
        &self.binding
    }

    /// Caller-supplied request time.
    pub fn at(&self) -> Timestamp {
        self.at
    }
}

/// One recorded payment intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentIntent {
    id: PaymentIntentId,
    binding: IntentBinding,
    status: IntentStatus,
    processor_token: Option<ProcessorToken>,
    captured_amount: Option<Money>,
    refunded_amount: Option<Money>,
    void_reason: Option<String>,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl PaymentIntent {
    fn new(id: PaymentIntentId, binding: IntentBinding, at: Timestamp) -> Self {
        Self {
            id,
            binding,
            status: IntentStatus::Created,
            processor_token: None,
            captured_amount: None,
            refunded_amount: None,
            void_reason: None,
            created_at: at,
            updated_at: at,
        }
    }

    /// The intent identifier.
    pub fn id(&self) -> &PaymentIntentId {
        &self.id
    }

    /// The bound check, amount, terminal, operator and tender.
    pub fn binding(&self) -> &IntentBinding {
        &self.binding
    }

    /// The check this intent pays.
    pub fn check_id(&self) -> &CheckId {
        &self.binding.check_id
    }

    /// The requested amount.
    pub fn amount(&self) -> Money {
        self.binding.amount
    }

    /// The requested currency.
    pub fn currency(&self) -> Currency {
        self.binding.currency()
    }

    /// The terminal that created the intent.
    pub fn terminal_id(&self) -> &TerminalId {
        &self.binding.terminal_id
    }

    /// The operator who created the intent.
    pub fn operator_id(&self) -> &EmployeeId {
        &self.binding.operator_id
    }

    /// The tender method.
    pub fn method(&self) -> PaymentMethod {
        self.binding.method
    }

    /// The current lifecycle state.
    pub fn status(&self) -> IntentStatus {
        self.status
    }

    /// The opaque processor token, if authorization has happened.
    pub fn processor_token(&self) -> Option<&ProcessorToken> {
        self.processor_token.as_ref()
    }

    /// The captured amount, if capture has happened.
    pub fn captured_amount(&self) -> Option<Money> {
        self.captured_amount
    }

    /// The refunded amount, if refund has happened.
    pub fn refunded_amount(&self) -> Option<Money> {
        self.refunded_amount
    }

    /// The reason recorded by a void.
    pub fn void_reason(&self) -> Option<&str> {
        self.void_reason.as_deref()
    }

    /// Creation time supplied by the caller.
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Last transition time supplied by the caller.
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// `true` when no further transition is permitted.
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }
}

/// Result of a create request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateOutcome {
    /// The first request created the intent.
    Created(PaymentIntent),
    /// An identical request returned the original cached result.
    Duplicate(PaymentIntent),
}

impl CreateOutcome {
    /// The returned intent snapshot.
    pub fn intent(&self) -> &PaymentIntent {
        match self {
            CreateOutcome::Created(intent) | CreateOutcome::Duplicate(intent) => intent,
        }
    }

    /// `true` when the request was a duplicate.
    pub fn is_duplicate(&self) -> bool {
        matches!(self, CreateOutcome::Duplicate(_))
    }
}

/// Result of a state-changing request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionOutcome {
    /// The transition was applied.
    Applied(PaymentIntent),
    /// The same transition had already been applied; nothing changed.
    Replayed(PaymentIntent),
}

impl TransitionOutcome {
    /// The returned intent snapshot.
    pub fn intent(&self) -> &PaymentIntent {
        match self {
            TransitionOutcome::Applied(intent) | TransitionOutcome::Replayed(intent) => intent,
        }
    }

    /// `true` when the request was a replay.
    pub fn is_replayed(&self) -> bool {
        matches!(self, TransitionOutcome::Replayed(_))
    }
}

/// One durable intent-journal entry.
///
/// The store appends an entry only after a transition is applied, so replaying
/// the journal reconstructs the same state. A duplicate request appends nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntentEvent {
    /// The first create request for an idempotency key.
    Created { request: CreateIntent },
    /// The processor authorized the intent.
    Authorized {
        intent_id: PaymentIntentId,
        token: ProcessorToken,
        at: Timestamp,
    },
    /// The processor captured the intent.
    Captured {
        intent_id: PaymentIntentId,
        amount: Money,
        token: ProcessorToken,
        at: Timestamp,
    },
    /// The captured amount was refunded.
    Refunded {
        intent_id: PaymentIntentId,
        amount: Money,
        at: Timestamp,
    },
    /// The intent was voided.
    Voided {
        intent_id: PaymentIntentId,
        reason: String,
        at: Timestamp,
    },
}

/// What the processor says happened, for crash reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessorReport {
    /// The processor has no record of the intent.
    NotFound,
    /// The processor authorized the intent.
    Authorized { token: ProcessorToken },
    /// The processor captured the intent.
    Captured {
        token: ProcessorToken,
        amount: Money,
    },
    /// The processor refunded the captured amount.
    Refunded { amount: Money },
    /// The processor voided or reversed the intent.
    Voided,
}

/// Result of reconciling one local intent with a processor report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    /// Local state already agrees with the processor.
    Matched(PaymentIntent),
    /// A valid next transition recovered the local state.
    Recovered(PaymentIntent),
    /// The report cannot be applied automatically; the intent is unchanged and
    /// needs manual reconciliation.
    Unresolved(PaymentIntent),
}

impl ReconciliationOutcome {
    /// The intent snapshot after reconciliation.
    pub fn intent(&self) -> &PaymentIntent {
        match self {
            ReconciliationOutcome::Matched(intent)
            | ReconciliationOutcome::Recovered(intent)
            | ReconciliationOutcome::Unresolved(intent) => intent,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IdempotencyRecord {
    binding: IntentBinding,
    result: PaymentIntent,
}

/// An in-memory idempotent payment-intent ledger.
///
/// The store is deterministic: the caller supplies every timestamp and token,
/// and no operation reads the system clock.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PaymentIntentStore {
    intents: BTreeMap<PaymentIntentId, PaymentIntent>,
    keys: BTreeMap<IdempotencyKey, IdempotencyRecord>,
    journal: Vec<IntentEvent>,
}

impl PaymentIntentStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct intents.
    pub fn len(&self) -> usize {
        self.intents.len()
    }

    /// `true` when the store has no intents.
    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// Look up one intent.
    pub fn intent(&self, id: &PaymentIntentId) -> Option<&PaymentIntent> {
        self.intents.get(id)
    }

    /// Intents that have not yet reached a terminal state, in identifier order.
    pub fn intents(&self) -> impl Iterator<Item = &PaymentIntent> {
        self.intents.values()
    }

    /// Intents that may need startup reconciliation (`Created` or `Authorized`).
    pub fn pending_intents(&self) -> impl Iterator<Item = &PaymentIntent> {
        self.intents.values().filter(|intent| {
            matches!(
                intent.status,
                IntentStatus::Created | IntentStatus::Authorized
            )
        })
    }

    /// The append-only journal used for crash recovery.
    pub fn journal(&self) -> &[IntentEvent] {
        &self.journal
    }

    /// Create an intent or return the original result for an identical request.
    ///
    /// A reused key with any different binding is rejected before a new intent
    /// exists. A duplicate never allocates a second intent or charge.
    pub fn create(&mut self, request: CreateIntent) -> Result<CreateOutcome, PosError> {
        if let Some(record) = self.keys.get(request.idempotency_key()) {
            if record.binding != *request.binding() {
                return Err(PosError::IdempotencyKeyConflict(
                    request.idempotency_key.clone(),
                ));
            }
            return Ok(CreateOutcome::Duplicate(record.result.clone()));
        }

        if self.intents.contains_key(&request.intent_id) {
            return Err(PosError::IntentAlreadyExists(request.intent_id.clone()));
        }

        let intent = PaymentIntent::new(
            request.intent_id.clone(),
            request.binding.clone(),
            request.at,
        );
        self.intents.insert(intent.id.clone(), intent.clone());
        self.keys.insert(
            request.idempotency_key.clone(),
            IdempotencyRecord {
                binding: request.binding.clone(),
                result: intent.clone(),
            },
        );
        self.journal.push(IntentEvent::Created {
            request: request.clone(),
        });
        Ok(CreateOutcome::Created(intent))
    }

    /// Authorize an intent with an opaque processor token.
    ///
    /// Repeating the authorization with the same token is a replay. A different
    /// token for the same intent is rejected.
    pub fn authorize(
        &mut self,
        id: &PaymentIntentId,
        token: ProcessorToken,
        at: Timestamp,
    ) -> Result<TransitionOutcome, PosError> {
        let intent = self.lookup(id)?;
        match intent.status {
            IntentStatus::Created => {
                let mut next = intent;
                next.status = IntentStatus::Authorized;
                next.processor_token = Some(token.clone());
                next.updated_at = at;
                self.commit(next.clone());
                self.journal.push(IntentEvent::Authorized {
                    intent_id: id.clone(),
                    token,
                    at,
                });
                Ok(TransitionOutcome::Applied(next))
            }
            IntentStatus::Authorized
            | IntentStatus::Captured
            | IntentStatus::Refunded
            | IntentStatus::Voided => {
                if intent.processor_token.as_ref() != Some(&token) {
                    return Err(PosError::IntentTokenMismatch(id.clone()));
                }
                Ok(TransitionOutcome::Replayed(intent))
            }
        }
    }

    /// Capture the full authorized amount.
    ///
    /// The amount must match the intent exactly; a different amount or currency
    /// is rejected. Repeating the capture is a replay and records no second
    /// charge, even after a later refund or void.
    pub fn capture(
        &mut self,
        id: &PaymentIntentId,
        amount: Money,
        token: ProcessorToken,
        at: Timestamp,
    ) -> Result<TransitionOutcome, PosError> {
        let intent = self.lookup(id)?;
        validate_amount(&intent, amount)?;

        match intent.status {
            IntentStatus::Authorized => {
                if intent.processor_token.as_ref() != Some(&token) {
                    return Err(PosError::IntentTokenMismatch(id.clone()));
                }
                let mut next = intent;
                next.status = IntentStatus::Captured;
                next.captured_amount = Some(amount);
                next.updated_at = at;
                self.commit(next.clone());
                self.journal.push(IntentEvent::Captured {
                    intent_id: id.clone(),
                    amount,
                    token,
                    at,
                });
                Ok(TransitionOutcome::Applied(next))
            }
            IntentStatus::Captured | IntentStatus::Refunded | IntentStatus::Voided => {
                if intent.captured_amount != Some(amount) {
                    return Err(PosError::InvalidIntentTransition {
                        from: intent.status,
                        to: IntentStatus::Captured,
                    });
                }
                if intent.processor_token.as_ref() != Some(&token) {
                    return Err(PosError::IntentTokenMismatch(id.clone()));
                }
                Ok(TransitionOutcome::Replayed(intent))
            }
            IntentStatus::Created => Err(PosError::InvalidIntentTransition {
                from: IntentStatus::Created,
                to: IntentStatus::Captured,
            }),
        }
    }

    /// Refund the full captured amount.
    ///
    /// Partial refunds are not modelled. A refund requires a capture, and a
    /// repeated refund is a replay.
    pub fn refund(
        &mut self,
        id: &PaymentIntentId,
        amount: Money,
        at: Timestamp,
    ) -> Result<TransitionOutcome, PosError> {
        let intent = self.lookup(id)?;
        validate_amount(&intent, amount)?;

        match intent.status {
            IntentStatus::Captured => {
                let mut next = intent;
                next.status = IntentStatus::Refunded;
                next.refunded_amount = Some(amount);
                next.updated_at = at;
                self.commit(next.clone());
                self.journal.push(IntentEvent::Refunded {
                    intent_id: id.clone(),
                    amount,
                    at,
                });
                Ok(TransitionOutcome::Applied(next))
            }
            IntentStatus::Refunded => Ok(TransitionOutcome::Replayed(intent)),
            IntentStatus::Created | IntentStatus::Authorized | IntentStatus::Voided => {
                Err(PosError::InvalidIntentTransition {
                    from: intent.status,
                    to: IntentStatus::Refunded,
                })
            }
        }
    }

    /// Void an intent with a required reason.
    ///
    /// Voiding is allowed from `Created`, `Authorized` and `Captured`. A repeat
    /// is a replay. A refunded intent cannot be voided.
    pub fn void(
        &mut self,
        id: &PaymentIntentId,
        reason: impl Into<String>,
        at: Timestamp,
    ) -> Result<TransitionOutcome, PosError> {
        let record = VoidRecord::new(reason, at)?;
        let intent = self.lookup(id)?;
        match intent.status {
            IntentStatus::Voided => Ok(TransitionOutcome::Replayed(intent)),
            IntentStatus::Refunded => Err(PosError::InvalidIntentTransition {
                from: IntentStatus::Refunded,
                to: IntentStatus::Voided,
            }),
            IntentStatus::Created | IntentStatus::Authorized | IntentStatus::Captured => {
                let mut next = intent;
                next.status = IntentStatus::Voided;
                next.void_reason = Some(record.reason().to_owned());
                next.updated_at = at;
                self.commit(next.clone());
                self.journal.push(IntentEvent::Voided {
                    intent_id: id.clone(),
                    reason: record.reason().to_owned(),
                    at,
                });
                Ok(TransitionOutcome::Applied(next))
            }
        }
    }

    /// Rebuild a store from its journal.
    ///
    /// This is the crash-recovery hook: persist the journal after every applied
    /// transition, then call `recover` at startup. Events are replayed through
    /// the same state machine, so an invalid transition is rejected and a
    /// repeated transition is a replay rather than a second change.
    pub fn recover(journal: &[IntentEvent]) -> Result<Self, PosError> {
        let mut store = Self::new();
        for event in journal {
            match event {
                IntentEvent::Created { request } => {
                    store.create(request.clone())?;
                }
                IntentEvent::Authorized {
                    intent_id,
                    token,
                    at,
                } => {
                    store.authorize(intent_id, token.clone(), *at)?;
                }
                IntentEvent::Captured {
                    intent_id,
                    amount,
                    token,
                    at,
                } => {
                    store.capture(intent_id, *amount, token.clone(), *at)?;
                }
                IntentEvent::Refunded {
                    intent_id,
                    amount,
                    at,
                } => {
                    store.refund(intent_id, *amount, *at)?;
                }
                IntentEvent::Voided {
                    intent_id,
                    reason,
                    at,
                } => {
                    store.void(intent_id, reason.clone(), *at)?;
                }
            }
        }
        Ok(store)
    }

    /// Reconcile one local intent with the processor's reported state.
    ///
    /// A report that proves a valid next transition is applied atomically and
    /// appended to the journal. A report that merely agrees with local state is
    /// `Matched`. A report that cannot be applied automatically (for example a
    /// capture report for an intent voided before capture) leaves the intent
    /// unchanged and returns `Unresolved` for manual handling.
    pub fn reconcile(
        &mut self,
        id: &PaymentIntentId,
        report: ProcessorReport,
        at: Timestamp,
    ) -> Result<ReconciliationOutcome, PosError> {
        let current = self.lookup(id)?;
        match report {
            ProcessorReport::NotFound => Ok(ReconciliationOutcome::Unresolved(current)),
            ProcessorReport::Authorized { token } => match current.status {
                IntentStatus::Created => {
                    let mut candidate = self.clone();
                    candidate.authorize(id, token, at)?;
                    *self = candidate;
                    Ok(ReconciliationOutcome::Recovered(self.lookup(id)?))
                }
                IntentStatus::Authorized => {
                    if current.processor_token.as_ref() != Some(&token) {
                        return Err(PosError::IntentTokenMismatch(id.clone()));
                    }
                    Ok(ReconciliationOutcome::Matched(current))
                }
                IntentStatus::Captured | IntentStatus::Refunded | IntentStatus::Voided => {
                    if current.processor_token.as_ref() != Some(&token) {
                        return Err(PosError::IntentTokenMismatch(id.clone()));
                    }
                    Ok(ReconciliationOutcome::Matched(current))
                }
            },
            ProcessorReport::Captured { token, amount } => {
                validate_amount(&current, amount)?;
                match current.status {
                    IntentStatus::Created => {
                        let mut candidate = self.clone();
                        candidate.authorize(id, token.clone(), at)?;
                        candidate.capture(id, amount, token, at)?;
                        *self = candidate;
                        Ok(ReconciliationOutcome::Recovered(self.lookup(id)?))
                    }
                    IntentStatus::Authorized => {
                        let mut candidate = self.clone();
                        candidate.capture(id, amount, token, at)?;
                        *self = candidate;
                        Ok(ReconciliationOutcome::Recovered(self.lookup(id)?))
                    }
                    IntentStatus::Captured | IntentStatus::Refunded => {
                        if current.captured_amount != Some(amount) {
                            return Err(PosError::InvalidIntentTransition {
                                from: current.status,
                                to: IntentStatus::Captured,
                            });
                        }
                        if current.processor_token.as_ref() != Some(&token) {
                            return Err(PosError::IntentTokenMismatch(id.clone()));
                        }
                        Ok(ReconciliationOutcome::Matched(current))
                    }
                    IntentStatus::Voided => Ok(ReconciliationOutcome::Unresolved(current)),
                }
            }
            ProcessorReport::Refunded { amount } => {
                validate_amount(&current, amount)?;
                match current.status {
                    IntentStatus::Captured => {
                        let mut candidate = self.clone();
                        candidate.refund(id, amount, at)?;
                        *self = candidate;
                        Ok(ReconciliationOutcome::Recovered(self.lookup(id)?))
                    }
                    IntentStatus::Refunded => Ok(ReconciliationOutcome::Matched(current)),
                    IntentStatus::Created | IntentStatus::Authorized | IntentStatus::Voided => {
                        Ok(ReconciliationOutcome::Unresolved(current))
                    }
                }
            }
            ProcessorReport::Voided => match current.status {
                IntentStatus::Voided => Ok(ReconciliationOutcome::Matched(current)),
                IntentStatus::Created | IntentStatus::Authorized | IntentStatus::Captured => {
                    let mut candidate = self.clone();
                    candidate.void(id, "processor reconciliation", at)?;
                    *self = candidate;
                    Ok(ReconciliationOutcome::Recovered(self.lookup(id)?))
                }
                IntentStatus::Refunded => Ok(ReconciliationOutcome::Unresolved(current)),
            },
        }
    }

    fn lookup(&self, id: &PaymentIntentId) -> Result<PaymentIntent, PosError> {
        self.intents
            .get(id)
            .cloned()
            .ok_or_else(|| PosError::IntentNotFound(id.clone()))
    }

    fn commit(&mut self, intent: PaymentIntent) {
        self.intents.insert(intent.id.clone(), intent);
    }
}

fn validate_amount(intent: &PaymentIntent, actual: Money) -> Result<(), PosError> {
    if actual.currency() != intent.currency() {
        return Err(PosError::CurrencyMismatch);
    }
    if actual != intent.amount() {
        return Err(PosError::IntentAmountMismatch {
            expected: intent.amount(),
            actual,
        });
    }
    Ok(())
}
