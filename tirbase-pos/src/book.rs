// SPDX-License-Identifier: AGPL-3.0-only

//! POS-02 — replicated split, transfer, void and merge rules.
//!
//! A [`PosBook`] is one offline replica of a set of orders. It stores a
//! deterministic operation log and rebuilds its state by applying every known
//! operation in one canonical order:
//!
//! ```text
//! (lamport, actor terminal id, operation id)
//! ```
//!
//! Two replicas that hold the same genesis and the same set of operations
//! therefore hold the same state and the same rejection set, independent of the
//! order in which operations arrived. [`PosBook::merge`] unions the logs and
//! rebuilds; replaying an operation with the same [`OperationId`] is recognised
//! as a replay and changes nothing.
//!
//! ## Conflict rules
//!
//! - Concurrent operations are ordered by `(lamport, actor, operation id)`.
//!   The first operation in that order wins when two operations are mutually
//!   exclusive (for example both move the same line item).
//! - An operation that loses a conflict is recorded in
//!   [`PosBook::rejected_operations`] with a deterministic error. It is never
//!   partially applied.
//! - Merges that would drop or guess at money are refused: different currency
//!   or rounding modes, duplicate line/payment identifiers, sealed checks,
//!   cross-store check transfers and lossy line splits.
//! - Voiding a line or payment is idempotent by operation id; voiding the same
//!   target again under a *different* operation id is rejected, never applied
//!   twice.
//!
//! ## Preservation
//!
//! - Splitting a check moves whole line items (so per-line discount, tax rate
//!   and tax amount are untouched) and splits tip and payments by exact
//!   amounts. Source and target totals sum to the original.
//! - Merging checks moves whole lines, whole payments and the full tip; the
//!   combined totals are the exact sum of the two checks.
//! - Splitting a line item recomputes each part; with
//!   `preserve_totals: true` the operation is rejected as [`PosError::LossySplit`]
//!   unless base, discount and tax of the two parts sum exactly to the original.

use std::collections::{BTreeMap, BTreeSet};

use crate::audit::Timestamp;
use crate::catalog::VersionPin;
use crate::check::{Check, VoidRecord};
use crate::error::PosError;
use crate::ids::{CheckId, LineItemId, OperationId, OrderId, PaymentId, TerminalId};
use crate::line_item::{Discount, DiscountKind, LineItem};
use crate::money::{Money, Quantity};
use crate::order::{ApplyOutcome, Order, OrderCommand};
use crate::ownership::{Organization, Ownership};

/// One exact slice of a source payment moved to a new check by a split.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentAllocation {
    /// Payment already linked to the source check.
    pub source_payment_id: PaymentId,
    /// Identifier for the new payment link on the target check.
    pub target_payment_id: PaymentId,
    /// Amount to move; must be positive and no larger than the source amount.
    pub amount: Money,
}

/// A POS-02 operation, wrapped in a replication envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookOp {
    /// Globally unique idempotency key.
    pub operation_id: OperationId,
    /// Order the operation primarily targets (the source order for a transfer).
    pub order_id: OrderId,
    /// Terminal that issued the operation.
    pub actor: TerminalId,
    /// Lamport clock value; ties are broken by `actor`, then `operation_id`.
    pub lamport: u64,
    /// Caller-supplied event time.
    pub at: Timestamp,
    /// The edit.
    pub kind: BookOpKind,
}

impl BookOp {
    /// Construct an operation envelope.
    pub fn new(
        operation_id: OperationId,
        order_id: OrderId,
        actor: TerminalId,
        lamport: u64,
        at: Timestamp,
        kind: BookOpKind,
    ) -> Self {
        Self {
            operation_id,
            order_id,
            actor,
            lamport,
            at,
            kind,
        }
    }
}

/// The edit carried by a [`BookOp`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BookOpKind {
    /// A POS-01 order command (create check, add line, tip, payment, state).
    Order(OrderCommand),
    /// Move whole lines, exact tip and exact payment slices to a new check.
    SplitCheck {
        /// Check being split.
        source_check_id: CheckId,
        /// New check to create.
        target_check_id: CheckId,
        /// Active lines to move.
        line_item_ids: Vec<LineItemId>,
        /// Exact part of the source tip to move.
        tip_to_target: Money,
        /// Exact payment slices to move.
        payment_allocations: Vec<PaymentAllocation>,
    },
    /// Split one line into two lines with the same attributes.
    SplitLineItem {
        /// Target check.
        check_id: CheckId,
        /// Line to split; keeps this identifier.
        line_item_id: LineItemId,
        /// Identifier for the second part.
        new_line_item_id: LineItemId,
        /// Quantity kept on the first part; the second gets the remainder.
        first_quantity: Quantity,
        /// Reject instead of recalculating when base, discount or tax would not
        /// sum exactly to the original line.
        preserve_totals: bool,
    },
    /// Move one active line to another check in the same order.
    TransferLineItem {
        /// Source check.
        from_check_id: CheckId,
        /// Destination check.
        to_check_id: CheckId,
        /// Line to move.
        line_item_id: LineItemId,
    },
    /// Move a whole check to another order in the same store.
    TransferCheck {
        /// Destination order.
        to_order_id: OrderId,
        /// Check to move (source is the envelope's `order_id`).
        check_id: CheckId,
    },
    /// Void one line item without removing it.
    VoidLineItem {
        /// Target check.
        check_id: CheckId,
        /// Line to void.
        line_item_id: LineItemId,
        /// Reason recorded on the void.
        reason: String,
    },
    /// Void one payment link without removing it.
    VoidPayment {
        /// Target check.
        check_id: CheckId,
        /// Payment to void.
        payment_id: PaymentId,
        /// Reason recorded on the void.
        reason: String,
    },
    /// Consolidate the source check into the target check.
    MergeChecks {
        /// Check being consumed.
        source_check_id: CheckId,
        /// Check that receives the content.
        target_check_id: CheckId,
    },
}

/// A description of what an accepted book operation changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BookAuditKind {
    /// A wrapped POS-01 order command changed one check.
    OrderCommand,
    /// A check was split into two checks.
    CheckSplit {
        /// Source check.
        source: CheckId,
        /// New check.
        target: CheckId,
        /// Number of whole lines moved.
        moved_lines: usize,
    },
    /// A line item was split into two.
    LineItemSplit {
        /// Check containing the lines.
        check_id: CheckId,
        /// Original/first line.
        line_item_id: LineItemId,
        /// New second line.
        new_line_item_id: LineItemId,
    },
    /// A line moved between checks.
    LineItemTransferred {
        /// Source check.
        from: CheckId,
        /// Destination check.
        to: CheckId,
        /// Moved line.
        line_item_id: LineItemId,
    },
    /// A check moved between orders.
    CheckTransferred {
        /// Source order.
        from: OrderId,
        /// Destination order.
        to: OrderId,
        /// Moved check.
        check_id: CheckId,
    },
    /// A line was voided.
    LineItemVoided {
        /// Check containing the line.
        check_id: CheckId,
        /// Voided line.
        line_item_id: LineItemId,
        /// Recorded reason.
        reason: String,
    },
    /// A payment was voided.
    PaymentVoided {
        /// Check containing the payment.
        check_id: CheckId,
        /// Voided payment.
        payment_id: PaymentId,
        /// Recorded reason.
        reason: String,
    },
    /// Two checks were merged.
    ChecksMerged {
        /// Consumed check.
        source: CheckId,
        /// Receiving check.
        target: CheckId,
    },
}

/// One accepted operation in the canonical audit order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookAuditEvent {
    /// Dense sequence starting at 1.
    pub sequence: u64,
    /// Operation id.
    pub operation_id: OperationId,
    /// Primary order.
    pub order_id: OrderId,
    /// Acting terminal.
    pub actor: TerminalId,
    /// Lamport value.
    pub lamport: u64,
    /// Caller-supplied event time.
    pub at: Timestamp,
    /// What changed.
    pub kind: BookAuditKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GenesisOrder {
    ownership: Ownership,
    opened_at: Timestamp,
    version_pin: Option<VersionPin>,
}

/// The immutable starting point shared by replicas: organization and orders.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BookGenesis {
    organization: Organization,
    orders: BTreeMap<OrderId, GenesisOrder>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BookState {
    orders: BTreeMap<OrderId, Order>,
    rejected: BTreeMap<OperationId, PosError>,
    audit: Vec<BookAuditEvent>,
}

/// One offline replica of a POS book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PosBook {
    genesis: BookGenesis,
    ops: BTreeMap<OperationId, BookOp>,
    orders: BTreeMap<OrderId, Order>,
    rejected: BTreeMap<OperationId, PosError>,
    audit: Vec<BookAuditEvent>,
}

impl PosBook {
    /// Create an empty replica with the ownership model all replicas share.
    pub fn new(organization: Organization) -> Self {
        Self {
            genesis: BookGenesis {
                organization,
                orders: BTreeMap::new(),
            },
            ops: BTreeMap::new(),
            orders: BTreeMap::new(),
            rejected: BTreeMap::new(),
            audit: Vec::new(),
        }
    }

    /// Register an order in the genesis. Must be called before any operation.
    pub fn add_order(
        &mut self,
        id: OrderId,
        ownership: Ownership,
        opened_at: Timestamp,
    ) -> Result<(), PosError> {
        self.add_order_inner(id, ownership, opened_at, None)
    }

    /// Register an order in the genesis with the POS-04 catalog, price-book and
    /// tax-table versions it will use. Must be called before any operation.
    pub fn add_order_pinned(
        &mut self,
        id: OrderId,
        ownership: Ownership,
        opened_at: Timestamp,
        version_pin: VersionPin,
    ) -> Result<(), PosError> {
        self.add_order_inner(id, ownership, opened_at, Some(version_pin))
    }

    fn add_order_inner(
        &mut self,
        id: OrderId,
        ownership: Ownership,
        opened_at: Timestamp,
        version_pin: Option<VersionPin>,
    ) -> Result<(), PosError> {
        if !self.ops.is_empty() {
            return Err(PosError::GenesisLocked);
        }
        if self.genesis.orders.contains_key(&id) {
            return Err(PosError::AlreadyRegistered("order"));
        }
        self.genesis.organization.validate_ownership(&ownership)?;
        let order = match &version_pin {
            Some(pin) => Order::open_pinned(
                id.clone(),
                ownership.clone(),
                &self.genesis.organization,
                opened_at,
                pin.clone(),
            )?,
            None => Order::open(
                id.clone(),
                ownership.clone(),
                &self.genesis.organization,
                opened_at,
            )?,
        };
        self.genesis.orders.insert(
            id.clone(),
            GenesisOrder {
                ownership,
                opened_at,
                version_pin,
            },
        );
        self.orders.insert(id, order);
        Ok(())
    }

    /// The shared ownership model.
    pub fn organization(&self) -> &Organization {
        &self.genesis.organization
    }

    /// Look up an order.
    pub fn order(&self, id: &OrderId) -> Option<&Order> {
        self.orders.get(id)
    }

    /// Orders in identifier order.
    pub fn orders(&self) -> impl Iterator<Item = (&OrderId, &Order)> {
        self.orders.iter()
    }

    /// Find a check anywhere in the book.
    pub fn check(&self, id: &CheckId) -> Option<&Check> {
        self.orders.values().find_map(|order| order.check(id))
    }

    /// Number of operations in the log.
    pub fn operation_count(&self) -> usize {
        self.ops.len()
    }

    /// Access the operation log.
    pub fn operations(&self) -> impl Iterator<Item = (&OperationId, &BookOp)> {
        self.ops.iter()
    }

    /// Operations rejected during the canonical rebuild, in identifier order.
    pub fn rejected_operations(&self) -> &BTreeMap<OperationId, PosError> {
        &self.rejected
    }

    /// The deterministic rejection for one operation, if it lost a conflict or
    /// was invalid in canonical order.
    pub fn rejection(&self, id: &OperationId) -> Option<&PosError> {
        self.rejected.get(id)
    }

    /// Accepted operations in canonical order.
    pub fn audit_events(&self) -> &[BookAuditEvent] {
        &self.audit
    }

    /// Apply one operation locally.
    ///
    /// The replica is always the canonical rebuild of the operations it knows.
    /// An operation that is invalid, or that loses a conflict against an
    /// already-known operation, is rejected without being stored.
    pub fn apply(&mut self, op: BookOp) -> Result<ApplyOutcome, PosError> {
        if let Some(existing) = self.ops.get(&op.operation_id) {
            if existing == &op {
                return Ok(ApplyOutcome::Replayed);
            }
            return Err(PosError::OperationConflict(op.operation_id));
        }

        let mut ops = self.ops.clone();
        ops.insert(op.operation_id.clone(), op.clone());
        let state = self.rebuild(&ops)?;
        if let Some(error) = state.rejected.get(&op.operation_id) {
            return Err(error.clone());
        }
        self.ops = ops;
        self.orders = state.orders;
        self.rejected = state.rejected;
        self.audit = state.audit;
        Ok(ApplyOutcome::Applied)
    }

    /// Apply a batch. Replaying an already-applied batch returns `Replayed` for
    /// every operation and changes nothing.
    pub fn replay(&mut self, ops: &[BookOp]) -> Result<Vec<ApplyOutcome>, PosError> {
        let mut outcomes = Vec::with_capacity(ops.len());
        for op in ops {
            outcomes.push(self.apply(op.clone())?);
        }
        Ok(outcomes)
    }

    /// Union another replica's operation log and rebuild.
    ///
    /// Commutative and associative over replicas with the same genesis. A
    /// reused operation id with different content is rejected outright.
    pub fn merge(&mut self, other: &PosBook) -> Result<(), PosError> {
        if self.genesis != other.genesis {
            return Err(PosError::IncompatibleReplica);
        }
        let mut ops = self.ops.clone();
        for (id, op) in &other.ops {
            if let Some(existing) = ops.get(id) {
                if existing != op {
                    return Err(PosError::OperationConflict(id.clone()));
                }
            } else {
                ops.insert(id.clone(), op.clone());
            }
        }
        let state = self.rebuild(&ops)?;
        self.ops = ops;
        self.orders = state.orders;
        self.rejected = state.rejected;
        self.audit = state.audit;
        Ok(())
    }

    fn rebuild(&self, ops: &BTreeMap<OperationId, BookOp>) -> Result<BookState, PosError> {
        let mut orders = BTreeMap::new();
        for (id, genesis) in &self.genesis.orders {
            let order = match &genesis.version_pin {
                Some(pin) => Order::open_pinned(
                    id.clone(),
                    genesis.ownership.clone(),
                    &self.genesis.organization,
                    genesis.opened_at,
                    pin.clone(),
                )?,
                None => Order::open(
                    id.clone(),
                    genesis.ownership.clone(),
                    &self.genesis.organization,
                    genesis.opened_at,
                )?,
            };
            orders.insert(id.clone(), order);
        }

        let mut ordered: Vec<&BookOp> = ops.values().collect();
        ordered.sort_by(|a, b| {
            a.lamport
                .cmp(&b.lamport)
                .then_with(|| a.actor.cmp(&b.actor))
                .then_with(|| a.operation_id.cmp(&b.operation_id))
        });

        let mut rejected = BTreeMap::new();
        let mut audit = Vec::new();
        let mut sequence = 1_u64;
        for op in ordered {
            // Apply to a clone so a rejected operation cannot leave a partial
            // move, split or merge behind.
            let mut candidate = orders.clone();
            match apply_op(&mut candidate, &self.genesis.organization, op) {
                Ok(kind) => {
                    orders = candidate;
                    audit.push(BookAuditEvent {
                        sequence,
                        operation_id: op.operation_id.clone(),
                        order_id: op.order_id.clone(),
                        actor: op.actor.clone(),
                        lamport: op.lamport,
                        at: op.at,
                        kind,
                    });
                    sequence += 1;
                }
                Err(error) => {
                    rejected.insert(op.operation_id.clone(), error);
                }
            }
        }

        Ok(BookState {
            orders,
            rejected,
            audit,
        })
    }
}

fn require_mutable(check: &Check) -> Result<(), PosError> {
    if check.status().is_mutable() {
        Ok(())
    } else {
        Err(PosError::CheckNotMutable {
            status: check.status(),
        })
    }
}

fn order_mut<'a>(
    orders: &'a mut BTreeMap<OrderId, Order>,
    id: &OrderId,
) -> Result<&'a mut Order, PosError> {
    orders
        .get_mut(id)
        .ok_or_else(|| PosError::UnknownOrder(id.clone()))
}

fn apply_op(
    orders: &mut BTreeMap<OrderId, Order>,
    organization: &Organization,
    op: &BookOp,
) -> Result<BookAuditKind, PosError> {
    // Every operation is attributed to a terminal in the order's store.
    {
        let order = orders
            .get(&op.order_id)
            .ok_or_else(|| PosError::UnknownOrder(op.order_id.clone()))?;
        let terminal = organization
            .terminal(&op.actor)
            .ok_or(PosError::UnknownTerminal)?;
        if terminal.store_id() != order.ownership().store_id() {
            return Err(PosError::ActorNotInStore);
        }
    }

    match &op.kind {
        BookOpKind::Order(command) => {
            if command.operation_id() != &op.operation_id || command.at() != op.at {
                return Err(PosError::EnvelopeMismatch);
            }
            order_mut(orders, &op.order_id)?.apply(command.clone())?;
            Ok(BookAuditKind::OrderCommand)
        }
        BookOpKind::SplitCheck {
            source_check_id,
            target_check_id,
            line_item_ids,
            tip_to_target,
            payment_allocations,
        } => split_check(
            orders,
            &op.order_id,
            op.at,
            source_check_id,
            target_check_id,
            line_item_ids,
            *tip_to_target,
            payment_allocations,
        ),
        BookOpKind::SplitLineItem {
            check_id,
            line_item_id,
            new_line_item_id,
            first_quantity,
            preserve_totals,
        } => split_line_item(
            orders,
            &op.order_id,
            check_id,
            line_item_id,
            new_line_item_id,
            *first_quantity,
            *preserve_totals,
        ),
        BookOpKind::TransferLineItem {
            from_check_id,
            to_check_id,
            line_item_id,
        } => transfer_line(
            orders,
            &op.order_id,
            from_check_id,
            to_check_id,
            line_item_id,
        ),
        BookOpKind::TransferCheck {
            to_order_id,
            check_id,
        } => transfer_check(orders, &op.order_id, to_order_id, check_id),
        BookOpKind::VoidLineItem {
            check_id,
            line_item_id,
            reason,
        } => void_line(orders, &op.order_id, check_id, line_item_id, reason, op.at),
        BookOpKind::VoidPayment {
            check_id,
            payment_id,
            reason,
        } => void_payment(orders, &op.order_id, check_id, payment_id, reason, op.at),
        BookOpKind::MergeChecks {
            source_check_id,
            target_check_id,
        } => merge_checks(orders, &op.order_id, source_check_id, target_check_id),
    }
}

#[allow(clippy::too_many_arguments)]
fn split_check(
    orders: &mut BTreeMap<OrderId, Order>,
    order_id: &OrderId,
    at: Timestamp,
    source_id: &CheckId,
    target_id: &CheckId,
    line_ids: &[LineItemId],
    tip_to_target: Money,
    allocations: &[PaymentAllocation],
) -> Result<BookAuditKind, PosError> {
    if source_id == target_id {
        return Err(PosError::SameCheck);
    }
    let order = order_mut(orders, order_id)?;
    if order.contains_check(target_id) {
        return Err(PosError::CheckAlreadyExists(target_id.clone()));
    }

    let mut seen_lines = BTreeSet::new();
    for id in line_ids {
        if !seen_lines.insert(id.clone()) {
            return Err(PosError::AmbiguousMerge("duplicate line in split"));
        }
    }
    let mut seen_sources = BTreeSet::new();
    let mut seen_targets = BTreeSet::new();
    for allocation in allocations {
        if !seen_sources.insert(allocation.source_payment_id.clone()) {
            return Err(PosError::AmbiguousMerge("duplicate payment allocation"));
        }
        if !seen_targets.insert(allocation.target_payment_id.clone()) {
            return Err(PosError::AmbiguousMerge("duplicate target payment id"));
        }
    }
    if line_ids.is_empty() && allocations.is_empty() && tip_to_target.is_zero() {
        return Err(PosError::AmbiguousMerge("split moves nothing"));
    }

    let (currency, rounding) = {
        let source = order
            .check(source_id)
            .ok_or_else(|| PosError::CheckNotFound(source_id.clone()))?;
        require_mutable(source)?;
        if tip_to_target.is_negative() {
            return Err(PosError::NegativeAmount);
        }
        if tip_to_target.currency() != source.currency() {
            return Err(PosError::CurrencyMismatch);
        }
        if tip_to_target.minor() > source.tip().minor() {
            return Err(PosError::TipAllocationExceeds {
                requested: tip_to_target,
                available: source.tip(),
            });
        }
        for id in line_ids {
            if source.line_item(id).is_none() {
                return Err(PosError::LineItemNotFound(id.clone()));
            }
            if source.line_is_voided(id) {
                return Err(PosError::LineItemVoided(id.clone()));
            }
        }
        for allocation in allocations {
            if source
                .payments()
                .any(|payment| payment.id() == &allocation.target_payment_id)
            {
                return Err(PosError::PaymentAlreadyLinked(
                    allocation.target_payment_id.clone(),
                ));
            }
            let payment = source
                .payments()
                .find(|payment| payment.id() == &allocation.source_payment_id)
                .ok_or_else(|| {
                    PosError::PaymentLinkNotFound(allocation.source_payment_id.clone())
                })?;
            if source.payment_is_voided(&allocation.source_payment_id) {
                return Err(PosError::PaymentVoided(
                    allocation.source_payment_id.clone(),
                ));
            }
            if allocation.amount.minor() > payment.amount().minor() {
                return Err(PosError::PaymentAllocationExceeds {
                    requested: allocation.amount,
                    available: payment.amount(),
                });
            }
        }
        (source.currency(), source.rounding())
    };

    let order = order_mut(orders, order_id)?;
    let source = order.check_mut(source_id)?;
    let mut moved_lines = Vec::with_capacity(line_ids.len());
    for id in line_ids {
        moved_lines.push(source.take_line(id)?);
    }
    let moved_tip = source.split_tip(tip_to_target)?;
    let mut target = Check::new(target_id.clone(), currency, rounding, at);
    target.set_tip(moved_tip)?;
    for line in moved_lines {
        target.add_line(line)?;
    }
    for allocation in allocations {
        let part = source.split_payment_off(
            &allocation.source_payment_id,
            allocation.target_payment_id.clone(),
            allocation.amount,
        )?;
        target.link_payment(part)?;
    }
    let moved_count = target.active_line_items().count();
    order.insert_check(target)?;

    Ok(BookAuditKind::CheckSplit {
        source: source_id.clone(),
        target: target_id.clone(),
        moved_lines: moved_count,
    })
}

fn split_line_item(
    orders: &mut BTreeMap<OrderId, Order>,
    order_id: &OrderId,
    check_id: &CheckId,
    line_id: &LineItemId,
    new_line_id: &LineItemId,
    first_quantity: Quantity,
    preserve_totals: bool,
) -> Result<BookAuditKind, PosError> {
    let order = order_mut(orders, order_id)?;
    let check = order.check_mut(check_id)?;
    require_mutable(check)?;
    if check.line_item(new_line_id).is_some() {
        return Err(PosError::LineItemAlreadyExists(new_line_id.clone()));
    }
    if check.line_is_voided(line_id) {
        return Err(PosError::LineItemVoided(line_id.clone()));
    }
    let line = check
        .line_item(line_id)
        .cloned()
        .ok_or_else(|| PosError::LineItemNotFound(line_id.clone()))?;

    let total_thousandths = line.quantity().thousandths();
    let remaining_thousandths = total_thousandths
        .checked_sub(first_quantity.thousandths())
        .ok_or(PosError::InvalidQuantity)?;
    if remaining_thousandths <= 0 {
        return Err(PosError::InvalidQuantity);
    }
    let second_quantity = Quantity::from_thousandths(remaining_thousandths)?;

    let (first_discount, second_discount) = split_discount(
        line.discount(),
        line.quantity(),
        first_quantity,
        second_quantity,
    )?;
    let first_line = rebuild_line(&line, line_id.clone(), first_quantity, first_discount)?;
    let second_line = rebuild_line(&line, new_line_id.clone(), second_quantity, second_discount)?;

    if preserve_totals {
        let rounding = check.rounding();
        let original = line.compute(rounding)?;
        let first = first_line.compute(rounding)?;
        let second = second_line.compute(rounding)?;
        let base = first.base.checked_add(second.base)?;
        let discount = first.discount.checked_add(second.discount)?;
        let tax = first.tax.checked_add(second.tax)?;
        if base != original.base || discount != original.discount || tax != original.tax {
            return Err(PosError::LossySplit);
        }
    }

    check.update_line(first_line)?;
    check.add_line(second_line)?;
    Ok(BookAuditKind::LineItemSplit {
        check_id: check_id.clone(),
        line_item_id: line_id.clone(),
        new_line_item_id: new_line_id.clone(),
    })
}

fn split_discount(
    discount: Option<&Discount>,
    total_quantity: Quantity,
    first_quantity: Quantity,
    second_quantity: Quantity,
) -> Result<(Option<Discount>, Option<Discount>), PosError> {
    let Some(discount) = discount else {
        return Ok((None, None));
    };
    match discount.kind() {
        DiscountKind::Percent(rate) => Ok((
            Some(Discount::percent(discount.label(), rate)?),
            Some(Discount::percent(discount.label(), rate)?),
        )),
        DiscountKind::Amount(amount) => {
            // Allocate by quantity, rounding down, and give the remainder to
            // the second part. The two discounts sum exactly to the original.
            let numerator = i128::from(amount.minor()) * i128::from(first_quantity.thousandths());
            let denominator = i128::from(total_quantity.thousandths());
            let first_minor = numerator / denominator;
            let first_minor =
                i64::try_from(first_minor).map_err(|_| PosError::ArithmeticOverflow)?;
            let first = Money::new(amount.currency(), first_minor);
            let second = amount.checked_sub(first)?;
            let total = first_quantity
                .thousandths()
                .checked_add(second_quantity.thousandths())
                .ok_or(PosError::ArithmeticOverflow)?;
            if total != total_quantity.thousandths() {
                return Err(PosError::InvalidQuantity);
            }
            Ok((
                Some(Discount::amount(discount.label(), first)?),
                Some(Discount::amount(discount.label(), second)?),
            ))
        }
    }
}

fn rebuild_line(
    original: &LineItem,
    id: LineItemId,
    quantity: Quantity,
    discount: Option<Discount>,
) -> Result<LineItem, PosError> {
    let mut line = LineItem::new(id, original.name(), quantity, original.unit_price())?;
    if let Some(sku) = original.sku() {
        line = line.with_sku(sku)?;
    }
    for modifier in original.modifiers() {
        line = line.with_modifier(modifier.clone())?;
    }
    if let Some(discount) = discount {
        line = line.with_discount(discount)?;
    }
    if let Some(rate) = original.tax_rate() {
        line = line.with_tax_rate(rate);
    }
    Ok(line)
}

fn transfer_line(
    orders: &mut BTreeMap<OrderId, Order>,
    order_id: &OrderId,
    from_id: &CheckId,
    to_id: &CheckId,
    line_id: &LineItemId,
) -> Result<BookAuditKind, PosError> {
    if from_id == to_id {
        return Err(PosError::SameCheck);
    }
    let order = order_mut(orders, order_id)?;
    {
        let from = order
            .check(from_id)
            .ok_or_else(|| PosError::CheckNotFound(from_id.clone()))?;
        let to = order
            .check(to_id)
            .ok_or_else(|| PosError::CheckNotFound(to_id.clone()))?;
        require_mutable(from)?;
        require_mutable(to)?;
        if from.currency() != to.currency() {
            return Err(PosError::IncompatibleChecks("currency differs"));
        }
        if from.rounding() != to.rounding() {
            return Err(PosError::IncompatibleChecks("rounding mode differs"));
        }
        if from.line_is_voided(line_id) {
            return Err(PosError::LineItemVoided(line_id.clone()));
        }
        if from.line_item(line_id).is_none() {
            return Err(PosError::LineItemNotFound(line_id.clone()));
        }
        if to.line_item(line_id).is_some() {
            return Err(PosError::LineItemAlreadyExists(line_id.clone()));
        }
    }
    let line = order.check_mut(from_id)?.take_line(line_id)?;
    order.check_mut(to_id)?.add_line(line)?;
    Ok(BookAuditKind::LineItemTransferred {
        from: from_id.clone(),
        to: to_id.clone(),
        line_item_id: line_id.clone(),
    })
}

fn transfer_check(
    orders: &mut BTreeMap<OrderId, Order>,
    from_order: &OrderId,
    to_order: &OrderId,
    check_id: &CheckId,
) -> Result<BookAuditKind, PosError> {
    if from_order == to_order {
        return Err(PosError::SameOrder);
    }
    {
        let source = orders
            .get(from_order)
            .ok_or_else(|| PosError::UnknownOrder(from_order.clone()))?;
        let target = orders
            .get(to_order)
            .ok_or_else(|| PosError::UnknownOrder(to_order.clone()))?;
        let check = source
            .check(check_id)
            .ok_or_else(|| PosError::CheckNotFound(check_id.clone()))?;
        require_mutable(check)?;
        if source.ownership().store_id() != target.ownership().store_id() {
            return Err(PosError::CrossStoreTransfer);
        }
        if target.contains_check(check_id) {
            return Err(PosError::CheckAlreadyExists(check_id.clone()));
        }
    }
    let check = order_mut(orders, from_order)?.take_check(check_id)?;
    order_mut(orders, to_order)?.insert_check(check)?;
    Ok(BookAuditKind::CheckTransferred {
        from: from_order.clone(),
        to: to_order.clone(),
        check_id: check_id.clone(),
    })
}

fn void_line(
    orders: &mut BTreeMap<OrderId, Order>,
    order_id: &OrderId,
    check_id: &CheckId,
    line_id: &LineItemId,
    reason: &str,
    at: Timestamp,
) -> Result<BookAuditKind, PosError> {
    let record = VoidRecord::new(reason, at)?;
    let check = order_mut(orders, order_id)?.check_mut(check_id)?;
    check.void_line(line_id, record)?;
    Ok(BookAuditKind::LineItemVoided {
        check_id: check_id.clone(),
        line_item_id: line_id.clone(),
        reason: reason.to_owned(),
    })
}

fn void_payment(
    orders: &mut BTreeMap<OrderId, Order>,
    order_id: &OrderId,
    check_id: &CheckId,
    payment_id: &PaymentId,
    reason: &str,
    at: Timestamp,
) -> Result<BookAuditKind, PosError> {
    let record = VoidRecord::new(reason, at)?;
    let check = order_mut(orders, order_id)?.check_mut(check_id)?;
    check.void_payment(payment_id, record)?;
    Ok(BookAuditKind::PaymentVoided {
        check_id: check_id.clone(),
        payment_id: payment_id.clone(),
        reason: reason.to_owned(),
    })
}

fn merge_checks(
    orders: &mut BTreeMap<OrderId, Order>,
    order_id: &OrderId,
    source_id: &CheckId,
    target_id: &CheckId,
) -> Result<BookAuditKind, PosError> {
    if source_id == target_id {
        return Err(PosError::SameCheck);
    }
    let order = order_mut(orders, order_id)?;

    let (lines, payments, tip) = {
        let source = order
            .check(source_id)
            .ok_or_else(|| PosError::CheckNotFound(source_id.clone()))?;
        let target = order
            .check(target_id)
            .ok_or_else(|| PosError::CheckNotFound(target_id.clone()))?;
        require_mutable(source)?;
        require_mutable(target)?;
        if source.currency() != target.currency() {
            return Err(PosError::IncompatibleChecks("currency differs"));
        }
        if source.rounding() != target.rounding() {
            return Err(PosError::IncompatibleChecks("rounding mode differs"));
        }

        let line_ids: Vec<LineItemId> = source
            .active_line_items()
            .map(|line| line.id().clone())
            .collect();
        for id in &line_ids {
            if target.line_item(id).is_some() {
                return Err(PosError::AmbiguousMerge("line id exists on both checks"));
            }
        }
        for payment in source.payments() {
            if source.payment_is_voided(payment.id()) {
                continue;
            }
            if target
                .payments()
                .any(|existing| existing.id() == payment.id())
            {
                return Err(PosError::AmbiguousMerge("payment id exists on both checks"));
            }
        }
        let tip = source.tip();
        target.tip().checked_add(tip)?;

        let source = order.check_mut(source_id)?;
        let mut lines = Vec::with_capacity(line_ids.len());
        for id in line_ids {
            lines.push(source.take_line(&id)?);
        }
        let payment_ids: Vec<PaymentId> = source.payments().map(|p| p.id().clone()).collect();
        let mut payments = Vec::with_capacity(payment_ids.len());
        for id in payment_ids {
            if source.payment_is_voided(&id) {
                continue;
            }
            payments.push(source.take_payment(&id)?);
        }
        let tip = source.split_tip(tip)?;
        (lines, payments, tip)
    };

    let target = order.check_mut(target_id)?;
    let combined_tip = target.tip().checked_add(tip)?;
    for line in lines {
        target.add_line(line)?;
    }
    for payment in payments {
        target.link_payment(payment)?;
    }
    target.set_tip(combined_tip)?;

    order.check_mut(source_id)?.mark_merged(target_id.clone())?;
    Ok(BookAuditKind::ChecksMerged {
        source: source_id.clone(),
        target: target_id.clone(),
    })
}
