// SPDX-License-Identifier: AGPL-3.0-only

//! The order aggregate: idempotent commands, replay and the audit trail.
//!
//! An [`Order`] groups one or more checks and owns the append-only
//! [`AuditEvent`] stream. Every content change is a [`OrderCommand`] carrying a
//! caller-supplied [`OperationId`]. Applying a command records the operation;
//! applying the same command again returns [`ApplyOutcome::Replayed`] without
//! touching state or the audit log. Reusing an operation id for *different*
//! content is rejected rather than guessed.
//!
//! This is what makes an offline retry safe: the device can resend its command
//! batch after a partition and the order converges to the same state.

use std::collections::BTreeMap;

use crate::audit::{AuditEvent, AuditEventKind, Timestamp};
use crate::catalog::{PricedCatalog, VersionPin, VersionStore};
use crate::check::{Check, CheckStatus, PaymentLink, Refund};
use crate::error::PosError;
use crate::ids::{validate_identifier, CheckId, EmployeeId, LineItemId, OperationId, OrderId};
use crate::line_item::LineItem;
use crate::money::{Currency, Money};
use crate::ownership::{Organization, Ownership};
use crate::rounding::RoundingMode;

/// A command that mutates an order or one of its checks.
///
/// Commands are values: they can be logged, resent, and compared. The
/// [`OperationId`] is the idempotency key; the remaining fields are the
/// content that must match on replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderCommand {
    /// Open a new check on the order.
    CreateCheck {
        /// Idempotency key.
        operation_id: OperationId,
        /// New check identifier.
        check_id: CheckId,
        /// Check currency, fixed for the life of the check.
        currency: Currency,
        /// Rounding mode, fixed for the life of the check.
        rounding: RoundingMode,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Add a line item.
    AddLineItem {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// Line to add.
        line: LineItem,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Replace an existing line item with the same identifier.
    UpdateLineItem {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// Replacement line.
        line: LineItem,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Remove a line item.
    RemoveLineItem {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// Line to remove.
        line_item_id: LineItemId,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Set the check tip.
    SetTip {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// New tip amount.
        tip: Money,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Link a payment to the check.
    LinkPayment {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// Payment link.
        payment: PaymentLink,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Park an open check.
    HoldCheck {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Resume a held check.
    ResumeCheck {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Close a fully paid check.
    CloseCheck {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Void an open or held check.
    VoidCheck {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// Reason recorded in the audit event; must not be blank.
        reason: String,
        /// Caller-supplied time.
        at: Timestamp,
    },
    /// Record a refund against a closed check.
    RefundCheck {
        /// Idempotency key.
        operation_id: OperationId,
        /// Target check.
        check_id: CheckId,
        /// Refund record.
        refund: Refund,
        /// Caller-supplied time.
        at: Timestamp,
    },
}

impl OrderCommand {
    /// The idempotency key.
    pub fn operation_id(&self) -> &OperationId {
        match self {
            OrderCommand::CreateCheck { operation_id, .. }
            | OrderCommand::AddLineItem { operation_id, .. }
            | OrderCommand::UpdateLineItem { operation_id, .. }
            | OrderCommand::RemoveLineItem { operation_id, .. }
            | OrderCommand::SetTip { operation_id, .. }
            | OrderCommand::LinkPayment { operation_id, .. }
            | OrderCommand::HoldCheck { operation_id, .. }
            | OrderCommand::ResumeCheck { operation_id, .. }
            | OrderCommand::CloseCheck { operation_id, .. }
            | OrderCommand::VoidCheck { operation_id, .. }
            | OrderCommand::RefundCheck { operation_id, .. } => operation_id,
        }
    }

    /// The check the command targets.
    pub fn check_id(&self) -> &CheckId {
        match self {
            OrderCommand::CreateCheck { check_id, .. }
            | OrderCommand::AddLineItem { check_id, .. }
            | OrderCommand::UpdateLineItem { check_id, .. }
            | OrderCommand::RemoveLineItem { check_id, .. }
            | OrderCommand::SetTip { check_id, .. }
            | OrderCommand::LinkPayment { check_id, .. }
            | OrderCommand::HoldCheck { check_id, .. }
            | OrderCommand::ResumeCheck { check_id, .. }
            | OrderCommand::CloseCheck { check_id, .. }
            | OrderCommand::VoidCheck { check_id, .. }
            | OrderCommand::RefundCheck { check_id, .. } => check_id,
        }
    }

    /// The caller-supplied event time.
    pub fn at(&self) -> Timestamp {
        match self {
            OrderCommand::CreateCheck { at, .. }
            | OrderCommand::AddLineItem { at, .. }
            | OrderCommand::UpdateLineItem { at, .. }
            | OrderCommand::RemoveLineItem { at, .. }
            | OrderCommand::SetTip { at, .. }
            | OrderCommand::LinkPayment { at, .. }
            | OrderCommand::HoldCheck { at, .. }
            | OrderCommand::ResumeCheck { at, .. }
            | OrderCommand::CloseCheck { at, .. }
            | OrderCommand::VoidCheck { at, .. }
            | OrderCommand::RefundCheck { at, .. } => *at,
        }
    }
}

/// Whether a command changed state or was recognised as an idempotent replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The command ran and appended audit events.
    Applied,
    /// The operation was already applied with identical content.
    Replayed,
}

/// The result of applying one command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyReceipt {
    /// The command's idempotency key.
    pub operation_id: OperationId,
    /// Applied or replayed.
    pub outcome: ApplyOutcome,
    /// Sequence number of the first audit event, absent on a replay.
    pub audit_sequence: Option<u64>,
}

/// A recorded command, used to detect conflicting reuse of an operation id.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AppliedCommand {
    command: OrderCommand,
    first_sequence: u64,
}

/// The order aggregate: ownership, checks, audit log and replay state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    id: OrderId,
    ownership: Ownership,
    opened_at: Timestamp,
    checks: BTreeMap<CheckId, Check>,
    version_pin: Option<VersionPin>,
    audit: Vec<AuditEvent>,
    applied: BTreeMap<OperationId, AppliedCommand>,
    next_sequence: u64,
}

impl Order {
    /// Create an order after validating its ownership against `organization`.
    ///
    /// The order starts with no checks; the first operation is normally
    /// [`OrderCommand::CreateCheck`].
    pub fn open(
        id: OrderId,
        ownership: Ownership,
        organization: &Organization,
        opened_at: Timestamp,
    ) -> Result<Self, PosError> {
        organization.validate_ownership(&ownership)?;
        Ok(Self {
            id,
            ownership,
            opened_at,
            checks: BTreeMap::new(),
            version_pin: None,
            audit: Vec::new(),
            applied: BTreeMap::new(),
            next_sequence: 1,
        })
    }

    /// Create an order bound to the catalog, price-book and tax-table versions
    /// it will price from (POS-04).
    ///
    /// The pin is immutable for the order's lifetime; the store keeps every
    /// version, so a later price or tax change cannot rewrite this order's
    /// provenance or its already-sealed checks.
    pub fn open_pinned(
        id: OrderId,
        ownership: Ownership,
        organization: &Organization,
        opened_at: Timestamp,
        version_pin: VersionPin,
    ) -> Result<Self, PosError> {
        let mut order = Self::open(id, ownership, organization, opened_at)?;
        order.version_pin = Some(version_pin);
        Ok(order)
    }

    /// The order identifier.
    pub fn id(&self) -> &OrderId {
        &self.id
    }

    /// The ownership record bound at order creation.
    pub fn ownership(&self) -> &Ownership {
        &self.ownership
    }

    /// The time the order was opened.
    pub fn opened_at(&self) -> Timestamp {
        self.opened_at
    }

    /// The versions this order pinned, when it was opened with
    /// [`Order::open_pinned`].
    pub fn version_pin(&self) -> Option<&VersionPin> {
        self.version_pin.as_ref()
    }

    /// Load the exact catalog, price-book and tax-table versions this order
    /// pinned. Fails with [`PosError::OrderNotPinned`] for a plain
    /// [`Order::open`] order.
    pub fn priced_catalog(&self, store: &VersionStore) -> Result<PricedCatalog, PosError> {
        let pin = self.version_pin.as_ref().ok_or(PosError::OrderNotPinned)?;
        store.snapshot(pin)
    }

    /// Checks in identifier order.
    pub fn checks(&self) -> impl Iterator<Item = &Check> {
        self.checks.values()
    }

    /// Look up one check.
    pub fn check(&self, id: &CheckId) -> Option<&Check> {
        self.checks.get(id)
    }

    /// Remove a check from the order (POS-02 transfer).
    pub(crate) fn take_check(&mut self, id: &CheckId) -> Result<Check, PosError> {
        self.checks
            .remove(id)
            .ok_or_else(|| PosError::CheckNotFound(id.clone()))
    }

    /// Insert an existing check, rejecting an identifier collision.
    pub(crate) fn insert_check(&mut self, check: Check) -> Result<(), PosError> {
        if self.checks.contains_key(check.id()) {
            return Err(PosError::CheckAlreadyExists(check.id().clone()));
        }
        self.checks.insert(check.id().clone(), check);
        Ok(())
    }

    /// Whether the order already contains this check.
    pub(crate) fn contains_check(&self, id: &CheckId) -> bool {
        self.checks.contains_key(id)
    }

    /// The append-only audit log.
    pub fn audit_events(&self) -> &[AuditEvent] {
        &self.audit
    }

    /// Number of distinct operations applied.
    pub fn applied_operation_count(&self) -> usize {
        self.applied.len()
    }

    /// `true` when `operation_id` has already been applied.
    pub fn is_operation_applied(&self, operation_id: &OperationId) -> bool {
        self.applied.contains_key(operation_id)
    }

    /// Apply one command, or recognise an exact replay.
    ///
    /// A failed command leaves the order unchanged: all validation happens
    /// before mutation and the audit sequence is checked for capacity first.
    pub fn apply(&mut self, command: OrderCommand) -> Result<ApplyReceipt, PosError> {
        let operation_id = command.operation_id().clone();
        if let Some(previous) = self.applied.get(&operation_id) {
            if previous.command == command {
                return Ok(ApplyReceipt {
                    operation_id,
                    outcome: ApplyOutcome::Replayed,
                    audit_sequence: None,
                });
            }
            return Err(PosError::OperationConflict(operation_id));
        }

        // Every command appends at least one event; a refund may append two.
        self.ensure_audit_capacity(2)?;

        let check_id = command.check_id().clone();
        let at = command.at();
        let actor = self.ownership.employee_id().clone();
        let kinds = self.execute(&command)?;
        let first_sequence = self.next_sequence;

        for kind in kinds {
            let event = AuditEvent::new(
                self.next_sequence,
                at,
                self.id.clone(),
                check_id.clone(),
                operation_id.clone(),
                actor.clone(),
                kind,
            );
            self.next_sequence += 1;
            self.audit.push(event);
        }

        self.applied.insert(
            operation_id.clone(),
            AppliedCommand {
                command,
                first_sequence,
            },
        );

        Ok(ApplyReceipt {
            operation_id,
            outcome: ApplyOutcome::Applied,
            audit_sequence: Some(first_sequence),
        })
    }

    /// Apply a command batch, stopping at the first rejection.
    ///
    /// Replaying the same batch a second time returns `Replayed` for every
    /// command and changes nothing.
    pub fn replay(&mut self, commands: &[OrderCommand]) -> Result<Vec<ApplyReceipt>, PosError> {
        let mut receipts = Vec::with_capacity(commands.len());
        for command in commands {
            receipts.push(self.apply(command.clone())?);
        }
        Ok(receipts)
    }

    fn ensure_audit_capacity(&self, events: u64) -> Result<(), PosError> {
        if self.next_sequence > u64::MAX - events {
            return Err(PosError::AuditSequenceExhausted);
        }
        Ok(())
    }

    pub(crate) fn check_mut(&mut self, id: &CheckId) -> Result<&mut Check, PosError> {
        self.checks
            .get_mut(id)
            .ok_or_else(|| PosError::CheckNotFound(id.clone()))
    }

    fn execute(&mut self, command: &OrderCommand) -> Result<Vec<AuditEventKind>, PosError> {
        match command {
            OrderCommand::CreateCheck {
                check_id,
                currency,
                rounding,
                at,
                ..
            } => {
                if self.checks.contains_key(check_id) {
                    return Err(PosError::CheckAlreadyExists(check_id.clone()));
                }
                let check = Check::new(check_id.clone(), *currency, *rounding, *at);
                self.checks.insert(check_id.clone(), check);
                Ok(vec![AuditEventKind::CheckCreated {
                    currency: *currency,
                }])
            }
            OrderCommand::AddLineItem { check_id, line, .. } => {
                let check = self.check_mut(check_id)?;
                let totals = check.add_line(line.clone())?;
                Ok(vec![AuditEventKind::LineItemAdded {
                    line_item_id: line.id().clone(),
                    line_total: totals.total,
                }])
            }
            OrderCommand::UpdateLineItem { check_id, line, .. } => {
                let check = self.check_mut(check_id)?;
                let (previous, new) = check.update_line(line.clone())?;
                Ok(vec![AuditEventKind::LineItemUpdated {
                    line_item_id: line.id().clone(),
                    previous_total: previous.total,
                    new_total: new.total,
                }])
            }
            OrderCommand::RemoveLineItem {
                check_id,
                line_item_id,
                ..
            } => {
                let check = self.check_mut(check_id)?;
                let totals = check.remove_line(line_item_id)?;
                Ok(vec![AuditEventKind::LineItemRemoved {
                    line_item_id: line_item_id.clone(),
                    line_total: totals.total,
                }])
            }
            OrderCommand::SetTip { check_id, tip, .. } => {
                let check = self.check_mut(check_id)?;
                let previous = check.set_tip(*tip)?;
                Ok(vec![AuditEventKind::TipSet {
                    previous,
                    new: *tip,
                }])
            }
            OrderCommand::LinkPayment {
                check_id, payment, ..
            } => {
                let check = self.check_mut(check_id)?;
                check.link_payment(payment.clone())?;
                Ok(vec![AuditEventKind::PaymentLinked {
                    payment_id: payment.id().clone(),
                    amount: payment.amount(),
                }])
            }
            OrderCommand::HoldCheck { check_id, .. } => {
                let check = self.check_mut(check_id)?;
                let from = check.status();
                check.hold()?;
                Ok(vec![AuditEventKind::StatusChanged {
                    from,
                    to: CheckStatus::Held,
                    reason: None,
                }])
            }
            OrderCommand::ResumeCheck { check_id, .. } => {
                let check = self.check_mut(check_id)?;
                let from = check.status();
                check.resume()?;
                Ok(vec![AuditEventKind::StatusChanged {
                    from,
                    to: CheckStatus::Open,
                    reason: None,
                }])
            }
            OrderCommand::CloseCheck { check_id, .. } => {
                let check = self.check_mut(check_id)?;
                let from = check.status();
                let grand_total = check.close()?;
                Ok(vec![
                    AuditEventKind::StatusChanged {
                        from,
                        to: CheckStatus::Closed,
                        reason: None,
                    },
                    AuditEventKind::TotalsSealed { grand_total },
                ])
            }
            OrderCommand::VoidCheck {
                check_id, reason, ..
            } => {
                if reason.trim().is_empty() {
                    return Err(PosError::MissingReason);
                }
                validate_identifier(reason, "void reason")?;
                let check = self.check_mut(check_id)?;
                let from = check.status();
                let grand_total = check.void()?;
                Ok(vec![
                    AuditEventKind::StatusChanged {
                        from,
                        to: CheckStatus::Voided,
                        reason: Some(reason.clone()),
                    },
                    AuditEventKind::TotalsSealed { grand_total },
                ])
            }
            OrderCommand::RefundCheck {
                check_id, refund, ..
            } => {
                let check = self.check_mut(check_id)?;
                let became_refunded = check.record_refund(refund.clone())?;
                let mut events = vec![AuditEventKind::RefundRecorded {
                    refund_id: refund.id().clone(),
                    amount: refund.amount(),
                    reason: refund.reason().to_owned(),
                }];
                if became_refunded {
                    events.push(AuditEventKind::StatusChanged {
                        from: CheckStatus::Closed,
                        to: CheckStatus::Refunded,
                        reason: None,
                    });
                }
                Ok(events)
            }
        }
    }
}

/// Convenience: the employee acting on an order, for callers building events.
pub fn actor_of(order: &Order) -> &EmployeeId {
    order.ownership().employee_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::PaymentMethod;
    use crate::ids::{PaymentId, RefundId, StoreId, TerminalId};
    use crate::money::Quantity;
    use crate::ownership::{Employee, EmployeeRole, Store, Terminal};

    fn fixture() -> (Organization, Ownership) {
        let store_id = StoreId::new("store-1").unwrap();
        let mut org = Organization::new();
        org.add_store(Store::new(store_id.clone(), "Store One").unwrap())
            .unwrap();
        org.add_terminal(
            Terminal::new(
                TerminalId::new("till-1").unwrap(),
                store_id.clone(),
                "Till 1",
            )
            .unwrap(),
        )
        .unwrap();
        org.add_employee(
            Employee::new(
                EmployeeId::new("emp-1").unwrap(),
                store_id.clone(),
                "Ada",
                vec![EmployeeRole::Cashier],
            )
            .unwrap(),
        )
        .unwrap();
        let ownership = Ownership::new(
            store_id,
            TerminalId::new("till-1").unwrap(),
            EmployeeId::new("emp-1").unwrap(),
            None,
        );
        (org, ownership)
    }

    fn open_order() -> (Order, CheckId) {
        let (org, ownership) = fixture();
        let checkout = CheckId::new("check-1").unwrap();
        let mut order = Order::open(
            OrderId::new("order-1").unwrap(),
            ownership,
            &org,
            Timestamp::from_millis(1),
        )
        .unwrap();
        order
            .apply(OrderCommand::CreateCheck {
                operation_id: OperationId::new("create").unwrap(),
                check_id: checkout.clone(),
                currency: Currency::from_code("USD").unwrap(),
                rounding: RoundingMode::HalfEven,
                at: Timestamp::from_millis(2),
            })
            .unwrap();
        (order, checkout)
    }

    fn line(minor: i64) -> LineItem {
        LineItem::new(
            LineItemId::new("line-1").unwrap(),
            "Coffee",
            Quantity::from_units(1).unwrap(),
            Money::new(Currency::from_code("USD").unwrap(), minor),
        )
        .unwrap()
    }

    fn add(check_id: &CheckId, id: &str, line: LineItem) -> OrderCommand {
        OrderCommand::AddLineItem {
            operation_id: OperationId::new(id).unwrap(),
            check_id: check_id.clone(),
            line,
            at: Timestamp::from_millis(3),
        }
    }

    fn payment(amount: Money) -> PaymentLink {
        PaymentLink::captured(
            PaymentId::new("payment-1").unwrap(),
            PaymentMethod::Cash,
            amount,
        )
        .unwrap()
    }

    #[test]
    fn hold_resume_close_and_refund_follow_the_state_machine() {
        let (mut order, check_id) = open_order();
        order.apply(add(&check_id, "add", line(1_000))).unwrap();
        order
            .apply(OrderCommand::HoldCheck {
                operation_id: OperationId::new("hold").unwrap(),
                check_id: check_id.clone(),
                at: Timestamp::from_millis(4),
            })
            .unwrap();
        assert_eq!(order.check(&check_id).unwrap().status(), CheckStatus::Held);

        order
            .apply(OrderCommand::ResumeCheck {
                operation_id: OperationId::new("resume").unwrap(),
                check_id: check_id.clone(),
                at: Timestamp::from_millis(5),
            })
            .unwrap();
        assert_eq!(order.check(&check_id).unwrap().status(), CheckStatus::Open);

        order
            .apply(OrderCommand::LinkPayment {
                operation_id: OperationId::new("pay").unwrap(),
                check_id: check_id.clone(),
                payment: payment(Money::new(Currency::from_code("USD").unwrap(), 1_000)),
                at: Timestamp::from_millis(6),
            })
            .unwrap();
        order
            .apply(OrderCommand::CloseCheck {
                operation_id: OperationId::new("close").unwrap(),
                check_id: check_id.clone(),
                at: Timestamp::from_millis(7),
            })
            .unwrap();
        let closed = order.check(&check_id).unwrap();
        assert_eq!(closed.status(), CheckStatus::Closed);
        assert!(closed.is_sealed());
        assert!(closed.sealed_totals_are_consistent().unwrap());

        order
            .apply(OrderCommand::RefundCheck {
                operation_id: OperationId::new("refund").unwrap(),
                check_id: check_id.clone(),
                refund: Refund::new(
                    RefundId::new("refund-1").unwrap(),
                    Money::new(Currency::from_code("USD").unwrap(), 1_000),
                    "Customer request",
                )
                .unwrap(),
                at: Timestamp::from_millis(8),
            })
            .unwrap();
        let refunded = order.check(&check_id).unwrap();
        assert_eq!(refunded.status(), CheckStatus::Refunded);
        let totals = refunded.totals().unwrap();
        assert_eq!(
            totals.net_paid,
            Money::zero(Currency::from_code("USD").unwrap())
        );
        assert_eq!(totals.amount_due, totals.grand_total);
        assert!(refunded.sealed_totals_are_consistent().unwrap());
    }

    #[test]
    fn close_requires_full_payment() {
        let (mut order, check_id) = open_order();
        order.apply(add(&check_id, "add", line(1_000))).unwrap();
        let err = order
            .apply(OrderCommand::CloseCheck {
                operation_id: OperationId::new("close").unwrap(),
                check_id: check_id.clone(),
                at: Timestamp::from_millis(4),
            })
            .unwrap_err();
        assert_eq!(
            err,
            PosError::CheckNotFullyPaid {
                amount_due: Money::new(Currency::from_code("USD").unwrap(), 1_000)
            }
        );
        assert_eq!(order.audit_events().len(), 2, "failed close must not audit");
        assert_eq!(order.check(&check_id).unwrap().status(), CheckStatus::Open);
    }

    #[test]
    fn void_requires_a_reason_and_is_terminal() {
        let (mut order, check_id) = open_order();
        order.apply(add(&check_id, "add", line(500))).unwrap();
        let err = order
            .apply(OrderCommand::VoidCheck {
                operation_id: OperationId::new("void").unwrap(),
                check_id: check_id.clone(),
                reason: "   ".into(),
                at: Timestamp::from_millis(4),
            })
            .unwrap_err();
        assert_eq!(err, PosError::MissingReason);

        order
            .apply(OrderCommand::VoidCheck {
                operation_id: OperationId::new("void").unwrap(),
                check_id: check_id.clone(),
                reason: "customer left".into(),
                at: Timestamp::from_millis(5),
            })
            .unwrap();
        let voided = order.check(&check_id).unwrap();
        assert_eq!(voided.status(), CheckStatus::Voided);
        assert!(voided.is_sealed());

        let err = order
            .apply(OrderCommand::CloseCheck {
                operation_id: OperationId::new("close").unwrap(),
                check_id: check_id.clone(),
                at: Timestamp::from_millis(6),
            })
            .unwrap_err();
        assert_eq!(
            err,
            PosError::InvalidTransition {
                from: CheckStatus::Voided,
                to: CheckStatus::Closed
            }
        );
        let err = order
            .apply(add(&check_id, "add-late", line(100)))
            .unwrap_err();
        assert_eq!(
            err,
            PosError::CheckNotMutable {
                status: CheckStatus::Voided
            }
        );
    }

    #[test]
    fn reusing_an_operation_id_with_different_content_is_rejected() {
        let (mut order, check_id) = open_order();
        order.apply(add(&check_id, "add", line(500))).unwrap();
        let audit_len = order.audit_events().len();
        let mut different = line(600);
        different = different.with_sku("different").unwrap();
        let err = order.apply(add(&check_id, "add", different)).unwrap_err();
        assert_eq!(
            err,
            PosError::OperationConflict(OperationId::new("add").unwrap())
        );
        assert_eq!(order.audit_events().len(), audit_len);
    }

    #[test]
    fn partial_refund_keeps_the_check_closed_until_fully_refunded() {
        let (mut order, check_id) = open_order();
        order.apply(add(&check_id, "add", line(1_000))).unwrap();
        order
            .apply(OrderCommand::LinkPayment {
                operation_id: OperationId::new("pay").unwrap(),
                check_id: check_id.clone(),
                payment: payment(Money::new(Currency::from_code("USD").unwrap(), 1_000)),
                at: Timestamp::from_millis(4),
            })
            .unwrap();
        order
            .apply(OrderCommand::CloseCheck {
                operation_id: OperationId::new("close").unwrap(),
                check_id: check_id.clone(),
                at: Timestamp::from_millis(5),
            })
            .unwrap();

        order
            .apply(OrderCommand::RefundCheck {
                operation_id: OperationId::new("refund-1").unwrap(),
                check_id: check_id.clone(),
                refund: Refund::new(
                    RefundId::new("refund-1").unwrap(),
                    Money::new(Currency::from_code("USD").unwrap(), 400),
                    "partial return",
                )
                .unwrap(),
                at: Timestamp::from_millis(6),
            })
            .unwrap();
        assert_eq!(
            order.check(&check_id).unwrap().status(),
            CheckStatus::Closed
        );

        order
            .apply(OrderCommand::RefundCheck {
                operation_id: OperationId::new("refund-2").unwrap(),
                check_id: check_id.clone(),
                refund: Refund::new(
                    RefundId::new("refund-2").unwrap(),
                    Money::new(Currency::from_code("USD").unwrap(), 600),
                    "rest of the return",
                )
                .unwrap(),
                at: Timestamp::from_millis(7),
            })
            .unwrap();
        assert_eq!(
            order.check(&check_id).unwrap().status(),
            CheckStatus::Refunded
        );

        let err = order
            .apply(OrderCommand::RefundCheck {
                operation_id: OperationId::new("refund-3").unwrap(),
                check_id: check_id.clone(),
                refund: Refund::new(
                    RefundId::new("refund-3").unwrap(),
                    Money::new(Currency::from_code("USD").unwrap(), 1),
                    "too much",
                )
                .unwrap(),
                at: Timestamp::from_millis(8),
            })
            .unwrap_err();
        assert_eq!(err, PosError::NothingToRefund);
    }
}
