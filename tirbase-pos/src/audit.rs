// SPDX-License-Identifier: AGPL-3.0-only

//! Append-only audit events for order and check state changes.
//!
//! Every command that mutates an order appends at least one event; a command
//! that fails validation appends none. The log is ordered by a dense
//! `sequence` starting at 1, and the order aggregate exposes it only as a
//! slice, so callers cannot rewrite history.
//!
//! Time is caller-supplied ([`Timestamp`]) rather than read from the system
//! clock, which keeps a replay deterministic and matches the repository's
//! injected-time rule (CLAIM-5.5).

use crate::check::CheckStatus;
use crate::ids::{CheckId, EmployeeId, LineItemId, OperationId, OrderId, PaymentId, RefundId};
use crate::money::{Currency, Money};

/// Milliseconds since the Unix epoch, supplied by the caller.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Construct from an exact millisecond value.
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// The raw millisecond value.
    pub const fn millis(self) -> i64 {
        self.0
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// What changed in one audited operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEventKind {
    /// A check was opened on the order.
    CheckCreated {
        /// The check currency fixed at creation.
        currency: Currency,
    },
    /// A check moved between states.
    StatusChanged {
        /// State before the transition.
        from: CheckStatus,
        /// State after the transition.
        to: CheckStatus,
        /// Caller-supplied reason (required for void).
        reason: Option<String>,
    },
    /// A line item was added.
    LineItemAdded {
        /// The new line.
        line_item_id: LineItemId,
        /// The line total under the check's rounding mode.
        line_total: Money,
    },
    /// A line item was replaced.
    LineItemUpdated {
        /// The replaced line.
        line_item_id: LineItemId,
        /// The line total before the update.
        previous_total: Money,
        /// The line total after the update.
        new_total: Money,
    },
    /// A line item was removed.
    LineItemRemoved {
        /// The removed line.
        line_item_id: LineItemId,
        /// The line total at removal.
        line_total: Money,
    },
    /// The tip changed.
    TipSet {
        /// Previous tip.
        previous: Money,
        /// New tip.
        new: Money,
    },
    /// A payment was linked to the check.
    PaymentLinked {
        /// The linked payment.
        payment_id: PaymentId,
        /// The payment amount.
        amount: Money,
    },
    /// A refund was recorded against a closed check.
    RefundRecorded {
        /// The new refund record.
        refund_id: RefundId,
        /// The refunded amount.
        amount: Money,
        /// Caller-supplied reason.
        reason: String,
    },
    /// Line-derived totals were frozen when the check closed or was voided.
    TotalsSealed {
        /// The frozen grand total.
        grand_total: Money,
    },
}

/// One immutable audit entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// Dense, monotonic sequence number starting at 1.
    pub sequence: u64,
    /// Caller-supplied event time.
    pub at: Timestamp,
    /// The order aggregate.
    pub order_id: OrderId,
    /// The check the operation targeted.
    pub check_id: CheckId,
    /// The idempotency key of the command that produced the event.
    pub operation_id: OperationId,
    /// The employee recorded on the order's ownership record.
    pub actor: EmployeeId,
    /// What changed.
    pub kind: AuditEventKind,
}

impl AuditEvent {
    pub(crate) fn new(
        sequence: u64,
        at: Timestamp,
        order_id: OrderId,
        check_id: CheckId,
        operation_id: OperationId,
        actor: EmployeeId,
        kind: AuditEventKind,
    ) -> Self {
        Self {
            sequence,
            at,
            order_id,
            check_id,
            operation_id,
            actor,
            kind,
        }
    }
}
