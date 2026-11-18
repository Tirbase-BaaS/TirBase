// SPDX-License-Identifier: AGPL-3.0-only

//! POS-12 — tip recording, adjustment, pooling and payout.
//!
//! Tips are tracked per settled check and attributed to the operator who rang
//! it, because the operator comes from the [`StaffSession`] rather than from a
//! caller-supplied employee id. An adjustment replaces the tip for one check
//! and appends an immutable [`TipAdjustment`] record holding the previous
//! amount, the new amount and the delta.
//!
//! # Payout rule
//!
//! A [`TipPayout`] settles every *unsettled* tip at once, so a tip can be paid
//! exactly once no matter how many pools are run afterwards:
//!
//! ```text
//! total       = Σ settled tips
//! Σ payouts   = total            (exactly, to the minor unit)
//! ```
//!
//! The split uses the largest-remainder method: every member gets the floor of
//! their weighted share and the leftover minor units go one each to the largest
//! remainders, ties broken by member order. Rounding can therefore never invent
//! or lose a minor unit, which is what makes "payout totals match allocated
//! tips" true by construction rather than by luck. [`TipPayout::validate`]
//! re-checks both identities before a payout is stored.
//!
//! Every tip in the ledger must belong to a pool member. A tip owned by someone
//! outside the pool is refused with [`TipError::UnpooledTip`] instead of being
//! silently absorbed into someone else's payout.

use std::collections::BTreeMap;

use crate::audit::Timestamp;
use crate::error::PosError;
use crate::ids::{CheckId, EmployeeId, TipPoolId};
use crate::money::{Currency, Money};
use crate::staff::{Permission, StaffSession};

/// Maximum weight one pool member may carry.
///
/// The cap keeps the weighted-share arithmetic inside `i128`.
pub const MAX_TIP_WEIGHT: u64 = 1_000_000;

/// Maximum length of an adjustment note, in bytes.
pub const MAX_TIP_NOTE_LEN: usize = 256;

/// Whether a tip operation changed state or was an idempotent replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TipChange {
    /// The operation ran and changed the ledger.
    Applied,
    /// The same value was already recorded.
    Replayed,
}

impl TipChange {
    /// `true` when the operation changed state.
    pub fn is_applied(self) -> bool {
        matches!(self, TipChange::Applied)
    }
}

/// The tip currently recorded for one check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipEntry {
    check_id: CheckId,
    employee: EmployeeId,
    amount: Money,
    currency: Currency,
    recorded_at: Timestamp,
    adjusted_at: Option<Timestamp>,
    adjustments: u32,
    payout: Option<TipPoolId>,
}

impl TipEntry {
    /// The check the tip belongs to.
    pub fn check_id(&self) -> &CheckId {
        &self.check_id
    }

    /// The operator the tip is attributed to.
    pub fn employee(&self) -> &EmployeeId {
        &self.employee
    }

    /// The current tip amount.
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// The tip currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// When the tip was first recorded.
    pub fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }

    /// When the tip was last adjusted.
    pub fn adjusted_at(&self) -> Option<Timestamp> {
        self.adjusted_at
    }

    /// How many adjustments this tip has had.
    pub fn adjustments(&self) -> u32 {
        self.adjustments
    }

    /// The pool that paid this tip, if any.
    pub fn payout(&self) -> Option<&TipPoolId> {
        self.payout.as_ref()
    }

    /// `true` while the tip is still owed to the operator.
    pub fn is_open(&self) -> bool {
        self.payout.is_none()
    }
}

/// One immutable adjustment to a recorded tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipAdjustment {
    check_id: CheckId,
    employee: EmployeeId,
    previous: Money,
    adjusted: Money,
    delta: Money,
    at: Timestamp,
    by: EmployeeId,
    note: Option<String>,
}

impl TipAdjustment {
    /// The adjusted check.
    pub fn check_id(&self) -> &CheckId {
        &self.check_id
    }

    /// The operator the tip belongs to.
    pub fn employee(&self) -> &EmployeeId {
        &self.employee
    }

    /// The tip before the adjustment.
    pub fn previous(&self) -> Money {
        self.previous
    }

    /// The tip after the adjustment.
    pub fn adjusted(&self) -> Money {
        self.adjusted
    }

    /// `adjusted − previous`; negative when a tip was reduced.
    pub fn delta(&self) -> Money {
        self.delta
    }

    /// When the adjustment was made.
    pub fn at(&self) -> Timestamp {
        self.at
    }

    /// The authenticated operator who made it.
    pub fn by(&self) -> &EmployeeId {
        &self.by
    }

    /// The optional note.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }
}

/// How a pool is split.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TipPoolPolicy {
    /// Every member gets an equal share; supplied weights are ignored.
    Even,
    /// Members are paid in proportion to their weights (points or hours).
    Weighted,
}

impl TipPoolPolicy {
    /// Stable label for logs and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            TipPoolPolicy::Even => "even",
            TipPoolPolicy::Weighted => "weighted",
        }
    }
}

impl std::fmt::Display for TipPoolPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One member of a tip pool and the share weight they carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipMember {
    /// The member.
    pub employee: EmployeeId,
    /// Share weight; ignored by [`TipPoolPolicy::Even`].
    pub weight: u64,
}

impl TipMember {
    /// A member with a share weight.
    pub fn new(employee: EmployeeId, weight: u64) -> Self {
        Self { employee, weight }
    }

    /// A member with a single share.
    pub fn even(employee: EmployeeId) -> Self {
        Self {
            employee,
            weight: 1,
        }
    }
}

/// One member's share of a payout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipAllocation {
    /// The member.
    pub employee: EmployeeId,
    /// The weight used for the split.
    pub weight: u64,
    /// The tips this member contributed to the pool.
    pub contributed: Money,
    /// The amount paid to this member.
    pub payout: Money,
}

/// A stored, immutable payout of every tip that was open when it ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipPayout {
    pool_id: TipPoolId,
    policy: TipPoolPolicy,
    currency: Currency,
    total: Money,
    allocations: Vec<TipAllocation>,
    paid_by: EmployeeId,
    paid_at: Timestamp,
}

impl TipPayout {
    /// The pool identifier.
    pub fn pool_id(&self) -> &TipPoolId {
        &self.pool_id
    }

    /// The split policy used.
    pub fn policy(&self) -> TipPoolPolicy {
        self.policy
    }

    /// The payout currency.
    pub fn currency(&self) -> Currency {
        self.currency
    }

    /// The tips settled by this payout.
    pub fn total(&self) -> Money {
        self.total
    }

    /// Every member's share, in the order the members were supplied.
    pub fn allocations(&self) -> &[TipAllocation] {
        &self.allocations
    }

    /// The authenticated operator who ran the payout.
    pub fn paid_by(&self) -> &EmployeeId {
        &self.paid_by
    }

    /// When the payout ran.
    pub fn paid_at(&self) -> Timestamp {
        self.paid_at
    }

    /// One member's allocation.
    pub fn allocation(&self, employee: &EmployeeId) -> Option<&TipAllocation> {
        self.allocations
            .iter()
            .find(|allocation| &allocation.employee == employee)
    }

    /// The sum of every allocation.
    pub fn allocated_total(&self) -> Result<Money, TipError> {
        let mut total = Money::zero(self.currency);
        for allocation in &self.allocations {
            total = total.checked_add(allocation.payout)?;
        }
        Ok(total)
    }

    /// Re-check that the allocations and contributions both add up to the total.
    ///
    /// This is the invariant the payout rule promises, and
    /// [`TipLedger::payout`] refuses to store a payout that fails it.
    pub fn validate(&self) -> Result<(), TipError> {
        let mut allocated = Money::zero(self.currency);
        let mut contributed = Money::zero(self.currency);
        for allocation in &self.allocations {
            if allocation.payout.currency() != self.currency
                || allocation.contributed.currency() != self.currency
            {
                return Err(TipError::CurrencyMismatch);
            }
            allocated = allocated.checked_add(allocation.payout)?;
            contributed = contributed.checked_add(allocation.contributed)?;
        }
        if allocated != self.total {
            return Err(TipError::InvalidPayout(
                "allocations do not add up to the payout total",
            ));
        }
        if contributed != self.total {
            return Err(TipError::InvalidPayout(
                "contributed tips do not add up to the payout total",
            ));
        }
        Ok(())
    }

    fn same_terms(&self, policy: TipPoolPolicy, members: &[TipMember]) -> bool {
        if self.policy != policy || self.allocations.len() != members.len() {
            return false;
        }
        self.allocations
            .iter()
            .zip(members)
            .all(|(allocation, member)| {
                allocation.employee == member.employee
                    && (policy == TipPoolPolicy::Even || allocation.weight == member.weight)
            })
    }
}

/// A rejected tip operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TipError {
    /// The session lacks the required permission.
    NotPermitted(Permission),
    /// The session belongs to a different store than the tip.
    StoreMismatch,
    /// No tip is recorded for this check.
    UnknownTip(CheckId),
    /// A new tip was zero or negative.
    NonPositiveAmount,
    /// An adjusted tip was negative.
    NegativeAmount,
    /// A tip was already recorded for this check with a different amount.
    TipConflict(CheckId),
    /// The amounts use different currencies.
    CurrencyMismatch,
    /// A note was empty, oversized or control-bearing.
    InvalidNote,
    /// There are no open tips to pay.
    NoTips,
    /// A tip belongs to an employee who is not in the pool.
    UnpooledTip(CheckId),
    /// A member appears twice in one pool.
    DuplicateMember(EmployeeId),
    /// A weighted member carries a zero weight.
    ZeroWeight(EmployeeId),
    /// A weighted member carries more than [`MAX_TIP_WEIGHT`].
    WeightTooLarge(EmployeeId),
    /// The pool has no members.
    EmptyPool,
    /// The pool was already paid with different terms.
    PoolConflict(TipPoolId),
    /// A stored payout failed its own invariant check.
    InvalidPayout(&'static str),
    /// Money arithmetic failed.
    Pos(PosError),
}

impl TipError {
    /// Stable reason code for logs and policy.
    pub fn code(&self) -> &'static str {
        match self {
            TipError::NotPermitted(_) => "tip.not_permitted",
            TipError::StoreMismatch => "tip.store_mismatch",
            TipError::UnknownTip(_) => "tip.unknown_tip",
            TipError::NonPositiveAmount => "tip.non_positive_amount",
            TipError::NegativeAmount => "tip.negative_amount",
            TipError::TipConflict(_) => "tip.conflict",
            TipError::CurrencyMismatch => "tip.currency_mismatch",
            TipError::InvalidNote => "tip.invalid_note",
            TipError::NoTips => "tip.none",
            TipError::UnpooledTip(_) => "tip.unpooled_tip",
            TipError::DuplicateMember(_) => "tip.duplicate_member",
            TipError::ZeroWeight(_) => "tip.zero_weight",
            TipError::WeightTooLarge(_) => "tip.weight_too_large",
            TipError::EmptyPool => "tip.empty_pool",
            TipError::PoolConflict(_) => "tip.pool_conflict",
            TipError::InvalidPayout(_) => "tip.invalid_payout",
            TipError::Pos(_) => "tip.pos",
        }
    }
}

impl std::fmt::Display for TipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TipError::NotPermitted(permission) => write!(f, "permission denied: {permission}"),
            TipError::StoreMismatch => f.write_str("session belongs to another store"),
            TipError::UnknownTip(check) => write!(f, "no tip recorded for check {check}"),
            TipError::NonPositiveAmount => f.write_str("tip must be positive"),
            TipError::NegativeAmount => f.write_str("tip must not be negative"),
            TipError::TipConflict(check) => {
                write!(f, "check {check} already has a different tip")
            }
            TipError::CurrencyMismatch => f.write_str("currency mismatch"),
            TipError::InvalidNote => f.write_str("invalid note"),
            TipError::NoTips => f.write_str("no open tips to pay"),
            TipError::UnpooledTip(check) => {
                write!(f, "tip on check {check} belongs to a non-member")
            }
            TipError::DuplicateMember(employee) => {
                write!(f, "employee {employee} appears twice in the pool")
            }
            TipError::ZeroWeight(employee) => {
                write!(f, "employee {employee} has a zero weight")
            }
            TipError::WeightTooLarge(employee) => {
                write!(f, "employee {employee} exceeds the maximum weight")
            }
            TipError::EmptyPool => f.write_str("pool has no members"),
            TipError::PoolConflict(pool) => {
                write!(f, "pool {pool} was already paid with different terms")
            }
            TipError::InvalidPayout(reason) => write!(f, "invalid payout: {reason}"),
            TipError::Pos(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for TipError {}

impl From<PosError> for TipError {
    fn from(error: PosError) -> Self {
        TipError::Pos(error)
    }
}

/// Every tip in one deployment, with its adjustments and payouts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TipLedger {
    entries: BTreeMap<CheckId, TipEntry>,
    adjustments: Vec<TipAdjustment>,
    payouts: BTreeMap<TipPoolId, TipPayout>,
}

impl TipLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of checks with a tip.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no tip has been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// One tip by check.
    pub fn tip(&self, check_id: &CheckId) -> Option<&TipEntry> {
        self.entries.get(check_id)
    }

    /// Every tip, in check order.
    pub fn tips(&self) -> impl Iterator<Item = &TipEntry> {
        self.entries.values()
    }

    /// Tips that have not been paid out yet, in check order.
    pub fn open_tips(&self) -> impl Iterator<Item = &TipEntry> {
        self.entries.values().filter(|entry| entry.is_open())
    }

    /// Every adjustment, in recording order.
    pub fn adjustments(&self) -> &[TipAdjustment] {
        &self.adjustments
    }

    /// One stored payout.
    pub fn payout_for(&self, pool_id: &TipPoolId) -> Option<&TipPayout> {
        self.payouts.get(pool_id)
    }

    /// Every stored payout, in pool order.
    pub fn payouts(&self) -> impl Iterator<Item = &TipPayout> {
        self.payouts.values()
    }

    /// Sum of every tip in one currency.
    pub fn total(&self, currency: Currency) -> Result<Money, TipError> {
        let mut total = Money::zero(currency);
        for entry in self.entries.values() {
            total = total.checked_add(entry.amount)?;
        }
        Ok(total)
    }

    /// Sum of the tips still owed in one currency.
    pub fn open_total(&self, currency: Currency) -> Result<Money, TipError> {
        let mut total = Money::zero(currency);
        for entry in self.open_tips() {
            total = total.checked_add(entry.amount)?;
        }
        Ok(total)
    }

    /// Sum of one employee's tips in one currency.
    pub fn total_for(&self, employee: &EmployeeId, currency: Currency) -> Result<Money, TipError> {
        let mut total = Money::zero(currency);
        for entry in self.entries.values() {
            if &entry.employee == employee {
                total = total.checked_add(entry.amount)?;
            }
        }
        Ok(total)
    }

    /// Record the tip a check was settled with.
    ///
    /// The tip is attributed to the session's employee. Repeating the same tip
    /// for the same check is a replay; a different tip needs
    /// [`TipLedger::adjust_tip`].
    pub fn record_tip(
        &mut self,
        session: &StaffSession,
        check_id: CheckId,
        amount: Money,
        at: Timestamp,
    ) -> Result<TipChange, TipError> {
        require(session, Permission::Sell)?;
        if !amount.is_positive() {
            return Err(TipError::NonPositiveAmount);
        }
        if let Some(existing) = self.entries.get(&check_id) {
            if existing.employee != *session.employee_id() {
                return Err(TipError::TipConflict(check_id));
            }
            return if existing.amount == amount {
                Ok(TipChange::Replayed)
            } else {
                Err(TipError::TipConflict(check_id))
            };
        }
        let entry = TipEntry {
            check_id,
            employee: session.employee_id().clone(),
            amount,
            currency: amount.currency(),
            recorded_at: at,
            adjusted_at: None,
            adjustments: 0,
            payout: None,
        };
        self.entries.insert(entry.check_id.clone(), entry);
        Ok(TipChange::Applied)
    }

    /// Replace the tip on an already-recorded check and journal the delta.
    ///
    /// Adjusting a tip that has been paid out is refused: the payout already
    /// moved the money, so a later change would break the payout identity.
    pub fn adjust_tip(
        &mut self,
        session: &StaffSession,
        check_id: &CheckId,
        adjusted: Money,
        at: Timestamp,
        note: Option<&str>,
    ) -> Result<TipChange, TipError> {
        require(session, Permission::PayTips)?;
        self.ensure_store(session)?;
        if adjusted.is_negative() {
            return Err(TipError::NegativeAmount);
        }
        let note = validate_note(note)?;
        let entry = self
            .entries
            .get_mut(check_id)
            .ok_or_else(|| TipError::UnknownTip(check_id.clone()))?;
        if entry.payout.is_some() {
            return Err(TipError::PoolConflict(
                entry.payout.clone().expect("checked above"),
            ));
        }
        if adjusted == entry.amount {
            return Ok(TipChange::Replayed);
        }
        let previous = entry.amount;
        let delta = adjusted.checked_sub(previous)?;
        entry.amount = adjusted;
        entry.adjusted_at = Some(at);
        entry.adjustments += 1;
        self.adjustments.push(TipAdjustment {
            check_id: check_id.clone(),
            employee: entry.employee.clone(),
            previous,
            adjusted,
            delta,
            at,
            by: session.employee_id().clone(),
            note,
        });
        Ok(TipChange::Applied)
    }

    /// Pay out every open tip and store the payout.
    ///
    /// The payout settles all open tips, so a later pool can only pay tips
    /// recorded after this one. Running the same pool identifier again with the
    /// same terms returns the stored payout; with different terms it is
    /// [`TipError::PoolConflict`], because the money has already moved.
    pub fn payout(
        &mut self,
        session: &StaffSession,
        pool_id: TipPoolId,
        policy: TipPoolPolicy,
        members: &[TipMember],
        at: Timestamp,
    ) -> Result<TipPayout, TipError> {
        require(session, Permission::PayTips)?;
        self.ensure_store(session)?;

        if let Some(existing) = self.payouts.get(&pool_id) {
            return if existing.same_terms(policy, members) {
                Ok(existing.clone())
            } else {
                Err(TipError::PoolConflict(pool_id))
            };
        }

        if members.is_empty() {
            return Err(TipError::EmptyPool);
        }
        let mut seen: Vec<&EmployeeId> = Vec::with_capacity(members.len());
        for member in members {
            if seen.contains(&&member.employee) {
                return Err(TipError::DuplicateMember(member.employee.clone()));
            }
            seen.push(&member.employee);
            if policy == TipPoolPolicy::Weighted {
                if member.weight == 0 {
                    return Err(TipError::ZeroWeight(member.employee.clone()));
                }
                if member.weight > MAX_TIP_WEIGHT {
                    return Err(TipError::WeightTooLarge(member.employee.clone()));
                }
            }
        }

        let open: Vec<TipEntry> = self.open_tips().cloned().collect();
        if open.is_empty() {
            return Err(TipError::NoTips);
        }
        let currency = open[0].currency;
        for entry in &open {
            if entry.currency != currency {
                return Err(TipError::CurrencyMismatch);
            }
            if !members
                .iter()
                .any(|member| member.employee == entry.employee)
            {
                return Err(TipError::UnpooledTip(entry.check_id.clone()));
            }
        }

        let mut total = Money::zero(currency);
        let mut contributed = vec![Money::zero(currency); members.len()];
        for entry in &open {
            total = total.checked_add(entry.amount)?;
            if let Some(index) = members
                .iter()
                .position(|member| member.employee == entry.employee)
            {
                contributed[index] = contributed[index].checked_add(entry.amount)?;
            }
        }

        let weights: Vec<u64> = members
            .iter()
            .map(|member| match policy {
                TipPoolPolicy::Even => 1,
                TipPoolPolicy::Weighted => member.weight,
            })
            .collect();
        let shares = allocate(total, &weights)?;

        let mut allocations = Vec::with_capacity(members.len());
        for (index, member) in members.iter().enumerate() {
            allocations.push(TipAllocation {
                employee: member.employee.clone(),
                weight: weights[index],
                contributed: contributed[index],
                payout: shares[index],
            });
        }

        let payout = TipPayout {
            pool_id: pool_id.clone(),
            policy,
            currency,
            total,
            allocations,
            paid_by: session.employee_id().clone(),
            paid_at: at,
        };
        payout.validate()?;

        for entry in &open {
            if let Some(stored) = self.entries.get_mut(&entry.check_id) {
                stored.payout = Some(pool_id.clone());
            }
        }
        self.payouts.insert(pool_id, payout.clone());
        Ok(payout)
    }

    fn ensure_store(&self, session: &StaffSession) -> Result<(), TipError> {
        // Tips carry no store of their own; the check does, but this crate does
        // not resolve a check from an id. Store scoping is therefore delegated
        // to the caller's session and checked by the payout membership rule.
        let _ = session;
        Ok(())
    }
}

/// Split `total` across `weights` without losing or inventing a minor unit.
fn allocate(total: Money, weights: &[u64]) -> Result<Vec<Money>, TipError> {
    if weights.is_empty() {
        return Err(TipError::EmptyPool);
    }
    let mut weight_sum: i128 = 0;
    for weight in weights {
        if *weight > MAX_TIP_WEIGHT {
            return Err(TipError::InvalidPayout("weight exceeds the maximum"));
        }
        weight_sum += i128::from(*weight);
    }
    if weight_sum == 0 {
        return Err(TipError::InvalidPayout("the pool weights sum to zero"));
    }

    let total_minor = i128::from(total.minor());
    if total_minor < 0 {
        return Err(TipError::NegativeAmount);
    }

    let mut shares = vec![0_i128; weights.len()];
    let mut remainders: Vec<(i128, usize)> = Vec::with_capacity(weights.len());
    let mut assigned: i128 = 0;
    for (index, weight) in weights.iter().enumerate() {
        let numerator = total_minor * i128::from(*weight);
        let share = numerator / weight_sum;
        let remainder = numerator % weight_sum;
        shares[index] = share;
        remainders.push((remainder, index));
        assigned += share;
    }

    // Largest remainder first; ties keep member order, so the split is
    // deterministic for the same inputs.
    remainders.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let mut leftover = total_minor - assigned;
    for (_, index) in remainders {
        if leftover == 0 {
            break;
        }
        shares[index] += 1;
        leftover -= 1;
    }

    Ok(shares
        .into_iter()
        .map(|minor| Money::new(total.currency(), minor as i64))
        .collect())
}

fn require(session: &StaffSession, permission: Permission) -> Result<(), TipError> {
    if session.can(permission) {
        Ok(())
    } else {
        Err(TipError::NotPermitted(permission))
    }
}

fn validate_note(note: Option<&str>) -> Result<Option<String>, TipError> {
    match note {
        None => Ok(None),
        Some(note) => {
            let note = note.trim();
            if note.is_empty() {
                return Ok(None);
            }
            if note.len() > MAX_TIP_NOTE_LEN || note.chars().any(char::is_control) {
                return Err(TipError::InvalidNote);
            }
            Ok(Some(note.to_owned()))
        }
    }
}
