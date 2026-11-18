// SPDX-License-Identifier: AGPL-3.0-only

//! POS-11 — employees, roles, credentials and operational permissions.
//!
//! The existing [`Employee`] is the ownership record for an order. This module
//! adds the operational profile a shift needs: a permission set derived from
//! the employee's roles, opaque PIN/badge references, and a scoped
//! [`StaffSession`] created only after the caller has authenticated the
//! employee.
//!
//! # Credentials
//!
//! [`PinRef`] and [`BadgeRef`] are *references* to credentials held by F-03,
//! not the PIN digits or badge secret. This crate never stores, hashes or
//! compares a password/PIN; authentication and credential verification remain
//! in the F-03 layer. Keeping only a non-secret reference avoids turning a
//! domain model into a weak password store.
//!
//! # Permissions
//!
//! [`PermissionSet`] is a small, deterministic bit set. [`PermissionSet::for_roles`]
//! maps POS ownership roles to operational permissions:
//!
//! | Role | Permissions |
//! |---|---|
//! | `Cashier` | sell, count drawer, view X report |
//! | `Supervisor` | all operational permissions except employee administration |
//! | `Manager` | all permissions |
//!
//! A caller can grant or revoke individual permissions when creating an
//! [`EmployeeAccess`]. A [`StaffSession`] snapshots the resulting set, so a
//! later directory change does not silently widen an already-open session.

use std::collections::BTreeMap;

use crate::ids::{validate_identifier, EmployeeId, StoreId, TerminalId};
use crate::ownership::{Employee, EmployeeRole};

/// One operational capability checked by the shift and reporting layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// Ring and record a sale on a shift.
    Sell,
    /// Record a refund against a sale.
    Refund,
    /// Record a discount (the actual discount arithmetic remains POS-01).
    Discount,
    /// Record a void.
    Void,
    /// Open a shift.
    OpenShift,
    /// Close a shift and produce the Z report.
    CloseShift,
    /// Add cash to the drawer.
    CashIn,
    /// Remove cash from the drawer.
    CashOut,
    /// Remove cash for a safe drop.
    SafeDrop,
    /// Count the drawer.
    CountDrawer,
    /// Read an X report.
    ViewXReport,
    /// Run a Z report (through [`Permission::CloseShift`]).
    RunZReport,
    /// Import and reconcile offline shift events.
    ReconcileOffline,
    /// Add or change employee access and permissions.
    ManageEmployees,
    /// Ingest settlement files and reconcile them against payment intents.
    SettleBatch,
    /// Work a chargeback case and pay a lost one.
    ManageChargebacks,
    /// Adjust tips and run a tip-pool payout.
    PayTips,
}

impl Permission {
    /// Every permission, in stable order.
    pub const ALL: [Permission; 17] = [
        Permission::Sell,
        Permission::Refund,
        Permission::Discount,
        Permission::Void,
        Permission::OpenShift,
        Permission::CloseShift,
        Permission::CashIn,
        Permission::CashOut,
        Permission::SafeDrop,
        Permission::CountDrawer,
        Permission::ViewXReport,
        Permission::RunZReport,
        Permission::ReconcileOffline,
        Permission::ManageEmployees,
        Permission::SettleBatch,
        Permission::ManageChargebacks,
        Permission::PayTips,
    ];

    /// Stable label for logs and policy.
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Sell => "sell",
            Permission::Refund => "refund",
            Permission::Discount => "discount",
            Permission::Void => "void",
            Permission::OpenShift => "open_shift",
            Permission::CloseShift => "close_shift",
            Permission::CashIn => "cash_in",
            Permission::CashOut => "cash_out",
            Permission::SafeDrop => "safe_drop",
            Permission::CountDrawer => "count_drawer",
            Permission::ViewXReport => "view_x_report",
            Permission::RunZReport => "run_z_report",
            Permission::ReconcileOffline => "reconcile_offline",
            Permission::ManageEmployees => "manage_employees",
            Permission::SettleBatch => "settle_batch",
            Permission::ManageChargebacks => "manage_chargebacks",
            Permission::PayTips => "pay_tips",
        }
    }

    const fn bit(self) -> u32 {
        1_u32 << (self as u32)
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A deterministic set of [`Permission`]s.
///
/// The set is a `u32` bit field, so it can hold up to 32 permissions without
/// changing its representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PermissionSet(u32);

impl PermissionSet {
    /// An empty set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Every permission.
    pub fn all() -> Self {
        let mut set = Self::empty();
        for permission in Permission::ALL {
            set.insert(permission);
        }
        set
    }

    /// Build from an explicit list.
    pub fn from_permissions(permissions: impl IntoIterator<Item = Permission>) -> Self {
        let mut set = Self::empty();
        for permission in permissions {
            set.insert(permission);
        }
        set
    }

    /// The permission set implied by one or more ownership roles.
    pub fn for_roles(roles: &[EmployeeRole]) -> Self {
        let mut set = Self::empty();
        for role in roles {
            match role {
                EmployeeRole::Cashier => {
                    set.insert(Permission::Sell);
                    set.insert(Permission::CountDrawer);
                    set.insert(Permission::ViewXReport);
                }
                EmployeeRole::Supervisor => {
                    set = set.union(Self::all().without(Permission::ManageEmployees));
                }
                EmployeeRole::Manager => set = Self::all(),
            }
        }
        set
    }

    /// `true` when `permission` is present.
    pub const fn contains(self, permission: Permission) -> bool {
        self.0 & permission.bit() != 0
    }

    /// Grant one permission.
    pub fn insert(&mut self, permission: Permission) {
        self.0 |= permission.bit();
    }

    /// Revoke one permission.
    pub fn remove(&mut self, permission: Permission) {
        self.0 &= !permission.bit();
    }

    /// Union of two sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// This set with `permission` removed.
    pub fn without(self, permission: Permission) -> Self {
        let mut set = self;
        set.remove(permission);
        set
    }

    /// `true` when the set contains no permissions.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Number of permissions in the set.
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }
}

/// Opaque reference to a PIN credential held by F-03.
///
/// This is not the PIN. It is a stable lookup handle; the secret is never
/// passed into or stored by this crate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinRef(String);

impl PinRef {
    /// Construct a reference. Empty, oversized or control-bearing values are
    /// rejected.
    pub fn new(reference: impl Into<String>) -> Result<Self, StaffError> {
        let reference = reference.into();
        validate_identifier(&reference, "PIN reference").map_err(|_| StaffError::InvalidPinRef)?;
        Ok(Self(reference))
    }

    /// The opaque reference text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque reference to a badge credential held by F-03.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BadgeRef(String);

impl BadgeRef {
    /// Construct a reference. Empty, oversized or control-bearing values are
    /// rejected.
    pub fn new(reference: impl Into<String>) -> Result<Self, StaffError> {
        let reference = reference.into();
        validate_identifier(&reference, "badge reference")
            .map_err(|_| StaffError::InvalidBadgeRef)?;
        Ok(Self(reference))
    }

    /// The opaque reference text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An employee plus operational access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmployeeAccess {
    employee: Employee,
    permissions: PermissionSet,
    pin: Option<PinRef>,
    badge: Option<BadgeRef>,
}

impl EmployeeAccess {
    /// Build access for an employee. At least one PIN or badge reference is
    /// required, and permissions start from the employee's roles.
    pub fn new(
        employee: Employee,
        pin: Option<PinRef>,
        badge: Option<BadgeRef>,
    ) -> Result<Self, StaffError> {
        if pin.is_none() && badge.is_none() {
            return Err(StaffError::NoCredential);
        }
        let permissions = PermissionSet::for_roles(employee.roles());
        Ok(Self {
            employee,
            permissions,
            pin,
            badge,
        })
    }

    /// Replace the role-derived permission set. This is how a deployment
    /// applies least privilege or a temporary grant.
    pub fn with_permissions(mut self, permissions: PermissionSet) -> Self {
        self.permissions = permissions;
        self
    }

    /// The ownership employee record.
    pub fn employee(&self) -> &Employee {
        &self.employee
    }

    /// The employee identifier.
    pub fn employee_id(&self) -> &EmployeeId {
        self.employee.id()
    }

    /// The employee's store.
    pub fn store_id(&self) -> &StoreId {
        self.employee.store_id()
    }

    /// The employee's ownership roles.
    pub fn roles(&self) -> &[EmployeeRole] {
        self.employee.roles()
    }

    /// The effective operational permissions.
    pub fn permissions(&self) -> PermissionSet {
        self.permissions
    }

    /// The opaque PIN reference, if configured.
    pub fn pin(&self) -> Option<&PinRef> {
        self.pin.as_ref()
    }

    /// The opaque badge reference, if configured.
    pub fn badge(&self) -> Option<&BadgeRef> {
        self.badge.as_ref()
    }
}

/// A directory of employees and their operational access.
///
/// The directory is an in-memory value object. It does not authenticate a
/// credential; F-03 verifies the PIN/badge and then the caller asks for a
/// session by employee id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EmployeeDirectory {
    employees: BTreeMap<EmployeeId, EmployeeAccess>,
}

impl EmployeeDirectory {
    /// An empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register access. Employee, PIN and badge references are unique.
    pub fn add(&mut self, access: EmployeeAccess) -> Result<(), StaffError> {
        if self.employees.contains_key(access.employee_id()) {
            return Err(StaffError::DuplicateEmployee(access.employee_id().clone()));
        }
        if let Some(pin) = access.pin() {
            if self
                .employees
                .values()
                .any(|existing| existing.pin() == Some(pin))
            {
                return Err(StaffError::DuplicatePin(pin.clone()));
            }
        }
        if let Some(badge) = access.badge() {
            if self
                .employees
                .values()
                .any(|existing| existing.badge() == Some(badge))
            {
                return Err(StaffError::DuplicateBadge(badge.clone()));
            }
        }
        self.employees.insert(access.employee_id().clone(), access);
        Ok(())
    }

    /// Look up an employee's access.
    pub fn access(&self, employee_id: &EmployeeId) -> Option<&EmployeeAccess> {
        self.employees.get(employee_id)
    }

    /// Borrow every employee, in identifier order.
    pub fn employees(&self) -> impl Iterator<Item = &EmployeeAccess> {
        self.employees.values()
    }

    /// Create a session for an authenticated employee at a terminal.
    ///
    /// The session snapshots the permission set. The caller is responsible for
    /// having authenticated the credential through F-03.
    pub fn session(
        &self,
        employee_id: &EmployeeId,
        terminal_id: TerminalId,
    ) -> Result<StaffSession, StaffError> {
        let access = self
            .access(employee_id)
            .ok_or_else(|| StaffError::UnknownEmployee(employee_id.clone()))?;
        Ok(StaffSession {
            employee_id: employee_id.clone(),
            store_id: access.store_id().clone(),
            terminal_id,
            permissions: access.permissions(),
        })
    }
}

/// An authenticated employee scoped to one store and terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaffSession {
    employee_id: EmployeeId,
    store_id: StoreId,
    terminal_id: TerminalId,
    permissions: PermissionSet,
}

impl StaffSession {
    /// The employee operating the session.
    pub fn employee_id(&self) -> &EmployeeId {
        &self.employee_id
    }

    /// The employee's store.
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// The terminal the employee is using.
    pub fn terminal_id(&self) -> &TerminalId {
        &self.terminal_id
    }

    /// The snapshotted permission set.
    pub fn permissions(&self) -> PermissionSet {
        self.permissions
    }

    /// `true` when the session carries `permission`.
    pub fn can(&self, permission: Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Require `permission` or return a stable denial.
    pub fn require(&self, permission: Permission) -> Result<(), StaffError> {
        if self.can(permission) {
            Ok(())
        } else {
            Err(StaffError::NotPermitted(permission))
        }
    }
}

/// A rejected employee, credential or permission operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StaffError {
    /// The PIN reference was empty, oversized or control-bearing.
    InvalidPinRef,
    /// The badge reference was empty, oversized or control-bearing.
    InvalidBadgeRef,
    /// Neither a PIN nor a badge reference was supplied.
    NoCredential,
    /// The employee already exists in the directory.
    DuplicateEmployee(EmployeeId),
    /// The PIN reference is already bound to another employee.
    DuplicatePin(PinRef),
    /// The badge reference is already bound to another employee.
    DuplicateBadge(BadgeRef),
    /// The employee is not registered.
    UnknownEmployee(EmployeeId),
    /// The session lacks the required permission.
    NotPermitted(Permission),
}

impl StaffError {
    /// Stable reason code for logs and policy.
    pub fn code(&self) -> &'static str {
        match self {
            StaffError::InvalidPinRef => "staff.invalid_pin_ref",
            StaffError::InvalidBadgeRef => "staff.invalid_badge_ref",
            StaffError::NoCredential => "staff.no_credential",
            StaffError::DuplicateEmployee(_) => "staff.duplicate_employee",
            StaffError::DuplicatePin(_) => "staff.duplicate_pin",
            StaffError::DuplicateBadge(_) => "staff.duplicate_badge",
            StaffError::UnknownEmployee(_) => "staff.unknown_employee",
            StaffError::NotPermitted(_) => "staff.not_permitted",
        }
    }
}

impl std::fmt::Display for StaffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StaffError::InvalidPinRef => f.write_str("invalid PIN reference"),
            StaffError::InvalidBadgeRef => f.write_str("invalid badge reference"),
            StaffError::NoCredential => f.write_str("employee has no PIN or badge reference"),
            StaffError::DuplicateEmployee(id) => write!(f, "duplicate employee: {id}"),
            StaffError::DuplicatePin(reference) => {
                write!(f, "duplicate PIN reference: {}", reference.as_str())
            }
            StaffError::DuplicateBadge(reference) => {
                write!(f, "duplicate badge reference: {}", reference.as_str())
            }
            StaffError::UnknownEmployee(id) => write!(f, "unknown employee: {id}"),
            StaffError::NotPermitted(permission) => {
                write!(f, "permission denied: {permission}")
            }
        }
    }
}

impl std::error::Error for StaffError {}
