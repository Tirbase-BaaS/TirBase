// SPDX-License-Identifier: AGPL-3.0-only

//! Store, terminal, employee and customer ownership.
//!
//! An order is owned by exactly one store, terminal and employee, with an
//! optional customer. The [`Organization`] registry is the authority for those
//! relationships: creating an order validates that the terminal and employee
//! belong to the stated store and that any customer reference resolves.
//!
//! The model is jurisdiction-neutral. It records *who* a sale belongs to, not a
//! tax identity, address or other locally regulated attribute.

use std::collections::BTreeMap;

use crate::error::PosError;
use crate::ids::{validate_identifier, CustomerId, EmployeeId, StoreId, TerminalId};

/// A selling location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    id: StoreId,
    name: String,
}

impl Store {
    /// Construct a store.
    pub fn new(id: StoreId, name: impl Into<String>) -> Result<Self, PosError> {
        let name = name.into();
        validate_identifier(&name, "store name")?;
        Ok(Self { id, name })
    }

    /// The store identifier.
    pub fn id(&self) -> &StoreId {
        &self.id
    }

    /// The display name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A till or self-service terminal that belongs to one store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terminal {
    id: TerminalId,
    store_id: StoreId,
    label: String,
}

impl Terminal {
    /// Construct a terminal owned by `store_id`.
    pub fn new(
        id: TerminalId,
        store_id: StoreId,
        label: impl Into<String>,
    ) -> Result<Self, PosError> {
        let label = label.into();
        validate_identifier(&label, "terminal label")?;
        Ok(Self {
            id,
            store_id,
            label,
        })
    }

    /// The terminal identifier.
    pub fn id(&self) -> &TerminalId {
        &self.id
    }

    /// The owning store.
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// The display label.
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Coarse employee role. Authorisation policy is not modelled here; POS-02
/// decides which role may void, discount or refund.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmployeeRole {
    /// Operates a till.
    Cashier,
    /// May supervise or correct a check.
    Supervisor,
    /// May administer the store.
    Manager,
}

/// An employee assigned to one store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Employee {
    id: EmployeeId,
    store_id: StoreId,
    display_name: String,
    roles: Vec<EmployeeRole>,
}

impl Employee {
    /// Construct an employee assigned to `store_id`.
    pub fn new(
        id: EmployeeId,
        store_id: StoreId,
        display_name: impl Into<String>,
        roles: Vec<EmployeeRole>,
    ) -> Result<Self, PosError> {
        let display_name = display_name.into();
        validate_identifier(&display_name, "employee name")?;
        if roles.is_empty() {
            return Err(PosError::InvalidIdentifier("employee role"));
        }
        Ok(Self {
            id,
            store_id,
            display_name,
            roles,
        })
    }

    /// The employee identifier.
    pub fn id(&self) -> &EmployeeId {
        &self.id
    }

    /// The store the employee is assigned to.
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// The display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The assigned roles.
    pub fn roles(&self) -> &[EmployeeRole] {
        &self.roles
    }
}

/// An optional customer attached to an order.
///
/// Only a caller-supplied reference and display name are modelled. The crate
/// stores no payment-card, government-identity or contact data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Customer {
    id: CustomerId,
    display_name: Option<String>,
}

impl Customer {
    /// Construct a customer with an optional display name.
    pub fn new(id: CustomerId, display_name: Option<String>) -> Result<Self, PosError> {
        if let Some(name) = &display_name {
            validate_identifier(name, "customer name")?;
        }
        Ok(Self { id, display_name })
    }

    /// The customer identifier.
    pub fn id(&self) -> &CustomerId {
        &self.id
    }

    /// The optional display name.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
}

/// Who an order belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ownership {
    store_id: StoreId,
    terminal_id: TerminalId,
    employee_id: EmployeeId,
    customer_id: Option<CustomerId>,
}

impl Ownership {
    /// Construct an ownership record. Structural validity is checked by
    /// [`Organization::validate_ownership`].
    pub fn new(
        store_id: StoreId,
        terminal_id: TerminalId,
        employee_id: EmployeeId,
        customer_id: Option<CustomerId>,
    ) -> Self {
        Self {
            store_id,
            terminal_id,
            employee_id,
            customer_id,
        }
    }

    /// The owning store.
    pub fn store_id(&self) -> &StoreId {
        &self.store_id
    }

    /// The terminal the sale was rung on.
    pub fn terminal_id(&self) -> &TerminalId {
        &self.terminal_id
    }

    /// The employee responsible for the sale.
    pub fn employee_id(&self) -> &EmployeeId {
        &self.employee_id
    }

    /// The optional customer.
    pub fn customer_id(&self) -> Option<&CustomerId> {
        self.customer_id.as_ref()
    }
}

/// The registry that owns stores, terminals, employees and customers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Organization {
    stores: BTreeMap<StoreId, Store>,
    terminals: BTreeMap<TerminalId, Terminal>,
    employees: BTreeMap<EmployeeId, Employee>,
    customers: BTreeMap<CustomerId, Customer>,
}

impl Organization {
    /// An empty ownership registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a store.
    pub fn add_store(&mut self, store: Store) -> Result<(), PosError> {
        if self.stores.contains_key(store.id()) {
            return Err(PosError::AlreadyRegistered("store"));
        }
        self.stores.insert(store.id().clone(), store);
        Ok(())
    }

    /// Register a terminal. The referenced store must already exist.
    pub fn add_terminal(&mut self, terminal: Terminal) -> Result<(), PosError> {
        if self.terminals.contains_key(terminal.id()) {
            return Err(PosError::AlreadyRegistered("terminal"));
        }
        if !self.stores.contains_key(terminal.store_id()) {
            return Err(PosError::UnknownStore);
        }
        self.terminals.insert(terminal.id().clone(), terminal);
        Ok(())
    }

    /// Register an employee. The referenced store must already exist.
    pub fn add_employee(&mut self, employee: Employee) -> Result<(), PosError> {
        if self.employees.contains_key(employee.id()) {
            return Err(PosError::AlreadyRegistered("employee"));
        }
        if !self.stores.contains_key(employee.store_id()) {
            return Err(PosError::UnknownStore);
        }
        self.employees.insert(employee.id().clone(), employee);
        Ok(())
    }

    /// Register a customer.
    pub fn add_customer(&mut self, customer: Customer) -> Result<(), PosError> {
        if self.customers.contains_key(customer.id()) {
            return Err(PosError::AlreadyRegistered("customer"));
        }
        self.customers.insert(customer.id().clone(), customer);
        Ok(())
    }

    /// Look up a store.
    pub fn store(&self, id: &StoreId) -> Option<&Store> {
        self.stores.get(id)
    }

    /// Look up a terminal.
    pub fn terminal(&self, id: &TerminalId) -> Option<&Terminal> {
        self.terminals.get(id)
    }

    /// Look up an employee.
    pub fn employee(&self, id: &EmployeeId) -> Option<&Employee> {
        self.employees.get(id)
    }

    /// Look up a customer.
    pub fn customer(&self, id: &CustomerId) -> Option<&Customer> {
        self.customers.get(id)
    }

    /// Validate that every reference in `ownership` resolves and is consistent.
    ///
    /// Checks, in order: the store exists, the terminal exists and belongs to
    /// that store, the employee exists and belongs to that store, and the
    /// optional customer exists.
    pub fn validate_ownership(&self, ownership: &Ownership) -> Result<(), PosError> {
        if !self.stores.contains_key(ownership.store_id()) {
            return Err(PosError::UnknownStore);
        }
        let terminal = self
            .terminals
            .get(ownership.terminal_id())
            .ok_or(PosError::UnknownTerminal)?;
        if terminal.store_id() != ownership.store_id() {
            return Err(PosError::TerminalNotInStore);
        }
        let employee = self
            .employees
            .get(ownership.employee_id())
            .ok_or(PosError::UnknownEmployee)?;
        if employee.store_id() != ownership.store_id() {
            return Err(PosError::EmployeeNotInStore);
        }
        if let Some(customer_id) = ownership.customer_id() {
            if !self.customers.contains_key(customer_id) {
                return Err(PosError::UnknownCustomer);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn organization() -> (Organization, Ownership) {
        let mut org = Organization::new();
        let store = Store::new(StoreId::new("store-1").unwrap(), "Store One").unwrap();
        let other = Store::new(StoreId::new("store-2").unwrap(), "Store Two").unwrap();
        let store_id = store.id().clone();
        let other_id = other.id().clone();
        org.add_store(store).unwrap();
        org.add_store(other).unwrap();
        org.add_terminal(
            Terminal::new(
                TerminalId::new("till-1").unwrap(),
                store_id.clone(),
                "Till 1",
            )
            .unwrap(),
        )
        .unwrap();
        org.add_terminal(
            Terminal::new(TerminalId::new("till-2").unwrap(), other_id, "Till 2").unwrap(),
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
        org.add_customer(
            Customer::new(CustomerId::new("cust-1").unwrap(), Some("Grace".into())).unwrap(),
        )
        .unwrap();
        let ownership = Ownership::new(
            store_id,
            TerminalId::new("till-1").unwrap(),
            EmployeeId::new("emp-1").unwrap(),
            Some(CustomerId::new("cust-1").unwrap()),
        );
        (org, ownership)
    }

    #[test]
    fn valid_ownership_resolves() {
        let (org, ownership) = organization();
        assert_eq!(org.validate_ownership(&ownership), Ok(()));
        assert_eq!(org.store(ownership.store_id()).unwrap().name(), "Store One");
        assert_eq!(
            org.terminal(ownership.terminal_id()).unwrap().label(),
            "Till 1"
        );
        assert_eq!(
            org.employee(ownership.employee_id()).unwrap().roles(),
            [EmployeeRole::Cashier]
        );
    }

    #[test]
    fn terminal_from_another_store_is_rejected() {
        let (org, ownership) = organization();
        let bad = Ownership::new(
            ownership.store_id().clone(),
            TerminalId::new("till-2").unwrap(),
            ownership.employee_id().clone(),
            None,
        );
        assert_eq!(
            org.validate_ownership(&bad),
            Err(PosError::TerminalNotInStore)
        );
    }

    #[test]
    fn employee_from_another_store_is_rejected() {
        let (org, ownership) = organization();
        let other_store = StoreId::new("store-2").unwrap();
        let mut org_with_employee = org.clone();
        org_with_employee
            .add_employee(
                Employee::new(
                    EmployeeId::new("emp-2").unwrap(),
                    other_store.clone(),
                    "Linus",
                    vec![EmployeeRole::Manager],
                )
                .unwrap(),
            )
            .unwrap();
        let bad = Ownership::new(
            ownership.store_id().clone(),
            ownership.terminal_id().clone(),
            EmployeeId::new("emp-2").unwrap(),
            None,
        );
        assert_eq!(
            org_with_employee.validate_ownership(&bad),
            Err(PosError::EmployeeNotInStore)
        );
    }

    #[test]
    fn unknown_references_are_rejected() {
        let (org, ownership) = organization();
        let unknown_store = Ownership::new(
            StoreId::new("nope").unwrap(),
            ownership.terminal_id().clone(),
            ownership.employee_id().clone(),
            None,
        );
        assert_eq!(
            org.validate_ownership(&unknown_store),
            Err(PosError::UnknownStore)
        );

        let unknown_terminal = Ownership::new(
            ownership.store_id().clone(),
            TerminalId::new("nope").unwrap(),
            ownership.employee_id().clone(),
            None,
        );
        assert_eq!(
            org.validate_ownership(&unknown_terminal),
            Err(PosError::UnknownTerminal)
        );

        let unknown_customer = Ownership::new(
            ownership.store_id().clone(),
            ownership.terminal_id().clone(),
            ownership.employee_id().clone(),
            Some(CustomerId::new("nope").unwrap()),
        );
        assert_eq!(
            org.validate_ownership(&unknown_customer),
            Err(PosError::UnknownCustomer)
        );
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let (mut org, ownership) = organization();
        let duplicate = Store::new(ownership.store_id().clone(), "Again").unwrap();
        assert_eq!(
            org.add_store(duplicate),
            Err(PosError::AlreadyRegistered("store"))
        );
        let orphan_terminal = Terminal::new(
            TerminalId::new("till-x").unwrap(),
            StoreId::new("nope").unwrap(),
            "X",
        )
        .unwrap();
        assert_eq!(
            org.add_terminal(orphan_terminal),
            Err(PosError::UnknownStore)
        );
    }
}
