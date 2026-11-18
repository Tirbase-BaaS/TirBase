// SPDX-License-Identifier: AGPL-3.0-only

//! Opaque string identifiers for the POS ownership and order model.
//!
//! Identifiers are supplied by the caller (the offline device or a future
//! connector). The model never mints one from a clock or random source, so a
//! replayed command stream carries identical identifiers.

use crate::error::PosError;

/// Maximum accepted identifier or label length, in bytes.
pub const MAX_ID_LEN: usize = 128;

pub(crate) fn validate_identifier(value: &str, what: &'static str) -> Result<(), PosError> {
    if value.is_empty() || value.len() > MAX_ID_LEN || value.chars().any(char::is_control) {
        return Err(PosError::InvalidIdentifier(what));
    }
    Ok(())
}

macro_rules! id_newtype {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(
            Clone,
            Debug,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Construct an identifier, rejecting empty/oversized/control input.
            pub fn new(value: impl Into<String>) -> Result<Self, PosError> {
                let value = value.into();
                validate_identifier(&value, $what)?;
                Ok(Self(value))
            }

            /// Borrow the identifier text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = PosError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        // Deserialisation goes through `new`, so a wire value cannot bypass the
        // empty/oversized/control-character validation.
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

id_newtype!(
    /// Identifies a selling location.
    StoreId,
    "store id"
);
id_newtype!(
    /// Identifies a till or self-service terminal inside one store.
    TerminalId,
    "terminal id"
);
id_newtype!(
    /// Identifies the employee operating the terminal.
    EmployeeId,
    "employee id"
);
id_newtype!(
    /// Identifies an optional customer attached to the order.
    CustomerId,
    "customer id"
);
id_newtype!(
    /// Identifies the order aggregate.
    OrderId,
    "order id"
);
id_newtype!(
    /// Identifies one check (a payable bill) inside an order.
    CheckId,
    "check id"
);
id_newtype!(
    /// Identifies one line item inside a check.
    LineItemId,
    "line item id"
);
id_newtype!(
    /// Identifies one payment link.
    PaymentId,
    "payment id"
);
id_newtype!(
    /// Identifies one refund record.
    RefundId,
    "refund id"
);
id_newtype!(
    /// Caller-supplied idempotency key for one order command.
    OperationId,
    "operation id"
);
id_newtype!(
    /// Identifies one payment intent.
    PaymentIntentId,
    "payment intent id"
);
id_newtype!(
    /// Caller-supplied idempotency key for one payment intent request.
    IdempotencyKey,
    "idempotency key"
);
id_newtype!(
    /// Caller-supplied anti-replay nonce for one payment envelope (POS-06).
    ///
    /// A nonce is globally unique inside one [`crate::envelope::PaymentDesk`]:
    /// reusing it on another terminal, epoch or operation is a conflict, never
    /// a replay.
    PaymentNonce,
    "payment nonce"
);
id_newtype!(
    /// Caller-supplied idempotent identifier for one kitchen-display ticket.
    KdsTicketId,
    "KDS ticket id"
);
id_newtype!(
    /// Identifies one immutable catalog version.
    CatalogVersionId,
    "catalog version id"
);
id_newtype!(
    /// Identifies one immutable price-book version.
    PriceBookVersionId,
    "price book version id"
);
id_newtype!(
    /// Identifies one immutable tax-table version.
    TaxTableVersionId,
    "tax table version id"
);
id_newtype!(
    /// Identifies a sellable catalog item.
    CatalogItemId,
    "catalog item id"
);
id_newtype!(
    /// Identifies a catalog modifier.
    ModifierId,
    "modifier id"
);
id_newtype!(
    /// Identifies a menu that links catalog items.
    MenuId,
    "menu id"
);
id_newtype!(
    /// Identifies one recipe component linked to an item.
    RecipeComponentId,
    "recipe component id"
);
id_newtype!(
    /// Identifies a tax jurisdiction.
    JurisdictionId,
    "jurisdiction id"
);
id_newtype!(
    /// Caller-supplied identifier for one approval request.
    ApprovalId,
    "approval id"
);
id_newtype!(
    /// Identifies one operator shift on one terminal (POS-11).
    ShiftId,
    "shift id"
);
id_newtype!(
    /// Caller-supplied idempotent identifier for one drawer cash movement.
    CashMovementId,
    "cash movement id"
);
id_newtype!(
    /// Caller-supplied idempotent identifier for one drawer count.
    DrawerCountId,
    "drawer count id"
);
id_newtype!(
    /// Identifies one processor settlement batch (POS-12).
    SettlementBatchId,
    "settlement batch id"
);
id_newtype!(
    /// Identifies one record inside a processor settlement file (POS-12).
    ProcessorRecordId,
    "processor record id"
);
id_newtype!(
    /// Identifies one chargeback case (POS-12).
    ChargebackId,
    "chargeback id"
);
id_newtype!(
    /// Identifies one tip pool payout (POS-12).
    TipPoolId,
    "tip pool id"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_reject_empty_and_control_characters() {
        assert_eq!(
            StoreId::new(""),
            Err(PosError::InvalidIdentifier("store id"))
        );
        assert_eq!(
            CheckId::new("check\n1"),
            Err(PosError::InvalidIdentifier("check id"))
        );
    }

    #[test]
    fn identifiers_reject_oversized_input() {
        let long = "x".repeat(MAX_ID_LEN + 1);
        assert!(StoreId::new(long).is_err());
    }

    #[test]
    fn identifiers_are_transparent_in_serde() {
        let id = CheckId::new("check-1").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"check-1\"");
        let back: CheckId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
