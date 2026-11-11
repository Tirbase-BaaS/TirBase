//! Table-driven authorization matrix (PV-3.3, CLAIM-56.1).
//!
//! `AUTHORIZATION_MATRIX` enumerates each operation and, per `CommandRole`,
//! whether a credential of that role is authorized (`✓`) or denied (`—`).
//! Negative tests are auto-generated for every denied cell and a property test
//! (P19) asserts every denied cell yields a typed authorization error.
//!
//! Production callers: role/authorization checks in `tirbase-guard` (policy,
//! lockdown, epoch, time-ratchet, quarantine replay, admin-signed operations)
//! and cross-role rejection coverage (task 9.6). The matrix is the single
//! source of truth for "—" coverage.

use core::fmt;

use tirbase_types::CommandRole;

/// Guard-side authorization operations (first seven role columns of the
/// Operation × Role Authorization Matrix in requirements).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthOperation {
    SubmitCommand,
    ReadStateAudit,
    PublishTighteningPolicy,
    InitiatePolicyLoosening,
    CoSignPolicyLoosening,
    SignMigrationFirmware,
    RevokeDidKey,
    EnrollDevice,
    DecommissionDevice,
    SaturateLegacy,
    VerifyDataAdminCloseLegacy,
    LeaseTermination,
    MigrationRevocation,
    ManualQuarantineReplaySchema,
    LockdownExit,
    SubmitTimeBeacon,
    TimeRatchetResetLargeJump,
    EnrollmentEpochBumpRestore,
    EmergencyProfileActivation,
}

impl AuthOperation {
    /// Stable operation name used in diagnostics/tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubmitCommand => "Submit command",
            Self::ReadStateAudit => "Read state / audit",
            Self::PublishTighteningPolicy => "Publish tightening policy",
            Self::InitiatePolicyLoosening => "Initiate policy loosening",
            Self::CoSignPolicyLoosening => "Co-sign policy loosening",
            Self::SignMigrationFirmware => "Sign migration/firmware",
            Self::RevokeDidKey => "Revoke DID / key",
            Self::EnrollDevice => "Enroll device",
            Self::DecommissionDevice => "Decommission device",
            Self::SaturateLegacy => "Saturate (legacy)",
            Self::VerifyDataAdminCloseLegacy => "VERIFY_DATA / ADMIN_CLOSE (legacy)",
            Self::LeaseTermination => "Lease termination",
            Self::MigrationRevocation => "Migration revocation",
            Self::ManualQuarantineReplaySchema => "Manual quarantine replay (Schema)",
            Self::LockdownExit => "LOCKDOWN exit",
            Self::SubmitTimeBeacon => "Submit time beacon",
            Self::TimeRatchetResetLargeJump => "Time-ratchet reset (large jump)",
            Self::EnrollmentEpochBumpRestore => "Enrollment epoch bump (restore)",
            Self::EmergencyProfileActivation => "Emergency profile activation",
        }
    }

    /// All matrix operations in declaration order.
    pub const ALL: [AuthOperation; 19] = [
        Self::SubmitCommand,
        Self::ReadStateAudit,
        Self::PublishTighteningPolicy,
        Self::InitiatePolicyLoosening,
        Self::CoSignPolicyLoosening,
        Self::SignMigrationFirmware,
        Self::RevokeDidKey,
        Self::EnrollDevice,
        Self::DecommissionDevice,
        Self::SaturateLegacy,
        Self::VerifyDataAdminCloseLegacy,
        Self::LeaseTermination,
        Self::MigrationRevocation,
        Self::ManualQuarantineReplaySchema,
        Self::LockdownExit,
        Self::SubmitTimeBeacon,
        Self::TimeRatchetResetLargeJump,
        Self::EnrollmentEpochBumpRestore,
        Self::EmergencyProfileActivation,
    ];
}

/// Per-cell authorization in the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixCell {
    /// `✓` — role is authorized for the operation (possibly with qualifiers
    /// documented in requirements; qualifiers are enforced by the specific
    /// operation path, not by this cell).
    Allowed,
    /// `—` — role credential is rejected for the operation.
    Denied,
}

/// One row of the authorization matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatrixRow {
    pub operation: AuthOperation,
    /// [CommandIssuer, PolicyAuthority, UpdateSigner, RevocationManager, Auditor, TimeAnchor]
    pub cells: [MatrixCell; 6],
}

/// Roles covered by the matrix columns (cross-role tests SHALL cover every `—`
/// cell in the first seven columns; "Root Keys" are offline ceremony keys and
/// not issued as Biscuit roles, so not modeled here).
pub const MATRIX_ROLES: [CommandRole; 6] = [
    CommandRole::CommandIssuer,
    CommandRole::PolicyAuthority,
    CommandRole::UpdateSigner,
    CommandRole::RevocationManager,
    CommandRole::Auditor,
    CommandRole::TimeAnchor,
];

/// Column index for a matrix role.
pub const fn role_index(role: CommandRole) -> usize {
    match role {
        CommandRole::CommandIssuer => 0,
        CommandRole::PolicyAuthority => 1,
        CommandRole::UpdateSigner => 2,
        CommandRole::RevocationManager => 3,
        CommandRole::Auditor => 4,
        CommandRole::TimeAnchor => 5,
    }
}

/// Table-driven Operation × Role Authorization Matrix (PV-3.3).
///
/// Source of truth: requirements authorization matrix (first six role columns).
/// `—` => `Denied`, `✓...` => `Allowed`.
pub const AUTHORIZATION_MATRIX: [MatrixRow; 19] = [
    MatrixRow {
        operation: AuthOperation::SubmitCommand,
        cells: [
            MatrixCell::Allowed, // CommandIssuer
            MatrixCell::Denied,  // PolicyAuthority
            MatrixCell::Denied,  // UpdateSigner
            MatrixCell::Denied,  // RevocationManager
            MatrixCell::Denied,  // Auditor
            MatrixCell::Denied,  // TimeAnchor
        ],
    },
    MatrixRow {
        operation: AuthOperation::ReadStateAudit,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Allowed, // Auditor
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::PublishTighteningPolicy,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Allowed, // PolicyAuthority
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::InitiatePolicyLoosening,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Allowed, // PolicyAuthority (initiates)
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::CoSignPolicyLoosening,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Allowed, // PolicyAuthority
            MatrixCell::Denied,
            MatrixCell::Allowed, // RevocationManager (counts toward M)
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::SignMigrationFirmware,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Allowed, // UpdateSigner
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::RevokeDidKey,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Allowed, // RevocationManager (M-of-N required)
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::EnrollDevice,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Allowed, // PolicyAuthority (Enroller sub-role)
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::DecommissionDevice,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Allowed, // RevocationManager
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::SaturateLegacy,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::VerifyDataAdminCloseLegacy,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Allowed, // PolicyAuthority (mapped)
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::LeaseTermination,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Allowed, // RevocationManager (mapped)
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::MigrationRevocation,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Allowed, // UpdateSigner (co-sign)
            MatrixCell::Allowed, // RevocationManager (co-sign)
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::ManualQuarantineReplaySchema,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Allowed, // PolicyAuthority
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::LockdownExit,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Allowed, // PolicyAuthority (M-of-N, distinct roles)
            MatrixCell::Denied,
            MatrixCell::Allowed, // RevocationManager (counts toward M)
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::SubmitTimeBeacon,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Allowed, // TimeAnchor
        ],
    },
    MatrixRow {
        operation: AuthOperation::TimeRatchetResetLargeJump,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Denied,
            MatrixCell::Allowed, // TimeAnchor (M-of-N)
        ],
    },
    MatrixRow {
        operation: AuthOperation::EnrollmentEpochBumpRestore,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Allowed, // PolicyAuthority
            MatrixCell::Denied,
            MatrixCell::Allowed, // RevocationManager (co-sign)
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
    MatrixRow {
        operation: AuthOperation::EmergencyProfileActivation,
        cells: [
            MatrixCell::Denied,
            MatrixCell::Allowed, // PolicyAuthority (M-of-N)
            MatrixCell::Denied,
            MatrixCell::Allowed, // RevocationManager (counts toward M)
            MatrixCell::Denied,
            MatrixCell::Denied,
        ],
    },
];

/// Typed authorization failure for a denied matrix cell (PV-3.2/PV-3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixAuthorizationError {
    pub operation: AuthOperation,
    pub attempted_role: CommandRole,
}

impl fmt::Display for MatrixAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "role {} is not authorized for operation '{}'",
            self.attempted_role.as_str(),
            self.operation.as_str()
        )
    }
}

impl std::error::Error for MatrixAuthorizationError {}

/// Look up the matrix cell for `(operation, role)`.
pub fn cell_for(operation: AuthOperation, role: CommandRole) -> MatrixCell {
    for row in AUTHORIZATION_MATRIX {
        if row.operation == operation {
            return row.cells[role_index(role)];
        }
    }
    // Exhaustive over AuthOperation; unreachable in practice.
    MatrixCell::Denied
}

/// Check a role credential against the authorization matrix (typed result).
pub fn check_role_authorization(
    operation: AuthOperation,
    attempted_role: CommandRole,
) -> Result<(), MatrixAuthorizationError> {
    match cell_for(operation, attempted_role) {
        MatrixCell::Allowed => Ok(()),
        MatrixCell::Denied => Err(MatrixAuthorizationError {
            operation,
            attempted_role,
        }),
    }
}

/// Iterator over every denied (`—`) cell in the matrix.
pub fn denied_cells() -> impl Iterator<Item = (AuthOperation, CommandRole)> {
    AUTHORIZATION_MATRIX.into_iter().flat_map(|row| {
        MATRIX_ROLES
            .into_iter()
            .enumerate()
            .filter_map(move |(idx, role)| {
                if matches!(row.cells[idx], MatrixCell::Denied) {
                    Some((row.operation, role))
                } else {
                    None
                }
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_denied_cell_rejected_with_typed_error() {
        let mut count = 0usize;
        for (op, role) in denied_cells() {
            let err = check_role_authorization(op, role).expect_err("denied cell must reject");
            assert_eq!(err.operation, op);
            assert_eq!(err.attempted_role, role);
            assert!(!err.to_string().is_empty());
            count += 1;
        }
        assert!(count > 0, "matrix must contain denied cells");
    }
}
