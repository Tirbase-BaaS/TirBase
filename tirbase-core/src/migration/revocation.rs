//! Migration revocation — halt in-progress transforms, block future execution (Req 18.5–18.7).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::errors::TirBaseError;
use crate::migration::migration_delta::{MigrationId, MigrationRevocationDelta};

/// Registry of revoked migration IDs.
/// Once a migration is revoked it can never be applied again.
#[derive(Debug, Default)]
pub struct RevokedMigrationRegistry {
    revoked: std::collections::HashSet<MigrationId>,
}

impl RevokedMigrationRegistry {
    /// Check if a migration has been revoked.
    pub fn is_revoked(&self, id: &MigrationId) -> bool {
        self.revoked.contains(id)
    }

    /// Process an incoming MigrationRevocationDelta (Req 18.5–18.7).
    ///
    /// Verifies M-of-N Manager signatures, halts any in-progress sandbox
    /// execution, and permanently blocks the migration.
    pub fn apply_revocation(
        &mut self,
        revocation: MigrationRevocationDelta,
        threshold_m: usize,
    ) -> Result<(), TirBaseError> {
        todo!("Task 8: implement revocation with M-of-N check and sandbox halt")
    }
}
