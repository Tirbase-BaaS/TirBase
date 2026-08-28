//! Schema Migration Engine — zero-trust gate, WASM sandbox, Side-Car replay (Req 17–19).

#![allow(dead_code, unused_variables, unused_imports)]

pub mod migration_delta;
pub mod quarantine;
pub mod revocation;
pub mod sidecar;
pub mod version_path;
pub mod wasm_sandbox;

use crate::errors::TirBaseError;
use migration_delta::{MigrationDelta, MigrationRevocationDelta};

/// The Schema Migration Engine orchestrates the zero-trust gate, sandbox
/// execution, quarantine management, and Side-Car replay.
pub struct SchemaMigrationEngine {
    // TODO(task-8): inject LocalStore, QuarantineLedger, SideCarLedger,
    //               RevokedMigrationRegistry, SchemaVersionPath handles
}

impl SchemaMigrationEngine {
    /// Receive and validate an incoming MigrationDelta (Req 18.2–18.3a).
    ///
    /// Checks in order:
    /// 1. CA signature over transform_bytes
    /// 2. SHA-256 of transform_bytes matches embedded hash
    /// 3. source_schema_hash == device current schema
    /// 4. target_schema_hash == next step in registered version path
    ///
    /// On any failure: reject, log, and (for CA/hash failures) blacklist sender.
    pub fn receive_migration_delta(
        &mut self,
        delta: MigrationDelta,
        sender_did: &str,
    ) -> Result<(), TirBaseError> {
        todo!("Task 8: implement zero-trust gate")
    }

    /// Receive a MigrationRevocationDelta and halt any in-progress transform (Req 18.5–18.7).
    pub fn receive_revocation_delta(
        &mut self,
        delta: MigrationRevocationDelta,
    ) -> Result<(), TirBaseError> {
        todo!("Task 8: implement revocation handling")
    }
}
