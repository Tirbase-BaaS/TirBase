// SPDX-License-Identifier: AGPL-3.0-only

//! Fleet precondition verification hook for Contract migrations (PV-8.5a).
//!
//! Full fleet inventory depends on . This module provides the hook so
//! Contract migrations are never approved without an explicit verifier; the
//! default rejects with `FleetPreconditionMissing`.

#![allow(dead_code)]

use crate::errors::TirBaseError;
use crate::events::ReasonCode;
use crate::migration::migration_delta::MigrationId;
use std::fmt::Debug;
use std::sync::Arc;

pub trait FleetPreconditionVerifier: Send + Sync + Debug {
    fn verify_contract(
        &self,
        migration_id: &MigrationId,
        fleet_precondition_hash: &[u8; 32],
    ) -> Result<(), TirBaseError>;
}

/// Default verifier (37.5 not integrated): rejects Contract migrations.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnverifiedFleetInventory;

impl FleetPreconditionVerifier for UnverifiedFleetInventory {
    fn verify_contract(
        &self,
        migration_id: &MigrationId,
        _fleet_precondition_hash: &[u8; 32],
    ) -> Result<(), TirBaseError> {
        Err(TirBaseError::FleetPreconditionMissing {
            migration_id: hex::encode(migration_id),
        })
    }
}

/// Test/injected verifier that accepts any fleet precondition hash.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptAllFleetPreconditions;

impl FleetPreconditionVerifier for AcceptAllFleetPreconditions {
    fn verify_contract(
        &self,
        _migration_id: &MigrationId,
        _fleet_precondition_hash: &[u8; 32],
    ) -> Result<(), TirBaseError> {
        Ok(())
    }
}

pub type DynFleetPreconditionVerifier = Arc<dyn FleetPreconditionVerifier>;
