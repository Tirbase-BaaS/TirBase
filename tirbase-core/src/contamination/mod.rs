//! Causal Contamination Engine (CCE) — taint propagation through the
//! Changeset DAG and Incident Context Object management (Req 10, 11).
//!
//! The CCE accepts taint from exactly three source types (Req 10.1):
//!   1. `DeviceRevocation` — triggered by a Revocation_Delta
//!   2. `BadMigration`     — triggered by a Migration_Revocation_Delta
//!   3. `HumanReaction`    — triggered by a write on a contaminated projection
//!
//! Any other source is rejected with `UnsupportedTaintSource`.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod human_reaction;
pub mod incident;
pub mod resolution;
pub mod taint;

use crate::crdt::delta::{Did, DeltaId, Ed25519Signature};
use crate::errors::TirBaseError;
use incident::{IncidentContextObject, IncidentId, IncidentState, TaintSource};

/// The Causal Contamination Engine.
pub struct CausalContaminationEngine {
    // TODO(task-7): inject LocalStore, ChangesetDag handles
}

impl CausalContaminationEngine {
    /// Tag `root_delta_id` as a contamination root and walk all descendants
    /// in the ChangesetDag, appending `DeltaTag::Contaminated` to each.
    ///
    /// Rejects any source other than the three supported types with
    /// `TirBaseError::UnsupportedTaintSource` (Req 10.1).
    pub fn tag_contamination_root(
        &mut self,
        root_delta_id: DeltaId,
        source: TaintSource,
    ) -> Result<IncidentId, TirBaseError> {
        todo!("Task 7: implement BFS walk and ICO allocation")
    }

    /// Submit a VERIFY_DATA operation for a Contamination_Root (Req 11.1).
    pub fn verify_data(
        &mut self,
        root_delta_id: DeltaId,
        manager_did: Did,
        manager_sig: Ed25519Signature,
        manager_token_expiry: i64,
    ) -> Result<(), TirBaseError> {
        todo!("Task 7: implement verify_data")
    }

    /// Submit an ADMIN_CLOSE operation for an Incident Context Object (Req 11.2).
    pub fn admin_close(
        &mut self,
        incident_id: IncidentId,
        manager_did: Did,
        manager_sig: Ed25519Signature,
        manager_token_expiry: i64,
    ) -> Result<(), TirBaseError> {
        todo!("Task 7: implement admin_close")
    }

    /// Retrieve an Incident Context Object by ID.
    pub fn get_incident(&self, id: IncidentId) -> Result<Option<IncidentContextObject>, TirBaseError> {
        todo!("Task 7: implement ICO retrieval")
    }

    /// Return all currently OPEN incidents.
    pub fn open_incidents(&self) -> Result<Vec<IncidentContextObject>, TirBaseError> {
        todo!("Task 7: implement incident listing")
    }
}
