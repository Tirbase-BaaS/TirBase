//! Contamination resolution — verify_data(), admin_close(), audit log (Req 11).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::contamination::incident::{IncidentId, IncidentContextObject};
use crate::crdt::delta::{Did, DeltaId, Ed25519Signature};
use crate::errors::TirBaseError;

/// Submit a VERIFY_DATA operation for a Contamination_Root (Req 11.1).
///
/// Appends `DeltaTag::Resolved` to the root Delta, writes an audit entry,
/// and propagates `DeltaTag::Decontaminated` to all descendants once all
/// roots are resolved. Decomposes any CompositeIncidentInstance that included
/// this root if surviving independent chains remain.
pub fn verify_data(
    root_delta_id: DeltaId,
    manager_did: Did,
    manager_sig: Ed25519Signature,
    manager_token_expiry: i64,
) -> Result<(), TirBaseError> {
    todo!("Task 7: implement contamination resolution")
}

/// Submit an ADMIN_CLOSE operation for an Incident Context Object (Req 11.2–11.3).
///
/// Transitions the ICO from OPEN → CLOSED and appends an audit entry.
/// Rejects with `InvalidIncidentState` if the ICO is not in OPEN state.
/// Delta tags are not modified.
pub fn admin_close(
    incident_id: IncidentId,
    manager_did: Did,
    manager_sig: Ed25519Signature,
    manager_token_expiry: i64,
) -> Result<(), TirBaseError> {
    todo!("Task 7: implement admin_close")
}

/// Append an immutable audit record to the ICO's audit log (Req 11.4).
pub(crate) fn append_audit_entry(
    incident_id: &IncidentId,
    entry: crate::contamination::incident::AuditEntry,
) -> Result<(), TirBaseError> {
    todo!("Task 7: implement with LocalStore")
}

/// Verify a Manager signature and token expiry.
/// Returns `AuthorisationFailed` on any check failure (Req 11.5).
pub(crate) fn verify_manager_auth(
    manager_did: &Did,
    sig: &Ed25519Signature,
    payload: &[u8],
    token_expiry: i64,
) -> Result<(), TirBaseError> {
    todo!("Task 7: implement manager auth check")
}
