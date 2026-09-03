//! Human-reaction auto-tagging (Req 19.5).
//!
//! Whenever a device commits a write while its local projection is in
//! CONTAMINATED state or while its incoming Delta stream is quarantined,
//! the resulting Delta is automatically tagged with
//! `DeltaTag::ContaminatedByHumanReaction`. No operator acknowledgement
//! is required.
//!
//! ## Integration with the CCE
//!
//! `on_write_commit` now returns `Ok(Some((delta_id, incident_id)))` when a
//! `ContaminatedByHumanReaction` tag was appended, and `Ok(None)` when the
//! write context is clean. The caller (`CoreHandle::write`) is responsible for
//! acting on the returned value by calling
//! `CausalContaminationEngine::tag_contamination_root` with
//! `TaintSource::HumanReaction { triggered_by_incident_id: incident_id }`.
//! This keeps the CCE lock outside of the `on_write_commit` call, avoiding a
//! double-borrow of `CoreHandle` fields.

#![allow(dead_code, unused_variables, unused_imports)]

use crate::contamination::incident::IncidentId;
use crate::crdt::delta::{Delta, DeltaId, DeltaTag};
use crate::errors::TirBaseError;

/// Context passed to `on_write_commit` to determine whether auto-tagging applies.
pub struct WriteContext {
    /// True if the local projection for the target table is currently tagged CONTAMINATED.
    pub local_projection_contaminated: bool,
    /// True if the incoming Delta stream for this table is currently quarantined.
    pub quarantine_active: bool,
    /// The active Incident ID driving the contamination (if any).
    pub active_incident_id: Option<IncidentId>,
}

/// Called immediately after a write is committed to the Local Store.
///
/// If `ctx` indicates the local context is tainted, appends
/// `DeltaTag::ContaminatedByHumanReaction` to `delta.tags`.
///
/// Returns:
/// - `Ok(Some((delta_id, incident_id)))` — a tag was appended; the caller must
///   call `CausalContaminationEngine::tag_contamination_root` with
///   `TaintSource::HumanReaction { triggered_by_incident_id: incident_id }` to
///   register the new Delta in the active ICO and update `affected_rows` (Req 19.5).
/// - `Ok(None)` — the write context is clean; no tagging was performed.
/// - `Err(_)` — an unexpected error occurred.
///
/// The CCE lock is intentionally **not** held here. The caller is responsible
/// for acting on the returned `Option` after `on_write_commit` returns, so that
/// the CCE borrow happens at the call site where no other CCE lock is held.
pub fn on_write_commit(
    delta: &mut Delta,
    ctx: &WriteContext,
) -> Result<Option<(DeltaId, IncidentId)>, TirBaseError> {
    if !ctx.local_projection_contaminated && !ctx.quarantine_active {
        return Ok(None);
    }
    if let Some(incident_id) = ctx.active_incident_id {
        delta.tags.push(DeltaTag::ContaminatedByHumanReaction { incident_id });
        return Ok(Some((delta.id, incident_id)));
    }
    // Conditions were true but no incident_id was provided — tag is not appended.
    Ok(None)
}
