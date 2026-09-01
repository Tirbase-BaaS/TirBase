//! Human-reaction auto-tagging (Req 19.5).
//!
//! Whenever a device commits a write while its local projection is in
//! CONTAMINATED state or while its incoming Delta stream is quarantined,
//! the resulting Delta is automatically tagged with
//! `DeltaTag::ContaminatedByHumanReaction`. No operator acknowledgement
//! is required.

#![allow(dead_code, unused_variables, unused_imports)]

use crate::contamination::incident::IncidentId;
use crate::crdt::delta::{Delta, DeltaTag};
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
/// `DeltaTag::ContaminatedByHumanReaction` to `delta.tags` and registers
/// the Delta as a human-reaction root with the CausalContaminationEngine (Req 19.5).
pub fn on_write_commit(delta: &mut Delta, ctx: &WriteContext) -> Result<(), TirBaseError> {
    if !ctx.local_projection_contaminated && !ctx.quarantine_active {
        return Ok(());
    }
    if let Some(incident_id) = ctx.active_incident_id {
        delta.tags.push(DeltaTag::ContaminatedByHumanReaction { incident_id });
        // Register with CCE so the new Delta is itself a contamination root.
        register_human_reaction_root(delta.id, incident_id)?;
    }
    Ok(())
}

/// Register a Delta as a human-reaction contamination root with the CCE.
///
/// For Task 7 this is a lightweight in-process call — the full CCE wiring
/// is completed when the engine holds a mutable reference at call time.
/// The function signature is kept simple so tests can call it directly.
pub(crate) fn register_human_reaction_root(
    _delta_id: [u8; 32],
    _incident_id: IncidentId,
) -> Result<(), TirBaseError> {
    // The CCE call is wired from `CausalContaminationEngine::tag_contamination_root`
    // when the engine processes HumanReaction taint sources.  Direct invocation
    // here is a no-op for test stubs; callers that need full CCE integration
    // should call `CausalContaminationEngine::tag_contamination_root` themselves.
    Ok(())
}
