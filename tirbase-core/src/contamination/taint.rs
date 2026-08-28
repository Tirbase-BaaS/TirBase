//! Taint propagation — tag_root(), walk_dag(), append_tag() (Req 10.2).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::contamination::incident::{IncidentContextObject, IncidentId, TaintSource};
use crate::crdt::delta::DeltaId;
use crate::errors::TirBaseError;

/// Tag the given Delta as a contamination root and walk all descendants in the
/// ChangesetDag, appending `DeltaTag::Contaminated` to each (Req 10.2).
///
/// Returns the ID of the newly created Incident Context Object.
pub fn tag_contamination_root(
    root_delta_id: DeltaId,
    source: TaintSource,
) -> Result<IncidentId, TirBaseError> {
    todo!("Task 7: BFS/DFS walk, ICO allocation, composite merge")
}

/// BFS walk from `root_delta_id` following forward child edges in the DAG.
/// Returns all reachable descendant Delta IDs (inclusive of root).
pub(crate) fn walk_dag_descendants(
    root_delta_id: &DeltaId,
) -> Result<Vec<DeltaId>, TirBaseError> {
    todo!("Task 7: implement with ChangesetDag")
}

/// Append a `DeltaTag` entry to the tag log of the given Delta.
/// This operation is **append-only** — existing tags are never modified (Req 10.4).
pub(crate) fn append_tag(
    delta_id: &DeltaId,
    tag: crate::crdt::delta::DeltaTag,
) -> Result<(), TirBaseError> {
    todo!("Task 7: implement with LocalStore")
}
