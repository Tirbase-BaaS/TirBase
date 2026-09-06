//! Contamination resolution — verify_data(), admin_close(), audit log (Req 11).

#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::contamination::incident::{
    AuditEntry, AuditOperation, CompositeIncidentInstance, IncidentContextObject, IncidentId,
    IncidentState,
};
use crate::crdt::delta::{DeltaId, DeltaTag, Did, Ed25519Signature};
use crate::errors::TirBaseError;

// ─── Timestamp helper ────────────────────────────────────────────────────────

pub(crate) fn now_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

// ─── Manager auth ────────────────────────────────────────────────────────────

/// Verify a Manager signature and token expiry (Req 11.5).
///
/// Checks:
/// 1. `token_expiry > now_micros()` — rejects expired tokens.
/// 2. Resolves manager DID to Ed25519 public key via `identity::did::resolve_did`.
/// 3. Verifies the Ed25519 signature over `payload` using `ed25519_dalek`.
///
/// Returns `AuthorisationFailed` on any check failure.
pub(crate) fn verify_manager_auth(
    manager_did: &Did,
    sig: &Ed25519Signature,
    payload: &[u8],
    token_expiry: i64,
) -> Result<(), TirBaseError> {
    // 1. Token expiry check.
    if token_expiry <= now_micros() {
        return Err(TirBaseError::AuthorisationFailed {
            reason: format!("manager token expired (expiry={token_expiry})"),
        });
    }

    // 2. Resolve DID → public key.
    let public_key = crate::identity::did::resolve_did(manager_did).map_err(|e| {
        TirBaseError::AuthorisationFailed {
            reason: format!("DID resolution failed for {manager_did}: {e}"),
        }
    })?;

    // 3. Verify Ed25519 signature.
    crate::identity::keypair::verify(&public_key, payload, sig).map_err(|e| {
        TirBaseError::AuthorisationFailed {
            reason: format!("manager signature invalid: {e}"),
        }
    })
}

// ─── verify_data ─────────────────────────────────────────────────────────────

/// Submit a VERIFY_DATA operation for a contamination root (Req 11.1).
///
/// 1. Verify manager auth (sig + token expiry).
/// 2. Append `DeltaTag::Resolved` to the root Delta's `tags_json` in `dag_nodes`.
/// 3. For every ICO that lists `root_delta_id` in its `contamination_roots`:
///    a. Append an `AuditEntry` to the ICO.
///    b. If ALL roots in that ICO now carry a `Resolved` tag → BFS walk and append
///       `DeltaTag::Decontaminated` to every reachable descendant.
/// 4. Late-arrival decontamination walk (Req 10.3 gap fix):
///    a. For each resolved root, query the live DAG for descendants not present
///       in the original `contaminated_deltas` snapshot and append
///       `DeltaTag::Decontaminated` to each.
///    b. For each unresolved root in an active ICO, query the live DAG for
///       descendants not in the snapshot, append `DeltaTag::Contaminated`, and
///       add them to the ICO's `contaminated_deltas`.
/// 5. Decompose composite incidents that contain this root if surviving sub-chains
///    still have unresolved roots.
#[cfg(feature = "native")]
pub fn verify_data(
    root_delta_id: DeltaId,
    manager_did: Did,
    manager_sig: Ed25519Signature,
    manager_token_expiry: i64,
    conn: &rusqlite::Connection,
    dag: &crate::crdt::dag::ChangesetDag,
    incidents: &mut HashMap<IncidentId, IncidentContextObject>,
    composite_incidents: &mut HashMap<IncidentId, CompositeIncidentInstance>,
) -> Result<DecompositionResult, TirBaseError> {
    // 1. Auth.
    verify_manager_auth(
        &manager_did,
        &manager_sig,
        &root_delta_id,
        manager_token_expiry,
    )?;

    // 2. Append Resolved tag to the root Delta.
    let at = now_micros();
    crate::contamination::taint::append_tag(
        conn,
        &root_delta_id,
        DeltaTag::Resolved {
            by_manager_did: manager_did.clone(),
            at,
        },
    )?;

    // 3. For each ICO referencing this root, record audit entry + check if all roots resolved.
    let ico_ids: Vec<IncidentId> = incidents
        .values()
        .filter(|ico| ico.contamination_roots.contains(&root_delta_id))
        .map(|ico| ico.id)
        .collect();

    for ico_id in &ico_ids {
        let ico = match incidents.get_mut(ico_id) {
            Some(i) => i,
            None => continue,
        };

        // Append audit entry.
        ico.audit_log.push(AuditEntry {
            operation: AuditOperation::VerifyData,
            manager_did: manager_did.clone(),
            utc_timestamp: at,
            affected_delta_ids: vec![root_delta_id],
        });
        ico.updated_at = at;

        // Check if all roots are now resolved.
        let all_resolved = ico
            .contamination_roots
            .iter()
            .all(|root_id| has_resolved_tag(conn, root_id));

        if all_resolved {
            // Propagate Decontaminated to every reachable descendant.
            let all_contaminated: Vec<DeltaId> = ico.contaminated_deltas.iter().copied().collect();
            for delta_id in &all_contaminated {
                let _ = crate::contamination::taint::append_tag(
                    conn,
                    delta_id,
                    DeltaTag::Decontaminated {
                        incident_id: ico.id,
                        resolved_at: at,
                    },
                );
            }

            // Clear projection-layer contamination flags for all affected rows (Req 11.1).
            for row in &ico.affected_rows {
                let _ = crate::store::projection::clear_row_contamination(
                    conn,
                    &row.table,
                    &row.row_key,
                );
            }
        }
    }

    // ─── Step 4: Late-arrival decontamination walk (Req 10.3 gap fix) ─────────
    //
    // Deltas that descended from a contamination root *after* the initial
    // `tag_contamination_root` snapshot was taken are not in the ICO's
    // `contaminated_deltas` snapshot.  We now query the live DAG to find
    // those late-arriving descendants and tag them:
    //
    //   • Roots that are now fully resolved → late descendants receive
    //     DeltaTag::Decontaminated.
    //   • Roots that remain unresolved → late descendants receive
    //     DeltaTag::Contaminated and are added to the active ICO's
    //     contaminated_deltas.
    //
    // We process both regular ICOs and composite incidents that reference
    // `root_delta_id` in their contamination_roots.

    // Collect composite incident IDs that reference this root.
    let composite_ico_ids: Vec<IncidentId> = composite_incidents
        .values()
        .filter(|c| {
            c.state == IncidentState::Open
                && c.contamination_roots.contains(&root_delta_id)
        })
        .map(|c| c.id)
        .collect();

    for ico_id in &ico_ids {
        let ico = match incidents.get_mut(ico_id) {
            Some(i) => i,
            None => continue,
        };

        let all_resolved = ico
            .contamination_roots
            .iter()
            .all(|root_id| has_resolved_tag(conn, root_id));

        // For a fully resolved ICO, late descendants of the root should be
        // decontaminated.
        if all_resolved {
            for root_id in &ico.contamination_roots {
                if has_resolved_tag(conn, root_id) {
                    let late = crate::contamination::taint::walk_late_arrival_descendants(
                        root_id,
                        dag,
                        &ico.contaminated_deltas,
                        true,
                        conn,
                        *ico_id,
                    )?;
                    // Add late arrivals to the ICO's contaminated_deltas so
                    // they are tracked (they will already carry Decontaminated
                    // tags from the walk above).
                    for delta_id in &late {
                        ico.contaminated_deltas.insert(*delta_id);
                    }
                }
            }
        } else {
            // For an unresolved ICO, late descendants of unresolved roots
            // should receive Contaminated tags and join contaminated_deltas.
            for root_id in &ico.contamination_roots {
                if !has_resolved_tag(conn, root_id) {
                    let late = crate::contamination::taint::walk_late_arrival_descendants(
                        root_id,
                        dag,
                        &ico.contaminated_deltas,
                        false,
                        conn,
                        *ico_id,
                    )?;
                    for delta_id in &late {
                        ico.contaminated_deltas.insert(*delta_id);
                    }
                }
            }
        }
    }

    // Process composite incidents referencing this root.
    for comp_id in &composite_ico_ids {
        let comp = match composite_incidents.get_mut(comp_id) {
            Some(c) => c,
            None => continue,
        };

        let all_resolved = comp
            .contamination_roots
            .iter()
            .all(|root_id| has_resolved_tag(conn, root_id));

        if all_resolved {
            for root_id in &comp.contamination_roots {
                if has_resolved_tag(conn, root_id) {
                    let late = crate::contamination::taint::walk_late_arrival_descendants(
                        root_id,
                        dag,
                        &comp.contaminated_deltas,
                        true,
                        conn,
                        *comp_id,
                    )?;
                    for delta_id in &late {
                        comp.contaminated_deltas.insert(*delta_id);
                    }
                }
            }
        } else {
            for root_id in &comp.contamination_roots {
                if !has_resolved_tag(conn, root_id) {
                    let late = crate::contamination::taint::walk_late_arrival_descendants(
                        root_id,
                        dag,
                        &comp.contaminated_deltas,
                        false,
                        conn,
                        *comp_id,
                    )?;
                    for delta_id in &late {
                        comp.contaminated_deltas.insert(*delta_id);
                    }
                }
            }
        }
    }

    // 5. Decompose any composite incidents that include this root.
    //    The returned DecompositionResult carries the new ICOs' affected_rows
    //    so the caller (CausalContaminationEngine::verify_data) can repopulate
    //    its `contaminated_rows` O(1) index for the surviving sub-chains
    //    (Req 10.6 — affected rows remain CONTAMINATED via the unresolved lineage).
    let decomposition = decompose_composites_if_needed(
        root_delta_id,
        conn,
        dag,
        incidents,
        composite_incidents,
        at,
    )?;

    Ok(decomposition)
}

/// Return `true` if the given Delta has at least one `DeltaTag::Resolved` entry in `dag_nodes`.
#[cfg(feature = "native")]
fn has_resolved_tag(conn: &rusqlite::Connection, delta_id: &DeltaId) -> bool {
    let tags = crate::contamination::taint::read_tags_from_db(conn, delta_id).unwrap_or_default();
    tags.iter().any(|t| matches!(t, DeltaTag::Resolved { .. }))
}

/// Result of decomposing a composite incident.
///
/// Records the new ICOs created for surviving unresolved sub-chains, along
/// with their resolved `affected_rows`, so the caller can repopulate the
/// `contaminated_rows` O(1) index.
#[derive(Debug, Default)]
pub struct DecompositionResult {
    /// (new_ico_id, affected_rows) pairs for each re-registered unresolved root.
    pub new_icos: Vec<(IncidentId, Vec<crate::contamination::incident::AffectedRow>)>,
}

/// Attempt to decompose composite incidents whose composite chains now have all
/// roots resolved for one sub-chain but not the other (Req 10.6 / 11.1).
///
/// For each surviving unresolved root, a fresh `IncidentContextObject` is
/// created with `affected_rows` resolved from the projection layer (not left
/// empty), and those rows are re-marked CONTAMINATED in the projection store
/// so that `is_row_contaminated` continues to return `true` for rows still
/// reachable through the unresolved lineage (Req 10.6).
///
/// Returns a [`DecompositionResult`] listing the new ICOs and their affected
/// rows so the caller can repopulate its `contaminated_rows` index.
///
/// Note: the BFS walk uses `bfs_descendants_raw` (direct SQL on the connection)
/// rather than `dag.bfs_descendants` because the caller holds `conn_guard`
/// across this call — `dag.bfs_descendants` would deadlock by re-locking the
/// same `Arc<Mutex<Connection>>`.
#[cfg(feature = "native")]
fn decompose_composites_if_needed(
    resolved_root: DeltaId,
    conn: &rusqlite::Connection,
    _dag: &crate::crdt::dag::ChangesetDag,
    incidents: &mut HashMap<IncidentId, IncidentContextObject>,
    composite_incidents: &mut HashMap<IncidentId, CompositeIncidentInstance>,
    at: i64,
) -> Result<DecompositionResult, TirBaseError> {
    let mut result = DecompositionResult::default();

    // Find composites that contain this root.
    let composite_ids: Vec<IncidentId> = composite_incidents
        .values()
        .filter(|c| c.contamination_roots.contains(&resolved_root))
        .map(|c| c.id)
        .collect();

    for composite_id in &composite_ids {
        let composite = match composite_incidents.get_mut(composite_id) {
            Some(c) => c,
            None => continue,
        };

        // Identify sub-chains with unresolved roots.
        let unresolved_roots: Vec<DeltaId> = composite
            .contamination_roots
            .iter()
            .filter(|r| !has_resolved_tag(conn, r))
            .copied()
            .collect();

        // If surviving unresolved roots exist, decompose into a fresh ICO.
        if !unresolved_roots.is_empty() {
            composite.state = IncidentState::Decomposed;

            // Re-register each unresolved root as a new independent ICO.
            for root_id in &unresolved_roots {
                let new_ico_id = uuid::Uuid::now_v7();
                // BFS walk from this root to find its descendants — use the
                // raw connection (already locked) to avoid deadlocking the
                // shared Mutex<Connection> that ChangesetDag would re-lock.
                let descendants = crate::contamination::taint::bfs_descendants_raw(conn, root_id)
                    .unwrap_or_else(|_| vec![*root_id]);
                let contaminated_deltas = descendants.iter().copied().collect();

                // Resolve affected projection rows for the surviving sub-chain
                // and re-mark them CONTAMINATED so the unresolved lineage
                // keeps its rows tainted (Req 10.6, acceptance criteria:
                // "affected rows remain CONTAMINATED via the unresolved lineage").
                let affected_rows = crate::contamination::taint::resolve_affected_rows(
                    conn,
                    &descendants,
                    *root_id,
                )?;
                for row in &affected_rows {
                    let _ = crate::store::projection::mark_row_contaminated(
                        conn,
                        &row.table,
                        &row.row_key,
                    );
                }

                let new_ico = IncidentContextObject {
                    id: new_ico_id,
                    state: IncidentState::Open,
                    taint_source: crate::contamination::incident::TaintSource::DeviceRevocation {
                        revocation_delta_id: *root_id,
                    },
                    contamination_roots: vec![*root_id],
                    contaminated_deltas,
                    affected_rows: affected_rows.clone(),
                    composite_of: None,
                    created_at: at,
                    updated_at: at,
                    audit_log: vec![],
                };
                incidents.insert(new_ico_id, new_ico);
                result.new_icos.push((new_ico_id, affected_rows));
            }
        } else {
            // All roots resolved — mark composite as decomposed.
            composite.state = IncidentState::Decomposed;
        }
    }

    Ok(result)
}

// ─── admin_close ─────────────────────────────────────────────────────────────

/// Submit an ADMIN_CLOSE operation for an Incident Context Object (Req 11.2–11.3).
///
/// 1. Verify manager auth.
/// 2. Load ICO; return `InvalidIncidentState` if not in `Open` state.
/// 3. Transition ICO to `Closed`.
/// 4. Append an `AdminClose` audit entry.
/// 5. Delta tags are **not** modified.
pub fn admin_close(
    incident_id: IncidentId,
    manager_did: Did,
    manager_sig: Ed25519Signature,
    manager_token_expiry: i64,
    incidents: &mut HashMap<IncidentId, IncidentContextObject>,
) -> Result<(), TirBaseError> {
    // 1. Auth — sign payload is the incident_id bytes.
    verify_manager_auth(
        &manager_did,
        &manager_sig,
        incident_id.as_bytes(),
        manager_token_expiry,
    )?;

    // 2. Load ICO.
    let ico =
        incidents
            .get_mut(&incident_id)
            .ok_or_else(|| TirBaseError::LocalStoreWriteFailed {
                reason: format!("incident {incident_id} not found"),
            })?;

    // 3. Guard — must be Open.
    if ico.state != IncidentState::Open {
        return Err(TirBaseError::InvalidIncidentState { got: ico.state });
    }

    let at = now_micros();

    // 4. Transition to Closed.
    ico.state = IncidentState::Closed;
    ico.updated_at = at;

    // 5. Audit entry.
    ico.audit_log.push(AuditEntry {
        operation: AuditOperation::AdminClose,
        manager_did,
        utc_timestamp: at,
        affected_delta_ids: vec![],
    });

    Ok(())
}

// ─── Append audit entry helper ────────────────────────────────────────────────

/// Append an immutable audit record to the ICO's audit log (Req 11.4).
pub(crate) fn append_audit_entry(
    incident_id: &IncidentId,
    entry: AuditEntry,
    incidents: &mut HashMap<IncidentId, IncidentContextObject>,
) -> Result<(), TirBaseError> {
    let ico =
        incidents
            .get_mut(incident_id)
            .ok_or_else(|| TirBaseError::LocalStoreWriteFailed {
                reason: format!("incident {incident_id} not found for audit"),
            })?;
    ico.audit_log.push(entry);
    Ok(())
}
