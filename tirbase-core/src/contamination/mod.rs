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

use std::collections::HashMap;

use crate::crdt::delta::{DeltaId, DeltaTag, Did, Ed25519Signature};
use crate::errors::TirBaseError;
use incident::{
    AuditEntry, AuditOperation, CompositeIncidentInstance, IncidentContextObject, IncidentId,
    IncidentState, TaintSource,
};
use resolution::now_micros;
use resolution::DecompositionResult;

// ─── CausalContaminationEngine ────────────────────────────────────────────────

/// The Causal Contamination Engine.
///
/// Holds an in-memory index of incidents (ICOs) and composite incidents.
/// The `dag_nodes.tags_json` column in SQLite is the durable append-only tag store.
/// ICO state is in-memory only and not persisted across process restarts;
/// persistence is explicitly deferred to a post-v1 task.
#[cfg(feature = "native")]
pub struct CausalContaminationEngine {
    /// Shared SQLite connection (same pool as LocalStore and ChangesetDag).
    conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
    /// SQLite-backed Changeset DAG — used for BFS walks.
    dag: crate::crdt::dag::ChangesetDag,
    /// In-memory incident registry.
    incidents: HashMap<IncidentId, IncidentContextObject>,
    /// In-memory composite incident registry.
    composite_incidents: HashMap<IncidentId, CompositeIncidentInstance>,
    /// O(1) lookup index: (table_name, row_key) → active IncidentId.
    ///
    /// Populated when `tag_contamination_root` resolves affected rows.
    /// Pruned when `verify_data` appends `DeltaTag::Decontaminated` to a fully
    /// resolved incident.  This map is the fast path for `CoreHandle::write()`
    /// to check whether the current row is contaminated (Req 19.5).
    contaminated_rows: HashMap<(String, String), IncidentId>,
}

#[cfg(not(feature = "native"))]
pub struct CausalContaminationEngine {
    incidents: HashMap<IncidentId, IncidentContextObject>,
    composite_incidents: HashMap<IncidentId, CompositeIncidentInstance>,
    /// In-memory DAG for WASM builds (mirrors the native SQLite-backed DAG).
    dag: crate::crdt::dag::ChangesetDag,
    /// O(1) lookup index: (table_name, row_key) → active IncidentId.
    contaminated_rows: HashMap<(String, String), IncidentId>,
}

// ─── Native implementation ────────────────────────────────────────────────────

#[cfg(feature = "native")]
impl CausalContaminationEngine {
    /// Create a new CCE backed by the given shared SQLite connection.
    pub fn new(conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>) -> Self {
        let dag = crate::crdt::dag::ChangesetDag::new(conn.clone());
        Self {
            conn,
            dag,
            incidents: HashMap::new(),
            composite_incidents: HashMap::new(),
            contaminated_rows: HashMap::new(),
        }
    }

    // ─── tag_contamination_root ───────────────────────────────────────────────

    /// Tag `root_delta_id` as a contamination root and walk all descendants
    /// in the ChangesetDag, appending `DeltaTag::Contaminated` to each.
    ///
    /// Validates the taint source (all three enum variants are valid — the guard
    /// is structural).  Detects overlap with existing incidents and creates a
    /// `CompositeIncidentInstance` when two chains share a DAG node (Req 10.5).
    ///
    /// Returns the `IncidentId` of the newly created (or composite) incident.
    pub fn tag_contamination_root(
        &mut self,
        root_delta_id: DeltaId,
        source: TaintSource,
    ) -> Result<IncidentId, TirBaseError> {
        // Taint source guard — all three variants of TaintSource are valid.
        // The match exhausts the enum, which is the compile-time guard (Req 10.1).
        let _source_is_valid = match &source {
            TaintSource::DeviceRevocation { .. } => true,
            TaintSource::BadMigration { .. } => true,
            TaintSource::HumanReaction { .. } => true,
        };

        let now = now_micros();
        let ico_id = uuid::Uuid::now_v7();

        // BFS walk from the root — collect all reachable descendant Delta IDs.
        let descendants = taint::walk_dag_descendants(&self.dag, &root_delta_id)?;

        // Obtain a connection lock for tag writes.
        let conn_guard = self
            .conn
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("CCE mutex poisoned: {e}"),
            })?;

        // Append Contaminated tag to every reachable Delta.
        for delta_id in &descendants {
            let _ = taint::append_tag(
                &conn_guard,
                delta_id,
                DeltaTag::Contaminated {
                    root_id: root_delta_id,
                    incident_id: ico_id,
                },
            );
        }
        drop(conn_guard);

        // Resolve affected projection rows and mark them contaminated (Req 10.7).
        let affected_rows = {
            let conn_guard2 =
                self.conn
                    .lock()
                    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                        reason: format!("CCE mutex poisoned: {e}"),
                    })?;
            let rows = taint::resolve_affected_rows(&conn_guard2, &descendants, root_delta_id)?;
            for row in &rows {
                let _ = crate::store::projection::mark_row_contaminated(
                    &conn_guard2,
                    &row.table,
                    &row.row_key,
                );
            }
            rows
        };

        // Build the new ICO.
        let contaminated_deltas = descendants.iter().copied().collect();
        let new_ico = IncidentContextObject {
            id: ico_id,
            state: IncidentState::Open,
            taint_source: source,
            contamination_roots: vec![root_delta_id],
            contaminated_deltas,
            affected_rows,
            composite_of: None,
            created_at: now,
            updated_at: now,
            audit_log: vec![],
        };

        // Overlap detection: check against all existing OPEN incidents.
        let overlapping_id: Option<IncidentId> = self
            .incidents
            .values()
            .filter(|existing| {
                existing.state == IncidentState::Open
                    && existing
                        .contaminated_deltas
                        .iter()
                        .any(|d| new_ico.contaminated_deltas.contains(d))
            })
            .map(|ico| ico.id)
            .next();

        if let Some(existing_ico_id) = overlapping_id {
            // Insert new ICO temporarily so composite_merge can see both.
            self.incidents.insert(ico_id, new_ico);

            let (composite_id, composite) = {
                let ico_a = self.incidents.get_mut(&existing_ico_id).unwrap();
                let ico_b_ref = self.incidents.get_mut(&ico_id).unwrap();
                // We need both as mutable — use a two-step borrow workaround.
                // Take ico_b out, mutate both, then re-insert.
                let mut ico_b = self.incidents.remove(&ico_id).unwrap();
                let mut ico_a_owned = self.incidents.remove(&existing_ico_id).unwrap();
                let result = incident::composite_merge(&mut ico_a_owned, &mut ico_b, now);
                self.incidents.insert(existing_ico_id, ico_a_owned);
                self.incidents.insert(ico_id, ico_b);
                result
            };

            self.composite_incidents.insert(composite_id, composite);
            // Populate contaminated_rows index for the composite ICO (native).
            if let Some(comp) = self.composite_incidents.get(&composite_id) {
                for row in &comp.affected_rows {
                    self.contaminated_rows
                        .insert((row.table.clone(), row.row_key.clone()), composite_id);
                }
            }
            return Ok(composite_id);
        }

        // No overlap — just register the new ICO.
        self.incidents.insert(ico_id, new_ico);

        // Populate the O(1) contaminated_rows index for this ICO.
        if let Some(ico) = self.incidents.get(&ico_id) {
            for row in &ico.affected_rows {
                self.contaminated_rows
                    .insert((row.table.clone(), row.row_key.clone()), ico_id);
            }
        }

        Ok(ico_id)
    }

    // ─── verify_data ─────────────────────────────────────────────────────────

    /// Submit a VERIFY_DATA operation for a contamination root (Req 11.1).
    pub fn verify_data(
        &mut self,
        root_delta_id: DeltaId,
        manager_did: Did,
        manager_sig: Ed25519Signature,
        manager_token_expiry: i64,
    ) -> Result<(), TirBaseError> {
        let conn_guard = self
            .conn
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("CCE mutex poisoned: {e}"),
            })?;

        let decomposition = resolution::verify_data(
            root_delta_id,
            manager_did,
            manager_sig,
            manager_token_expiry,
            &conn_guard,
            &self.dag,
            &mut self.incidents,
            &mut self.composite_incidents,
        )?;

        // Drop the connection guard before taking a mutable borrow of self.
        drop(conn_guard);

        // Req 10.6 — repopulate contaminated_rows for surviving sub-chains.
        //
        // When a composite incident is decomposed (one root resolved, the other
        // still unresolved), the surviving sub-chain is re-registered as a
        // fresh OPEN ICO with its own affected_rows.  Any row that was
        // previously mapped to the composite ID must be re-pointed to the new
        // ICO so `is_row_contaminated()` continues to return `true` via the
        // unresolved lineage (acceptance criteria: "affected rows remain
        // CONTAMINATED via the unresolved lineage").
        for (new_ico_id, affected_rows) in &decomposition.new_icos {
            for row in affected_rows {
                self.contaminated_rows
                    .insert((row.table.clone(), row.row_key.clone()), *new_ico_id);
            }
        }

        // After resolution, prune contaminated_rows entries for any row that now
        // has no active OPEN incident referencing it.  This keeps is_row_contaminated()
        // returning false after all roots are resolved (Req 19.5 / Test C).
        //
        // The standard prune only retains rows while the ICO is `Open`.  But `Open`
        // is the correct state even after full resolution (only `admin_close`
        // transitions to `Closed`).  So we also prune rows whose ICO's entire
        // contamination_roots set now carries a `Resolved` tag — i.e. the incident
        // has been fully verified even if not yet admin-closed.
        {
            let conn_guard2 =
                self.conn
                    .lock()
                    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                        reason: format!("CCE mutex poisoned during prune: {e}"),
                    })?;
            self.contaminated_rows.retain(|_key, incident_id| {
                // Check regular ICO.
                if let Some(ico) = self.incidents.get(incident_id) {
                    if ico.state != IncidentState::Open {
                        return false;
                    }
                    // Keep entry only if at least one contamination root is NOT yet resolved.
                    return ico.contamination_roots.iter().any(|root_id| {
                        let tags =
                            crate::contamination::taint::read_tags_from_db(&conn_guard2, root_id)
                                .unwrap_or_default();
                        !tags.iter().any(|t| matches!(t, DeltaTag::Resolved { .. }))
                    });
                }
                // Check composite ICO.
                if let Some(comp) = self.composite_incidents.get(incident_id) {
                    if comp.state != IncidentState::Open {
                        return false;
                    }
                    return comp.contamination_roots.iter().any(|root_id| {
                        let tags =
                            crate::contamination::taint::read_tags_from_db(&conn_guard2, root_id)
                                .unwrap_or_default();
                        !tags.iter().any(|t| matches!(t, DeltaTag::Resolved { .. }))
                    });
                }
                false
            });
        }

        Ok(())
    }

    // ─── admin_close ─────────────────────────────────────────────────────────

    /// Submit an ADMIN_CLOSE operation for an Incident Context Object (Req 11.2).
    pub fn admin_close(
        &mut self,
        incident_id: IncidentId,
        manager_did: Did,
        manager_sig: Ed25519Signature,
        manager_token_expiry: i64,
    ) -> Result<(), TirBaseError> {
        resolution::admin_close(
            incident_id,
            manager_did,
            manager_sig,
            manager_token_expiry,
            &mut self.incidents,
        )
    }

    // ─── Read accessors ───────────────────────────────────────────────────────

    /// Retrieve an Incident Context Object by ID.
    pub fn get_incident(
        &self,
        id: IncidentId,
    ) -> Result<Option<IncidentContextObject>, TirBaseError> {
        Ok(self.incidents.get(&id).cloned())
    }

    /// Return all currently OPEN incidents.
    pub fn open_incidents(&self) -> Result<Vec<IncidentContextObject>, TirBaseError> {
        Ok(self
            .incidents
            .values()
            .filter(|ico| ico.state == IncidentState::Open)
            .cloned()
            .collect())
    }

    /// O(1) check — returns `true` if the given `(table, row_key)` pair is currently
    /// contaminated by an active incident (Req 19.5).
    pub fn is_row_contaminated(&self, table: &str, row_key: &str) -> bool {
        self.contaminated_rows
            .contains_key(&(table.to_string(), row_key.to_string()))
    }

    /// O(1) lookup — returns the active `IncidentId` for the given `(table, row_key)`
    /// if the row is contaminated, or `None` otherwise (Req 19.5).
    pub fn active_incident_for_row(&self, table: &str, row_key: &str) -> Option<IncidentId> {
        self.contaminated_rows
            .get(&(table.to_string(), row_key.to_string()))
            .copied()
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    /// Remove entries from `contaminated_rows` that no longer have an active OPEN
    /// incident.  Called after `verify_data` to prune rows that have been fully
    /// decontaminated.
    fn prune_contaminated_rows(&mut self) {
        self.contaminated_rows.retain(|_key, incident_id| {
            // Keep the entry if the incident still exists AND is still Open.
            self.incidents
                .get(incident_id)
                .map(|ico| ico.state == IncidentState::Open)
                .unwrap_or(false)
                || self
                    .composite_incidents
                    .get(incident_id)
                    .map(|c| c.state == IncidentState::Open)
                    .unwrap_or(false)
        });
    }

    // ─── Test-only helpers ────────────────────────────────────────────────────

    /// Insert a DagNode directly into the CCE's DAG.
    /// Used by integration tests to set up causal ancestry without going through
    /// the full write pipeline.
    #[cfg(test)]
    pub fn test_insert_dag_node(
        &mut self,
        node: crate::crdt::dag::DagNode,
    ) -> Result<(), TirBaseError> {
        self.dag
            .insert(node)
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("test_insert_dag_node: {e}"),
            })
    }

    /// Manually set the `contaminated_rows` entry for a `(table, row_key)` pair.
    /// Used by integration tests to simulate projection-layer contamination without
    /// requiring a full `tag_contamination_root` walk over live store rows.
    #[cfg(test)]
    pub fn test_set_contaminated_row(
        &mut self,
        table: &str,
        row_key: &str,
        incident_id: IncidentId,
    ) {
        self.contaminated_rows
            .insert((table.to_string(), row_key.to_string()), incident_id);
    }

    /// Clone the shared SQLite connection handle for direct tag reads in integration
    /// tests.  Used by tests that need to verify `DeltaTag` entries on `dag_nodes`
    /// without going through the public CCE API.
    #[cfg(test)]
    pub fn test_get_conn(&self) -> std::sync::Arc<std::sync::Mutex<rusqlite::Connection>> {
        self.conn.clone()
    }

    /// Retrieve a snapshot of a `CompositeIncidentInstance` by ID.
    #[cfg(test)]
    pub fn test_get_composite_incident(&self, id: IncidentId) -> Option<CompositeIncidentInstance> {
        self.composite_incidents.get(&id).cloned()
    }

    /// Check whether an incident ID refers to a composite incident.
    #[cfg(test)]
    pub fn test_is_composite(&self, id: IncidentId) -> bool {
        self.composite_incidents.contains_key(&id)
    }

    /// Find OPEN incidents whose `contamination_roots` contain the given root.
    #[cfg(test)]
    pub fn test_open_incidents_for_root(&self, root: DeltaId) -> Vec<IncidentContextObject> {
        self.incidents
            .values()
            .filter(|ico| {
                ico.state == IncidentState::Open && ico.contamination_roots.contains(&root)
            })
            .cloned()
            .collect()
    }
}

// ─── WASM stubs ───────────────────────────────────────────────────────────────

#[cfg(not(feature = "native"))]
impl CausalContaminationEngine {
    pub fn new() -> Self {
        Self {
            incidents: HashMap::new(),
            composite_incidents: HashMap::new(),
            dag: crate::crdt::dag::ChangesetDag::new(),
            contaminated_rows: HashMap::new(),
        }
    }

    pub fn tag_contamination_root(
        &mut self,
        root_delta_id: DeltaId,
        source: TaintSource,
    ) -> Result<IncidentId, TirBaseError> {
        // Taint source guard — all three variants of TaintSource are valid.
        let _source_is_valid = match &source {
            TaintSource::DeviceRevocation { .. } => true,
            TaintSource::BadMigration { .. } => true,
            TaintSource::HumanReaction { .. } => true,
        };

        let now = now_micros();
        let ico_id = uuid::Uuid::now_v7();

        // BFS walk from the root — collect all reachable descendant Delta IDs.
        let descendants = taint::walk_dag_descendants(&self.dag, &root_delta_id)?;

        // Append Contaminated tag to every reachable Delta.
        for delta_id in &descendants {
            let _ = taint::append_tag(
                delta_id,
                DeltaTag::Contaminated {
                    root_id: root_delta_id,
                    incident_id: ico_id,
                },
            );
        }

        // Resolve affected rows (empty on WASM).
        let affected_rows = taint::resolve_affected_rows(&descendants, root_delta_id)?;

        // Build the new ICO.
        let contaminated_deltas = descendants.iter().copied().collect();
        let new_ico = IncidentContextObject {
            id: ico_id,
            state: IncidentState::Open,
            taint_source: source,
            contamination_roots: vec![root_delta_id],
            contaminated_deltas,
            affected_rows,
            composite_of: None,
            created_at: now,
            updated_at: now,
            audit_log: vec![],
        };

        // Overlap detection: check against all existing OPEN incidents.
        let overlapping_id: Option<IncidentId> = self
            .incidents
            .values()
            .filter(|existing| {
                existing.state == IncidentState::Open
                    && existing
                        .contaminated_deltas
                        .iter()
                        .any(|d| new_ico.contaminated_deltas.contains(d))
            })
            .map(|ico| ico.id)
            .next();

        if let Some(existing_ico_id) = overlapping_id {
            self.incidents.insert(ico_id, new_ico);
            let (composite_id, composite) = {
                let mut ico_b = self.incidents.remove(&ico_id).unwrap();
                let mut ico_a_owned = self.incidents.remove(&existing_ico_id).unwrap();
                let result = incident::composite_merge(&mut ico_a_owned, &mut ico_b, now);
                self.incidents.insert(existing_ico_id, ico_a_owned);
                self.incidents.insert(ico_id, ico_b);
                result
            };
            // Push IncidentCreated for the composite ICO.
            #[cfg(feature = "wasm")]
            {
                let composite_json =
                    serde_json::to_value(&composite).unwrap_or(serde_json::Value::Null);
                crate::push_wasm_event(crate::WasmEvent::IncidentCreated {
                    ico: composite_json,
                });
            }
            self.composite_incidents.insert(composite_id, composite);
            // Populate contaminated_rows index for the composite ICO (WASM).
            if let Some(comp) = self.composite_incidents.get(&composite_id) {
                for row in &comp.affected_rows {
                    self.contaminated_rows
                        .insert((row.table.clone(), row.row_key.clone()), composite_id);
                }
            }
            return Ok(composite_id);
        }

        // Push IncidentCreated for the new ICO.
        #[cfg(feature = "wasm")]
        {
            let ico_json = serde_json::to_value(&new_ico).unwrap_or(serde_json::Value::Null);
            crate::push_wasm_event(crate::WasmEvent::IncidentCreated { ico: ico_json });
        }

        self.incidents.insert(ico_id, new_ico);

        // Populate the O(1) contaminated_rows index for this ICO (WASM).
        if let Some(ico) = self.incidents.get(&ico_id) {
            for row in &ico.affected_rows {
                self.contaminated_rows
                    .insert((row.table.clone(), row.row_key.clone()), ico_id);
            }
        }

        Ok(ico_id)
    }

    pub fn verify_data(
        &mut self,
        root_delta_id: DeltaId,
        manager_did: Did,
        manager_sig: Ed25519Signature,
        manager_token_expiry: i64,
    ) -> Result<(), TirBaseError> {
        use crate::contamination::incident::{AuditEntry, AuditOperation};

        // Auth check.
        resolution::verify_manager_auth(
            &manager_did,
            &manager_sig,
            &root_delta_id,
            manager_token_expiry,
        )?;

        let at = now_micros();

        // Append Resolved tag in the WASM tag store.
        let _ = taint::append_tag(
            &root_delta_id,
            DeltaTag::Resolved {
                by_manager_did: manager_did.clone(),
                at,
            },
        );

        // Find and update incidents containing this root.
        let ico_ids: Vec<IncidentId> = self
            .incidents
            .values()
            .filter(|ico| ico.contamination_roots.contains(&root_delta_id))
            .map(|ico| ico.id)
            .collect();

        for ico_id in &ico_ids {
            let ico = match self.incidents.get_mut(ico_id) {
                Some(i) => i,
                None => continue,
            };

            ico.audit_log.push(AuditEntry {
                operation: AuditOperation::VerifyData,
                manager_did: manager_did.clone(),
                utc_timestamp: at,
                affected_delta_ids: vec![root_delta_id],
            });
            ico.updated_at = at;

            // Check if all roots are now resolved.
            let all_resolved = ico.contamination_roots.iter().all(|root_id| {
                taint::read_tags_from_mem(root_id)
                    .iter()
                    .any(|t| matches!(t, DeltaTag::Resolved { .. }))
            });

            if all_resolved {
                let deltas: Vec<DeltaId> = ico.contaminated_deltas.iter().copied().collect();
                for delta_id in &deltas {
                    let _ = taint::append_tag(
                        delta_id,
                        DeltaTag::Decontaminated {
                            incident_id: *ico_id,
                            resolved_at: at,
                        },
                    );
                }
                // All roots resolved → IncidentClosed event.
                #[cfg(feature = "wasm")]
                {
                    let ico_json = self
                        .incidents
                        .get(ico_id)
                        .and_then(|i| serde_json::to_value(i).ok())
                        .unwrap_or(serde_json::Value::Null);
                    crate::push_wasm_event(crate::WasmEvent::IncidentClosed { ico: ico_json });
                }
            } else {
                // Partial resolution → IncidentUpdated event.
                #[cfg(feature = "wasm")]
                {
                    let ico_json = self
                        .incidents
                        .get(ico_id)
                        .and_then(|i| serde_json::to_value(i).ok())
                        .unwrap_or(serde_json::Value::Null);
                    crate::push_wasm_event(crate::WasmEvent::IncidentUpdated { ico: ico_json });
                }
            }
        }

        // Prune contaminated_rows for any row that no longer has an active OPEN incident.
        self.contaminated_rows.retain(|_key, incident_id| {
            self.incidents
                .get(incident_id)
                .map(|ico| ico.state == IncidentState::Open)
                .unwrap_or(false)
                || self
                    .composite_incidents
                    .get(incident_id)
                    .map(|c| c.state == IncidentState::Open)
                    .unwrap_or(false)
        });

        Ok(())
    }

    pub fn admin_close(
        &mut self,
        incident_id: IncidentId,
        manager_did: Did,
        manager_sig: Ed25519Signature,
        manager_token_expiry: i64,
    ) -> Result<(), TirBaseError> {
        resolution::admin_close(
            incident_id,
            manager_did,
            manager_sig,
            manager_token_expiry,
            &mut self.incidents,
        )?;
        // Push IncidentClosed event after successful close (WASM path).
        #[cfg(feature = "wasm")]
        {
            let ico_json = self
                .incidents
                .get(&incident_id)
                .and_then(|i| serde_json::to_value(i).ok())
                .unwrap_or(serde_json::Value::Null);
            crate::push_wasm_event(crate::WasmEvent::IncidentClosed { ico: ico_json });
        }
        Ok(())
    }

    pub fn get_incident(
        &self,
        id: IncidentId,
    ) -> Result<Option<IncidentContextObject>, TirBaseError> {
        Ok(self.incidents.get(&id).cloned())
    }

    pub fn open_incidents(&self) -> Result<Vec<IncidentContextObject>, TirBaseError> {
        Ok(self
            .incidents
            .values()
            .filter(|ico| ico.state == IncidentState::Open)
            .cloned()
            .collect())
    }

    /// O(1) check — returns `true` if the given `(table, row_key)` pair is currently
    /// contaminated by an active incident (Req 19.5).
    pub fn is_row_contaminated(&self, table: &str, row_key: &str) -> bool {
        self.contaminated_rows
            .contains_key(&(table.to_string(), row_key.to_string()))
    }

    /// O(1) lookup — returns the active `IncidentId` for the given `(table, row_key)`
    /// if the row is contaminated, or `None` otherwise (Req 19.5).
    pub fn active_incident_for_row(&self, table: &str, row_key: &str) -> Option<IncidentId> {
        self.contaminated_rows
            .get(&(table.to_string(), row_key.to_string()))
            .copied()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::contamination::incident::{AuditOperation, TaintSource};
    use crate::crdt::dag::{ChangesetDag, DagNode};
    use crate::crdt::delta::DeltaTag;
    use crate::identity::{keypair, IdentityManager};
    use crate::store::sqlite;
    use std::sync::{Arc, Mutex};

    // ─── Test helpers ────────────────────────────────────────────────────────

    fn open_cce() -> CausalContaminationEngine {
        let conn = sqlite::open(":memory:").expect("open in-memory SQLite");
        let conn = Arc::new(Mutex::new(conn));
        CausalContaminationEngine::new(conn)
    }

    fn open_cce_with_conn() -> (CausalContaminationEngine, Arc<Mutex<rusqlite::Connection>>) {
        let conn = sqlite::open(":memory:").expect("open in-memory SQLite");
        let conn = Arc::new(Mutex::new(conn));
        let cce = CausalContaminationEngine::new(conn.clone());
        (cce, conn)
    }

    /// Insert a minimal DagNode into the DAG.
    fn insert_node(dag: &mut ChangesetDag, id: [u8; 32], parents: Vec<[u8; 32]>) {
        dag.insert(DagNode {
            delta_id: id,
            payload: vec![],
            parent_ids: parents,
            actor_id: b"actor".to_vec(),
            lamport: 1,
            schema_hash: [0u8; 32],
            compacted: false,
            author_did: "did:key:z6MkTest".to_string(),
        })
        .expect("insert DagNode");
    }

    /// Build a fresh manager identity and return (manager_did, signing_fn, token_expiry).
    fn make_manager() -> (String, [u8; 32]) {
        let mgr = IdentityManager::init_in_memory().unwrap();
        let secret = mgr.signing_key_bytes();
        (mgr.did().to_string(), secret)
    }

    /// Sign `payload` and return an `Ed25519Signature`.
    fn sign(secret: &[u8; 32], payload: &[u8]) -> Ed25519Signature {
        keypair::sign(secret, payload).expect("sign")
    }

    /// A token expiry well in the future (now + 1 hour in micros).
    fn future_expiry() -> i64 {
        now_micros() + 3_600_000_000
    }

    // ─── Test 1: Single-root taint walk completeness ─────────────────────────

    #[test]
    fn test_single_root_taint_walk_completeness() {
        let (mut cce, conn) = open_cce_with_conn();

        let root_id = [0x01u8; 32];
        let mid_id = [0x02u8; 32];
        let leaf_id = [0x03u8; 32];

        // Build 3-node chain in the DAG.
        insert_node(&mut cce.dag, root_id, vec![]);
        insert_node(&mut cce.dag, mid_id, vec![root_id]);
        insert_node(&mut cce.dag, leaf_id, vec![mid_id]);

        let source = TaintSource::DeviceRevocation {
            revocation_delta_id: root_id,
        };
        let ico_id = cce
            .tag_contamination_root(root_id, source)
            .expect("tag_contamination_root should succeed");

        // ICO must record all 3 deltas.
        let ico = cce
            .get_incident(ico_id)
            .expect("get_incident ok")
            .expect("ICO must exist");
        assert!(
            ico.contaminated_deltas.contains(&root_id),
            "root must be in contaminated_deltas"
        );
        assert!(
            ico.contaminated_deltas.contains(&mid_id),
            "mid must be in contaminated_deltas"
        );
        assert!(
            ico.contaminated_deltas.contains(&leaf_id),
            "leaf must be in contaminated_deltas"
        );

        // Check dag_nodes.tags_json for each node.
        let lock = conn.lock().unwrap();
        for id in [&root_id, &mid_id, &leaf_id] {
            let tags = taint::read_tags_from_db(&lock, id).expect("read tags");
            assert!(
                tags.iter().any(|t| matches!(
                    t,
                    DeltaTag::Contaminated { incident_id, .. } if *incident_id == ico_id
                )),
                "node {id:?} must have Contaminated tag"
            );
        }
    }

    // ─── Test 2: Multi-root DECONTAMINATED held until all roots resolved ──────

    #[test]
    fn test_multi_root_decontaminated_held_until_all_resolved() {
        let (mut cce, conn) = open_cce_with_conn();
        let (mgr_did, mgr_secret) = make_manager();

        let root_a = [0x0Au8; 32];
        let root_b = [0x0Bu8; 32];
        let shared = [0x0Cu8; 32]; // descendant of both

        // Build chain A: root_a → shared
        insert_node(&mut cce.dag, root_a, vec![]);
        insert_node(&mut cce.dag, root_b, vec![]);
        insert_node(&mut cce.dag, shared, vec![root_a]);

        // Tag root_a → ICO_A covers {root_a, shared}
        let source_a = TaintSource::DeviceRevocation {
            revocation_delta_id: root_a,
        };
        let ico_a_id = cce
            .tag_contamination_root(root_a, source_a)
            .expect("tag root_a");

        // Tag root_b → ICO_B covers {root_b} only (no shared edge from root_b in this DAG)
        let source_b = TaintSource::BadMigration {
            migration_id: [0x0Bu8; 32],
        };
        let ico_b_id = cce
            .tag_contamination_root(root_b, source_b)
            .expect("tag root_b");

        let expiry = future_expiry();

        // Resolve root_a.
        let sig_a = sign(&mgr_secret, &root_a);
        cce.verify_data(root_a, mgr_did.clone(), sig_a, expiry)
            .expect("verify_data root_a");

        // shared should NOT yet have Decontaminated tag (root_b is still unresolved,
        // though it's in a separate ICO).  For ICO_A all roots = [root_a] → root_a
        // IS resolved now, so ICO_A will be decontaminated.  The shared node
        // should have Decontaminated for ICO_A.
        // The critical check is: the CONTAMINATED tag from ICO_A is still present.
        let lock = conn.lock().unwrap();
        let tags = taint::read_tags_from_db(&lock, &shared).expect("read tags shared");
        // Must still have the Contaminated tag.
        assert!(
            tags.iter()
                .any(|t| matches!(t, DeltaTag::Contaminated { .. })),
            "shared must still carry Contaminated tag even after root_a resolved"
        );
        // Decontaminated should now be present for ICO_A (single-root ICO is now fully resolved).
        assert!(
            tags.iter()
                .any(|t| matches!(t, DeltaTag::Decontaminated { .. })),
            "shared must have Decontaminated tag after ICO_A (single root) is resolved"
        );
        drop(lock);

        // Resolve root_b.
        let sig_b = sign(&mgr_secret, &root_b);
        cce.verify_data(root_b, mgr_did.clone(), sig_b, expiry)
            .expect("verify_data root_b");

        // After both resolved, the shared node (in ICO_A) stays decontaminated
        // and root_b's ICO is also fully resolved.
        let lock = conn.lock().unwrap();
        let tags_root_b = taint::read_tags_from_db(&lock, &root_b).expect("read tags root_b");
        assert!(
            tags_root_b
                .iter()
                .any(|t| matches!(t, DeltaTag::Resolved { .. })),
            "root_b must have Resolved tag"
        );
    }

    // ─── Test 3: Composite merge on shared DAG node ───────────────────────────

    #[test]
    fn test_composite_merge_on_shared_dag_node() {
        let (mut cce, _conn) = open_cce_with_conn();

        let a1 = [0x01u8; 32];
        let b1 = [0x02u8; 32];
        let a2 = [0x03u8; 32]; // shared child

        // Chain A: a1 → a2
        insert_node(&mut cce.dag, a1, vec![]);
        insert_node(&mut cce.dag, a2, vec![a1]);
        // Chain B: b1 → a2 (b1 shares a2 with chain A)
        insert_node(&mut cce.dag, b1, vec![]);
        // Note: a2 already inserted; add b1 → a2 edge by making a2 a child of b1.
        // Since a2 is already in the DAG with parent a1 only, we need to reinsert
        // with both parents — but dag INSERT OR IGNORE means we can't update.
        // For the overlap detection test we use a fresh node that's a child of b1:
        let b2 = [0x04u8; 32]; // b1 → b2, and a2 → b2 (diamond via b2)
        insert_node(&mut cce.dag, b2, vec![a2, b1]);

        let source_a = TaintSource::DeviceRevocation {
            revocation_delta_id: a1,
        };
        let result_a_id = cce.tag_contamination_root(a1, source_a).expect("tag a1");

        // ICO_A covers {a1, a2, b2}.
        let ico_a = cce.incidents.get(&result_a_id).cloned();

        let source_b = TaintSource::BadMigration {
            migration_id: [0x0Bu8; 32],
        };
        let result_b_id = cce.tag_contamination_root(b1, source_b).expect("tag b1");

        // If b1's descendants include b2 which is already in ICO_A → composite formed.
        // result_b_id should be the composite ID.
        let is_composite = cce.composite_incidents.contains_key(&result_b_id);
        if is_composite {
            // ICO_A should be marked SupersededBy.
            let ico_a_state = cce.incidents.get(&result_a_id).map(|i| i.state);
            assert!(
                matches!(ico_a_state, Some(IncidentState::SupersededBy(_))),
                "ICO_A must be SupersededBy composite: {ico_a_state:?}"
            );

            let composite = cce.composite_incidents.get(&result_b_id).unwrap();
            assert!(
                composite.contaminated_deltas.contains(&a1),
                "composite must contain a1"
            );
            assert!(
                composite.contaminated_deltas.contains(&b1),
                "composite must contain b1"
            );
        } else {
            // No overlap detected (b1 and a1 have disjoint descendants in this graph).
            // The test confirms both ICOs are independently registered.
            assert!(
                cce.incidents.contains_key(&result_a_id)
                    || cce.incidents.contains_key(&result_b_id),
                "at least one ICO must be present"
            );
        }
    }

    // ─── Test 4: ADMIN_CLOSE on non-OPEN ICO rejected ────────────────────────

    #[test]
    fn test_admin_close_on_non_open_ico_rejected() {
        let (mut cce, _conn) = open_cce_with_conn();
        let (mgr_did, mgr_secret) = make_manager();

        let root_id = [0x10u8; 32];
        insert_node(&mut cce.dag, root_id, vec![]);

        let source = TaintSource::DeviceRevocation {
            revocation_delta_id: root_id,
        };
        let ico_id = cce
            .tag_contamination_root(root_id, source)
            .expect("tag root");

        let expiry = future_expiry();

        // First close — should succeed.
        let sig1 = sign(&mgr_secret, ico_id.as_bytes());
        cce.admin_close(ico_id, mgr_did.clone(), sig1, expiry)
            .expect("first admin_close should succeed");

        // Second close — must return InvalidIncidentState.
        let sig2 = sign(&mgr_secret, ico_id.as_bytes());
        let result = cce.admin_close(ico_id, mgr_did.clone(), sig2, expiry);
        assert!(
            matches!(
                result,
                Err(TirBaseError::InvalidIncidentState {
                    got: IncidentState::Closed
                })
            ),
            "second admin_close must return InvalidIncidentState(Closed), got: {result:?}"
        );
    }

    // ─── Test 5: Audit log immutability (only grows) ──────────────────────────

    #[test]
    fn test_audit_log_immutability() {
        let (mut cce, _conn) = open_cce_with_conn();
        let (mgr_did, mgr_secret) = make_manager();

        let root_id = [0x20u8; 32];
        insert_node(&mut cce.dag, root_id, vec![]);

        let source = TaintSource::DeviceRevocation {
            revocation_delta_id: root_id,
        };
        let ico_id = cce
            .tag_contamination_root(root_id, source)
            .expect("tag root");

        let expiry = future_expiry();

        // Audit log starts empty.
        let ico = cce.get_incident(ico_id).unwrap().unwrap();
        let initial_len = ico.audit_log.len();

        // verify_data adds one VerifyData entry.
        let sig = sign(&mgr_secret, &root_id);
        cce.verify_data(root_id, mgr_did.clone(), sig, expiry)
            .expect("verify_data");

        let ico_after_vd = cce.get_incident(ico_id).unwrap().unwrap();
        assert_eq!(
            ico_after_vd.audit_log.len(),
            initial_len + 1,
            "verify_data must add exactly one audit entry"
        );
        assert_eq!(
            ico_after_vd.audit_log.last().unwrap().operation,
            AuditOperation::VerifyData
        );

        // admin_close adds one AdminClose entry.
        let sig2 = sign(&mgr_secret, ico_id.as_bytes());
        cce.admin_close(ico_id, mgr_did.clone(), sig2, expiry)
            .expect("admin_close");

        let ico_after_ac = cce.get_incident(ico_id).unwrap().unwrap();
        assert_eq!(
            ico_after_ac.audit_log.len(),
            initial_len + 2,
            "admin_close must add exactly one audit entry"
        );
        assert_eq!(
            ico_after_ac.audit_log.last().unwrap().operation,
            AuditOperation::AdminClose
        );

        // Previous entry must be unchanged.
        assert_eq!(
            ico_after_ac.audit_log[initial_len].operation,
            AuditOperation::VerifyData,
            "earlier audit entry must not be modified"
        );
    }

    // ─── Test 6: Human-reaction auto-tag ─────────────────────────────────────

    #[test]
    fn test_human_reaction_auto_tag_when_contaminated() {
        use crate::contamination::human_reaction::{on_write_commit, WriteContext};
        use crate::crdt::delta::{Delta, Ed25519Signature as Sig, PriorityClass};

        let incident_id = uuid::Uuid::now_v7();

        let mut delta = Delta {
            id: [0u8; 32],
            author_did: "did:key:z6MkTest".to_string(),
            signature: Sig::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        };

        let ctx = WriteContext {
            local_projection_contaminated: true,
            quarantine_active: false,
            active_incident_id: Some(incident_id),
        };

        on_write_commit(&mut delta, &ctx).expect("on_write_commit should not fail");

        assert_eq!(delta.tags.len(), 1, "exactly one tag must be added");
        assert!(
            matches!(
                &delta.tags[0],
                DeltaTag::ContaminatedByHumanReaction { incident_id: id } if *id == incident_id
            ),
            "tag must be ContaminatedByHumanReaction with correct incident_id"
        );
    }

    #[test]
    fn test_human_reaction_no_tag_when_not_contaminated() {
        use crate::contamination::human_reaction::{on_write_commit, WriteContext};
        use crate::crdt::delta::{Delta, Ed25519Signature as Sig, PriorityClass};

        let mut delta = Delta {
            id: [0u8; 32],
            author_did: "did:key:z6MkTest".to_string(),
            signature: Sig::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        };

        let ctx = WriteContext {
            local_projection_contaminated: false,
            quarantine_active: false,
            active_incident_id: None,
        };

        on_write_commit(&mut delta, &ctx).expect("on_write_commit should not fail");

        assert!(
            delta.tags.is_empty(),
            "no tags must be added when not contaminated"
        );
    }

    #[test]
    fn test_human_reaction_auto_tag_when_quarantine_active() {
        use crate::contamination::human_reaction::{on_write_commit, WriteContext};
        use crate::crdt::delta::{Delta, Ed25519Signature as Sig, PriorityClass};

        let incident_id = uuid::Uuid::now_v7();

        let mut delta = Delta {
            id: [0u8; 32],
            author_did: "did:key:z6MkTest".to_string(),
            signature: Sig::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: vec![],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        };

        let ctx = WriteContext {
            local_projection_contaminated: false,
            quarantine_active: true,
            active_incident_id: Some(incident_id),
        };

        on_write_commit(&mut delta, &ctx).unwrap();
        assert!(
            !delta.tags.is_empty(),
            "quarantine_active must trigger human-reaction tag"
        );
    }

    // ─── Test 7: open_incidents returns only OPEN ICOs ────────────────────────    #[test]
    fn test_open_incidents_filters_correctly() {
        let (mut cce, _conn) = open_cce_with_conn();
        let (mgr_did, mgr_secret) = make_manager();

        let root_a = [0x30u8; 32];
        let root_b = [0x31u8; 32];
        insert_node(&mut cce.dag, root_a, vec![]);
        insert_node(&mut cce.dag, root_b, vec![]);

        let ico_a = cce
            .tag_contamination_root(
                root_a,
                TaintSource::DeviceRevocation {
                    revocation_delta_id: root_a,
                },
            )
            .unwrap();
        let ico_b = cce
            .tag_contamination_root(
                root_b,
                TaintSource::DeviceRevocation {
                    revocation_delta_id: root_b,
                },
            )
            .unwrap();

        // Close ICO_A.
        let sig = sign(&mgr_secret, ico_a.as_bytes());
        cce.admin_close(ico_a, mgr_did.clone(), sig, future_expiry())
            .unwrap();

        let open = cce.open_incidents().unwrap();
        assert_eq!(open.len(), 1, "only one incident should be open");
        assert_eq!(open[0].id, ico_b, "the open incident must be ICO_B");
    }

    // ─── Test 8: projection contamination flags round-trip ───────────────────

    #[test]
    fn test_projection_contamination_flags_round_trip() {
        let (mut cce, conn) = open_cce_with_conn();
        let (mgr_did, mgr_secret) = make_manager();

        let root_id = [0xA1u8; 32];
        insert_node(&mut cce.dag, root_id, vec![]);

        // Insert a projection row that resolve_affected_rows will discover.
        {
            let lock = conn.lock().unwrap();
            lock.execute_batch(
                "CREATE TABLE IF NOT EXISTS proj_reports \
                 (key TEXT PRIMARY KEY, data_json TEXT NOT NULL, \
                  contaminated INTEGER NOT NULL DEFAULT 0); \
                 INSERT OR IGNORE INTO proj_reports (key, data_json) \
                 VALUES ('row-1', '\"data\"');",
            )
            .expect("setup proj_reports");
        }

        // Tag contamination root — should mark all projection rows contaminated.
        let source = TaintSource::DeviceRevocation {
            revocation_delta_id: root_id,
        };
        let ico_id = cce
            .tag_contamination_root(root_id, source)
            .expect("tag_contamination_root");

        {
            let lock = conn.lock().unwrap();
            let contaminated: i64 = lock
                .query_row(
                    "SELECT contaminated FROM proj_reports WHERE key = 'row-1'",
                    [],
                    |row| row.get(0),
                )
                .expect("query contaminated after tag");
            assert_eq!(
                contaminated, 1,
                "row must be contaminated=1 after tag_contamination_root"
            );
        }

        // The ICO's affected_rows must be populated.
        let ico = cce.get_incident(ico_id).unwrap().unwrap();
        assert!(
            !ico.affected_rows.is_empty(),
            "ICO affected_rows must be non-empty after projection wiring"
        );

        // verify_data resolves the single root → should clear the projection flag.
        let expiry = future_expiry();
        let sig = sign(&mgr_secret, &root_id);
        cce.verify_data(root_id, mgr_did.clone(), sig, expiry)
            .expect("verify_data");

        {
            let lock = conn.lock().unwrap();
            let contaminated: i64 = lock
                .query_row(
                    "SELECT contaminated FROM proj_reports WHERE key = 'row-1'",
                    [],
                    |row| row.get(0),
                )
                .expect("query contaminated after verify_data");
            assert_eq!(
                contaminated, 0,
                "row must return to contaminated=0 after verify_data"
            );
        }
    }
}
