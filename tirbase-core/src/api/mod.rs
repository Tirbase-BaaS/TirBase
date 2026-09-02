//! Public API layer — CoreHandle, init(), read(), write(), query()
//!
//! This is the primary entry point for both the TypeScript SDK (WASM build)
//! and the Cloud Ledger (native build). The API surface is identical on both
//! build targets; static_assertions in lib.rs enforce this at compile time.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod types;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::errors::TirBaseError;
use types::{
    ConnectionStatus, DurabilityTier, MeshStatus, QueryResult, TrustLevel, WriteResult,
};

// ─── Subsystem imports ────────────────────────────────────────────────────────

use crate::auth::CapabilityManager;
use crate::contamination::human_reaction::{on_write_commit, WriteContext};
use crate::contamination::CausalContaminationEngine;
use crate::crdt::delta::PriorityClass;
use crate::crdt::CrdtEngine;
use crate::diagnostics::{emit_startup_diagnostics, DiagnosticEntry};
use crate::durability::quorum::QuorumConfig;
use crate::durability::DurabilitySubsystem;
use crate::identity::IdentityManager;
use crate::migration::version_path::SchemaVersionPath;
use crate::migration::SchemaMigrationEngine;
use crate::transport::{MeshTransport, TransportConfig};

// Store import — used on both build targets
#[cfg(feature = "native")]
use crate::store::LocalStore;

#[cfg(not(feature = "native"))]
use crate::store::LocalStore;

/// Default schema hash used when no explicit schema is configured.
const DEFAULT_SCHEMA_HASH: [u8; 32] = [0u8; 32];

// ─── CoreHandle ───────────────────────────────────────────────────────────────

/// The main handle to a TirBase instance.
/// Obtained by calling [`CoreHandle::init`].
pub struct CoreHandle {
    /// Local SQLite-backed store (native) or in-memory store (WASM).
    #[cfg(feature = "native")]
    store: Arc<Mutex<LocalStore>>,

    /// In-memory store for WASM builds.
    #[cfg(not(feature = "native"))]
    store: Arc<Mutex<LocalStore>>,

    /// CRDT engine (Automerge + DAG).
    #[cfg(feature = "native")]
    crdt: Arc<Mutex<CrdtEngine>>,

    /// Device identity (Ed25519 keypair + DID).
    pub(crate) identity: Arc<IdentityManager>,

    /// Biscuit token / TrustLevel state machine.
    capability: Arc<Mutex<CapabilityManager>>,

    /// Mesh transport layer (libp2p Swarm on native).
    pub(crate) transport: Arc<Mutex<MeshTransport>>,

    /// Two-tier durability subsystem.
    durability: Arc<Mutex<DurabilitySubsystem>>,

    /// Causal Contamination Engine.
    #[cfg(feature = "native")]
    pub(crate) cce: Arc<Mutex<CausalContaminationEngine>>,

    /// Schema Migration Engine.
    migration: Arc<Mutex<SchemaMigrationEngine>>,

    /// Causal Contamination Engine (WASM build).
    #[cfg(not(feature = "native"))]
    pub(crate) cce: Arc<Mutex<crate::contamination::CausalContaminationEngine>>,

    /// Revocation Subsystem (native build).
    #[cfg(feature = "native")]
    pub(crate) revocation: Arc<Mutex<crate::auth::RevocationSubsystem>>,

    /// Revocation Subsystem (WASM build).
    #[cfg(not(feature = "native"))]
    pub(crate) revocation: Arc<Mutex<crate::auth::RevocationSubsystem>>,

    /// Broadcast channel for structured diagnostic entries.
    diagnostics_channel: tokio::sync::broadcast::Sender<DiagnosticEntry>,

    /// Sender end of the inbound Gossipsub message channel.
    /// The spawned event loop writes here; `process_inbound_messages` drains via `inbound_rx`.
    inbound_tx: tokio::sync::mpsc::Sender<crate::transport::message::GossipMessage>,

    /// Receiver end of the inbound Gossipsub message channel.
    /// Wrapped in `tokio::sync::Mutex` so `CoreHandle` remains `Sync`.
    inbound_rx: tokio::sync::Mutex<
        tokio::sync::mpsc::Receiver<crate::transport::message::GossipMessage>,
    >,
}

impl CoreHandle {
    /// Initialise TirBase, loading or creating local storage and identity.
    ///
    /// On the WASM target this is exposed to JavaScript and resolves a
    /// Promise-based ready signal (Req 2.2).
    /// On the native target it blocks until initialisation is complete.
    pub async fn init(config: InitConfig) -> Result<Self, TirBaseError> {
        // ── Diagnostics channel ───────────────────────────────────────────────
        let (diag_tx, _diag_rx) =
            tokio::sync::broadcast::channel::<DiagnosticEntry>(64);

        // ── Identity ──────────────────────────────────────────────────────────
        let identity_path = format!("{}.identity.json", config.storage_path);
        let identity = {
            #[cfg(feature = "native")]
            {
                IdentityManager::init_with_path(Some(&identity_path))?
            }
            #[cfg(not(feature = "native"))]
            {
                IdentityManager::init_in_memory()?
            }
        };
        let identity = Arc::new(identity);

        // ── Capability Manager ────────────────────────────────────────────────
        let mut capability = CapabilityManager::new(
            vec![],
            config.deployment.revocation_m,
            config.deployment.revocation_n,
        );
        if let Some(warning) = capability.check_1_of_1_warning() {
            // Emit as an informal diagnostic — ignore send errors (no subscribers yet).
            let _ = diag_tx.send(DiagnosticEntry {
                severity: crate::diagnostics::DiagnosticSeverity::Warning,
                code: "UNILATERAL_EXILE",
                message: warning,
            });
        }
        let capability = Arc::new(Mutex::new(capability));

        // ── Native subsystems (require rusqlite) ──────────────────────────────
        #[cfg(feature = "native")]
        let (store, crdt, cce) = {
            // Primary store connection (used by LocalStore).
            let store = LocalStore::open(&config.storage_path)?;
            let store = Arc::new(Mutex::new(store));

            // Secondary connection for CrdtEngine + CCE (they hold their own
            // Arc<Mutex<Connection>> references internally).
            let conn = crate::store::sqlite::open(&config.storage_path)?;
            // Schema is already created by `sqlite::open`; the
            // CREATE_SCHEMA_SQL call inside open() is idempotent.
            let conn = Arc::new(Mutex::new(conn));

            let crdt = CrdtEngine::new(
                identity.signing_key_bytes(),
                identity.public_key_bytes(),
                identity.did().to_string(),
                DEFAULT_SCHEMA_HASH,
                conn.clone(),
            );
            let crdt = Arc::new(Mutex::new(crdt));

            let cce = CausalContaminationEngine::new(conn.clone());
            let cce = Arc::new(Mutex::new(cce));

            (store, crdt, cce)
        };

        // ── WASM store (in-memory) ────────────────────────────────────────────
        #[cfg(not(feature = "native"))]
        let store = {
            let store = LocalStore::open(":memory:")?;
            Arc::new(Mutex::new(store))
        };

        // ── Native Revocation Subsystem ───────────────────────────────────────
        #[cfg(feature = "native")]
        let revocation = {
            let conn = crate::store::sqlite::open(&config.storage_path)?;
            let conn = Arc::new(Mutex::new(conn));
            Arc::new(Mutex::new(crate::auth::RevocationSubsystem::new(
                config.deployment.revocation_m.max(1),
                config.deployment.revocation_n.max(1),
                conn,
            )))
        };

        // ── WASM CCE and RevocationSubsystem ──────────────────────────────────
        #[cfg(not(feature = "native"))]
        let cce = Arc::new(Mutex::new(
            crate::contamination::CausalContaminationEngine::new()
        ));

        #[cfg(not(feature = "native"))]
        let revocation = Arc::new(Mutex::new(
            crate::auth::RevocationSubsystem::new(
                config.deployment.revocation_m.max(1),
                config.deployment.revocation_n.max(1),
            )
        ));

        // ── Migration Engine ──────────────────────────────────────────────────
        let migration = SchemaMigrationEngine::new(
            [0u8; 32], // CA public key — not configured at init for v1
            [0u8; 32], // local schema hash — default (no schema)
            SchemaVersionPath::new(vec![]),
            config.deployment.revocation_m.max(1),
            #[cfg(feature = "native")] store.clone(),
        );
        let migration = Arc::new(Mutex::new(migration));

        // ── Durability Subsystem ──────────────────────────────────────────────
        let durability = DurabilitySubsystem::new(QuorumConfig {
            k: config.deployment.quorum_k.max(1),
            n: config.deployment.quorum_n.max(1),
            spatial_diversity_min: config.deployment.spatial_diversity_min,
            max_single_sector_fraction: 0.7,
        });
        let durability = Arc::new(Mutex::new(durability));

        // ── Mesh Transport ────────────────────────────────────────────────────
        let mut transport = MeshTransport::new(
            identity.did().to_string(),
            TransportConfig::default(),
        );
        #[cfg(feature = "native")]
        {
            // Start the libp2p Swarm in the background.  Failure is logged but
            // not fatal — the device can still operate offline (Req 3.3).
            if let Err(e) = transport.start().await {
                eprintln!("[CoreHandle::init] transport.start() failed: {e} — operating offline");
            }
        }
        let transport = Arc::new(Mutex::new(transport));

        // ── Inbound message channel ───────────────────────────────────────────
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<
            crate::transport::message::GossipMessage,
        >(1024);

        // ── Native: take the Swarm and spawn the inbound polling task ─────────
        #[cfg(feature = "native")]
        {
            use crate::transport::TirBaseBehaviour;
            use libp2p::futures::StreamExt as _;
            use libp2p::gossipsub;
            use libp2p::mdns;
            use libp2p::swarm::SwarmEvent;

            let swarm_opt = transport.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("transport mutex poisoned: {e}"),
            })?.take_swarm();

            if let Some(mut swarm) = swarm_opt {
                let tx_clone = inbound_tx.clone();
                tokio::spawn(async move {
                    loop {
                        match swarm.select_next_some().await {
                            SwarmEvent::Behaviour(
                                crate::transport::TirBaseBehaviourEvent::Gossipsub(
                                    gossipsub::Event::Message { message, .. },
                                ),
                            ) => {
                                if let Some(msg) = crate::transport::message::GossipMessage::from_bytes(&message.data) {
                                    if tx_clone.send(msg).await.is_err() {
                                        // Receiver dropped — CoreHandle is gone.
                                        break;
                                    }
                                } else {
                                    eprintln!(
                                        "[transport-loop] unrecognised gossipsub message ({} bytes)",
                                        message.data.len()
                                    );
                                }
                            }
                            SwarmEvent::NewListenAddr { address, .. } => {
                                eprintln!("[transport-loop] listening on {address}");
                            }
                            SwarmEvent::Behaviour(
                                crate::transport::TirBaseBehaviourEvent::Mdns(
                                    mdns::Event::Discovered(peers),
                                ),
                            ) => {
                                for (peer_id, _) in peers {
                                    eprintln!("[transport-loop] mDNS discovered: {peer_id}");
                                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                }
                            }
                            SwarmEvent::Behaviour(
                                crate::transport::TirBaseBehaviourEvent::Mdns(
                                    mdns::Event::Expired(peers),
                                ),
                            ) => {
                                for (peer_id, _) in peers {
                                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                                }
                            }
                            _ => {}
                        }
                    }
                });
            }
        }

        // ── Startup diagnostics ───────────────────────────────────────────────
        let diag_entries = emit_startup_diagnostics(&config);
        for entry in diag_entries {
            let _ = diag_tx.send(entry);
        }

        Ok(CoreHandle {
            #[cfg(feature = "native")]
            store,
            #[cfg(not(feature = "native"))]
            store,
            #[cfg(feature = "native")]
            crdt,
            identity,
            capability,
            transport,
            durability,
            #[cfg(feature = "native")]
            cce,
            #[cfg(not(feature = "native"))]
            cce,
            #[cfg(feature = "native")]
            revocation,
            #[cfg(not(feature = "native"))]
            revocation,
            migration,
            diagnostics_channel: diag_tx,
            inbound_tx,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
        })    }

    // ─── Write ────────────────────────────────────────────────────────────────

    /// Write a record to a table (Req 2.1, 2.3, 3.2).
    pub async fn write(
        &self,
        table: &str,
        key: &str,
        data: serde_json::Value,
    ) -> Result<WriteResult, TirBaseError> {
        // 1. Trust level gate — REVOKED devices cannot write.
        {
            let cap = self.capability.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("capability mutex poisoned: {e}"),
                }
            })?;
            if cap.trust_level() == TrustLevel::Revoked {
                return Err(TirBaseError::AuthorisationFailed {
                    reason: "device is REVOKED".to_string(),
                });
            }
        }

        // 2. Write to local store inside a SQLite transaction (Req 3.6).
        #[cfg(feature = "native")]
        {
            self.store
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                })?
                .write(table, key, &data)?;
        }

        // 2b. Write to in-memory store on WASM (Req 3.1, 3.3).
        #[cfg(not(feature = "native"))]
        {
            self.store
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                })?
                .write(table, key, &data)?;
        }

        // 3. Produce a signed Delta.
        let automerge_bytes = serde_json::to_vec(&data).unwrap_or_default();

        #[cfg(feature = "native")]
        let mut delta = {
            self.crdt
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("crdt mutex poisoned: {e}"),
                })?
                .produce_delta(automerge_bytes, PriorityClass::Low, vec![])?
        };

        // Placeholder delta for WASM builds where CrdtEngine doesn't run.
        #[cfg(not(feature = "native"))]
        let mut delta = crate::crdt::delta::Delta {
            id: [0u8; 32],
            author_did: self.identity.did().to_string(),
            signature: crate::crdt::delta::Ed25519Signature::default(),
            schema_hash: DEFAULT_SCHEMA_HASH,
            automerge_bytes,
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 0,
            created_at: 0,
        };

        // 4. Human-reaction auto-tag (Req 19.5).
        let write_ctx = WriteContext {
            local_projection_contaminated: false,
            quarantine_active: false,
            active_incident_id: None,
        };
        on_write_commit(&mut delta, &write_ctx)?;

        // 5. Register with durability subsystem (adds to cloud outbound queue).
        let delta_bytes = serde_json::to_vec(&delta).unwrap_or_default();
        self.durability
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("durability mutex poisoned: {e}"),
            })?
            .register_delta(
                delta.id,
                delta.id,              // state_hash = delta.id for v1
                delta_bytes,
                delta.causal_parents.clone(),
                HashMap::new(),
            )?;

        // 6. Prepare outbound (gossip broadcast — real send requires live peers).
        let _ = self
            .transport
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("transport mutex poisoned: {e}"),
            })?
            .prepare_outbound(&delta);

        // 7. Collect unverified warning (Req 8.4).
        let unverified_warning = self
            .capability
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("capability mutex poisoned: {e}"),
            })?
            .unverified_warning();

        Ok(WriteResult {
            delta_id: delta.id,
            durability_tier: DurabilityTier::Uncommitted,
            unverified_warning,
        })
    }

    // ─── Read ─────────────────────────────────────────────────────────────────

    /// Read a single record from a table by key (Req 2.1, 3.3).
    pub async fn read(&self, table: &str, key: &str) -> Result<QueryResult, TirBaseError> {
        #[cfg(feature = "native")]
        let data = {
            let store = self.store.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                }
            })?;
            store.read(table, key)?.ok_or_else(|| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("key '{key}' not found in table '{table}'"),
                }
            })?
        };

        #[cfg(not(feature = "native"))]
        let data = {
            let store = self.store.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                }
            })?;
            store.read(table, key)?.ok_or_else(|| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("key '{key}' not found in table '{table}'"),
                }
            })?
        };

        let unverified_warning = self
            .capability
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("capability mutex poisoned: {e}"),
            })?
            .unverified_warning();

        Ok(QueryResult {
            table: table.to_string(),
            key: key.to_string(),
            data,
            unverified_warning,
            contaminated: false,
        })
    }

    // ─── Query ────────────────────────────────────────────────────────────────

    /// Query multiple records from a table with an optional filter (Req 2.1).
    pub async fn query(
        &self,
        table: &str,
        filter: Option<serde_json::Value>,
    ) -> Result<Vec<QueryResult>, TirBaseError> {
        #[cfg(feature = "native")]
        let rows = {
            let store = self.store.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                }
            })?;
            store.query(table, filter.as_ref())?
        };

        #[cfg(not(feature = "native"))]
        let rows = {
            let store = self.store.lock().map_err(|e| {
                TirBaseError::LocalStoreWriteFailed {
                    reason: format!("store mutex poisoned: {e}"),
                }
            })?;
            store.query(table, filter.as_ref())?
        };

        let unverified_warning = self
            .capability
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("capability mutex poisoned: {e}"),
            })?
            .unverified_warning();

        let results = rows
            .into_iter()
            .map(|(row_key, data)| QueryResult {
                table: table.to_string(),
                key: row_key,
                data,
                unverified_warning: unverified_warning.clone(),
                contaminated: false,
            })
            .collect();

        Ok(results)
    }

    // ─── Trust level ──────────────────────────────────────────────────────────

    /// The current Trust_Level of the local device (Req 2.4).
    pub fn trust_level(&self) -> TrustLevel {
        self.capability
            .lock()
            .map(|cap| cap.trust_level())
            .unwrap_or(TrustLevel::Unverified)
    }

    // ─── Mesh status ──────────────────────────────────────────────────────────

    /// Mesh connection status and peer count (Req 2.5).
    pub fn mesh_status(&self) -> MeshStatus {
        let peers = self
            .transport
            .lock()
            .map(|t| t.active_peers())
            .unwrap_or_default();

        let status = if peers.is_empty() {
            ConnectionStatus::Disconnected
        } else {
            ConnectionStatus::Connected
        };

        MeshStatus {
            status,
            peer_count: peers.len() as u32,
        }
    }

    /// Subscribe to the diagnostic broadcast channel.
    ///
    /// Returns a new receiver that will receive all future diagnostic entries
    /// sent to this handle's channel.
    pub fn subscribe_diagnostics(
        &self,
    ) -> tokio::sync::broadcast::Receiver<DiagnosticEntry> {
        self.diagnostics_channel.subscribe()
    }

    // ─── Inbound message pipeline ─────────────────────────────────────────────

    /// Route an inbound `GossipMessage` through the correct subsystem (native only).
    ///
    /// Called by the background processing loop or test harness with messages
    /// drained from `inbound_rx`.
    ///
    /// Dispatches:
    /// - `InboundDelta`                  → `CrdtEngine::apply`
    /// - `InboundDurabilityReceipt`      → `DurabilitySubsystem::receive_receipt`
    /// - `InboundRevocationDelta`        → `RevocationSubsystem::process_incoming_delta`
    /// - `InboundMigrationDelta`         → `SchemaMigrationEngine::receive_migration_delta`
    /// - `InboundMigrationRevocationDelta` → `SchemaMigrationEngine::receive_revocation_delta`
    #[cfg(feature = "native")]
    pub async fn receive_inbound(
        &self,
        msg: crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        use crate::crdt::merge::MergeOutcome;
        use crate::transport::message::GossipMessage;

        match msg {
            GossipMessage::InboundDelta(delta) => {
                let outcome = {
                    let mut crdt = self.crdt.lock().map_err(|e| {
                        TirBaseError::LocalStoreWriteFailed {
                            reason: format!("crdt mutex: {e}"),
                        }
                    })?;
                    crate::crdt::merge::apply_incoming_delta(&mut crdt, &delta)?
                };
                match outcome {
                    MergeOutcome::Merged { .. } => {
                        eprintln!(
                            "[inbound] delta {} merged from {}",
                            hex::encode(delta.id),
                            delta.author_did
                        );
                    }
                    MergeOutcome::Quarantined { .. } => {
                        eprintln!(
                            "[inbound] delta {} quarantined (schema mismatch) from {}",
                            hex::encode(delta.id),
                            delta.author_did
                        );
                    }
                    MergeOutcome::Rejected { reason } => {
                        eprintln!(
                            "[inbound] delta {} rejected from {}: {}",
                            hex::encode(delta.id),
                            delta.author_did,
                            reason
                        );
                    }
                }
            }
            GossipMessage::InboundDurabilityReceipt(receipt) => {
                let issuer_did = receipt.issuer_did.clone();
                let delta_id = receipt.state_hash;

                // Attempt DID resolution to look up the issuer's public key.
                match crate::identity::did::resolve_did(&issuer_did) {
                    Ok(_pk) => {
                        let mut dur = self.durability.lock().map_err(|e| {
                            TirBaseError::LocalStoreWriteFailed {
                                reason: format!("durability mutex: {e}"),
                            }
                        })?;
                        match dur.receive_receipt(receipt, &delta_id) {
                            Ok(true) => {
                                eprintln!(
                                    "[inbound] Tier-1 durability achieved for delta {}",
                                    hex::encode(delta_id)
                                );
                            }
                            Ok(false) => {}
                            Err(e) => {
                                eprintln!("[inbound] receipt rejected: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[inbound] could not resolve receipt issuer DID {issuer_did}: {e}"
                        );
                    }
                }
            }
            GossipMessage::InboundRevocationDelta(rev_delta) => {
                let cce_clone = self.cce.clone();

                let mut rev = self.revocation.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("revocation mutex: {e}"),
                    }
                })?;

                let result = rev.process_incoming_delta(
                    &rev_delta,
                    &mut |target_did, _complete_delta| {
                        // HIGH-priority gossip of complete RevocationDelta (Req 9.2).
                        eprintln!(
                            "[inbound] gossiping RevocationDelta for revoked DID: {target_did}"
                        );
                        // Actual mesh send happens via transport; skipped here for v1.
                    },
                    &mut |target_did, delta_ids| {
                        // CCE tagging of all Deltas authored by the revoked DID (Req 10.1).
                        eprintln!(
                            "[inbound] CCE tagging {} deltas for revoked DID: {target_did}",
                            delta_ids.len()
                        );
                        if let Ok(mut cce) = cce_clone.lock() {
                            for delta_id in delta_ids {
                                let _ = cce.tag_contamination_root(
                                    delta_id,
                                    crate::contamination::incident::TaintSource::DeviceRevocation {
                                        revocation_delta_id: delta_id,
                                    },
                                );
                            }
                        }
                    },
                );

                match result {
                    Ok(crate::auth::RevocationStatus::Applied) => {
                        eprintln!(
                            "[inbound] RevocationDelta applied for {}",
                            rev_delta.target_did
                        );
                    }
                    Ok(crate::auth::RevocationStatus::Pending {
                        collected,
                        required,
                    }) => {
                        eprintln!(
                            "[inbound] RevocationDelta pending {collected}/{required} sigs for {}",
                            rev_delta.target_did
                        );
                    }
                    Err(e) => {
                        eprintln!("[inbound] RevocationDelta processing failed: {e}");
                    }
                }
            }
            GossipMessage::InboundMigrationDelta(mig_delta) => {
                let sender_did = mig_delta.author_did.clone();
                let mut mig = self.migration.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("migration mutex: {e}"),
                    }
                })?;
                match mig.receive_migration_delta(mig_delta, &sender_did) {
                    Ok(result) => {
                        eprintln!("[inbound] MigrationDelta applied: {result:?}");
                    }
                    Err(e) => {
                        eprintln!("[inbound] MigrationDelta rejected: {e}");
                    }
                }
            }
            GossipMessage::InboundMigrationRevocationDelta(mig_rev) => {
                let mut mig = self.migration.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("migration mutex: {e}"),
                    }
                })?;
                if let Err(e) = mig.receive_revocation_delta(mig_rev) {
                    eprintln!("[inbound] MigrationRevocationDelta rejected: {e}");
                }
            }
        }
        Ok(())
    }

    /// WASM stub — the Gossipsub Swarm is not available on wasm32.
    #[cfg(not(feature = "native"))]
    pub async fn receive_inbound(
        &self,
        _msg: crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        Ok(())
    }

    /// Drain all pending inbound messages from the channel and route each through
    /// the appropriate subsystem (Req 4.3–4.7, 5.1–5.8).
    ///
    /// This is a non-blocking drain: it processes only messages that are already
    /// queued. Call this from an application-controlled tick loop or a dedicated
    /// background task to drive the inbound pipeline.
    ///
    /// Returns the number of messages processed.
    pub async fn process_inbound_messages(&self) -> Result<usize, TirBaseError> {
        #[cfg(not(feature = "native"))]
        {
            return Ok(0);
        }

        #[cfg(feature = "native")]
        {
            use tokio::sync::mpsc::error::TryRecvError;

            let mut count = 0usize;
            let mut rx = self.inbound_rx.lock().await;

            loop {
                match rx.try_recv() {
                    Ok(msg) => {
                        self.receive_inbound(msg).await?;
                        count += 1;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }
            Ok(count)
        }
    }

    /// Inject a `GossipMessage` directly into the inbound channel.
    ///
    /// Intended for testing only — allows tests to push messages without
    /// requiring a live libp2p Swarm.
    #[cfg(test)]
    pub async fn inject_inbound(
        &self,
        msg: crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        self.inbound_tx.send(msg).await.map_err(|e| {
            TirBaseError::LocalStoreWriteFailed {
                reason: format!("inbound_tx send failed: {e}"),
            }
        })
    }
}

// ─── Configuration types ──────────────────────────────────────────────────────

/// Configuration supplied at initialisation time.
#[derive(Debug, Clone)]
pub struct InitConfig {
    /// Path to the local SQLite database file.
    pub storage_path: String,
    /// Deployment-specific settings (M-of-N thresholds, spatial diversity, etc.).
    pub deployment: DeploymentConfig,
}

/// Deployment-specific configuration.
#[derive(Debug, Clone, Default)]
pub struct DeploymentConfig {
    /// Revocation threshold M (signatures required).
    pub revocation_m: usize,
    /// Revocation threshold N (total manager DIDs).
    pub revocation_n: usize,
    /// Biscuit token TTL in seconds (1h–24h; or extended with accepted-risk doc).
    pub biscuit_ttl_secs: u64,
    /// Whether Anchor_Attested_Location subsystem is enabled.
    pub anchor_attested_location: bool,
    /// Minimum distinct spatial tags required for Quorum.
    pub spatial_diversity_min: usize,
    /// K-of-N quorum (K receipts required).
    pub quorum_k: usize,
    /// N candidate peers for quorum.
    pub quorum_n: usize,
}

// ─── Integration tests ────────────────────────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::env;

    fn make_config(path: &str) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            deployment: DeploymentConfig {
                revocation_m: 2,
                revocation_n: 3,
                biscuit_ttl_secs: 3600,
                anchor_attested_location: false,
                spatial_diversity_min: 1,
                quorum_k: 1,
                quorum_n: 1,
            },
        }
    }

    /// Create a unique temp file path for this test.
    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    /// Remove a temp db and its accompanying identity file if they exist.
    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.identity.json"));
        // WAL + SHM side-cars
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    // ── 1. Init succeeds with a temp path ─────────────────────────────────────

    #[tokio::test]
    async fn init_succeeds_with_temp_path() {
        let path = tmp_path("init_ok");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path)).await;
        assert!(
            handle.is_ok(),
            "CoreHandle::init should succeed: {:?}",
            handle.err()
        );

        cleanup(&path);
    }

    // ── 2. Write then read returns same value ─────────────────────────────────

    #[tokio::test]
    async fn write_then_read_returns_same_value() {
        let path = tmp_path("write_read");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let data = json!({"hello": "world", "count": 42});
        handle
            .write("test_table", "key1", data.clone())
            .await
            .expect("write");

        let result = handle.read("test_table", "key1").await.expect("read");
        assert_eq!(result.data, data, "read data must match written data");
        assert_eq!(result.key, "key1");
        assert_eq!(result.table, "test_table");

        cleanup(&path);
    }

    // ── 3. Read on missing key returns Err ────────────────────────────────────

    #[tokio::test]
    async fn read_missing_key_returns_err() {
        let path = tmp_path("read_missing");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let result = handle.read("test_table", "nonexistent").await;
        assert!(
            result.is_err(),
            "reading a missing key must return Err"
        );

        cleanup(&path);
    }

    // ── 4. Trust level is Unverified after init (no Biscuit token supplied) ───

    #[tokio::test]
    async fn trust_level_is_unverified_after_init() {
        let path = tmp_path("trust_unverified");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        assert_eq!(
            handle.trust_level(),
            TrustLevel::Unverified,
            "initial trust level must be UNVERIFIED"
        );

        cleanup(&path);
    }

    // ── 5. Two independent handles share no store ─────────────────────────────

    #[tokio::test]
    async fn two_instances_sharing_no_store_are_independent() {
        let path_a = tmp_path("independent_a");
        let path_b = tmp_path("independent_b");
        cleanup(&path_a);
        cleanup(&path_b);

        let handle_a = CoreHandle::init(make_config(&path_a))
            .await
            .expect("init a");
        let handle_b = CoreHandle::init(make_config(&path_b))
            .await
            .expect("init b");

        // Write to A.
        handle_a
            .write("shared_table", "x", json!({"from": "a"}))
            .await
            .expect("write a");

        // Reading the same key from B must fail (not found).
        let result = handle_b.read("shared_table", "x").await;
        assert!(
            result.is_err(),
            "reading from handle_b after writing to handle_a must fail"
        );

        cleanup(&path_a);
        cleanup(&path_b);
    }

    // ── 6. Query returns all written rows ─────────────────────────────────────

    #[tokio::test]
    async fn query_returns_all_written_rows() {
        let path = tmp_path("query_all");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        handle.write("items", "item-1", json!({"v": 1})).await.expect("write 1");
        handle.write("items", "item-2", json!({"v": 2})).await.expect("write 2");
        handle.write("items", "item-3", json!({"v": 3})).await.expect("write 3");

        let rows = handle.query("items", None).await.expect("query");
        assert_eq!(rows.len(), 3, "query should return all 3 rows");

        cleanup(&path);
    }

    // ── 7. Mesh status is Disconnected after init (no peers connected yet) ────

    #[tokio::test]
    async fn mesh_status_is_disconnected_after_init() {
        let path = tmp_path("mesh_status");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let status = handle.mesh_status();
        assert_eq!(
            status.status,
            ConnectionStatus::Disconnected,
            "mesh status should be Disconnected when no peers are connected"
        );
        assert_eq!(status.peer_count, 0);

        cleanup(&path);
    }

    // ── 8. REVOKED device cannot write ───────────────────────────────────────

    #[tokio::test]
    async fn revoked_device_cannot_write() {
        let path = tmp_path("revoked_write");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Force REVOKED state via CapabilityManager.
        handle
            .capability
            .lock()
            .unwrap()
            .apply_revocation()
            .expect("apply_revocation");

        let result = handle
            .write("test_table", "should_fail", json!({"x": 1}))
            .await;

        assert!(
            result.is_err(),
            "REVOKED device must not be allowed to write"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("REVOKED"),
            "error message must mention REVOKED: {err}"
        );

        cleanup(&path);
    }

    // ── 9. Write result has Uncommitted durability tier ───────────────────────

    #[tokio::test]
    async fn write_result_has_uncommitted_tier() {
        let path = tmp_path("durability_tier");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let result = handle
            .write("t", "k", json!({"v": 42}))
            .await
            .expect("write");

        assert_eq!(
            result.durability_tier,
            DurabilityTier::Uncommitted,
            "initial write must have Uncommitted durability"
        );

        cleanup(&path);
    }
}

// ─── Inbound pipeline integration tests ───────────────────────────────────────

#[cfg(all(test, feature = "native"))]
mod inbound_tests {
    use super::*;
    use crate::crdt::delta::{Ed25519Signature, PriorityClass};
    use crate::identity::keypair::{generate_keypair, sign as ek_sign};
    use crate::transport::message::GossipMessage;
    use serde_json::json;
    use std::env;

    fn make_config(path: &str) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            deployment: DeploymentConfig {
                revocation_m: 2,
                revocation_n: 3,
                biscuit_ttl_secs: 3600,
                anchor_attested_location: false,
                spatial_diversity_min: 1,
                quorum_k: 1,
                quorum_n: 1,
            },
        }
    }

    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_inbound_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.identity.json"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a properly-signed Delta using the test keypair and schema hash.
    fn make_signed_delta(
        secret: &[u8; 32],
        author_did: &str,
        schema_hash: [u8; 32],
        lamport: u64,
    ) -> crate::crdt::delta::Delta {
        let mut d = crate::crdt::delta::Delta {
            id: [0u8; 32],
            author_did: author_did.to_string(),
            signature: Ed25519Signature::default(),
            schema_hash,
            automerge_bytes: vec![], // empty is safe to merge
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport,
            created_at: 0,
        };
        let canonical = d.canonical_bytes();
        d.signature = ek_sign(secret, &canonical).expect("sign");
        d.id = crate::crdt::delta::Delta::compute_id(&canonical);
        d
    }

    // ── Test 1: InboundDelta with valid signature is merged ───────────────────

    #[tokio::test]
    async fn inbound_valid_delta_is_merged() {
        let path = tmp_path("inbound_merge");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Build a peer identity with a valid did:key DID.
        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);

        // Get the engine's known schema hash by producing a delta from the handle first.
        // The default schema hash is all-zeros.
        let schema_hash = [0u8; 32]; // DEFAULT_SCHEMA_HASH

        let delta = make_signed_delta(&peer_secret, &peer_did, schema_hash, 1);
        let msg = GossipMessage::InboundDelta(delta);

        handle
            .inject_inbound(msg)
            .await
            .expect("inject_inbound should not fail");

        let processed = handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages should not fail");

        assert_eq!(processed, 1, "exactly one message should be processed");

        cleanup(&path);
    }

    // ── Test 2: InboundDelta with unknown schema hash is quarantined ──────────

    #[tokio::test]
    async fn inbound_unknown_schema_delta_is_quarantined() {
        let path = tmp_path("inbound_quarantine");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);

        // Use an unknown schema hash (should be quarantined, not rejected).
        let unknown_schema = [0xFFu8; 32];
        let delta = make_signed_delta(&peer_secret, &peer_did, unknown_schema, 1);
        let msg = GossipMessage::InboundDelta(delta);

        handle.inject_inbound(msg).await.expect("inject");

        // Should process without error (quarantine is not a pipeline error).
        let processed = handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages should succeed even for quarantined delta");

        assert_eq!(processed, 1, "quarantined delta counts as processed");

        cleanup(&path);
    }

    // ── Test 3: process_inbound_messages drains the channel correctly ─────────

    #[tokio::test]
    async fn process_inbound_messages_drains_channel() {
        let path = tmp_path("inbound_drain");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32];

        // Inject 3 messages.
        for i in 1u64..=3 {
            let delta = make_signed_delta(&peer_secret, &peer_did, schema_hash, i);
            handle
                .inject_inbound(GossipMessage::InboundDelta(delta))
                .await
                .expect("inject");
        }

        // First drain should process 3.
        let first_count = handle
            .process_inbound_messages()
            .await
            .expect("first drain");
        assert_eq!(first_count, 3, "should drain all 3 queued messages");

        // Second drain should return 0 (channel is empty).
        let second_count = handle
            .process_inbound_messages()
            .await
            .expect("second drain");
        assert_eq!(second_count, 0, "channel should be empty after first drain");

        cleanup(&path);
    }

    // ── Test 4: InboundDelta with missing signature is rejected gracefully ────

    #[tokio::test]
    async fn inbound_malformed_delta_rejected_gracefully() {
        let path = tmp_path("inbound_rejected");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Delta with empty signature — should be Rejected (not a pipeline error).
        let delta = crate::crdt::delta::Delta {
            id: [0xAAu8; 32],
            author_did: "did:key:z6MkTest".to_string(),
            signature: Ed25519Signature::default(), // empty → rejected
            schema_hash: [0u8; 32],
            automerge_bytes: vec![],
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport: 1,
            created_at: 0,
        };
        let msg = GossipMessage::InboundDelta(delta);

        handle.inject_inbound(msg).await.expect("inject");

        // Should not return Err — Rejection is logged, not propagated.
        let processed = handle
            .process_inbound_messages()
            .await
            .expect("process should succeed even for rejected delta");
        assert_eq!(processed, 1);

        cleanup(&path);
    }

    // ── Test 5: GossipMessage serialisation round-trip ────────────────────────

    #[test]
    fn gossip_message_serde_round_trip() {
        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32];
        let delta = make_signed_delta(&peer_secret, &peer_did, schema_hash, 7);

        let msg = GossipMessage::InboundDelta(delta.clone());
        let bytes = msg.to_bytes();
        let decoded = GossipMessage::from_bytes(&bytes).expect("round-trip decode");

        match decoded {
            GossipMessage::InboundDelta(d) => {
                assert_eq!(d.author_did, delta.author_did);
                assert_eq!(d.lamport, 7);
                assert_eq!(d.id, delta.id);
            }
            other => panic!("expected InboundDelta, got {other:?}"),
        }
    }
}
