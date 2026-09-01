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

    /// Revocation Subsystem (WASM build).
    #[cfg(not(feature = "native"))]
    pub(crate) revocation: Arc<Mutex<crate::auth::RevocationSubsystem>>,

    /// Broadcast channel for structured diagnostic entries.
    diagnostics_channel: tokio::sync::broadcast::Sender<DiagnosticEntry>,
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
            #[cfg(not(feature = "native"))]
            revocation,
            migration,
            diagnostics_channel: diag_tx,
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
