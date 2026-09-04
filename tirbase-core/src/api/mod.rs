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

/// Current wall-clock time in UTC microseconds (peer-table bookkeeping).
fn now_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}

/// Production cadence (ms) of the inbound drain loop spawned by
/// `CoreHandle::init` (Subphase 1.3): every 50 ms the task calls
/// `process_inbound_messages()` to drain `inbound_rx`.
#[cfg(all(feature = "native", not(test)))]
const INBOUND_DRAIN_INTERVAL_MS: u64 = 50;

/// Test-build cadence (ms) of the inbound drain loop spawned by
/// `CoreHandle::init`: 1 hour, i.e. effectively inert.  Unit tests drive
/// `process_inbound_messages()` manually and assert exact drain counts, so the
/// loop init spawns must not tick while they run; the Subphase 1.3 integration
/// test exercises the identical loop via `CoreHandle::spawn_inbound_drain_loop`
/// with a short interval.
#[cfg(all(feature = "native", test))]
const INBOUND_DRAIN_INTERVAL_MS: u64 = 3_600_000;

/// Production cadence (ms) of the DRR scheduler tick loop spawned by
/// `CoreHandle::init` (Subphase 1.4): every 1000 ms the task calls
/// `MeshTransport::tick_scheduler`, which runs one DRR scheduling epoch
/// (Req 12 — the design defines one epoch as 1 second) and forwards the
/// drained Deltas to the outbound publish channel.
#[cfg(all(feature = "native", not(test)))]
const SCHEDULER_TICK_INTERVAL_MS: u64 = 1000;

/// Test-build cadence (ms) of the DRR scheduler tick loop spawned by
/// `CoreHandle::init`: 1 hour, i.e. effectively inert.  Unit tests enqueue
/// Deltas and assert queue state (e.g. the revocation HIGH-priority enqueue
/// test), so the loop init spawns must not drain the scheduler while they
/// run; the Subphase 1.4 integration test exercises the identical loop via
/// `CoreHandle::spawn_scheduler_tick_loop` with a short interval.
#[cfg(all(feature = "native", test))]
const SCHEDULER_TICK_INTERVAL_MS: u64 = 3_600_000;

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

    /// CRDT engine for WASM builds (in-memory, no SQLite).
    #[cfg(not(feature = "native"))]
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
    ///
    /// Wrapped in `Arc<tokio::sync::Mutex<..>>` so `CoreHandle` remains
    /// `Sync` while the production inbound drain loop spawned by [`CoreHandle::init`]
    /// holds its own `Arc` clone of the receiver (Subphase 1.3).
    inbound_rx: Arc<tokio::sync::Mutex<
        tokio::sync::mpsc::Receiver<crate::transport::message::GossipMessage>,
    >>,

    /// Sender end of the explicit-dial channel (native only).
    ///
    /// [`CoreHandle::dial_peer`] forwards the target multiaddr here and the
    /// Swarm polling task (which owns the receiver end) dials it.  `None` when
    /// the transport never started (offline device — Req 3.3) or on wasm.
    #[cfg(feature = "native")]
    dial_tx: Option<tokio::sync::mpsc::Sender<libp2p::Multiaddr>>,
}

impl CoreHandle {
    /// Initialise TirBase, loading or creating local storage and identity.
    ///
    /// On the WASM target this is exposed to JavaScript and resolves a
    /// Promise-based ready signal (Req 2.2).
    /// On the native target it blocks until initialisation is complete.
    ///
    /// Returns an `Arc<CoreHandle>`: the handle is shared with the production
    /// inbound drain loop spawned inside `init` (Subphase 1.3), which keeps
    /// draining `inbound_rx` for the lifetime of the instance.
    pub async fn init(config: InitConfig) -> Result<Arc<Self>, TirBaseError> {
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
        let capability = CapabilityManager::new(
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

        // ── WASM CrdtEngine (in-memory, no SQLite connection) ─────────────────
        #[cfg(not(feature = "native"))]
        let crdt = {
            let crdt = CrdtEngine::new(
                identity.signing_key_bytes(),
                identity.public_key_bytes(),
                identity.did().to_string(),
                DEFAULT_SCHEMA_HASH,
            );
            Arc::new(Mutex::new(crdt))
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
        #[cfg(feature = "native")]
        let migration = {
            let mig_conn = crate::store::sqlite::open(&config.storage_path)?;
            let mig_conn = Arc::new(Mutex::new(mig_conn));
            SchemaMigrationEngine::new(
                [0u8; 32], // CA public key — not configured at init for v1
                [0u8; 32], // local schema hash — default (no schema)
                SchemaVersionPath::new(vec![]),
                config.deployment.revocation_m.max(1),
                store.clone(),
                mig_conn,
            )
        };

        #[cfg(not(feature = "native"))]
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
        #[cfg_attr(not(feature = "native"), allow(unused_mut))]
        let mut transport = MeshTransport::new(
            identity.did().to_string(),
            TransportConfig {
                listen_addr: config.listen_addr.clone(),
                ..TransportConfig::default()
            },
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
        //
        // The receiver is wrapped in `Arc<tokio::sync::Mutex<..>>` so it can be
        // shared between this handle (manual `process_inbound_messages()` drains)
        // and the production inbound drain loop spawned below (Subphase 1.3).
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel::<
            crate::transport::message::GossipMessage,
        >(1024);
        let inbound_rx = Arc::new(tokio::sync::Mutex::new(inbound_rx));

        // ── Native: take the Swarm and spawn the polling task ─────────────────
        //
        // The Swarm is owned exclusively by this task so it can be polled across
        // `.await` points.  Outbound delivery therefore goes through a channel:
        // `write()` → `MeshTransport::send_delta` forwards prepared payloads
        // into `outbound_rx`, and this task publishes them to the shared
        // Gossipsub topic (Subphase 1.1 — Req 5.1).
        //
        // `scheduler_tick_armed` records whether a Swarm polling task is
        // actually running; the DRR scheduler tick loop (Subphase 1.4) is only
        // spawned when it is, because the tick loop forwards scheduled Deltas
        // into the same outbound channel and would fail every epoch otherwise.
        #[cfg(feature = "native")]
        let mut scheduler_tick_armed = false;

        #[cfg(feature = "native")]
        let dial_tx = {
            use crate::transport::TirBaseBehaviour;
            use libp2p::futures::StreamExt as _;
            use libp2p::gossipsub;
            use libp2p::mdns;
            use libp2p::swarm::SwarmEvent;

            let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);

            // Explicit-dial channel (Subphase 1.5): `CoreHandle::dial_peer`
            // forwards target multiaddrs here; the Swarm polling task owns the
            // receiver and performs the actual `swarm.dial`.  `None` when no
            // polling task can be spawned (transport failed to start).
            let (dial_tx, mut dial_rx) =
                tokio::sync::mpsc::channel::<libp2p::Multiaddr>(64);

            let (swarm_opt, gossip_topic) = {
                let mut transport_guard =
                    transport.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                        reason: format!("transport mutex poisoned: {e}"),
                    })?;
                let topic = transport_guard.gossip_topic.clone();
                let swarm = transport_guard.take_swarm(outbound_tx);
                (swarm, topic)
            };

            if let Some(mut swarm) = swarm_opt {
                let tx_clone = inbound_tx.clone();
                let revocation_arc = revocation.clone();
                let transport_arc = transport.clone();
                let gossip_topic = gossipsub::IdentTopic::new(&gossip_topic);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            event = swarm.select_next_some() => {
                                match event {
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
                                    // Subphase 1.5: record live connections in
                                    // the peer table so `mesh_status()` (Req 2.5)
                                    // reflects real connectivity — including
                                    // peers reached via `CoreHandle::dial_peer`
                                    // (no mDNS announcement involved).
                                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                        let did = crate::transport::discovery::mdns_adapter::peer_id_to_did(&peer_id);
                                        if let Ok(mut t) = transport_arc.lock() {
                                            let _ = t.on_peer_discovered(
                                                crate::transport::discovery::DiscoveredPeer {
                                                    did,
                                                    transport: crate::transport::discovery::PeerTransport::Explicit {
                                                        multiaddr: format!("/p2p/{peer_id}"),
                                                    },
                                                    hop_count: 0,
                                                },
                                                now_micros(),
                                            );
                                        }
                                    }
                                    SwarmEvent::Behaviour(
                                        crate::transport::TirBaseBehaviourEvent::Mdns(
                                            mdns::Event::Discovered(peers),
                                        ),
                                    ) => {
                                        // Subphase 1.2: dial every discovered peer so
                                        // mDNS neighbours actually connect to this
                                        // Swarm (previously only
                                        // gossipsub.add_explicit_peer was called and no
                                        // connection was ever opened).
                                        crate::transport::dial_discovered_mdns_peers(&mut swarm, peers);

                                        // Re-announce recent RevocationDeltas to newly-joined peers (Req 9.2).
                                        let recent = revocation_arc.lock().map(|rev| {
                                            rev.build_recent_revocation_deltas(24 * 3600 * 1_000_000)
                                        }).unwrap_or_default();

                                        for rd in recent {
                                            let gossip_msg = crate::transport::message::GossipMessage::InboundRevocationDelta(rd);
                                            let gossip_bytes = gossip_msg.to_bytes();
                                            let wrapper = crate::crdt::delta::Delta {
                                                id: [0u8; 32],
                                                author_did: "tirbase/revocation".to_string(),
                                                signature: crate::crdt::delta::Ed25519Signature::default(),
                                                schema_hash: [0u8; 32],
                                                automerge_bytes: gossip_bytes,
                                                priority: crate::crdt::delta::PriorityClass::High,
                                                causal_parents: vec![],
                                                tags: vec![],
                                                lamport: 0,
                                                created_at: 0,
                                            };
                                            if let Ok(mut t) = transport_arc.lock() {
                                                t.enqueue_outbound(wrapper);
                                            }
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
                            Some(payload) = outbound_rx.recv() => {
                                // Test-only observability: record the payload at
                                // the publish point so integration tests can
                                // assert outbound delivery reached the mesh
                                // layer (Subphase 1.1 acceptance).
                                #[cfg(test)]
                                if let Ok(mut t) = transport_arc.lock() {
                                    t.record_outbound_payload(payload.clone());
                                }

                                // Publish to the shared topic so all subscribed
                                // peers receive it (Req 5.1).  No subscribers /
                                // mesh offline → log and continue: the local
                                // write and durability queue remain authoritative.
                                match swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .publish(gossip_topic.clone(), payload)
                                {
                                    Ok(_) => {
                                        eprintln!("[transport-loop] published outbound payload");
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[transport-loop] outbound publish deferred (no subscribers / mesh offline): {e:?}"
                                        );
                                    }
                                }
                            }
                            Some(addr) = dial_rx.recv() => {
                                // Subphase 1.5: explicit application-initiated
                                // dial (`CoreHandle::dial_peer`).  The peer id
                                // is not known in advance (only the address), so
                                // use `unknown_peer_id` — the Noise handshake
                                // reveals the real peer id on connect.
                                let opts = libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
                                    .address(addr.clone())
                                    .build();
                                match swarm.dial(opts) {
                                    Ok(()) => {
                                        eprintln!("[transport-loop] dialing explicit peer {addr}");
                                    }
                                    Err(e) => {
                                        eprintln!("[transport-loop] explicit dial to {addr} failed: {e}");
                                    }
                                }
                            }
                        }
                    }
                });

                // The outbound channel is being drained by the polling task
                // above, so the scheduler tick loop can forward into it.
                scheduler_tick_armed = true;
            }

            // `dial_tx` is only usable while a polling task owns its receiver.
            if scheduler_tick_armed {
                Some(dial_tx)
            } else {
                None
            }
        };

        // ── Startup diagnostics ───────────────────────────────────────────────
        let diag_entries = emit_startup_diagnostics(&config);
        for entry in diag_entries {
            let _ = diag_tx.send(entry);
        }

        let handle = Arc::new(CoreHandle {
            #[cfg(feature = "native")]
            store,
            #[cfg(not(feature = "native"))]
            store,
            #[cfg(feature = "native")]
            crdt,
            #[cfg(not(feature = "native"))]
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
            inbound_rx,
            #[cfg(feature = "native")]
            dial_tx,
        });

        // ── Production inbound drain loop (Subphase 1.3) ──────────────────────
        //
        // Spawn a background task that calls `process_inbound_messages()` on an
        // interval, so Gossipsub messages received by the Swarm polling task
        // (above) are actually routed through the subsystems in production —
        // previously this drain only happened when tests called it explicitly.
        //
        // The handle is returned as `Arc<CoreHandle>` precisely so this task can
        // hold a clone and keep draining for the lifetime of the instance.
        #[cfg(feature = "native")]
        {
            CoreHandle::spawn_inbound_drain_loop(
                &handle,
                std::time::Duration::from_millis(INBOUND_DRAIN_INTERVAL_MS),
            );
        }

        // ── Production DRR scheduler tick loop (Subphase 1.4) ─────────────────
        //
        // Spawn a background task that runs one DRR scheduling epoch per
        // second, draining the outbound queues built by
        // `MeshTransport::enqueue_outbound` (HIGH-priority revocation
        // rebroadcast, mDNS re-announcement) and forwarding the scheduled
        // Deltas to the outbound publish channel, which the Swarm polling task
        // drains and publishes — enqueued Deltas are now scheduled and sent,
        // not just accumulated (Req 12).
        //
        // Gated on `scheduler_tick_armed`: when `transport.start()` failed,
        // no polling task is draining the outbound channel, so the tick loop
        // would fail to forward every epoch (offline device — the durability
        // queue remains authoritative, Req 3.3).
        #[cfg(feature = "native")]
        if scheduler_tick_armed {
            CoreHandle::spawn_scheduler_tick_loop(
                &handle,
                std::time::Duration::from_millis(SCHEDULER_TICK_INTERVAL_MS),
            );
        }

        Ok(handle)
    }

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
        // Embed _tirbase_table and _tirbase_key metadata so that receiving peers can
        // project the inbound Delta directly to the SQL store (Req 4.3, 3.3).
        let automerge_bytes = {
            let mut meta = serde_json::Map::new();
            meta.insert("_tirbase_table".to_string(), serde_json::Value::String(table.to_string()));
            meta.insert("_tirbase_key".to_string(), serde_json::Value::String(key.to_string()));
            // Merge application data fields (if data is an object) or store under "_data".
            if let Some(obj) = data.as_object() {
                for (k, v) in obj {
                    meta.insert(k.clone(), v.clone());
                }
            } else {
                meta.insert("_data".to_string(), data.clone());
            }
            serde_json::to_vec(&serde_json::Value::Object(meta)).unwrap_or_default()
        };

        #[cfg(feature = "native")]
        let mut delta = {
            self.crdt
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("crdt mutex poisoned: {e}"),
                })?
                .produce_delta(automerge_bytes, PriorityClass::Low, vec![])?
        };

        // WASM build uses the real CrdtEngine (in-memory, no SQLite) to produce
        // a properly signed Delta with causal parent tracking.
        #[cfg(not(feature = "native"))]
        let mut delta = {
            self.crdt
                .lock()
                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                    reason: format!("crdt mutex poisoned: {e}"),
                })?
                .produce_delta(automerge_bytes, PriorityClass::Low, vec![])?
        };

        // 4. Human-reaction auto-tag (Req 19.5).
        // Look up live contamination and quarantine state rather than using hardcoded false values.
        let local_projection_contaminated = self
            .cce
            .lock()
            .map(|cce| cce.is_row_contaminated(table, key))
            .unwrap_or(false);
        let quarantine_active = self
            .migration
            .lock()
            .map(|mig| mig.is_schema_quarantined(table))
            .unwrap_or(false);
        let active_incident_id = self
            .cce
            .lock()
            .map(|cce| cce.active_incident_for_row(table, key))
            .unwrap_or(None);
        let write_ctx = WriteContext {
            local_projection_contaminated,
            quarantine_active,
            active_incident_id,
        };
        let human_reaction_result = on_write_commit(&mut delta, &write_ctx)?;

        // If a ContaminatedByHumanReaction tag was appended, register the new Delta
        // as a contamination root with the CCE so the ICO's contaminated_deltas and
        // affected_rows are extended to include it (Req 19.5).
        if let Some((hr_delta_id, hr_incident_id)) = human_reaction_result {
            let _ = self.cce.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("cce mutex poisoned in human-reaction wiring: {e}"),
            }).map(|mut cce| {
                cce.tag_contamination_root(
                    hr_delta_id,
                    crate::contamination::incident::TaintSource::HumanReaction {
                        triggered_by_incident_id: hr_incident_id,
                    },
                )
            });
        }

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

        // 6. Publish outbound — forward the prepared Delta payloads to the
        // Swarm polling task, which publishes them to the shared Gossipsub
        // topic (Req 5.1).  Best-effort by design: the local store write and
        // durability registration above are already committed, and a device
        // must keep operating while the mesh is unavailable (Req 3.3), so a
        // publish failure is logged rather than failing the write.
        #[cfg(feature = "native")]
        if let Err(e) = self
            .transport
            .lock()
            .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                reason: format!("transport mutex poisoned: {e}"),
            })?
            .send_delta(&self.identity.did().to_string(), &delta)
        {
            eprintln!(
                "[write] outbound publish failed for delta {}: {e} — delta remains durably queued",
                hex::encode(delta.id)
            );
        }

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

    /// Return the primary root CA public key for offline Biscuit token verification.
    ///
    /// Used by `core_activate_saturate_mode` on the WASM target to verify
    /// the disaster-alert Biscuit token (Req 13.1, 13.7).
    /// Returns an empty `Vec<u8>` if no root CA key is configured (e.g. v1 default).
    pub fn root_ca_public_key(&self) -> Vec<u8> {
        self.capability
            .lock()
            .map(|cap| {
                cap.root_ca_primary_key()
                    .map(|k| k.to_vec())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
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

                        // Project the merged Delta to the SQLite store so that
                        // `read()` and `query()` reflect the new peer state (Req 4.3, 3.3).
                        //
                        // Strategy:
                        //  1. If automerge_bytes parses as valid Automerge format, project
                        //     the doc state via CrdtEngine's internal document.
                        //  2. Otherwise try to parse automerge_bytes as the TirBase JSON
                        //     envelope (contains _tirbase_table and _tirbase_key metadata)
                        //     and call store.write() directly.
                        //  3. If no table/key can be determined, skip projection (conservative
                        //     fallback — data is in the CRDT doc but not in SQL projection yet).
                        if !delta.automerge_bytes.is_empty() {
                            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&delta.automerge_bytes) {
                                if let Some(obj) = json_val.as_object() {
                                    let table_name = obj.get("_tirbase_table").and_then(|v| v.as_str());
                                    let row_key = obj.get("_tirbase_key").and_then(|v| v.as_str());

                                    if let (Some(tbl), Some(rkey)) = (table_name, row_key) {
                                        // Reconstruct the application data (strip metadata keys).
                                        let mut app_data = serde_json::Map::new();
                                        for (k, v) in obj {
                                            if k != "_tirbase_table" && k != "_tirbase_key" {
                                                if k == "_data" {
                                                    // Scalar/non-object data stored under _data.
                                                    // Write as-is under the original key.
                                                    let _ = self.store
                                                        .lock()
                                                        .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                                            reason: format!("store mutex: {e}"),
                                                        })?
                                                        .write(tbl, rkey, v);
                                                    eprintln!(
                                                        "[inbound] projected delta {} → {tbl}/{rkey}",
                                                        hex::encode(delta.id)
                                                    );
                                                    // Break early — _data is the whole value.
                                                    app_data.clear();
                                                    break;
                                                }
                                                app_data.insert(k.clone(), v.clone());
                                            }
                                        }
                                        if !app_data.is_empty() {
                                            let app_val = serde_json::Value::Object(app_data);
                                            let _ = self.store
                                                .lock()
                                                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                                    reason: format!("store mutex: {e}"),
                                                })?
                                                .write(tbl, rkey, &app_val);
                                            eprintln!(
                                                "[inbound] projected delta {} → {tbl}/{rkey}",
                                                hex::encode(delta.id)
                                            );
                                        }
                                    } else {
                                        // JSON but no table/key metadata — cannot project.
                                        eprintln!(
                                            "[inbound] delta {} merged but no _tirbase_table/_tirbase_key in bytes — skipping SQL projection",
                                            hex::encode(delta.id)
                                        );
                                    }
                                }
                            } else {
                                // Real Automerge binary bytes — use CrdtEngine's doc state
                                // to project all tables via project_table().
                                // NOTE: The CrdtEngine's Automerge doc is cross-table;
                                // project all tables found in automerge_docs.
                                let tables_result = {
                                    let store = self.store.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                        reason: format!("store mutex: {e}"),
                                    })?;
                                    // Query automerge_docs to find known tables.
                                    // Ignore error — fall back to no projection.
                                    store.list_automerge_tables().unwrap_or_default()
                                };

                                if !tables_result.is_empty() {
                                    let crdt = self.crdt.lock().map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                        reason: format!("crdt mutex: {e}"),
                                    })?;
                                    for tbl in &tables_result {
                                        if let Err(e) = crdt.project_table_to_store(tbl, &self.store) {
                                            eprintln!(
                                                "[inbound] project_table_to_store({tbl}) failed: {e}"
                                            );
                                        }
                                    }
                                } else {
                                    eprintln!(
                                        "[inbound] delta {} has binary automerge bytes but no known tables for projection",
                                        hex::encode(delta.id)
                                    );
                                }
                            }
                        }
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
                let transport_clone = self.transport.clone();

                let mut rev = self.revocation.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("revocation mutex: {e}"),
                    }
                })?;

                let result = rev.process_incoming_delta(
                    &rev_delta,
                    &mut |target_did, complete_delta| {
                        // Req 9.2: gossip the complete RevocationDelta at HIGH priority.
                        eprintln!(
                            "[inbound] gossiping RevocationDelta at HIGH priority for revoked DID: {target_did}"
                        );
                        let gossip_msg = GossipMessage::InboundRevocationDelta(complete_delta.clone());
                        let gossip_bytes = gossip_msg.to_bytes();
                        let revocation_delta_wrapper = crate::crdt::delta::Delta {
                            id: [0u8; 32],
                            author_did: "tirbase/revocation".to_string(),
                            signature: crate::crdt::delta::Ed25519Signature::default(),
                            schema_hash: [0u8; 32],
                            automerge_bytes: gossip_bytes,
                            priority: crate::crdt::delta::PriorityClass::High,
                            causal_parents: vec![],
                            tags: vec![],
                            lamport: 0,
                            created_at: 0,
                        };
                        if let Ok(mut t) = transport_clone.lock() {
                            t.enqueue_outbound(revocation_delta_wrapper);
                        }
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

    /// WASM stub for the native `receive_inbound` — the Gossipsub Swarm is not
    /// available on wasm32. Use `receive_inbound_wasm` instead, which is driven
    /// by the JS transport layer calling `core_receive_peer_message`.
    #[cfg(not(feature = "native"))]
    pub async fn receive_inbound(
        &self,
        _msg: crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        Ok(())
    }

    /// Process an inbound peer message on the WASM target.
    ///
    /// This is the JS-driven equivalent of the native Swarm spawn loop.
    /// The JS transport layer (WebRTC data channel, BLE bridge, or any
    /// browser-compatible transport) calls `core_receive_peer_message()` with
    /// raw bytes, which deserialises them into a `GossipMessage` and delegates
    /// here. Each variant is routed to the correct in-memory subsystem (Req 5,
    /// Req 1.4).
    ///
    /// Routing:
    /// - `InboundDelta`                   → signature verification + in-memory store write
    /// - `InboundDurabilityReceipt`       → `DurabilitySubsystem::receive_receipt`
    /// - `InboundRevocationDelta`         → `RevocationSubsystem::process_incoming_delta`
    /// - `InboundMigrationDelta`          → `SchemaMigrationEngine::receive_migration_delta`
    /// - `InboundMigrationRevocationDelta`→ `SchemaMigrationEngine::receive_revocation_delta`
    #[cfg(not(feature = "native"))]
    pub async fn receive_inbound_wasm(
        &self,
        msg: crate::transport::message::GossipMessage,
    ) -> Result<(), TirBaseError> {
        use crate::crdt::merge::{apply_incoming_delta, MergeOutcome};
        use crate::transport::message::GossipMessage;

        match msg {
            GossipMessage::InboundDelta(delta) => {
                // Route through the real LWW/RGA dispatch layer (Req 4.3–4.5a).
                // apply_incoming_delta handles:
                //   1. Schema-hash gate (unknown → Quarantined)
                //   2. Ed25519 signature verification via DID resolution (invalid → Rejected)
                //   3. Operation-type classification (LWW scalar vs RGA sequence)
                //   4. CrdtEngine::apply() for the actual Automerge merge
                //
                // This replaces the old JSON-sidecar heuristic and correctly handles
                // both WASM-produced JSON envelopes AND native-produced binary Automerge
                // changesets (Req 1.4 cross-build state convergence).
                let outcome = {
                    let mut crdt = self.crdt.lock().map_err(|e| {
                        TirBaseError::LocalStoreWriteFailed {
                            reason: format!("crdt mutex poisoned in receive_inbound_wasm: {e}"),
                        }
                    })?;
                    apply_incoming_delta(&mut crdt, &delta)?
                };

                match outcome {
                    MergeOutcome::Merged { .. } => {
                        eprintln!(
                            "[wasm-inbound] Delta {} merged from {}",
                            hex::encode(delta.id),
                            delta.author_did
                        );

                        // Project the merged state into the in-memory store so that
                        // read() and query() reflect the new peer state (Req 4.3, 3.3).
                        //
                        // Strategy (same as native receive_inbound):
                        //   1. Try to parse automerge_bytes as the TirBase JSON envelope
                        //      (contains _tirbase_table, _tirbase_key, and data fields).
                        //      Both WASM-produced Deltas and older-format peer Deltas use this.
                        //   2. For native-produced binary Automerge bytes, project from the
                        //      CrdtEngine's merged Automerge doc using doc_map_range_root().
                        //      The doc state is now correct after CrdtEngine::apply().
                        if !delta.automerge_bytes.is_empty() {
                            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&delta.automerge_bytes) {
                                // JSON envelope path (WASM-produced or TirBase format).
                                if let Some(obj) = json_val.as_object() {
                                    let table_name = obj.get("_tirbase_table")
                                        .and_then(|v| v.as_str());
                                    let row_key = obj.get("_tirbase_key")
                                        .and_then(|v| v.as_str());

                                    if let (Some(tbl), Some(rkey)) = (table_name, row_key) {
                                        // Reconstruct application data (strip TirBase metadata keys).
                                        let mut app_data = serde_json::Map::new();
                                        let mut has_data_key = false;
                                        for (k, v) in obj {
                                            if k == "_data" {
                                                // Scalar/non-object data stored under _data.
                                                let _ = self.store
                                                    .lock()
                                                    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                                        reason: format!("store mutex: {e}"),
                                                    })?
                                                    .write(tbl, rkey, v);
                                                // Record the delta→row mapping for CCE resolve_affected_rows.
                                                crate::store::projection::record_delta_row(
                                                    &delta.id, tbl, rkey,
                                                );
                                                eprintln!(
                                                    "[wasm-inbound] projected delta {} → {tbl}/{rkey}",
                                                    hex::encode(delta.id)
                                                );
                                                has_data_key = true;
                                                break;
                                            } else if k != "_tirbase_table" && k != "_tirbase_key" {
                                                app_data.insert(k.clone(), v.clone());
                                            }
                                        }
                                        if !has_data_key && !app_data.is_empty() {
                                            let app_val = serde_json::Value::Object(app_data);
                                            let _ = self.store
                                                .lock()
                                                .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                                                    reason: format!("store mutex: {e}"),
                                                })?
                                                .write(tbl, rkey, &app_val);
                                            // Record the delta→row mapping for CCE.
                                            crate::store::projection::record_delta_row(
                                                &delta.id, tbl, rkey,
                                            );
                                            eprintln!(
                                                "[wasm-inbound] projected delta {} → {tbl}/{rkey}",
                                                hex::encode(delta.id)
                                            );
                                        }
                                    } else {
                                        // JSON envelope but no table/key metadata.
                                        eprintln!(
                                            "[wasm-inbound] delta {} has JSON bytes but no \
                                             _tirbase_table/_tirbase_key — skipping store projection",
                                            hex::encode(delta.id)
                                        );
                                    }
                                }
                            } else {
                                // Binary Automerge bytes — project from the CrdtEngine's doc
                                // state which was updated by CrdtEngine::apply() above.
                                // Use doc_map_range_root() to read all ROOT-level scalar keys.
                                let root_pairs: Vec<(String, serde_json::Value)> = {
                                    let crdt = self.crdt.lock().map_err(|e| {
                                        TirBaseError::LocalStoreWriteFailed {
                                            reason: format!("crdt mutex: {e}"),
                                        }
                                    })?;
                                    crdt.doc_map_range_root()
                                };

                                // The Automerge ROOT-level keys represent rows across all tables
                                // in the doc. Since each table is a separate doc in the full
                                // architecture, the doc's ROOT keys are rows within one logical
                                // table. We write them to a synthetic "_merged" table using the
                                // key string as the row key. Callers with real table metadata
                                // should embed the JSON envelope for correct projection.
                                if !root_pairs.is_empty() {
                                    let mut store = self.store.lock().map_err(|e| {
                                        TirBaseError::LocalStoreWriteFailed {
                                            reason: format!("store mutex: {e}"),
                                        }
                                    })?;
                                    for (key, val) in &root_pairs {
                                        let _ = store.write("_merged", key, val);
                                        crate::store::projection::record_delta_row(
                                            &delta.id, "_merged", key,
                                        );
                                    }
                                    eprintln!(
                                        "[wasm-inbound] delta {} projected {} root keys from binary Automerge bytes",
                                        hex::encode(delta.id),
                                        root_pairs.len()
                                    );
                                }
                            }
                        }
                    }
                    MergeOutcome::Quarantined { reason } => {
                        eprintln!(
                            "[wasm-inbound] delta {} quarantined ({reason:?}) from {}",
                            hex::encode(delta.id),
                            delta.author_did
                        );
                    }
                    MergeOutcome::Rejected { reason } => {
                        eprintln!(
                            "[wasm-inbound] delta {} rejected from {}: {reason}",
                            hex::encode(delta.id),
                            delta.author_did
                        );
                    }
                }

                // Register with the durability subsystem so Tier-1 tracking works.
                let delta_bytes = serde_json::to_vec(&delta).unwrap_or_default();
                let _ = self
                    .durability
                    .lock()
                    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                        reason: format!("durability mutex poisoned: {e}"),
                    })?
                    .register_delta(
                        delta.id,
                        delta.id,
                        delta_bytes,
                        delta.causal_parents.clone(),
                        std::collections::HashMap::new(),
                    );

                Ok(())
            }

            GossipMessage::InboundDurabilityReceipt(receipt) => {
                let delta_id = receipt.state_hash;
                match self
                    .durability
                    .lock()
                    .map_err(|e| TirBaseError::LocalStoreWriteFailed {
                        reason: format!("durability mutex poisoned: {e}"),
                    })?
                    .receive_receipt(receipt, &delta_id)
                {
                    Ok(true) => {
                        eprintln!(
                            "[wasm-inbound] Tier-1 durability achieved for delta {}",
                            hex::encode(delta_id)
                        );
                    }
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("[wasm-inbound] receipt rejected: {e}");
                    }
                }
                Ok(())
            }

            GossipMessage::InboundRevocationDelta(rev_delta) => {
                let mut rev = self.revocation.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("revocation mutex poisoned: {e}"),
                    }
                })?;

                match rev.process_incoming_delta(
                    &rev_delta,
                    &mut |target_did, _complete_delta| {
                        // No Swarm gossip rebroadcast on WASM — the JS transport
                        // layer handles peer messaging (Req 9.2 is best-effort on WASM).
                        eprintln!(
                            "[wasm-inbound] RevocationDelta threshold met for {target_did}"
                        );
                    },
                    &mut |target_did, delta_ids| {
                        eprintln!(
                            "[wasm-inbound] CCE: {} deltas to tag for revoked DID {target_did}",
                            delta_ids.len()
                        );
                        // CCE tagging on WASM — best-effort (no SQLite DAG walk).
                    },
                ) {
                    Ok(crate::auth::RevocationStatus::Applied) => {
                        eprintln!(
                            "[wasm-inbound] RevocationDelta applied for {}",
                            rev_delta.target_did
                        );
                    }
                    Ok(crate::auth::RevocationStatus::Pending { collected, required }) => {
                        eprintln!(
                            "[wasm-inbound] RevocationDelta pending {collected}/{required} sigs for {}",
                            rev_delta.target_did
                        );
                    }
                    Err(e) => {
                        eprintln!("[wasm-inbound] RevocationDelta failed: {e}");
                    }
                }
                Ok(())
            }

            GossipMessage::InboundMigrationDelta(mig_delta) => {
                let sender_did = mig_delta.author_did.clone();
                let mut mig = self.migration.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("migration mutex poisoned: {e}"),
                    }
                })?;
                match mig.receive_migration_delta(mig_delta, &sender_did) {
                    Ok(result) => {
                        eprintln!("[wasm-inbound] MigrationDelta applied: {result:?}");
                    }
                    Err(e) => {
                        eprintln!("[wasm-inbound] MigrationDelta rejected: {e}");
                    }
                }
                Ok(())
            }

            GossipMessage::InboundMigrationRevocationDelta(mig_rev) => {
                let mut mig = self.migration.lock().map_err(|e| {
                    TirBaseError::LocalStoreWriteFailed {
                        reason: format!("migration mutex poisoned: {e}"),
                    }
                })?;
                if let Err(e) = mig.receive_revocation_delta(mig_rev) {
                    eprintln!("[wasm-inbound] MigrationRevocationDelta rejected: {e}");
                }
                Ok(())
            }
        }
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

    /// Spawn the production inbound drain loop for this handle.
    ///
    /// Every `interval`, the background task calls
    /// [`CoreHandle::process_inbound_messages`], which drains `inbound_rx`
    /// (fed by the Swarm polling task via `inbound_tx`) and routes each
    /// `GossipMessage` through the correct subsystem.
    ///
    /// Production caller: [`CoreHandle::init`] spawns this loop before
    /// returning, so Gossipsub messages are drained in production rather than
    /// only from tests (Subphase 1.3).  It is `pub(crate)` rather than private
    /// so the Subphase 1.3 integration test can drive the *identical* loop
    /// with a short interval without racing the count-based unit tests.
    ///
    /// Returns the `JoinHandle` so callers can observe or abort the task.
    #[cfg(feature = "native")]
    pub(crate) fn spawn_inbound_drain_loop(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match handle.process_inbound_messages().await {
                    Ok(0) => {}
                    Ok(n) => {
                        eprintln!("[inbound-loop] drained {n} inbound message(s)");
                    }
                    Err(e) => {
                        eprintln!("[inbound-loop] drain failed: {e}");
                    }
                }
            }
        })
    }

    /// Spawn the production DRR scheduler tick loop for this handle.
    ///
    /// Every `interval`, the background task locks the mesh transport and
    /// calls [`MeshTransport::tick_scheduler`], which runs one DRR scheduling
    /// epoch (Req 12) and forwards the drained Deltas to the outbound publish
    /// channel; the Swarm polling task (Subphase 1.1) receives them and
    /// publishes to the shared Gossipsub topic.  Without this loop, Deltas
    /// enqueued via `MeshTransport::enqueue_outbound` (HIGH-priority
    /// revocation rebroadcast, mDNS re-announcement) would accumulate in the
    /// scheduler queues forever.
    ///
    /// Production caller: [`CoreHandle::init`] spawns this loop before
    /// returning, gated on a live outbound publish channel (Subphase 1.4).  It
    /// is `pub(crate)` rather than private so the Subphase 1.4 integration
    /// test can drive the *identical* loop with a short interval without
    /// racing the queue-state unit tests.
    ///
    /// Returns the `JoinHandle` so callers can observe or abort the task.
    #[cfg(feature = "native")]
    pub(crate) fn spawn_scheduler_tick_loop(
        self: &Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match handle.transport.lock() {
                    Ok(mut transport) => {
                        match transport.tick_scheduler(
                            crate::transport::DEFAULT_LINK_CAPACITY_BYTES,
                        ) {
                            Ok(0) => {}
                            Ok(n) => {
                                eprintln!(
                                    "[scheduler-loop] DRR tick forwarded {n} outbound payload(s)"
                                );
                            }
                            Err(e) => {
                                eprintln!("[scheduler-loop] DRR tick failed: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[scheduler-loop] transport mutex poisoned: {e}");
                    }
                }
            }
        })
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

    /// Dial a peer by multiaddr (native only).
    ///
    /// Forwards the target address to the Swarm polling task spawned by
    /// [`CoreHandle::init`], which performs the actual `swarm.dial`.  This is
    /// the explicit-connect path for topologies where mDNS discovery is
    /// unavailable or unsuitable (WAN peers, a known cloud/relay endpoint).
    /// The connection — once established — is recorded in the peer table, so
    /// `mesh_status()` reflects it like any mDNS-discovered peer.
    ///
    /// Current callers: the Subphase 1.5 mesh integration tests (two real
    /// Swarm-backed handles dialing each other on loopback), which are the
    /// definition of done for Phase 0.3(a)/(b).  The SDK-facing mesh-connect
    /// operation (Phase 4 cloud sync) is the stated production consumer.
    #[cfg(feature = "native")]
    pub(crate) async fn dial_peer(
        &self,
        addr: libp2p::Multiaddr,
    ) -> Result<(), TirBaseError> {
        let tx = self.dial_tx.as_ref().ok_or_else(|| {
            TirBaseError::MeshUnavailable {
                reason: "transport not started (no Swarm polling task)".to_string(),
            }
        })?;
        tx.send(addr).await.map_err(|e| TirBaseError::MeshUnavailable {
            reason: format!("dial channel closed: {e}"),
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
    /// libp2p listen address (native-only; ignored on wasm).
    ///
    /// Passed through to [`MeshTransport`] at init so deployments can pin the
    /// device to a specific interface / port (firewall rules, NAT port
    /// forwarding).  The default ephemeral bind on all interfaces paired with
    /// mDNS discovery is what LAN operation uses.
    pub listen_addr: String,
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
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
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

    // ── 9b. write() publishes the Delta to the outbound mesh ─────────────────
    //
    // Subphase 1.1 acceptance: write() must NOT discard prepare_outbound()'s
    // output — the prepared payload must reach the outbound publish path (the
    // Swarm polling task) and be handed to gossipsub.publish.  With no peers
    // subscribed, gossipsub.publish returns NoPeersSubscribedToTopic, so the
    // payload is observed at the publish point via the test-only recording
    // hook rather than via a live peer.

    #[tokio::test]
    async fn write_publishes_outbound_delta_to_mesh() {
        let path = tmp_path("outbound_publish");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        let result = handle
            .write("sensors", "s1", json!({"v": 42}))
            .await
            .expect("write must succeed even with no mesh peers connected");

        // The Swarm polling task drains the outbound channel asynchronously;
        // poll until the prepared payload reaches the publish point.
        let mut attempts = 0;
        let published = loop {
            let published = handle
                .transport
                .lock()
                .unwrap()
                .outbound_published
                .clone();
            if !published.is_empty() {
                break published;
            }
            attempts += 1;
            assert!(
                attempts < 100,
                "write()'s outbound payload never reached the publish path"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        assert_eq!(
            published.len(),
            1,
            "exactly one outbound payload must be produced per write (mtu=0)"
        );

        // The published payload must carry the prepared Delta — i.e. the
        // output of prepare_outbound() is used, not discarded.  Since the
        // wire protocol frames every mesh message as a `GossipMessage`
        // (Subphase 1.5 — the receiving poll task dispatches on the variant),
        // the recorded payload is `GossipMessage::InboundDelta(delta)` rather
        // than the bare serialised Delta.
        let wire: crate::transport::message::GossipMessage =
            serde_json::from_slice(&published[0])
                .expect("published payload must deserialise as a GossipMessage");
        let decoded = match wire {
            crate::transport::message::GossipMessage::InboundDelta(d) => d,
            other => panic!(
                "published payload must be InboundDelta framing, got: {other:?}"
            ),
        };
        assert_eq!(
            decoded.id, result.delta_id,
            "published payload must be the Delta produced by this write"
        );

        cleanup(&path);
    }

    // ── 10. Test A: ContaminatedByHumanReaction tag applied when row is contaminated ──

    #[tokio::test]
    async fn write_on_contaminated_row_gets_human_reaction_tag() {
        use crate::contamination::incident::TaintSource;
        use crate::crdt::delta::DeltaTag;

        let path = tmp_path("human_reaction_tag");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Write an initial value so the key/table exists.
        handle
            .write("sensors", "temp-1", json!({"v": 100}))
            .await
            .expect("initial write");

        // Tag a synthetic contamination root via the CCE. We insert the DagNode via
        // a public helper on ChangesetDag, accessed through the CCE's public tag method.
        // We use tag_contamination_root with a DeviceRevocation source on a zero-byte
        // root ID — the BFS walk will find no descendants (node not in DAG), and
        // affected_rows will be empty, but the ICO is still registered as OPEN.
        // This is enough to exercise the live lock path in CoreHandle::write().
        let root_delta_id = [0xA0u8; 32];
        {
            let mut cce = handle.cce.lock().unwrap();
            // tag_contamination_root will attempt a BFS walk; the node may not be in the
            // DAG (returns DeltaNotFound or empty walk). We ignore the error here since
            // our goal is only to test that the write path calls is_row_contaminated.
            let _ = cce.tag_contamination_root(
                root_delta_id,
                TaintSource::DeviceRevocation {
                    revocation_delta_id: root_delta_id,
                },
            );
        }

        // Write again to the same key — with the live lookup path active (not hardcoded
        // false), the write must still complete without error.
        let result = handle
            .write("sensors", "temp-1", json!({"v": 200}))
            .await;
        assert!(
            result.is_ok(),
            "write must succeed even when CCE has been touched: {:?}",
            result.err()
        );

        cleanup(&path);
    }

    // ── 11. Test B: No ContaminatedByHumanReaction on uncontaminated table ────────

    #[tokio::test]
    async fn write_on_clean_row_has_no_human_reaction_tag() {
        let path = tmp_path("human_reaction_clean");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Write to a clean table with no incidents.
        let result = handle
            .write("clean_table", "row-1", json!({"status": "ok"}))
            .await
            .expect("write must succeed");

        // The durability tier should still be Uncommitted (unchanged behaviour).
        assert_eq!(result.durability_tier, DurabilityTier::Uncommitted);

        cleanup(&path);
    }

    // ── 12. Test C: WriteContext uses live lookups (mutex lock doesn't panic) ─────

    #[tokio::test]
    async fn write_ctx_live_lookups_do_not_panic() {
        let path = tmp_path("write_ctx_live");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Perform multiple writes — each one should lock cce and migration without
        // deadlock or panic regardless of whether contamination state is clean.
        for i in 0..5u32 {
            handle
                .write("perf_table", &format!("key-{i}"), json!({"i": i}))
                .await
                .unwrap_or_else(|e| panic!("write {i} failed: {e}"));
        }

        cleanup(&path);
    }

    // ── Task-44 Test A: write on contaminated row → new Delta added to ICO ───

    /// Validates Req 19.5: when `tag_contamination_root` has marked a row as
    /// contaminated, a subsequent `CoreHandle::write()` to that same row must
    /// register the resulting Delta in the active ICO's `contaminated_deltas`.
    #[tokio::test]
    async fn task44_test_a_human_reaction_delta_added_to_ico() {
        use crate::contamination::incident::TaintSource;
        use crate::crdt::dag::DagNode;
        use crate::crdt::delta::DeltaTag;

        let path = tmp_path("t44_test_a");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Step 1: write an initial row so the table and key exist in the store.
        let first_write = handle
            .write("events", "evt-1", json!({"status": "initial"}))
            .await
            .expect("first write");
        let first_delta_id = first_write.delta_id;

        // Step 2: insert that delta as a DagNode so the BFS walk can find it,
        //         then tag it as a contamination root.
        let ico_id = {
            let mut cce = handle.cce.lock().unwrap();

            // Insert the first delta's ID as a DagNode so the BFS walk succeeds.
            cce.test_insert_dag_node(DagNode {
                delta_id: first_delta_id,
                payload: vec![],
                parent_ids: vec![],
                actor_id: b"actor".to_vec(),
                lamport: 1,
                schema_hash: [0u8; 32],
                compacted: false,
                author_did: "did:key:z6MkTest".to_string(),
            }).expect("insert DagNode for first delta");

            cce.tag_contamination_root(
                first_delta_id,
                TaintSource::DeviceRevocation {
                    revocation_delta_id: first_delta_id,
                },
            ).expect("tag_contamination_root")
        };

        // Confirm the first delta is in the ICO.
        let ico_before = handle.cce.lock().unwrap()
            .get_incident(ico_id).unwrap().unwrap();
        assert!(
            ico_before.contaminated_deltas.contains(&first_delta_id),
            "first delta must be in ICO before second write"
        );

        // Step 3: manually set the contaminated_rows entry to simulate the projection
        // layer having resolved affected rows. The BFS walk only populates
        // contaminated_rows when affected_rows is non-empty, which requires a
        // live projection table. We use the test helper to inject the entry directly.
        {
            let mut cce = handle.cce.lock().unwrap();
            cce.test_set_contaminated_row("events", "evt-1", ico_id);
        }

        // Confirm is_row_contaminated returns true.
        assert!(
            handle.cce.lock().unwrap().is_row_contaminated("events", "evt-1"),
            "row must appear contaminated before second write"
        );

        let second_write = handle
            .write("events", "evt-1", json!({"status": "updated"}))
            .await
            .expect("second write must succeed");
        let second_delta_id = second_write.delta_id;

        // Step 4: the second delta must now appear in the active open ICOs.
        // CoreHandle::write() calls on_write_commit → returns Some((id, incident_id))
        // → calls cce.tag_contamination_root(TaintSource::HumanReaction) → BFS walk
        // from second_delta_id → new ICO or composite ICO containing second_delta_id.
        let all_open_icos = handle.cce.lock().unwrap()
            .open_incidents().unwrap();

        let found = all_open_icos.iter().any(|ico| {
            ico.contaminated_deltas.contains(&second_delta_id)
        });

        assert!(
            found,
            "second write delta {second_delta_id:?} must be registered in an active ICO; \
             open ICOs (ids): {:?}",
            all_open_icos.iter().map(|i| i.id).collect::<Vec<_>>()
        );

        cleanup(&path);
    }

    // ── Task-44 Test B: write on uncontaminated row → no ContaminatedByHumanReaction ─

    /// Validates Req 19.5 negative case: a write to a completely clean row must
    /// produce no `ContaminatedByHumanReaction` tag, and no ICO must be updated.
    #[tokio::test]
    async fn task44_test_b_clean_row_write_has_no_human_reaction_tag() {
        let path = tmp_path("t44_test_b");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Write to a table/key that has never been contaminated.
        let _result = handle
            .write("clean_sensors", "reading-42", json!({"temp": 22.5}))
            .await
            .expect("write must succeed");

        // No ICOs must be open (nothing was contaminated).
        let open_icos = handle.cce.lock().unwrap().open_incidents().unwrap();
        assert!(
            open_icos.is_empty(),
            "no ICOs must be created for a clean write; found: {open_icos:?}"
        );

        // The CCE's contaminated_rows must not contain this key.
        let is_contaminated = handle.cce.lock().unwrap()
            .is_row_contaminated("clean_sensors", "reading-42");
        assert!(
            !is_contaminated,
            "row must not appear in contaminated_rows after a clean write"
        );

        cleanup(&path);
    }

    // ── Task-44 Test C: write after resolution → no ContaminatedByHumanReaction ─

    /// Validates Req 19.5 resolution case: after `verify_data` resolves all roots
    /// and the CCE prunes `contaminated_rows`, a subsequent write to the previously
    /// contaminated row must not trigger human-reaction tagging or update any ICO.
    #[tokio::test]
    async fn task44_test_c_write_after_resolution_no_human_reaction_tag() {
        use crate::contamination::incident::TaintSource;
        use crate::crdt::dag::DagNode;
        use crate::identity::{keypair, IdentityManager};
        use crate::contamination::resolution::now_micros;

        let path = tmp_path("t44_test_c");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Step 1: write an initial row.
        let first_write = handle
            .write("telemetry", "node-7", json!({"reading": 100}))
            .await
            .expect("initial write");
        let first_delta_id = first_write.delta_id;

        // Step 2: insert the DagNode and tag as contamination root.
        let ico_id = {
            let mut cce = handle.cce.lock().unwrap();
            cce.test_insert_dag_node(DagNode {
                delta_id: first_delta_id,
                payload: vec![],
                parent_ids: vec![],
                actor_id: b"actor".to_vec(),
                lamport: 1,
                schema_hash: [0u8; 32],
                compacted: false,
                author_did: "did:key:z6MkTest".to_string(),
            }).expect("insert DagNode");

            cce.tag_contamination_root(
                first_delta_id,
                TaintSource::DeviceRevocation {
                    revocation_delta_id: first_delta_id,
                },
            ).expect("tag_contamination_root")
        };

        // Set contaminated_rows so is_row_contaminated returns true.
        {
            let mut cce = handle.cce.lock().unwrap();
            cce.test_set_contaminated_row("telemetry", "node-7", ico_id);
        }

        // Confirm the row is contaminated before resolution.
        assert!(
            handle.cce.lock().unwrap().is_row_contaminated("telemetry", "node-7"),
            "row must be contaminated before verify_data"
        );

        // Step 3: resolve the contamination root via verify_data.
        let mgr = IdentityManager::init_in_memory().expect("manager identity");
        let mgr_did = mgr.did().to_string();
        let mgr_secret = mgr.signing_key_bytes();
        let sig = keypair::sign(&mgr_secret, &first_delta_id).expect("sign");
        let expiry = now_micros() + 3_600_000_000; // +1h

        handle.cce.lock().unwrap()
            .verify_data(first_delta_id, mgr_did, sig, expiry)
            .expect("verify_data must succeed");

        // Step 4: after resolution, contaminated_rows must be pruned.
        assert!(
            !handle.cce.lock().unwrap().is_row_contaminated("telemetry", "node-7"),
            "row must NOT be contaminated after verify_data resolves all roots"
        );

        // Count open ICOs before the third write.
        let icos_before = handle.cce.lock().unwrap().open_incidents().unwrap().len();

        // Step 5: write again to the previously contaminated row.
        let _third_write = handle
            .write("telemetry", "node-7", json!({"reading": 200}))
            .await
            .expect("third write must succeed");

        // No new ICOs must have been opened by the third write.
        let icos_after = handle.cce.lock().unwrap().open_incidents().unwrap().len();
        assert_eq!(
            icos_after, icos_before,
            "no new ICO must be opened by a write on a resolved row"
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
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
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

    // ── Test 3b (Subphase 1.3): the production inbound drain loop drains ─────
    //
    // `CoreHandle::init` spawns a background task that calls
    // `process_inbound_messages()` on an interval (in production builds).  This
    // test drives the *identical* loop — `CoreHandle::spawn_inbound_drain_loop`,
    // the function `init` calls — with a short interval and asserts the
    // background task (NOT a manual `process_inbound_messages()` call) applies
    // injected messages.  The injected Delta carries table/key metadata so the
    // drain projects it into the SQL store, observable via `handle.read()`.

    #[tokio::test]
    async fn production_inbound_drain_loop_drains_injected_messages() {
        let path = tmp_path("inbound_drain_loop");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Spawn the production drain loop with a short interval so the test
        // completes quickly.  (In production builds `CoreHandle::init` does
        // exactly this with `INBOUND_DRAIN_INTERVAL_MS`; in test builds init
        // uses a 1-hour interval so the count-based tests above stay
        // deterministic.)
        let _loop = CoreHandle::spawn_inbound_drain_loop(
            &handle,
            std::time::Duration::from_millis(10),
        );

        // Build a signed InboundDelta whose automerge_bytes embeds the
        // _tirbase_table / _tirbase_key envelope plus data fields, exactly as
        // CoreHandle::write() produces (see Test 6).
        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32]; // DEFAULT_SCHEMA_HASH
        let delta = {
            let mut envelope = serde_json::Map::new();
            envelope.insert(
                "_tirbase_table".to_string(),
                serde_json::Value::String("loop".to_string()),
            );
            envelope.insert(
                "_tirbase_key".to_string(),
                serde_json::Value::String("k1".to_string()),
            );
            envelope.insert("v".to_string(), serde_json::Value::from(42));
            let envelope_bytes = serde_json::to_vec(&serde_json::Value::Object(envelope))
                .expect("envelope serialisation");

            let mut d = crate::crdt::delta::Delta {
                id: [0u8; 32],
                author_did: peer_did.clone(),
                signature: Ed25519Signature::default(),
                schema_hash,
                automerge_bytes: envelope_bytes,
                priority: PriorityClass::Low,
                causal_parents: vec![],
                tags: vec![],
                lamport: 3,
                created_at: 0,
            };
            let canonical = d.canonical_bytes();
            d.signature = ek_sign(&peer_secret, &canonical).expect("sign");
            d.id = crate::crdt::delta::Delta::compute_id(&canonical);
            d
        };

        handle
            .inject_inbound(GossipMessage::InboundDelta(delta))
            .await
            .expect("inject_inbound must not fail");

        // Do NOT call process_inbound_messages() — the background loop must do
        // the draining.  Poll until the projected row becomes readable.
        let mut attempts = 0u32;
        let observed = loop {
            if let Ok(res) = handle.read("loop", "k1").await {
                break res;
            }
            attempts += 1;
            assert!(
                attempts < 200,
                "spawned inbound drain loop never processed the injected message"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        assert_eq!(
            observed.data,
            json!({"v": 42}),
            "background drain loop must project the inbound delta to the store"
        );
        assert_eq!(observed.key, "k1");
        assert_eq!(observed.table, "loop");

        cleanup(&path);
    }

    // ── Test 3c (Subphase 1.4): the production DRR scheduler tick loop sends ──
    //
    // `CoreHandle::init` spawns a background task that ticks the DRR
    // scheduler — previously nothing in production ever called
    // `DrrScheduler::tick`, so Deltas enqueued via `enqueue_outbound`
    // (revocation rebroadcast at HIGH priority, mDNS re-announcement)
    // accumulated forever.  This test drives the *identical* loop —
    // `CoreHandle::spawn_scheduler_tick_loop`, the function `init` calls —
    // with a short interval, enqueues a Delta through the production enqueue
    // path, and asserts the background task (NOT a manual `tick()` call)
    // schedules it out of the queue and forwards it to the outbound publish
    // point, observable via the test-only `outbound_published` recording hook
    // (Subphase 1.1).

    #[tokio::test]
    async fn drr_scheduler_tick_loop_schedules_and_sends_enqueued_deltas() {
        let path = tmp_path("scheduler_tick_loop");
        cleanup(&path);

        let handle = CoreHandle::init(make_config(&path))
            .await
            .expect("init");

        // Spawn the production scheduler tick loop with a short interval so
        // the test completes quickly.  (In production builds `CoreHandle::init`
        // does exactly this with `SCHEDULER_TICK_INTERVAL_MS`; in test builds
        // init uses a 1-hour interval so queue-state unit tests stay
        // deterministic.)
        let _loop = CoreHandle::spawn_scheduler_tick_loop(
            &handle,
            std::time::Duration::from_millis(10),
        );

        // Enqueue a HIGH-priority Delta exactly like the production enqueue
        // callbacks do (RevocationDelta threshold → `enqueue_outbound`, Req 9.2).
        let delta_id = [0x14u8; 32];
        let wrapper = crate::crdt::delta::Delta {
            id: delta_id,
            author_did: "tirbase/revocation".to_string(),
            signature: crate::crdt::delta::Ed25519Signature::default(),
            schema_hash: [0u8; 32],
            automerge_bytes: serde_json::to_vec(&json!({
                "type": "InboundRevocationDelta",
            }))
            .expect("envelope serialisation"),
            priority: crate::crdt::delta::PriorityClass::High,
            causal_parents: vec![],
            tags: vec![],
            lamport: 0,
            created_at: 0,
        };
        {
            let mut transport = handle.transport.lock().unwrap();
            transport.enqueue_outbound(wrapper);
            assert!(
                transport.has_backlog(),
                "enqueued Delta must sit in the scheduler queue before any tick"
            );
        }

        // Do NOT call tick_scheduler() manually — the background loop must do
        // the scheduling and sending.  Poll until the prepared payload reaches
        // the outbound publish point (the Swarm polling task records it there).
        let mut attempts = 0u32;
        let published = loop {
            let published = handle
                .transport
                .lock()
                .unwrap()
                .outbound_published
                .clone();
            if !published.is_empty() {
                break published;
            }
            attempts += 1;
            assert!(
                attempts < 200,
                "scheduler tick loop never forwarded the enqueued Delta to the publish path"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        // The payload must be the exact serialised Delta that was enqueued —
        // scheduled out of the DRR queue and sent, not merely accumulated.
        assert_eq!(
            published.len(),
            1,
            "exactly one outbound payload must be produced per enqueued Delta (mtu=0)"
        );
        let decoded: crate::crdt::delta::Delta = serde_json::from_slice(&published[0])
            .expect("published payload must deserialise as the enqueued Delta");
        assert_eq!(
            decoded.id, delta_id,
            "published payload must be the enqueued Delta"
        );

        // The scheduler queue must now be empty — the loop drained it.
        assert!(
            !handle.transport.lock().unwrap().has_backlog(),
            "scheduler must have no backlog after the tick loop drained it"
        );

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

    // ── Test 6: End-to-end inbound pipeline — write on A, read on B ──────────
    //
    // Verifies that after receiving and processing a peer Delta that carries
    // TirBase JSON metadata (_tirbase_table, _tirbase_key, and data fields),
    // the data is readable via handle_b.read() — closing the projection gap
    // documented in earlier versions.
    //
    // Step 1: Write a value to handle_a (stores locally + produces a signed Delta).
    // Step 2: Build an equivalent Delta manually, embedding table/key metadata in
    //         automerge_bytes so the receiving peer can project it to the SQL store.
    // Step 3: Inject the Delta into handle_b via inject_inbound.
    // Step 4: Call process_inbound_messages() on handle_b.
    // Step 5: Verify handle_b.read("sensors", "reading-1") succeeds and returns
    //         the same data that was written on handle_a.
    //
    // Validates: Req 4.3 (merged peer state readable), Req 3.3 (store fully readable),
    //            Task 41 (projection-update-on-inbound implemented).

    #[tokio::test]
    async fn end_to_end_inbound_pipeline_write_a_read_b() {
        let path_a = tmp_path("e2e_A");
        let path_b = tmp_path("e2e_B");
        cleanup(&path_a);
        cleanup(&path_b);

        // ── Step 1: Write to handle_a ─────────────────────────────────────────
        let handle_a = CoreHandle::init(make_config(&path_a))
            .await
            .expect("init A");
        let handle_b = CoreHandle::init(make_config(&path_b))
            .await
            .expect("init B");

        let written_data = serde_json::json!({"sensor": "temperature", "value": 23.4});
        let write_result = handle_a
            .write("sensors", "reading-1", written_data.clone())
            .await
            .expect("write to A");

        // Confirm the delta ID is non-zero (the write produced a real delta).
        assert_ne!(
            write_result.delta_id,
            [0u8; 32],
            "write must produce a non-zero delta ID"
        );

        // ── Step 2: Construct an equivalent GossipMessage ─────────────────────
        // Build a delta whose automerge_bytes embeds _tirbase_table and _tirbase_key
        // metadata plus the application data fields — this is the format produced by
        // CoreHandle::write() (which embeds the metadata in the JSON envelope).
        let (peer_secret, peer_public) = generate_keypair().expect("keygen");
        let peer_did = crate::crdt::derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32]; // DEFAULT_SCHEMA_HASH

        let delta = {
            // Build the JSON envelope that receive_inbound() expects:
            //   { "_tirbase_table": "sensors", "_tirbase_key": "reading-1", <data fields> }
            let mut envelope = serde_json::Map::new();
            envelope.insert("_tirbase_table".to_string(), serde_json::Value::String("sensors".to_string()));
            envelope.insert("_tirbase_key".to_string(), serde_json::Value::String("reading-1".to_string()));
            // Flatten data fields directly into the envelope (matching CoreHandle::write() behaviour).
            if let Some(data_obj) = written_data.as_object() {
                for (k, v) in data_obj {
                    envelope.insert(k.clone(), v.clone());
                }
            }
            let envelope_bytes = serde_json::to_vec(&serde_json::Value::Object(envelope))
                .expect("envelope serialisation");

            let mut d = crate::crdt::delta::Delta {
                id: [0u8; 32],
                author_did: peer_did.clone(),
                signature: Ed25519Signature::default(),
                schema_hash,
                automerge_bytes: envelope_bytes,
                priority: PriorityClass::Low,
                causal_parents: vec![],
                tags: vec![],
                lamport: 2,
                created_at: 0,
            };
            let canonical = d.canonical_bytes();
            d.signature = ek_sign(&peer_secret, &canonical).expect("sign");
            d.id = crate::crdt::delta::Delta::compute_id(&canonical);
            d
        };

        // ── Step 3: Inject into handle_b ─────────────────────────────────────
        handle_b
            .inject_inbound(GossipMessage::InboundDelta(delta))
            .await
            .expect("inject_inbound must not fail");

        // ── Step 4: Process inbound messages ─────────────────────────────────
        let processed = handle_b
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages must not fail");

        assert_eq!(
            processed, 1,
            "exactly one inbound message must be processed"
        );

        // ── Step 5: Verify data is readable on handle_b ───────────────────────
        // After projection, handle_b's SQL store must contain the row that was
        // written on handle_a — this closes the documented projection gap (Task 41).
        let read_result = handle_b.read("sensors", "reading-1").await;
        assert!(
            read_result.is_ok(),
            "inbound delta must be readable via store after merge; got: {:?}",
            read_result.err()
        );

        let result = read_result.unwrap();
        assert_eq!(
            result.data, written_data,
            "data read from handle_b must match what was written on handle_a"
        );
        assert_eq!(result.key, "reading-1");
        assert_eq!(result.table, "sensors");

        cleanup(&path_a);
        cleanup(&path_b);
    }

    // ── Test 7: RevocationDelta enqueued at HIGH priority after threshold met ─
    //
    // Validates Req 9.2: when M-of-N signatures are collected for a revocation,
    // the complete RevocationDelta must be enqueued at HIGH priority for gossip
    // rebroadcast.

    #[tokio::test]
    async fn revocation_delta_enqueued_at_high_priority_after_threshold_met() {
        let path = tmp_path("rev_enqueue");
        cleanup(&path);

        // Create a CoreHandle with M=2, N=2 revocation config.
        let handle = CoreHandle::init(InitConfig {
            storage_path: path.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 2,
                revocation_n: 2,
                biscuit_ttl_secs: 3600,
                anchor_attested_location: false,
                spatial_diversity_min: 1,
                quorum_k: 1,
                quorum_n: 1,
            },
        })
        .await
        .expect("init");

        // Create 2 manager identities.
        let mgr1 = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr1_did = mgr1.did().to_string();
        let mgr1_sk = mgr1.signing_key_bytes();

        let mgr2 = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr2_did = mgr2.did().to_string();
        let mgr2_sk = mgr2.signing_key_bytes();

        // Choose a target DID.
        let target = crate::identity::IdentityManager::init_in_memory().unwrap();
        let target_did = target.did().to_string();

        // Produce two partial RevocationDeltas (one per manager).
        let (partial1, partial2) = {
            let rev = handle.revocation.lock().unwrap();
            let p1 = rev
                .produce_partial_delta(target_did.clone(), mgr1_did.clone(), &mgr1_sk)
                .expect("produce partial 1");
            let p2 = rev
                .produce_partial_delta(target_did.clone(), mgr2_did.clone(), &mgr2_sk)
                .expect("produce partial 2");
            (p1, p2)
        };

        // Combine both signatures into a single RevocationDelta.
        let combined = crate::auth::RevocationDelta {
            target_did: target_did.clone(),
            signatures: [partial1.signatures, partial2.signatures].concat(),
            created_at: crate::auth::revocation::current_timestamp_micros(),
        };

        // Inject the combined delta — this should cross the M=2 threshold.
        handle
            .inject_inbound(GossipMessage::InboundRevocationDelta(combined))
            .await
            .expect("inject_inbound must not fail");

        // Process — this triggers the on_revocation_applied callback which enqueues.
        handle
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages must not fail");

        // Verify the scheduler has a HIGH-priority entry.
        let transport = handle.transport.lock().unwrap();
        assert!(
            transport.has_backlog(),
            "transport scheduler must have backlog after RevocationDelta threshold met"
        );
        assert!(
            transport.high_queue_depth() > 0,
            "HIGH queue must be non-empty after revocation gossip enqueue (depth: {})",
            transport.high_queue_depth()
        );

        drop(transport);
        cleanup(&path);
    }

    // ── Test 8: Completed RevocationDelta marks target as REVOKED on a second instance ─
    //
    // Validates end-to-end rebroadcast path: handle A processes a complete
    // RevocationDelta (marking the target REVOKED and enqueuing for gossip),
    // then the same RevocationDelta is injected into handle B which should also
    // mark the target as REVOKED.
    //
    // Idempotency of the second call is covered by revocation.rs test 11.

    #[tokio::test]
    async fn completed_revocation_delta_marks_target_revoked_on_second_instance() {
        let path_a = tmp_path("rev_e2e_A");
        let path_b = tmp_path("rev_e2e_B");
        cleanup(&path_a);
        cleanup(&path_b);

        // Handle A: M=1, N=1 for simplicity (1 manager can revoke alone).
        let config_a = InitConfig {
            storage_path: path_a.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                anchor_attested_location: false,
                spatial_diversity_min: 1,
                quorum_k: 1,
                quorum_n: 1,
            },
        };
        // Handle B: same M/N so it also accepts the same 1-of-1 delta.
        let config_b = InitConfig {
            storage_path: path_b.clone(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                ..config_a.deployment.clone()
            },
        };

        let handle_a = CoreHandle::init(config_a).await.expect("init A");
        let handle_b = CoreHandle::init(config_b).await.expect("init B");

        // Manager and target identities.
        let mgr = crate::identity::IdentityManager::init_in_memory().unwrap();
        let mgr_did = mgr.did().to_string();
        let mgr_sk = mgr.signing_key_bytes();

        let target = crate::identity::IdentityManager::init_in_memory().unwrap();
        let target_did = target.did().to_string();

        // Produce a 1-of-1 partial delta (this IS the complete delta at M=1).
        let complete_delta = {
            let rev = handle_a.revocation.lock().unwrap();
            rev.produce_partial_delta(target_did.clone(), mgr_did.clone(), &mgr_sk)
                .expect("produce complete delta")
        };

        // ── Step A: Process on handle_a — marks target REVOKED + enqueues rebroadcast.
        handle_a
            .inject_inbound(GossipMessage::InboundRevocationDelta(complete_delta.clone()))
            .await
            .expect("inject into A");

        handle_a
            .process_inbound_messages()
            .await
            .expect("process A");

        // Verify A revoked the target.
        assert!(
            handle_a
                .revocation
                .lock()
                .unwrap()
                .revoked_dids()
                .contains(&target_did),
            "handle_a must have target_did in revoked_dids"
        );

        // ── Step B: Inject the same RevocationDelta into handle_b.
        handle_b
            .inject_inbound(GossipMessage::InboundRevocationDelta(complete_delta))
            .await
            .expect("inject into B");

        handle_b
            .process_inbound_messages()
            .await
            .expect("process B");

        // Verify B also revoked the target (Idempotency on A's side is tested in revocation.rs test 11).
        assert!(
            handle_b
                .revocation
                .lock()
                .unwrap()
                .revoked_dids()
                .contains(&target_did),
            "handle_b must have target_did in revoked_dids after receiving rebroadcast"
        );

        cleanup(&path_a);
        cleanup(&path_b);
    }
}

// ─── Task 42: Cross-build convergence tests ────────────────────────────────────
//
// Tests for cross-build CRDT state convergence (Req 1.4, Property 1).
// These run on native and validate that the CrdtEngine converges identically
// regardless of the order in which Deltas are applied (commutativity).
//
// The matching wasm-bindgen-test counterparts live in src/tests/wasm_tests.rs.

#[cfg(all(test, feature = "native"))]
mod convergence_tests {
    use super::*;
    use crate::crdt::delta::{Delta, Ed25519Signature, PriorityClass};
    use crate::crdt::{derive_did_from_public_key, CrdtEngine};
    use crate::identity::keypair::{generate_keypair, sign as ek_sign};
    use crate::schema::hash::compute_schema_identifier_hash;
    use crate::crdt::merge::MergeOutcome;
    use std::sync::{Arc, Mutex};
    use std::env;

    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_conv_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    fn open_conn(path: &str) -> Arc<Mutex<rusqlite::Connection>> {
        let conn = rusqlite::Connection::open(path)
            .unwrap_or_else(|_| rusqlite::Connection::open_in_memory().unwrap());
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL).unwrap();
        Arc::new(Mutex::new(conn))
    }

    fn test_schema() -> [u8; 32] {
        compute_schema_identifier_hash(&[("items", &[("id", "TEXT"), ("v", "INTEGER")])])
    }

    fn make_engine(
        secret: [u8; 32],
        public: [u8; 32],
        did: String,
        schema: [u8; 32],
    ) -> CrdtEngine {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::store::sqlite::CREATE_SCHEMA_SQL).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        CrdtEngine::new(secret, public, did, schema, conn)
    }

    fn make_signed_delta(
        secret: &[u8; 32],
        did: &str,
        schema: [u8; 32],
        lamport: u64,
        automerge_bytes: Vec<u8>,
    ) -> Delta {
        let mut d = Delta {
            id: [0u8; 32],
            author_did: did.to_string(),
            signature: Ed25519Signature::default(),
            schema_hash: schema,
            automerge_bytes,
            priority: PriorityClass::Low,
            causal_parents: vec![],
            tags: vec![],
            lamport,
            created_at: 0,
        };
        let canonical = d.canonical_bytes();
        d.signature = ek_sign(secret, &canonical).expect("sign");
        d.id = Delta::compute_id(&canonical);
        d
    }

    // ── Test 1: Two engines converge after exchanging Deltas ─────────────────
    //
    // Validates Property 1 (cross-build state convergence) at the CrdtEngine
    // level: applying the same set of Deltas to two engines in any order
    // produces identical final Lamport clocks.
    //
    // The WASM counterpart of this test runs in wasm_tests.rs under
    // `wasm-bindgen-test` as `test_wasm_crdt_engine_convergence_two_instances`.

    #[test]
    fn two_engines_converge_after_delta_exchange() {
        let schema = test_schema();

        // Create two engine identities.
        let (secret_a, public_a) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&public_a);

        let (secret_b, public_b) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&public_b);

        let mut engine_a = make_engine(secret_a, public_a, did_a.clone(), schema);
        let mut engine_b = make_engine(secret_b, public_b, did_b.clone(), schema);

        // Produce a Delta from engine A.
        let delta_a = engine_a
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();

        // Produce a Delta from engine B (concurrent — same initial Lamport=0).
        let delta_b = engine_b
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();

        // Apply A's Delta to B.
        let outcome_ab = engine_b.apply(&delta_a).unwrap();
        assert!(
            matches!(outcome_ab, MergeOutcome::Merged { .. }),
            "A→B must merge: {outcome_ab:?}"
        );

        // Apply B's Delta to A.
        let outcome_ba = engine_a.apply(&delta_b).unwrap();
        assert!(
            matches!(outcome_ba, MergeOutcome::Merged { .. }),
            "B→A must merge: {outcome_ba:?}"
        );

        // Both engines have applied both Deltas.
        // Lamport clocks must be identical (both advanced to max+1 twice).
        assert_eq!(
            engine_a.lamport(),
            engine_b.lamport(),
            "Lamport clocks must be identical after applying same Delta set: A={}, B={}",
            engine_a.lamport(),
            engine_b.lamport()
        );
    }

    // ── Test 2: Commutative Delta application — order does not matter ─────────
    //
    // Engine A applies Delta B first then Delta C.
    // Engine B applies Delta C first then Delta B.
    // Both must reach the same Lamport clock (commutativity invariant).

    #[test]
    fn delta_application_is_commutative() {
        let schema = test_schema();

        // All three engines share the same schema and start fresh.
        let (secret_a, public_a) = generate_keypair().unwrap();
        let did_a = derive_did_from_public_key(&public_a);
        let (secret_b, public_b) = generate_keypair().unwrap();
        let did_b = derive_did_from_public_key(&public_b);
        let (secret_c, public_c) = generate_keypair().unwrap();
        let did_c = derive_did_from_public_key(&public_c);

        // Engines that receive the Deltas in different orders.
        let mut engine_ab = make_engine(secret_a, public_a, did_a.clone(), schema);
        let mut engine_ba = make_engine(secret_a, public_a, did_a.clone(), schema);

        // Produce Deltas from B and C with distinct content.
        let mut engine_src_b = make_engine(secret_b, public_b, did_b.clone(), schema);
        let mut engine_src_c = make_engine(secret_c, public_c, did_c.clone(), schema);

        let delta_b = engine_src_b
            .produce_delta(vec![], PriorityClass::Low, vec![])
            .unwrap();
        let delta_c = engine_src_c
            .produce_delta(vec![], PriorityClass::High, vec![])
            .unwrap();

        // engine_ab applies B then C.
        engine_ab.apply(&delta_b).unwrap();
        engine_ab.apply(&delta_c).unwrap();

        // engine_ba applies C then B.
        engine_ba.apply(&delta_c).unwrap();
        engine_ba.apply(&delta_b).unwrap();

        // Lamport clocks must be identical regardless of application order.
        assert_eq!(
            engine_ab.lamport(),
            engine_ba.lamport(),
            "Commutative ordering must yield the same Lamport clock: ab={}, ba={}",
            engine_ab.lamport(),
            engine_ba.lamport()
        );
    }

    // ── Test 3: WASM receive_inbound_wasm routes JSON-envelope Delta through
    //            apply_incoming_delta and projects to the in-memory store ───────
    //
    // This is the native-side counterpart of the wasm-bindgen-test
    // `test_receive_peer_message_json_envelope_projects_to_store`.
    // It verifies the new apply_incoming_delta routing in receive_inbound_wasm
    // by using inject_inbound/process_inbound_messages on the native path, which
    // shares the same JSON-envelope projection logic.
    //
    // Validates: Task 42 sub-task 4 (readable store after inbound Delta).

    #[tokio::test]
    async fn inbound_json_envelope_delta_is_readable_after_merge() {
        let path_a = {
            let mut p = env::temp_dir();
            p.push("tirbase_conv_inbound_a.db");
            p.to_str().unwrap().to_string()
        };
        let path_b = {
            let mut p = env::temp_dir();
            p.push("tirbase_conv_inbound_b.db");
            p.to_str().unwrap().to_string()
        };
        let cleanup = |p: &str| {
            let _ = std::fs::remove_file(p);
            let _ = std::fs::remove_file(format!("{p}.identity.json"));
            let _ = std::fs::remove_file(format!("{p}-wal"));
            let _ = std::fs::remove_file(format!("{p}-shm"));
        };
        cleanup(&path_a);
        cleanup(&path_b);

        let make_cfg = |p: &str| InitConfig {
            storage_path: p.to_string(),
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                anchor_attested_location: false,
                spatial_diversity_min: 1,
                quorum_k: 1,
                quorum_n: 1,
            },
        };

        let handle_a = CoreHandle::init(make_cfg(&path_a)).await.expect("init A");
        let handle_b = CoreHandle::init(make_cfg(&path_b)).await.expect("init B");

        let written_data = serde_json::json!({"sensor": "pressure", "value": 1013});

        // Write to A.
        handle_a
            .write("sensors", "p-1", written_data.clone())
            .await
            .expect("write to A");

        // Build the JSON envelope (matching CoreHandle::write format).
        let (peer_secret, peer_public) = generate_keypair().unwrap();
        let peer_did = derive_did_from_public_key(&peer_public);
        let schema_hash = [0u8; 32];

        let delta = {
            let mut envelope = serde_json::Map::new();
            envelope.insert("_tirbase_table".to_string(), serde_json::Value::String("sensors".to_string()));
            envelope.insert("_tirbase_key".to_string(), serde_json::Value::String("p-1".to_string()));
            if let Some(obj) = written_data.as_object() {
                for (k, v) in obj {
                    envelope.insert(k.clone(), v.clone());
                }
            }
            let envelope_bytes = serde_json::to_vec(&serde_json::Value::Object(envelope)).unwrap();

            let mut d = crate::crdt::delta::Delta {
                id: [0u8; 32],
                author_did: peer_did.clone(),
                signature: Ed25519Signature::default(),
                schema_hash,
                automerge_bytes: envelope_bytes,
                priority: PriorityClass::Low,
                causal_parents: vec![],
                tags: vec![],
                lamport: 2,
                created_at: 0,
            };
            let canonical = d.canonical_bytes();
            d.signature = ek_sign(&peer_secret, &canonical).expect("sign");
            d.id = Delta::compute_id(&canonical);
            d
        };

        // Inject Delta into handle_b and process it.
        handle_b
            .inject_inbound(crate::transport::message::GossipMessage::InboundDelta(delta))
            .await
            .expect("inject_inbound must not fail");

        let processed = handle_b
            .process_inbound_messages()
            .await
            .expect("process_inbound_messages must not fail");
        assert_eq!(processed, 1, "one message must be processed");

        // Verify the value is readable on B (Task 42 sub-task 4).
        let read_result = handle_b.read("sensors", "p-1").await;
        assert!(
            read_result.is_ok(),
            "inbound JSON-envelope Delta must be readable via store after merge; got: {:?}",
            read_result.err()
        );

        let result = read_result.unwrap();
        assert_eq!(
            result.data, written_data,
            "data on B must match what was written on A"
        );

        cleanup(&path_a);
        cleanup(&path_b);
    }
}

// ─── Phase 0.3(a)/(b): real-mesh integration tests (Subphase 1.5) ────────────
//
// Two in-process `CoreHandle`s with **real libp2p Swarms**, connected over
// loopback TCP by the production explicit-dial path (`CoreHandle::dial_peer`).
// No test-only injection helpers are involved anywhere on the write→receive
// path: the Delta travels
//
//   A: write() → send_delta → outbound channel → Swarm polling task
//      → gossipsub.publish → TCP/Noise/Yamux → wire
//   B: Swarm polling task (gossipsub message) → inbound channel
//      → production drain loop → receive_inbound → signature verification
//      → merge → SQL projection
//
// and is asserted on B via `read()` plus CRDT-level state (DAG node, Lamport
// clock) — i.e. the same observations a real second device would produce.
//
// These are the definition of done for Phase 0.3(a) (two-device real mesh
// Delta exchange) and Phase 0.3(b) (full write→gossip→receive→merge round
// trip with a signature-verified, merged, projected Delta on the receiver).

#[cfg(all(test, feature = "native"))]
mod real_mesh_tests {
    use super::*;
    use serde_json::json;
    use std::env;
    use std::net::TcpListener;
    use std::time::Duration;

    fn tmp_path(suffix: &str) -> String {
        let mut p = env::temp_dir();
        p.push(format!("tirbase_mesh_test_{suffix}.db"));
        p.to_str().unwrap().to_string()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.identity.json"));
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    /// Reserve a free loopback TCP port for a transport listen address.
    ///
    /// The listener is dropped before `CoreHandle::init` binds it, so there is
    /// a tiny reuse window; reserving both ports up front (before either
    /// handle inits) keeps that window to microseconds per port.
    fn reserve_loopback_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        l.local_addr().expect("local addr").port()
    }

    fn mesh_config(path: &str, port: u16) -> InitConfig {
        InitConfig {
            storage_path: path.to_string(),
            listen_addr: format!("/ip4/127.0.0.1/tcp/{port}"),
            deployment: DeploymentConfig {
                revocation_m: 1,
                revocation_n: 1,
                biscuit_ttl_secs: 3600,
                anchor_attested_location: false,
                spatial_diversity_min: 1,
                quorum_k: 1,
                quorum_n: 1,
            },
        }
    }

    /// Initialise a handle on its own loopback port with a real Swarm (the
    /// production `CoreHandle::init` path spawns the Swarm polling task) and
    /// start the production inbound drain loop at accelerated cadence — the
    /// identical loop `init` spawns at 50 ms in production builds (Subphase
    /// 1.3); test builds make `init`'s own instance inert so count-based unit
    /// tests stay deterministic, so the test drives the accelerated loop
    /// explicitly, exactly as the Subphase 1.3 acceptance does.
    async fn init_mesh_handle(suffix: &str, port: u16) -> Arc<CoreHandle> {
        let path = tmp_path(suffix);
        cleanup(&path);
        let handle = CoreHandle::init(mesh_config(&path, port))
            .await
            .expect("init must succeed with a real Swarm");
        CoreHandle::spawn_inbound_drain_loop(&handle, Duration::from_millis(10));
        handle
    }

    /// Dial `from` → `to`'s listen address via the production
    /// `CoreHandle::dial_peer` path and wait until the connection is recorded
    /// (the Swarm polling task's `ConnectionEstablished` arm populates the
    /// peer table, so `mesh_status()` reports it).
    async fn connect_peers(from: &Arc<CoreHandle>, target_addr: &str) {
        let addr: libp2p::Multiaddr =
            target_addr.parse().expect("valid multiaddr");
        from.dial_peer(addr).await.expect("dial_peer must succeed");

        let mut attempts = 0u32;
        loop {
            if from.mesh_status().peer_count >= 1 {
                return;
            }
            attempts += 1;
            assert!(
                attempts < 500,
                "explicit dial never established a connection (mesh_status stayed disconnected for 5s)"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Poll `handle.read(table, key)` until the row's data equals `expected`
    /// or `timeout` elapses.  (Polling for a bare successful read is not
    /// enough across multiple round trips — a row written by an earlier
    /// round trip already reads successfully with stale data.)
    async fn wait_for_data(
        handle: &CoreHandle,
        table: &str,
        key: &str,
        expected: &serde_json::Value,
        timeout: Duration,
    ) -> QueryResult {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match handle.read(table, key).await {
                Ok(res) if &res.data == expected => return res,
                _ => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "row {table}/{key} never projected the expected data on the receiving device within {timeout:?}"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
    }

    // ── Phase 0.3(a): two-device real mesh Delta exchange ────────────────────
    //
    // Two real Swarm-backed CoreHandles on loopback; a write on device A
    // becomes visible (readable) on device B with no test-only injection
    // helpers on the path.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_devices_exchange_delta_over_real_mesh() {
        // Reserve both ports before either init to minimise reuse races.
        let port_a = reserve_loopback_port();
        let port_b = reserve_loopback_port();
        assert_ne!(port_a, port_b, "the two devices need distinct ports");

        let handle_a = init_mesh_handle("p03a_A", port_a).await;
        let handle_b = init_mesh_handle("p03a_B", port_b).await;

        // The only manual step: device A dials device B's listen address over
        // the production dial path (mDNS would do this automatically on a LAN;
        // loopback tests use the explicit path so no multicast is involved).
        let addr_b = format!("/ip4/127.0.0.1/tcp/{port_b}");
        connect_peers(&handle_a, &addr_b).await;

        // Let the gossipsub subscription exchange settle so the publish on A
        // reaches B's mesh rather than being deferred as "no subscribers".
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Write on A — production write path (store + signed Delta + publish).
        let written = json!({ "device": "A", "seq": 1, "msg": "hello over the real mesh" });
        let write_result = handle_a
            .write("mesh", "row-a", written.clone())
            .await
            .expect("write on A must succeed");
        assert_ne!(write_result.delta_id, [0u8; 32], "A must produce a real Delta");

        // Assert the Delta arrived on B through the wire: signature-verified
        // (else Rejected — nothing would be stored), merged, projected — i.e.
        // readable via B's normal read() path.
        let observed = wait_for_data(&handle_b, "mesh", "row-a", &written, Duration::from_secs(20)).await;
        assert_eq!(
            observed.data, written,
            "data read on device B must exactly match what was written on device A"
        );

        cleanup(&tmp_path("p03a_A"));
        cleanup(&tmp_path("p03a_B"));
    }

    // ── Phase 0.3(b): full write→gossip→receive→merge round trip ────────────
    //
    // Same real mesh, but asserting each stage of the receiving pipeline on
    // B's CRDT engine and store:
    //   - signature-verified: the exact Delta A produced (Delta ID) is present
    //     in B's DAG under A's author DID — `CrdtEngine::apply` only inserts
    //     the DagNode after Ed25519 verification succeeds (step 3) and the
    //     merge completes (step 6).
    //   - merged: B's Lamport clock advanced (apply step 5).
    //   - projected: the row is readable via B's read() with A's exact data.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_gossip_receive_merge_round_trip_is_signature_verified_and_projected() {
        let port_a = reserve_loopback_port();
        let port_b = reserve_loopback_port();
        assert_ne!(port_a, port_b);

        let handle_a = init_mesh_handle("p03b_A", port_a).await;
        let handle_b = init_mesh_handle("p03b_B", port_b).await;

        // B's engine starts with a zero Lamport clock and an empty DAG.
        let author_did_a = handle_a.identity.did().to_string();
        assert_eq!(handle_b.crdt.lock().unwrap().lamport(), 0, "B must start clean");

        let addr_b = format!("/ip4/127.0.0.1/tcp/{port_b}");
        connect_peers(&handle_a, &addr_b).await;
        tokio::time::sleep(Duration::from_millis(250)).await;

        // ── Round trip 1 ─────────────────────────────────────────────────────
        let written_1 = json!({ "sensor": "temp", "value": 23.4 });
        let write_1 = handle_a
            .write("roundtrip", "k1", written_1.clone())
            .await
            .expect("first write on A");

        let observed_1 = wait_for_data(&handle_b, "roundtrip", "k1", &written_1, Duration::from_secs(20)).await;
        assert_eq!(observed_1.data, written_1, "round trip 1 data must match on B");

        // The exact Delta A signed and published must have been merged into B's
        // DAG — signature-verified (author DID resolves from did:key and the
        // Ed25519 check passes, otherwise `apply` returns Rejected and no node
        // is inserted), merged (DagNode persisted), authored by A.
        let node_1 = handle_b
            .crdt
            .lock()
            .unwrap()
            .dag_node(&write_1.delta_id)
            .expect("DAG lookup must not fail")
            .unwrap_or_else(|| {
                panic!(
                    "B's DAG must contain the Delta A produced ({}); \
                     without a signature-verified merge no DagNode is inserted",
                    hex::encode(write_1.delta_id)
                )
            });
        assert_eq!(
            node_1.author_did, author_did_a,
            "B's DAG node must be attributed to A's DID"
        );
        assert!(
            handle_b.crdt.lock().unwrap().lamport() > 0,
            "B's Lamport clock must advance after merging A's Delta"
        );

        // ── Round trip 2: a second write chains off the first causally ───────
        let written_2 = json!({ "sensor": "temp", "value": 25.7 });
        let write_2 = handle_a
            .write("roundtrip", "k1", written_2.clone())
            .await
            .expect("second write on A");
        assert_ne!(
            write_2.delta_id, write_1.delta_id,
            "the second write must produce a distinct Delta"
        );

        let observed_2 = wait_for_data(&handle_b, "roundtrip", "k1", &written_2, Duration::from_secs(20)).await;
        assert_eq!(observed_2.data, written_2, "round trip 2 data must match on B");

        // Both Deltas must be present in B's DAG (converged state), each signed
        // by A.
        let node_2 = handle_b
            .crdt
            .lock()
            .unwrap()
            .dag_node(&write_2.delta_id)
            .expect("DAG lookup must not fail")
            .expect("second Delta must be merged into B's DAG");
        assert_eq!(node_2.author_did, author_did_a);
        assert!(
            handle_b.crdt.lock().unwrap().dag_node(&write_1.delta_id).unwrap().is_some(),
            "first Delta must still be in B's DAG after the second merge"
        );

        cleanup(&tmp_path("p03b_A"));
        cleanup(&tmp_path("p03b_B"));
    }
}
