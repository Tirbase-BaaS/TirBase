//! Production wiring between the gateway security log and the core mesh.
//!
//! Closes the loop on the mesh-facing security-log surfaces:
//! - 26.3 (PV-7.10): installs the checkpoint provider so the transport loop
//!   gossips the latest local checkpoint hash when a peer connection is
//!   established.
//! - 26.4 (PV-7.10): forwards peer checkpoint observations delivered by the
//!   mesh receive path into [`SecurityEventLog::observe_peer_checkpoint`], which
//!   performs the tail-truncation comparison.
//! - 26.7 (PV-7.10): supplies the real mesh-peer witness state at checkpoint
//!   time instead of a hardcoded "no witness" value. The cloud-anchor half of
//!   the witness state is set by [`crate::cloud_anchor`] when a verified anchor
//!   acknowledgement is ingested.
//! - 28.3 (PV-7.9): installs the local security-event sync publisher and the
//!   receive-path merge that persists peer records into
//!   `synced_security_events`.
//!
//! Production caller: `tirbase-gateway/src/main.rs` after `CoreHandle::init`.

use std::sync::Arc;

use tirbase_core::api::CoreHandle;
use tirbase_core::transport::security_event_sync::SecurityEventSyncBatch;

use crate::security_log::SecurityEventLog;

/// Wire a security event log to a running [`CoreHandle`] mesh.
///
/// `publisher` carries the outbound security-event sync batches. The gateway
/// passes a closure over `CoreHandle::publish_security_event_sync`; tests can
/// pass an in-process transport with the same signature. The background tasks
/// run for the lifetime of the process.
pub fn wire_security_log_to_mesh<P>(
    core: &Arc<CoreHandle>,
    log: &Arc<SecurityEventLog>,
    sender_did: impl Into<String>,
    publisher: P,
) where
    P: Fn(SecurityEventSyncBatch) + Send + Sync + 'static,
{
    // 26.3: the transport loop reads this provider on ConnectionEstablished.
    let provider_log = Arc::clone(log);
    core.set_checkpoint_provider(move || provider_log.latest_checkpoint_hash().ok().flatten());

    // 26.7: real observed mesh-peer witness state at checkpoint time.
    let witness_core = Arc::clone(core);
    log.set_witness_source(move || witness_core.mesh_status().peer_count > 0);

    // 28.3: outbound publisher for appended security events.
    log.set_security_event_sync_publisher(sender_did, publisher);

    // 26.4: consume observations published by `CoreHandle::receive_inbound`.
    let mut observations = core.subscribe_checkpoint_observations();
    let observer_log = Arc::clone(log);
    tokio::spawn(async move {
        while let Ok((peer_did, seq, checkpoint_hash, observed_at)) = observations.recv().await {
            if let Err(error) =
                observer_log.observe_peer_checkpoint(&peer_did, seq, checkpoint_hash, observed_at)
            {
                tracing::warn!(
                    %error,
                    peer = %peer_did,
                    "peer checkpoint observation failed (CLAIM-26.4)"
                );
            }
        }
    });

    // 28.3: receive path — persist accepted peer records (append-only merge).
    let mut inbound = core.subscribe_security_event_sync();
    let ingest_log = Arc::clone(log);
    tokio::spawn(async move {
        while let Ok(record) = inbound.recv().await {
            match ingest_log.persist_synced_event(&record) {
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    %error,
                    origin = %record.origin_did,
                    "failed to persist synced security event (CLAIM-28.3)"
                ),
            }
        }
    });

    log.spawn_security_event_sync_loop();
}
