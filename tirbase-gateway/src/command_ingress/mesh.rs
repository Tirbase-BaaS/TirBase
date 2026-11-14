// SPDX-License-Identifier: AGPL-3.0-only

//! P2P mesh command ingress (14 production callers).
//!
//! Commands delivered from the mesh (Paxos-confirmed) pass through the local
//! guard's `admit()` before actuation — mesh consensus is advisory, not
//! bypassing.

use std::io::Cursor;
use std::sync::Arc;

use tirbase_core::api::CoreHandle;
use tirbase_guard::admit::AdmitContext;
use tirbase_guard::{AdmitError, AdmittedCommand, CommandGuard, DriverProxy, IngressSource};
use tirbase_types::command::CommandMessage;

use crate::guard::{AdmitRequest, DispatchTarget, SqliteStage16Store, admit_and_dispatch_blocking};

/// Admit a mesh-delivered command (legacy path).
pub fn handle_mesh_command<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit(cmd, IngressSource::Mesh, proxy, frame)
}

/// Admit a mesh-delivered command with full pipeline context.
pub fn handle_mesh_command_with_context<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
    ctx: &AdmitContext<'_>,
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit_with_context(cmd, ctx, proxy, frame)
}

/// CLAIM-35.7: production mesh command receiver.
///
/// Subscribes to the core mesh command channel and runs every delivered
/// command through [`admit_and_dispatch_blocking`] — the same Stage 0–19 path
/// used by the local-admin and cloud receivers — with `IngressSource::Mesh`.
/// The transport is only a delivery channel: the guard still verifies
/// signature, role, token, envelope, anti-replay and quorum locally, so mesh
/// delivery cannot bypass admission.
pub async fn run_mesh_command_receiver(
    core: Arc<CoreHandle>,
    guard: Arc<CommandGuard>,
    stage16: Arc<SqliteStage16Store>,
) -> anyhow::Result<()> {
    let receiver = core.subscribe_mesh_commands();
    tracing::info!("mesh command ingress listening (CLAIM-35.7)");
    run_mesh_command_receiver_with(receiver, guard, stage16).await
}

/// Receiver loop over an already-subscribed channel.
///
/// Kept separate so tests can drive it with a local broadcast sender.
pub async fn run_mesh_command_receiver_with(
    mut receiver: tokio::sync::broadcast::Receiver<CommandMessage>,
    guard: Arc<CommandGuard>,
    stage16: Arc<SqliteStage16Store>,
) -> anyhow::Result<()> {
    use tokio::sync::broadcast::error::RecvError;

    loop {
        match receiver.recv().await {
            Ok(command) => {
                let issuer = command.issuer_did.as_str().to_string();
                let target = command.target_id.as_str().to_string();
                let decision = process_mesh_command(command, guard.clone(), stage16.clone()).await;
                let status = decision
                    .get("status")
                    .and_then(|value| value.as_str())
                    .unwrap_or("rejected");
                tracing::info!(
                    %issuer,
                    %target,
                    status,
                    "mesh command processed through the guard pipeline (CLAIM-35.7)"
                );
            }
            Err(RecvError::Lagged(dropped)) => {
                // A slow guard must not grow the mesh queue without bound.
                tracing::warn!(
                    dropped,
                    "mesh command receiver lagged; commands were dropped without admission"
                );
            }
            Err(RecvError::Closed) => break,
        }
    }
    Ok(())
}

/// Run one mesh-delivered command through the full gateway admission and
/// dispatch path. The default actuation frame names the mesh ingress so the
/// guard decision and the driver frame are attributable.
pub async fn process_mesh_command(
    command: CommandMessage,
    guard: Arc<CommandGuard>,
    stage16: Arc<SqliteStage16Store>,
) -> serde_json::Value {
    let source_key = format!("Mesh:{}", command.issuer_did.as_str());
    let frame = format!(
        "MESH:{}:{}",
        command.target_id.as_str(),
        command.param
    )
    .into_bytes();
    let (now_est, now_mono_secs) = pipeline_clock(&guard).unwrap_or_else(|| {
        let now = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
        (now, now)
    });

    admit_and_dispatch_blocking(
        guard,
        source_key,
        AdmitRequest {
            cmd: command,
            token: Vec::new(),
            ingress: IngressSource::Mesh,
            now_est,
            simulate: false,
        },
        DispatchTarget {
            store: stage16,
            proxy: DriverProxy::new(Vec::new()),
            frame,
            driver_reader: Cursor::new(Vec::new()),
            now_mono_secs,
        },
    )
    .await
}

fn pipeline_clock(guard: &CommandGuard) -> Option<(i64, i64)> {
    let pipeline = guard.pipeline()?;
    let now_est = {
        let ratchet = pipeline.ratchet().lock().ok()?;
        ratchet.now_est(pipeline.time_source().as_ref())
    };
    Some((now_est, pipeline.mono_secs_now()))
}
