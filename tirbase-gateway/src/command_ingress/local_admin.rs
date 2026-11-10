//! Local admin command ingress (task 11.3/14 production callers).
//!
//! Routes command submission through the same `CommandGuard` convergence point
//! as mesh and cloud ingress.

use std::io::Cursor;
use std::sync::Arc;

use serde::Deserialize;
use tirbase_guard::admit::AdmitContext;
use tirbase_guard::{AdmitError, AdmittedCommand, CommandGuard, DriverProxy, IngressSource};
use tirbase_types::command::CommandMessage;

use crate::guard::{admit_and_dispatch_blocking, SqliteStage16Store};

/// Admit a command received over the local admin API and dispatch via the
/// guard-owned proxy (legacy path; no Biscuit/pipeline context).
pub fn handle_local_admin_command<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit(cmd, IngressSource::LocalAdmin, proxy, frame)
}

/// Admit a command with full Task 14 pipeline context (Stages 0–15).
pub fn handle_local_admin_command_with_context<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
    ctx: &AdmitContext<'_>,
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit_with_context(cmd, ctx, proxy, frame)
}

/// One JSON-line request accepted by the local-admin command receiver.
#[derive(Debug, Deserialize)]
pub struct LocalAdminCommandRequest {
    /// Signed command to run through the guard pipeline.
    pub command: CommandMessage,
    /// Hex-encoded Biscuit token authorising the command issuer.
    #[serde(default)]
    pub biscuit_token_hex: Option<String>,
    /// Hex-encoded actuation frame forwarded to the driver after admission.
    #[serde(default)]
    pub frame_hex: Option<String>,
    /// Stage-0 pre-auth rate limit key (defaults to `LocalAdmin:<issuer>`).
    #[serde(default)]
    pub source_key: Option<String>,
    /// Authenticated time override; defaults to the pipeline ratchet.
    #[serde(default)]
    pub now_est_secs: Option<i64>,
    /// Dry-run: evaluate Stages 0–15 without writing the effects ledger.
    #[serde(default)]
    pub simulate: bool,
}

/// Production local-admin command receiver (task 35.4).
///
/// Listens on a loopback TCP socket, decodes one JSON request per line, and runs
/// each command through [`admit_and_dispatch_blocking`] — the Stage 16–19
/// guard-owned path that converges on the same `CommandGuard` as the
/// `handle_local_admin_command_with_context` Stage 0–15 wrapper.  Transport
/// failures are reported per connection; the listener itself keeps accepting.
pub async fn run_local_admin_command_listener(
    addr: std::net::SocketAddr,
    guard: Arc<CommandGuard>,
    stage16: Arc<SqliteStage16Store>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "local-admin command ingress listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            tracing::warn!(%peer, "rejecting non-loopback local-admin command connection");
            continue;
        }
        let guard = guard.clone();
        let stage16 = stage16.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_local_admin_command(stream, guard, stage16).await {
                tracing::warn!(%error, "local-admin command connection failed");
            }
        });
    }
}

async fn serve_local_admin_command(
    stream: tokio::net::TcpStream,
    guard: Arc<CommandGuard>,
    stage16: Arc<SqliteStage16Store>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<LocalAdminCommandRequest>(&line) {
            Ok(request) => {
                process_local_admin_request(request, guard.clone(), stage16.clone()).await
            }
            Err(error) => serde_json::json!({
                "status": "bad_request",
                "error": format!("invalid local-admin command request: {error}"),
            }),
        };
        write_half
            .write_all(response.to_string().as_bytes())
            .await?;
        write_half.write_all(b"\n").await?;
        write_half.flush().await?;
    }
    Ok(())
}

async fn process_local_admin_request(
    request: LocalAdminCommandRequest,
    guard: Arc<CommandGuard>,
    stage16: Arc<SqliteStage16Store>,
) -> serde_json::Value {
    let token = match request.biscuit_token_hex.as_deref() {
        Some(hex_token) => match hex::decode(hex_token.trim()) {
            Ok(token) => token,
            Err(error) => {
                return serde_json::json!({"status":"bad_request","error":format!("biscuit_token_hex: {error}")});
            }
        },
        None => Vec::new(),
    };
    let frame = match request.frame_hex.as_deref() {
        Some(hex_frame) => match hex::decode(hex_frame.trim()) {
            Ok(frame) => frame,
            Err(error) => {
                return serde_json::json!({"status":"bad_request","error":format!("frame_hex: {error}")});
            }
        },
        None => format!(
            "LOCAL_ADMIN:{}:{}",
            request.command.target_id.as_str(),
            request.command.param
        )
        .into_bytes(),
    };
    let source_key = request
        .source_key
        .unwrap_or_else(|| format!("LocalAdmin:{}", request.command.issuer_did.as_str()));
    let (now_est, now_mono_secs) = pipeline_now(&guard)
        .or_else(|| request.now_est_secs.map(|now| (now, now)))
        .unwrap_or_else(|| {
            let now = tirbase_core::traits::wall_hint_secs().unwrap_or_default();
            (now, now)
        });
    let now_est = request.now_est_secs.unwrap_or(now_est);

    let decision = admit_and_dispatch_blocking(
        guard,
        request.command,
        source_key,
        token,
        IngressSource::LocalAdmin,
        now_est,
        request.simulate,
        stage16,
        DriverProxy::new(Vec::new()),
        frame,
        Cursor::new(Vec::new()),
        now_mono_secs,
    )
    .await;

    serde_json::json!({
        "status": "ok",
        "ingress": "LocalAdmin",
        "decision": decision,
    })
}

fn pipeline_now(guard: &CommandGuard) -> Option<(i64, i64)> {
    let pipeline = guard.pipeline()?;
    let now_est = {
        let ratchet = pipeline.ratchet().lock().ok()?;
        ratchet.now_est(pipeline.time_source().as_ref())
    };
    Some((now_est, pipeline.mono_secs_now()))
}
