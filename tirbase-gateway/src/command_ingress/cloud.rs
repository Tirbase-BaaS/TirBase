//! Cloud API command ingress (14 production callers).

use tirbase_guard::admit::AdmitContext;
use tirbase_guard::{AdmitError, AdmittedCommand, CommandGuard, DriverProxy, IngressSource};
use tirbase_types::command::CommandMessage;

/// Admit a command received over the cloud API and dispatch via the guard-owned proxy.
pub fn handle_cloud_command<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit(cmd, IngressSource::CloudApi, proxy, frame)
}

/// Admit a cloud-API command with full pipeline context.
pub fn handle_cloud_command_with_context<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
    ctx: &AdmitContext<'_>,
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit_with_context(cmd, ctx, proxy, frame)
}
