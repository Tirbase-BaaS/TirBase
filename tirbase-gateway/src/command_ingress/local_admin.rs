//! Local admin command ingress (task 11.3/14 production callers).
//!
//! Routes command submission through the same `CommandGuard` convergence point
//! as mesh and cloud ingress.

use tirbase_guard::admit::AdmitContext;
use tirbase_guard::{
    AdmitError, AdmittedCommand, CommandGuard, DriverProxy, IngressSource,
};
use tirbase_types::command::CommandMessage;

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
