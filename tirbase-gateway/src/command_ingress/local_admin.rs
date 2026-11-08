//! Local admin command ingress (task 11.3 production caller).
//!
//! Shares the admin socket transport but routes command submission through the
//! same `CommandGuard::admit()` convergence point as mesh and cloud ingress.

use tirbase_guard::{
    AdmitError, AdmittedCommand, CommandGuard, DriverProxy, IngressSource,
};
use tirbase_types::command::CommandMessage;

/// Admit a command received over the local admin API and dispatch via the
/// guard-owned proxy.
pub fn handle_local_admin_command<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit(cmd, IngressSource::LocalAdmin, proxy, frame)
}
