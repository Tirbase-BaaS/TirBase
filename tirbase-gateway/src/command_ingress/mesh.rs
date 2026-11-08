//! Mesh command ingress (task 11.3 production caller).
//!
//! This handler is the mesh/gossipsub-side entry point.  It does not construct
//! `ActuationPermit`s and does not touch drivers directly — it calls through
//! `CommandGuard::admit()`, which is the only permit issuer.

use tirbase_guard::{
    AdmitError, AdmittedCommand, CommandGuard, DriverProxy, IngressSource,
};
use tirbase_types::command::CommandMessage;

/// Admit a command received over the mesh and dispatch via the guard-owned proxy.
pub fn handle_mesh_command<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit(cmd, IngressSource::Mesh, proxy, frame)
}
