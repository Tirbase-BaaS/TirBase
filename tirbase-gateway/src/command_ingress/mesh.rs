//! P2P mesh command ingress (tasks 11.3/14 production callers).
//!
//! Commands delivered from the mesh (Paxos-confirmed) pass through the local
//! guard's `admit()` before actuation — mesh consensus is advisory, not
//! bypassing.

use tirbase_guard::admit::AdmitContext;
use tirbase_guard::{AdmitError, AdmittedCommand, CommandGuard, DriverProxy, IngressSource};
use tirbase_types::command::CommandMessage;

/// Admit a mesh-delivered command (legacy path).
pub fn handle_mesh_command<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit(cmd, IngressSource::Mesh, proxy, frame)
}

/// Admit a mesh-delivered command with full Task 14 pipeline context.
pub fn handle_mesh_command_with_context<W: std::io::Write + Send>(
    guard: &CommandGuard,
    proxy: &mut DriverProxy<W>,
    cmd: &CommandMessage,
    frame: &[u8],
    ctx: &AdmitContext<'_>,
) -> Result<AdmittedCommand, AdmitError> {
    guard.admit_with_context(cmd, ctx, proxy, frame)
}
