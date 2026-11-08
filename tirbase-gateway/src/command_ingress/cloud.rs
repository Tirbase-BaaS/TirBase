//! Cloud API command ingress (task 11.3 production caller).

use tirbase_guard::{
    AdmitError, AdmittedCommand, CommandGuard, DriverProxy, IngressSource,
};
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
