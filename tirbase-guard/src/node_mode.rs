//! Node operational mode and the mode × operation matrix (task 13.1 —
//! CLAIM-13.1, PV-4.13, INV-5).
//!
//! Stage 1 of [`crate::guard::CommandGuard::admit`] reads the active mode and
//! rejects every command when the node is [`NodeMode::Lockdown`] or
//! [`NodeMode::Restricted`].  Mesh sync and log export are *not* commands; they
//! remain available in `Restricted` (and mesh sync remains available in
//! `Lockdown` for operator recovery coordination), which is enforced by the
//! subsystems that own those operations.  The guard's responsibility is the
//! command admission boundary.

use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Operational mode of a TirBase node.
///
/// The ordering is intentional: `Lockdown` is the most restrictive state and
/// `Normal` the least.  Transitions are governed by the lockdown/crash-loop
/// and recovery paths; this type only describes the state and its admission
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeMode {
    /// Boot/reconciliation in progress; commands are rejected until the node
    /// reaches a steady mode.
    Starting = 0,
    /// Full operation: commands, mesh sync, and log export are permitted
    /// (subject to normal guard checks).
    Normal = 1,
    /// Degraded connectivity/sensors: commands remain subject to guard policy;
    /// mesh sync and log export remain available.
    Degraded = 2,
    /// Security or ledger integrity concern: **commands are rejected**.  Mesh
    /// sync and log export remain available for diagnosis and recovery.
    Restricted = 3,
    /// Security LOCKDOWN: **commands are rejected**.  Only the operations
    /// required for authenticated recovery (e.g. mesh/log coordination paths
    /// owned by their subsystems) remain; command actuation is never permitted.
    Lockdown = 4,
}

impl NodeMode {
    /// Parse from a persisted/stable string name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Starting" => Some(NodeMode::Starting),
            "Normal" => Some(NodeMode::Normal),
            "Degraded" => Some(NodeMode::Degraded),
            "Restricted" => Some(NodeMode::Restricted),
            "Lockdown" => Some(NodeMode::Lockdown),
            _ => None,
        }
    }

    /// Stable name used in logs, DB rows, and admin responses.
    pub fn as_str(self) -> &'static str {
        match self {
            NodeMode::Starting => "Starting",
            NodeMode::Normal => "Normal",
            NodeMode::Degraded => "Degraded",
            NodeMode::Restricted => "Restricted",
            NodeMode::Lockdown => "Lockdown",
        }
    }

    /// Whether command admission is permitted in this mode.
    ///
    /// Commands are rejected in [`NodeMode::Starting`], [`NodeMode::Restricted`],
    /// and [`NodeMode::Lockdown`].  `Degraded` allows commands (the guard may
    /// apply narrower policy elsewhere); `Restricted`/`Lockdown` are hard stops
    /// at Stage 1.
    pub fn allows_commands(self) -> bool {
        matches!(self, NodeMode::Normal | NodeMode::Degraded)
    }

    /// Whether mesh synchronization is permitted.
    ///
    /// Mesh sync remains available in `Restricted` (and `Lockdown`) so recovery
    /// coordination and log/receipt propagation can proceed without allowing
    /// actuation.
    pub fn allows_mesh_sync(self) -> bool {
        true
    }

    /// Whether security/log export is permitted.
    ///
    /// Log export remains available in `Restricted` for diagnosis.  It is also
    /// available in `Lockdown` because operators need evidence for recovery.
    pub fn allows_log_export(self) -> bool {
        true
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => NodeMode::Starting,
            1 => NodeMode::Normal,
            2 => NodeMode::Degraded,
            3 => NodeMode::Restricted,
            4 => NodeMode::Lockdown,
            _ => NodeMode::Lockdown, // fail closed on corrupt/unknown state
        }
    }
}

impl fmt::Display for NodeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Shared, thread-safe holder for the current [`NodeMode`].
///
/// `CommandGuard::admit()` reads this at Stage 1.  Gateway/runtime code updates
/// it when entering or exiting lockdown/restricted states.
#[derive(Debug)]
pub struct NodeModeState {
    mode: AtomicU8,
}

impl NodeModeState {
    /// Create a state initialized to `mode`.
    pub fn new(mode: NodeMode) -> Arc<Self> {
        Arc::new(NodeModeState {
            mode: AtomicU8::new(mode as u8),
        })
    }

    /// Current mode.
    pub fn get(&self) -> NodeMode {
        NodeMode::from_u8(self.mode.load(Ordering::Acquire))
    }

    /// Set the mode, returning the previous mode.
    pub fn set(&self, mode: NodeMode) -> NodeMode {
        NodeMode::from_u8(self.mode.swap(mode as u8, Ordering::AcqRel))
    }

    /// Transition to `mode` only if currently `expected`.
    pub fn compare_set(&self, expected: NodeMode, mode: NodeMode) -> Result<NodeMode, NodeMode> {
        match self.mode.compare_exchange(
            expected as u8,
            mode as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(prev) => Ok(NodeMode::from_u8(prev)),
            Err(actual) => Err(NodeMode::from_u8(actual)),
        }
    }
}

impl Default for NodeModeState {
    fn default() -> Self {
        NodeModeState {
            mode: AtomicU8::new(NodeMode::Starting as u8),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_matrix_rejects_lockdown_and_restricted_and_starting() {
        assert!(!NodeMode::Starting.allows_commands());
        assert!(!NodeMode::Restricted.allows_commands());
        assert!(!NodeMode::Lockdown.allows_commands());
        assert!(NodeMode::Normal.allows_commands());
        assert!(NodeMode::Degraded.allows_commands());
    }

    #[test]
    fn mesh_and_log_export_remain_available_in_restricted() {
        for mode in [
            NodeMode::Starting,
            NodeMode::Normal,
            NodeMode::Degraded,
            NodeMode::Restricted,
            NodeMode::Lockdown,
        ] {
            assert!(mode.allows_mesh_sync(), "{mode} must allow mesh sync");
            assert!(mode.allows_log_export(), "{mode} must allow log export");
        }
        assert!(NodeMode::Restricted.allows_mesh_sync());
        assert!(NodeMode::Restricted.allows_log_export());
    }

    #[test]
    fn state_updates_atomically() {
        let state = NodeModeState::new(NodeMode::Starting);
        assert_eq!(state.get(), NodeMode::Starting);
        assert_eq!(state.set(NodeMode::Normal), NodeMode::Starting);
        assert_eq!(state.get(), NodeMode::Normal);
    }
}
