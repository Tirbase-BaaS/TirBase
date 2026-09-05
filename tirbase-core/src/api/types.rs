//! Shared API types — WriteResult, QueryResult, DurabilityTier, TrustLevel, MeshStatus
//!
//! These types are part of the public API surface that must be identical on
//! both the WASM and native build targets (Req 1.2, 1.5).

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Default Biscuit token TTL in seconds (1 hour — the spec minimum, Req 8.7).
/// Used when `DeploymentConfig.biscuit_ttl_secs` is 0 (unconfigured).
pub const DEFAULT_BISCUIT_TTL_SECS: u64 = 3600;

// ─── Trust Level ─────────────────────────────────────────────────────────────

/// The trust state of a device's identity (Req 8.2, 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Device holds a valid Biscuit_Token within its Epoch.
    Verified,
    /// Device's token has expired but no Revocation_Delta has been received.
    /// All operations are accompanied by an UNVERIFIED warning.
    Unverified,
    /// Device has been revoked via a Revocation_Delta.
    /// All Deltas from this device are rejected.
    Revoked,
}

// ─── Durability Tier ─────────────────────────────────────────────────────────

/// The durability tier of a committed set of Deltas (Req 14.1, 14.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DurabilityTier {
    /// Committed to local SQLite but not yet replicated.
    Uncommitted,
    /// K peers have returned signed Durability_Receipts spanning spatial diversity.
    Tier1,
    /// The Cloud_Ledger has acknowledged the Delta set.
    Tier2,
}

// ─── Mesh Status ─────────────────────────────────────────────────────────────

/// The mesh connectivity status of the local device (Req 2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshStatus {
    /// Connection state.
    pub status: ConnectionStatus,
    /// Number of currently active mesh peers.
    pub peer_count: u32,
}

/// Connection status variants (Req 2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Connected,
    Connecting,
    Disconnected,
}

// ─── Write Result ─────────────────────────────────────────────────────────────

/// Result returned from a successful write operation (Req 2.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResult {
    /// The ID of the Delta produced for this write.
    pub delta_id: [u8; 32],
    /// The durability tier at the time the write was acknowledged.
    pub durability_tier: DurabilityTier,
    /// Warning emitted when the device's Trust_Level is UNVERIFIED (Req 8.4).
    pub unverified_warning: Option<UnverifiedWarning>,
}

// ─── Query Result ─────────────────────────────────────────────────────────────

/// Result returned from a read or query operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Table name.
    pub table: String,
    /// Row key.
    pub key: String,
    /// The row data as a JSON value.
    pub data: serde_json::Value,
    /// Warning emitted when the device's Trust_Level is UNVERIFIED (Req 8.4).
    pub unverified_warning: Option<UnverifiedWarning>,
    /// Whether this row is tagged CONTAMINATED.
    pub contaminated: bool,
}

// ─── UNVERIFIED Warning ───────────────────────────────────────────────────────

/// Delivered on every operation while a device's Trust_Level is UNVERIFIED (Req 8.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnverifiedWarning {
    /// UTC timestamp (microseconds) when the device first became UNVERIFIED.
    pub unverified_since: i64,
}
