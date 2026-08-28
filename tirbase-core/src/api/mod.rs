//! Public API layer — CoreHandle, init(), read(), write(), query()
//!
//! This is the primary entry point for both the TypeScript SDK (WASM build)
//! and the Cloud Ledger (native build). The API surface is identical on both
//! build targets; static_assertions in lib.rs enforce this at compile time.

#![allow(dead_code, unused_variables, unused_imports)]

pub mod types;

use crate::errors::TirBaseError;
use types::{DurabilityTier, MeshStatus, QueryResult, TrustLevel, WriteResult};

/// The main handle to a TirBase instance.
/// Obtained by calling [`CoreHandle::init`].
pub struct CoreHandle {
    // TODO: embed LocalStore, CrdtEngine, IdentityManager, etc. in later tasks
}

impl CoreHandle {
    /// Initialise TirBase, loading or creating local storage and identity.
    ///
    /// On the WASM target this is exposed to JavaScript and resolves a
    /// Promise-based ready signal (Req 2.2).
    /// On the native target it blocks until initialisation is complete.
    pub async fn init(config: InitConfig) -> Result<Self, TirBaseError> {
        todo!("Task 1 scaffold — full implementation in later tasks")
    }

    /// Read a single record from a table by key (Req 2.1, 3.3).
    pub async fn read(&self, table: &str, key: &str) -> Result<QueryResult, TirBaseError> {
        todo!("Task 1 scaffold")
    }

    /// Write a record to a table (Req 2.1, 2.3, 3.2).
    pub async fn write(
        &self,
        table: &str,
        key: &str,
        data: serde_json::Value,
    ) -> Result<WriteResult, TirBaseError> {
        todo!("Task 1 scaffold")
    }

    /// Query multiple records from a table with an optional filter (Req 2.1).
    pub async fn query(
        &self,
        table: &str,
        filter: Option<serde_json::Value>,
    ) -> Result<Vec<QueryResult>, TirBaseError> {
        todo!("Task 1 scaffold")
    }

    /// The current Trust_Level of the local device (Req 2.4).
    pub fn trust_level(&self) -> TrustLevel {
        todo!("Task 1 scaffold")
    }

    /// Mesh connection status and peer count (Req 2.5).
    pub fn mesh_status(&self) -> MeshStatus {
        todo!("Task 1 scaffold")
    }
}

/// Configuration supplied at initialisation time.
#[derive(Debug, Clone)]
pub struct InitConfig {
    /// Path to the local SQLite database file.
    pub storage_path: String,
    /// Deployment-specific settings (M-of-N thresholds, spatial diversity, etc.).
    pub deployment: DeploymentConfig,
}

/// Deployment-specific configuration.
#[derive(Debug, Clone, Default)]
pub struct DeploymentConfig {
    /// Revocation threshold M (signatures required).
    pub revocation_m: usize,
    /// Revocation threshold N (total manager DIDs).
    pub revocation_n: usize,
    /// Biscuit token TTL in seconds (1h–24h; or extended with accepted-risk doc).
    pub biscuit_ttl_secs: u64,
    /// Whether Anchor_Attested_Location subsystem is enabled.
    pub anchor_attested_location: bool,
    /// Minimum distinct spatial tags required for Quorum.
    pub spatial_diversity_min: usize,
    /// K-of-N quorum (K receipts required).
    pub quorum_k: usize,
    /// N candidate peers for quorum.
    pub quorum_n: usize,
}
