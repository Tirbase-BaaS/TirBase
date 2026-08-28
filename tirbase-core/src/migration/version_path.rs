//! SchemaVersionPath registry — ordered list of schema hashes for the
//! deployment's registered schema-version update path (Req 18.3a).
//!
//! A Migration_Delta is accepted only if:
//!   migration.source_schema_hash == device.current_schema_hash
//!   migration.target_schema_hash == path.next_version(device.current_schema_hash)

#![allow(dead_code, unused_variables)]

use crate::errors::TirBaseError;
use crate::schema::hash::SchemaIdentifierHash;

/// Registry of the deployment's ordered schema-version update path.
#[derive(Debug, Clone, Default)]
pub struct SchemaVersionPath {
    /// Ordered list of schema hashes from oldest to newest.
    pub versions: Vec<SchemaIdentifierHash>,
}

impl SchemaVersionPath {
    /// Create a new registry from an ordered list of schema hashes.
    pub fn new(versions: Vec<SchemaIdentifierHash>) -> Self {
        Self { versions }
    }

    /// Return the next schema hash after `current`, or `None` if `current` is
    /// the latest or is not found in the path.
    pub fn next_version(
        &self,
        current: &SchemaIdentifierHash,
    ) -> Option<&SchemaIdentifierHash> {
        self.versions
            .iter()
            .position(|v| v == current)
            .and_then(|idx| self.versions.get(idx + 1))
    }

    /// Return the current (latest) schema hash, if any versions are registered.
    pub fn current_version(&self) -> Option<&SchemaIdentifierHash> {
        self.versions.last()
    }

    /// Check that a migration's source → target step is valid in this path.
    pub fn is_valid_step(
        &self,
        source: &SchemaIdentifierHash,
        target: &SchemaIdentifierHash,
    ) -> bool {
        match self.next_version(source) {
            Some(expected_next) => expected_next == target,
            None => false,
        }
    }
}
