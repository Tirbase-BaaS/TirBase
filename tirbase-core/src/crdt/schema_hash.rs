//! SchemaIdentifierHash — deterministic hash computation for schema versions.
//!
//! This module re-exports the canonical hash implementation from `schema/hash.rs`
//! so that both the CRDT engine and the schema parser share **exactly one**
//! implementation (Req 17.1, 20.5). No logic is duplicated here.

#![allow(dead_code)]

// The authoritative implementation lives in schema/hash.rs.
// This re-export ensures the CRDT layer uses the same computation.
pub use crate::schema::hash::{compute_schema_identifier_hash, SchemaIdentifierHash};
