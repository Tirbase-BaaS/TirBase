//! Canonical SchemaIdentifierHash computation (Req 17.1, 20.5).
//!
//! `SchemaIdentifierHash = SHA-256(sorted(table_name || sorted(field_name || field_type)
//!                                        for each table))`
//!
//! The hash is deterministic regardless of the order in which tables or fields
//! are declared. Two schemas with identical structure produce identical hashes
//! (Property 15).
//!
//! This is the **single authoritative implementation**. The CRDT engine imports
//! from here via `crdt/schema_hash.rs` (a re-export). No duplicate computation
//! exists (Req 20.5).

#![allow(dead_code)]

use sha2::{Digest, Sha256};

/// A 32-byte deterministic hash of a schema's structure.
pub type SchemaIdentifierHash = [u8; 32];

/// Compute the SchemaIdentifierHash for a schema defined by its tables.
///
/// `tables` is a slice of `(table_name, fields)` where `fields` is a slice of
/// `(field_name, field_type_str)`. Field type strings must be canonical
/// (e.g., "TEXT", "INTEGER", "REAL", "BLOB", "BOOLEAN").
///
/// The computation is order-independent: tables and fields are sorted before
/// hashing to guarantee identical output regardless of declaration order.
pub fn compute_schema_identifier_hash(
    tables: &[(&str, &[(&str, &str)])],
) -> SchemaIdentifierHash {
    let mut hasher = Sha256::new();

    // Sort tables by name for determinism.
    let mut sorted_tables: Vec<(&str, &[(&str, &str)])> = tables.to_vec();
    sorted_tables.sort_by_key(|(name, _)| *name);

    for (table_name, fields) in &sorted_tables {
        hasher.update(table_name.as_bytes());
        hasher.update(b"|");

        // Sort fields by name for determinism.
        let mut sorted_fields: Vec<(&str, &str)> = fields.to_vec();
        sorted_fields.sort_by_key(|(name, _)| *name);

        for (field_name, field_type) in &sorted_fields {
            hasher.update(field_name.as_bytes());
            hasher.update(b":");
            hasher.update(field_type.as_bytes());
            hasher.update(b";");
        }

        hasher.update(b"||");
    }

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_for_same_schema() {
        let tables: &[(&str, &[(&str, &str)])] = &[
            ("users", &[("id", "TEXT"), ("name", "TEXT"), ("age", "INTEGER")]),
            ("posts", &[("id", "TEXT"), ("body", "TEXT")]),
        ];
        let h1 = compute_schema_identifier_hash(tables);
        let h2 = compute_schema_identifier_hash(tables);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_is_order_independent_for_tables() {
        let tables_a: &[(&str, &[(&str, &str)])] = &[
            ("users", &[("id", "TEXT"), ("name", "TEXT")]),
            ("posts", &[("id", "TEXT"), ("body", "TEXT")]),
        ];
        let tables_b: &[(&str, &[(&str, &str)])] = &[
            ("posts", &[("id", "TEXT"), ("body", "TEXT")]),
            ("users", &[("id", "TEXT"), ("name", "TEXT")]),
        ];
        assert_eq!(
            compute_schema_identifier_hash(tables_a),
            compute_schema_identifier_hash(tables_b)
        );
    }

    #[test]
    fn hash_is_order_independent_for_fields() {
        let tables_a: &[(&str, &[(&str, &str)])] = &[
            ("users", &[("id", "TEXT"), ("name", "TEXT")]),
        ];
        let tables_b: &[(&str, &[(&str, &str)])] = &[
            ("users", &[("name", "TEXT"), ("id", "TEXT")]),
        ];
        assert_eq!(
            compute_schema_identifier_hash(tables_a),
            compute_schema_identifier_hash(tables_b)
        );
    }

    #[test]
    fn hash_differs_for_different_schemas() {
        let tables_a: &[(&str, &[(&str, &str)])] = &[
            ("users", &[("id", "TEXT"), ("name", "TEXT")]),
        ];
        let tables_b: &[(&str, &[(&str, &str)])] = &[
            ("users", &[("id", "INTEGER"), ("name", "TEXT")]),
        ];
        assert_ne!(
            compute_schema_identifier_hash(tables_a),
            compute_schema_identifier_hash(tables_b)
        );
    }
}
