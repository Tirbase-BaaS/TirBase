//! Field-level schema diffing — additive vs breaking classification (Req 17.3, 17.4).
//!
//! A received Delta carries only a [`SchemaIdentifierHash`]; to decide whether
//! the sender's schema is *forward compatible* with the local one the device
//! must resolve both hashes to full [`Schema`] definitions (the deployment
//! registers these alongside the schema-version path) and compare them
//! field-by-field.
//!
//! Classification rules (mirroring `schema/hash.rs` semantics — only table
//! names, field names, and field types participate; constraints, nullability,
//! defaults, and compaction policy do not affect the hash and therefore do not
//! affect compatibility):
//!
//! - **Additive** — the incoming schema differs from the local schema only by
//!   adding tables and/or fields; nothing was removed, renamed, or retyped.
//!   Deltas written under such a schema SHALL merge (Req 17.3).
//! - **Breaking** — the incoming schema removes, renames (a rename is
//!   structurally a removal plus an addition), or retypes a field that exists
//!   in the local schema, or drops an entire table.  Deltas written under such
//!   a schema SHALL be quarantined (Req 17.4).
//! - **Identical** — no structural difference (this implies identical hashes,
//!   so it is normally filtered out before diffing).
//!
//! This is the *only* place additive-vs-breaking is decided.  The CRDT engine
//! (`crdt/mod.rs`) imports [`diff_schemas`] through the schema hash gate.

use crate::schema::Schema;
use std::collections::{HashMap, HashSet};

/// A table-qualified field reference, used to name exactly what changed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldRef {
    pub table: String,
    pub field: String,
}

/// A field whose type changed between two schema versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetypedField {
    pub table: String,
    pub field: String,
    /// Canonical type string in the base (local) schema, e.g. "TEXT".
    pub from: String,
    /// Canonical type string in the incoming schema, e.g. "INTEGER".
    pub to: String,
}

/// The structural difference between a base (local) schema and an incoming
/// (peer-written) schema.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SchemaDiff {
    /// Whole tables present in `incoming` but absent from `base`.
    pub added_tables: Vec<String>,
    /// Whole tables present in `base` but absent from `incoming`.
    pub removed_tables: Vec<String>,
    /// Fields present in `incoming` but absent from `base` (on common tables).
    pub added_fields: Vec<FieldRef>,
    /// Fields present in `base` but absent from `incoming` (on common tables).
    /// A rename surfaces here (old name removed) plus an `added_fields` entry
    /// (new name introduced), so renames classify as breaking.
    pub removed_fields: Vec<FieldRef>,
    /// Fields whose type differs between the two schemas.
    pub retyped_fields: Vec<RetypedField>,
}

impl SchemaDiff {
    /// True when the two schemas are structurally identical.
    pub fn is_identical(&self) -> bool {
        self.added_tables.is_empty()
            && self.removed_tables.is_empty()
            && self.added_fields.is_empty()
            && self.removed_fields.is_empty()
            && self.retyped_fields.is_empty()
    }

    /// True when the only differences are additions (new tables / new fields).
    ///
    /// This is Req 17.3's compatibility predicate: no existing table was
    /// dropped and no existing field was removed, renamed, or retyped.
    pub fn is_additive(&self) -> bool {
        !self.is_identical()
            && self.removed_tables.is_empty()
            && self.removed_fields.is_empty()
            && self.retyped_fields.is_empty()
    }

    /// True when the incoming schema is *not* forward compatible with `base`:
    /// at least one existing table or field was removed/renamed (surfaces as a
    /// removal) or a field's type changed.  Req 17.4 → Quarantine_Ledger.
    pub fn is_breaking(&self) -> bool {
        !self.removed_tables.is_empty()
            || !self.removed_fields.is_empty()
            || !self.retyped_fields.is_empty()
    }

    /// One-line human-readable summary for rejection/acceptance logs.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for t in &self.removed_tables {
            parts.push(format!("removed table {t}"));
        }
        for t in &self.added_tables {
            parts.push(format!("added table {t}"));
        }
        for f in &self.removed_fields {
            parts.push(format!("removed {}.{}", f.table, f.field));
        }
        for f in &self.added_fields {
            parts.push(format!("added {}.{}", f.table, f.field));
        }
        for r in &self.retyped_fields {
            parts.push(format!(
                "retyped {}.{} {} -> {}",
                r.table, r.field, r.from, r.to
            ));
        }
        parts.join(", ")
    }
}

/// Compute the structural difference between `base` (the local schema) and
/// `incoming` (the schema the sender wrote its Delta under).
///
/// Output vectors are sorted by (table, field) for determinism.
pub fn diff_schemas(base: &Schema, incoming: &Schema) -> SchemaDiff {
    let mut diff = SchemaDiff::default();

    let base_tables: HashMap<&str, &crate::schema::TableDef> =
        base.tables.iter().map(|t| (t.name.as_str(), t)).collect();
    let incoming_tables: HashMap<&str, &crate::schema::TableDef> =
        incoming.tables.iter().map(|t| (t.name.as_str(), t)).collect();

    let mut base_names: Vec<&str> = base_tables.keys().copied().collect();
    base_names.sort();
    let mut incoming_names: Vec<&str> = incoming_tables.keys().copied().collect();
    incoming_names.sort();

    let base_set: HashSet<&str> = base_names.iter().copied().collect();
    let incoming_set: HashSet<&str> = incoming_names.iter().copied().collect();

    // Whole-table differences.
    for name in &base_names {
        if !incoming_set.contains(name) {
            diff.removed_tables.push((*name).to_string());
        }
    }
    for name in &incoming_names {
        if !base_set.contains(name) {
            diff.added_tables.push((*name).to_string());
        }
    }

    // Field-level differences on tables present in both schemas.
    for name in &base_names {
        if !incoming_set.contains(name) {
            continue; // whole-table removal already reported
        }
        let base_fields = &base_tables[name].fields;
        let incoming_fields = &incoming_tables[name].fields;

        let base_field_map: HashMap<&str, &crate::schema::FieldDef> =
            base_fields.iter().map(|f| (f.name.as_str(), f)).collect();
        let incoming_field_map: HashMap<&str, &crate::schema::FieldDef> =
            incoming_fields.iter().map(|f| (f.name.as_str(), f)).collect();

        let mut base_field_names: Vec<&str> = base_field_map.keys().copied().collect();
        base_field_names.sort();
        let mut incoming_field_names: Vec<&str> = incoming_field_map.keys().copied().collect();
        incoming_field_names.sort();

        let base_field_set: HashSet<&str> = base_field_names.iter().copied().collect();
        let incoming_field_set: HashSet<&str> = incoming_field_names.iter().copied().collect();

        for fname in &base_field_names {
            if !incoming_field_set.contains(fname) {
                diff.removed_fields.push(FieldRef {
                    table: (*name).to_string(),
                    field: (*fname).to_string(),
                });
            }
        }
        for fname in &incoming_field_names {
            if !base_field_set.contains(fname) {
                diff.added_fields.push(FieldRef {
                    table: (*name).to_string(),
                    field: (*fname).to_string(),
                });
            }
        }

        // Same-name fields whose type changed.
        for fname in &base_field_names {
            if !incoming_field_set.contains(fname) {
                continue;
            }
            let base_type = base_field_map[fname].field_type.canonical_str();
            let incoming_type = incoming_field_map[fname].field_type.canonical_str();
            if base_type != incoming_type {
                diff.retyped_fields.push(RetypedField {
                    table: (*name).to_string(),
                    field: (*fname).to_string(),
                    from: base_type.to_string(),
                    to: incoming_type.to_string(),
                });
            }
        }
    }

    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{FieldDef, FieldType, TableDef};
    use crate::store::compaction::CompactionPolicy;

    fn field(name: &str, ft: FieldType) -> FieldDef {
        FieldDef {
            name: name.to_string(),
            field_type: ft,
            nullable: true,
            default: None,
        }
    }

    fn table(name: &str, fields: Vec<FieldDef>) -> TableDef {
        TableDef {
            name: name.to_string(),
            fields,
            compaction_policy: CompactionPolicy::None,
            constraints: vec![],
        }
    }

    fn schema(tables: Vec<TableDef>) -> Schema {
        Schema {
            tables,
            version: "1.0.0".to_string(),
        }
    }

    fn base_v1() -> Schema {
        schema(vec![
            table(
                "users",
                vec![field("id", FieldType::Text), field("name", FieldType::Text)],
            ),
            table(
                "posts",
                vec![field("id", FieldType::Text), field("body", FieldType::Text)],
            ),
        ])
    }

    #[test]
    fn identical_schemas_produce_no_diff() {
        let diff = diff_schemas(&base_v1(), &base_v1());
        assert!(diff.is_identical(), "{diff:?}");
        assert!(!diff.is_additive());
        assert!(!diff.is_breaking());
    }

    #[test]
    fn added_field_is_additive() {
        let mut v2 = base_v1();
        v2.tables[0].fields.push(field("email", FieldType::Text));
        let diff = diff_schemas(&base_v1(), &v2);
        assert!(diff.is_additive(), "must classify as additive: {diff:?}");
        assert!(!diff.is_breaking(), "additive change must not be breaking");
        assert_eq!(diff.added_fields.len(), 1);
        assert_eq!(diff.added_fields[0].table, "users");
        assert_eq!(diff.added_fields[0].field, "email");
        assert!(diff.removed_fields.is_empty());
        assert!(diff.retyped_fields.is_empty());
    }

    #[test]
    fn added_table_is_additive() {
        let mut v2 = base_v1();
        v2.tables
            .push(table("audit_log", vec![field("entry", FieldType::Blob)]));
        let diff = diff_schemas(&base_v1(), &v2);
        assert!(diff.is_additive(), "{diff:?}");
        assert_eq!(diff.added_tables, vec!["audit_log".to_string()]);
    }

    #[test]
    fn removed_field_is_breaking() {
        let mut v2 = base_v1();
        v2.tables[0].fields.retain(|f| f.name != "name");
        let diff = diff_schemas(&base_v1(), &v2);
        assert!(diff.is_breaking(), "{diff:?}");
        assert!(!diff.is_additive());
        assert_eq!(diff.removed_fields.len(), 1);
        assert_eq!(diff.removed_fields[0].table, "users");
        assert_eq!(diff.removed_fields[0].field, "name");
    }

    #[test]
    fn renamed_field_is_breaking() {
        // A rename is structurally removal-of-old + addition-of-new.
        let mut v2 = base_v1();
        for f in v2.tables[0].fields.iter_mut() {
            if f.name == "name" {
                f.name = "display_name".to_string();
            }
        }
        let diff = diff_schemas(&base_v1(), &v2);
        assert!(diff.is_breaking(), "rename must be breaking: {diff:?}");
        assert!(!diff.is_additive());
        assert_eq!(diff.removed_fields.len(), 1);
        assert_eq!(diff.removed_fields[0].field, "name");
        assert_eq!(diff.added_fields.len(), 1);
        assert_eq!(diff.added_fields[0].field, "display_name");
    }

    #[test]
    fn retyped_field_is_breaking() {
        let mut v2 = base_v1();
        v2.tables[1].fields[1].field_type = FieldType::Blob; // body TEXT -> BLOB
        let diff = diff_schemas(&base_v1(), &v2);
        assert!(diff.is_breaking(), "{diff:?}");
        assert_eq!(diff.retyped_fields.len(), 1);
        let r = &diff.retyped_fields[0];
        assert_eq!((r.table.as_str(), r.field.as_str()), ("posts", "body"));
        assert_eq!(r.from, "TEXT");
        assert_eq!(r.to, "BLOB");
    }

    #[test]
    fn removed_table_is_breaking() {
        let v2 = schema(vec![table(
            "users",
            vec![field("id", FieldType::Text), field("name", FieldType::Text)],
        )]);
        let diff = diff_schemas(&base_v1(), &v2);
        assert!(diff.is_breaking(), "{diff:?}");
        assert_eq!(diff.removed_tables, vec!["posts".to_string()]);
    }

    #[test]
    fn combined_additive_and_breaking_reports_both() {
        let mut v2 = base_v1();
        // Additive: new field + new table.
        v2.tables[0].fields.push(field("email", FieldType::Text));
        v2.tables
            .push(table("audit_log", vec![field("entry", FieldType::Blob)]));
        // Breaking: drop "posts.body".
        v2.tables[1].fields.retain(|f| f.name != "body");
        let diff = diff_schemas(&base_v1(), &v2);
        assert!(diff.is_breaking(), "{diff:?}");
        assert!(
            !diff.is_additive(),
            "any breaking change poisons additivity"
        );
        assert_eq!(diff.added_fields.len(), 1);
        assert_eq!(diff.added_tables.len(), 1);
        assert_eq!(diff.removed_fields.len(), 1);
    }

    #[test]
    fn additive_change_yields_different_hash_but_non_breaking_diff() {
        // The gate contract: an additive schema must hash differently from the
        // local schema (otherwise it would already be "known") yet classify as
        // non-breaking at the field level.
        let mut v2 = base_v1();
        v2.tables[0].fields.push(field("email", FieldType::Text));

        assert_ne!(
            base_v1().identifier_hash(),
            v2.identifier_hash(),
            "additive change must change the hash"
        );
        let diff = diff_schemas(&base_v1(), &v2);
        assert!(diff.is_additive());
    }

    #[test]
    fn field_declaration_order_does_not_affect_result() {
        let mut a = schema(vec![table(
            "t",
            vec![field("id", FieldType::Text), field("name", FieldType::Text)],
        )]);
        let b = schema(vec![table(
            "t",
            vec![field("name", FieldType::Text), field("age", FieldType::Integer)],
        )]);

        let d1 = diff_schemas(&a, &b);
        // Reverse the base field order — same logical diff.
        a.tables[0].fields.swap(0, 1);
        let d2 = diff_schemas(&a, &b);
        assert_eq!(d1, d2);
        assert!(d1.is_breaking() && !d1.is_additive()); // removed name, added age
    }

    #[test]
    fn constraints_and_compaction_do_not_affect_classification() {
        // Schema versions differing only in non-hash-carrying attributes
        // (constraints / compaction) are structurally identical.
        let mut v2 = base_v1();
        v2.tables[0].compaction_policy = CompactionPolicy::Aggressive { threshold: 10 };
        v2.tables[1]
            .constraints
            .push(crate::schema::Constraint::NotNull("id".to_string()));
        let diff = diff_schemas(&base_v1(), &v2);
        assert!(diff.is_identical(), "{diff:?}");
    }

    #[test]
    fn summary_lists_all_changes() {
        let mut v2 = base_v1();
        v2.tables[0].fields.retain(|f| f.name != "name");
        v2.tables[0].fields.push(field("email", FieldType::Text));
        let s = diff_schemas(&base_v1(), &v2).summary();
        assert!(s.contains("removed users.name"), "{s}");
        assert!(s.contains("added users.email"), "{s}");
    }
}
