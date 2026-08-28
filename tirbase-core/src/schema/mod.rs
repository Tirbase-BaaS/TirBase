//! Schema object and supporting types (Req 17, 20).

#![allow(dead_code)]

pub mod hash;
pub mod parser;
pub mod printer;

use crate::store::compaction::CompactionPolicy;
use serde::{Deserialize, Serialize};

// ─── Schema ──────────────────────────────────────────────────────────────────

/// A parsed TirBase schema (design §Data Models / Schema Object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub tables: Vec<TableDef>,
    /// Semver string, e.g. "1.0.0".
    pub version: String,
}

/// A table definition within a schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
    pub compaction_policy: CompactionPolicy,
    pub constraints: Vec<Constraint>,
}

/// A field definition within a table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub field_type: FieldType,
    pub nullable: bool,
    pub default: Option<DefaultValue>,
}

/// Supported field types (design §Schema Object / FieldType).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldType {
    Text,
    Integer,
    Real,
    Blob,
    Boolean,
}

impl FieldType {
    /// Return the canonical string representation used in hash computation.
    pub fn canonical_str(&self) -> &'static str {
        match self {
            FieldType::Text    => "TEXT",
            FieldType::Integer => "INTEGER",
            FieldType::Real    => "REAL",
            FieldType::Blob    => "BLOB",
            FieldType::Boolean => "BOOLEAN",
        }
    }
}

/// A default value for a nullable or optional field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DefaultValue {
    Text(String),
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Null,
}

// Eq requires a manual impl because f64 doesn't implement Eq.
impl Eq for DefaultValue {}

/// A table-level constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Constraint {
    PrimaryKey(Vec<String>),
    Unique(Vec<String>),
    NotNull(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::compaction::CompactionPolicy;

    fn make_schema() -> Schema {
        Schema {
            tables: vec![
                TableDef {
                    name: "reports".to_string(),
                    fields: vec![
                        FieldDef {
                            name: "id".to_string(),
                            field_type: FieldType::Text,
                            nullable: false,
                            default: None,
                        },
                        FieldDef {
                            name: "score".to_string(),
                            field_type: FieldType::Real,
                            nullable: true,
                            default: Some(DefaultValue::Real(0.0)),
                        },
                        FieldDef {
                            name: "active".to_string(),
                            field_type: FieldType::Boolean,
                            nullable: false,
                            default: Some(DefaultValue::Boolean(true)),
                        },
                    ],
                    compaction_policy: CompactionPolicy::Aggressive { threshold: 500 },
                    constraints: vec![
                        Constraint::PrimaryKey(vec!["id".to_string()]),
                        Constraint::NotNull("id".to_string()),
                    ],
                },
                TableDef {
                    name: "audit_log".to_string(),
                    fields: vec![FieldDef {
                        name: "entry".to_string(),
                        field_type: FieldType::Blob,
                        nullable: false,
                        default: None,
                    }],
                    compaction_policy: CompactionPolicy::None,
                    constraints: vec![],
                },
            ],
            version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn schema_serde_round_trip() {
        let schema = make_schema();
        let json = serde_json::to_string(&schema).expect("serialise Schema");
        let decoded: Schema = serde_json::from_str(&json).expect("deserialise Schema");
        assert_eq!(schema, decoded);
    }

    #[test]
    fn table_def_serde_round_trip() {
        let td = make_schema().tables.into_iter().next().unwrap();
        let json = serde_json::to_string(&td).expect("serialise TableDef");
        let decoded: TableDef = serde_json::from_str(&json).expect("deserialise TableDef");
        assert_eq!(td, decoded);
    }

    #[test]
    fn field_type_canonical_str_coverage() {
        assert_eq!(FieldType::Text.canonical_str(), "TEXT");
        assert_eq!(FieldType::Integer.canonical_str(), "INTEGER");
        assert_eq!(FieldType::Real.canonical_str(), "REAL");
        assert_eq!(FieldType::Blob.canonical_str(), "BLOB");
        assert_eq!(FieldType::Boolean.canonical_str(), "BOOLEAN");
    }

    #[test]
    fn field_type_all_variants_serde_round_trip() {
        for ft in [
            FieldType::Text,
            FieldType::Integer,
            FieldType::Real,
            FieldType::Blob,
            FieldType::Boolean,
        ] {
            let json = serde_json::to_string(&ft).unwrap();
            let decoded: FieldType = serde_json::from_str(&json).unwrap();
            assert_eq!(ft, decoded);
        }
    }

    #[test]
    fn default_value_all_variants_serde_round_trip() {
        let values = vec![
            DefaultValue::Text("hello".to_string()),
            DefaultValue::Integer(-42),
            DefaultValue::Real(3.14),
            DefaultValue::Boolean(false),
            DefaultValue::Null,
        ];
        for dv in &values {
            let json = serde_json::to_string(dv).unwrap();
            let decoded: DefaultValue = serde_json::from_str(&json).unwrap();
            assert_eq!(*dv, decoded);
        }
    }

    #[test]
    fn constraint_all_variants_serde_round_trip() {
        let constraints = vec![
            Constraint::PrimaryKey(vec!["id".to_string()]),
            Constraint::Unique(vec!["email".to_string(), "tenant_id".to_string()]),
            Constraint::NotNull("name".to_string()),
        ];
        for c in &constraints {
            let json = serde_json::to_string(c).unwrap();
            let decoded: Constraint = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, decoded);
        }
    }
}
