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
