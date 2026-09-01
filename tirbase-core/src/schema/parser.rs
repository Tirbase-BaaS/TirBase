//! Schema definition parser — parses TirBase schema definition documents into
//! `Schema` objects with structured error reporting (Req 20.1–20.2).
//!
//! Implementation uses the `pest` parsing expression grammar library.
//! The grammar is defined in `schema/tirbase.pest`.

#![allow(dead_code)]

use pest::Parser;
use pest_derive::Parser;

use crate::errors::TirBaseError;
use crate::schema::{Constraint, DefaultValue, FieldDef, FieldType, Schema, TableDef};
use crate::store::compaction::CompactionPolicy;

/// The pest-derived parser for the TirBase schema definition language.
#[derive(Parser)]
#[grammar = "src/schema/tirbase.pest"]
struct TirBaseSchemaParser;

/// Parse a TirBase schema definition document into a `Schema` object (Req 20.1).
///
/// On success: returns the parsed `Schema`.
/// On failure: returns `Err(Vec<TirBaseError::SchemaParseError>)` with
///             line number, column number, and description for each error (Req 20.2).
pub fn parse(source: &str) -> Result<Schema, Vec<TirBaseError>> {
    let pairs = TirBaseSchemaParser::parse(Rule::schema, source).map_err(|e| {
        let (line, col) = match e.line_col {
            pest::error::LineColLocation::Pos((l, c)) => (l as u32, c as u32),
            pest::error::LineColLocation::Span((l, c), _) => (l as u32, c as u32),
        };
        vec![TirBaseError::SchemaParseError {
            line,
            col,
            description: e.variant.message().to_string(),
        }]
    })?;

    let mut errors: Vec<TirBaseError> = Vec::new();
    let mut schema_version = String::new();
    let mut tables: Vec<TableDef> = Vec::new();

    for pair in pairs {
        match pair.as_rule() {
            Rule::schema => {
                for inner in pair.into_inner() {
                    match inner.as_rule() {
                        Rule::version_directive => {
                            schema_version = parse_version_directive(inner);
                        }
                        Rule::table_def => match parse_table_def(inner) {
                            Ok(td) => tables.push(td),
                            Err(mut errs) => errors.append(&mut errs),
                        },
                        Rule::EOI => {}
                        _ => {}
                    }
                }
            }
            Rule::EOI => {}
            _ => {}
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(Schema {
        tables,
        version: schema_version,
    })
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn parse_version_directive(pair: pest::iterators::Pair<Rule>) -> String {
    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::string_literal {
            let s = inner.as_str();
            // Strip surrounding quotes
            return s[1..s.len() - 1].to_string();
        }
    }
    String::new()
}

fn parse_table_def(
    pair: pest::iterators::Pair<Rule>,
) -> Result<TableDef, Vec<TirBaseError>> {
    let mut name = String::new();
    let mut compaction_policy = CompactionPolicy::None;
    let mut fields: Vec<FieldDef> = Vec::new();
    let mut constraints: Vec<Constraint> = Vec::new();
    let mut errors: Vec<TirBaseError> = Vec::new();

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => {
                name = inner.as_str().to_string();
            }
            Rule::compaction_directive => {
                compaction_policy = parse_compaction_directive(inner);
            }
            Rule::table_item => {
                for item in inner.into_inner() {
                    match item.as_rule() {
                        Rule::field_def => match parse_field_def(item) {
                            Ok(fd) => fields.push(fd),
                            Err(mut errs) => errors.append(&mut errs),
                        },
                        Rule::constraint => match parse_constraint(item) {
                            Ok(c) => constraints.push(c),
                            Err(mut errs) => errors.append(&mut errs),
                        },
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(TableDef {
        name,
        fields,
        compaction_policy,
        constraints,
    })
}

fn parse_compaction_directive(pair: pest::iterators::Pair<Rule>) -> CompactionPolicy {
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::compaction_aggressive => {
                for lit in inner.into_inner() {
                    if lit.as_rule() == Rule::integer_literal {
                        if let Ok(threshold) = lit.as_str().parse::<u64>() {
                            return CompactionPolicy::Aggressive { threshold };
                        }
                    }
                }
            }
            Rule::compaction_none => return CompactionPolicy::None,
            _ => {}
        }
    }
    CompactionPolicy::None
}

fn parse_field_def(
    pair: pest::iterators::Pair<Rule>,
) -> Result<FieldDef, Vec<TirBaseError>> {
    let (line, col) = pair.line_col();
    let mut field_name = String::new();
    let mut field_type_opt: Option<FieldType> = None;
    let mut nullable = true;
    let mut default: Option<DefaultValue> = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::ident => {
                field_name = inner.as_str().to_string();
            }
            Rule::field_type => {
                field_type_opt = Some(parse_field_type(inner));
            }
            Rule::not_null_modifier => {
                nullable = false;
            }
            Rule::default_modifier => {
                default = Some(parse_default_modifier(inner));
            }
            _ => {}
        }
    }

    match field_type_opt {
        Some(field_type) => Ok(FieldDef {
            name: field_name,
            field_type,
            nullable,
            default,
        }),
        None => Err(vec![TirBaseError::SchemaParseError {
            line: line as u32,
            col: col as u32,
            description: format!("field '{}' has no type", field_name),
        }]),
    }
}

fn parse_field_type(pair: pest::iterators::Pair<Rule>) -> FieldType {
    match pair.as_str() {
        "TEXT"    => FieldType::Text,
        "INTEGER" => FieldType::Integer,
        "REAL"    => FieldType::Real,
        "BLOB"    => FieldType::Blob,
        "BOOLEAN" => FieldType::Boolean,
        _         => FieldType::Text, // unreachable given grammar
    }
}

fn parse_default_modifier(pair: pest::iterators::Pair<Rule>) -> DefaultValue {
    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::default_value {
            return parse_default_value(inner);
        }
    }
    DefaultValue::Null
}

fn parse_default_value(pair: pest::iterators::Pair<Rule>) -> DefaultValue {
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::real_literal => {
                let v: f64 = inner.as_str().parse().unwrap_or(0.0);
                return DefaultValue::Real(v);
            }
            Rule::integer_literal => {
                let v: i64 = inner.as_str().parse().unwrap_or(0);
                return DefaultValue::Integer(v);
            }
            Rule::string_literal => {
                let s = inner.as_str();
                return DefaultValue::Text(s[1..s.len() - 1].to_string());
            }
            Rule::bool_true => return DefaultValue::Boolean(true),
            Rule::bool_false => return DefaultValue::Boolean(false),
            Rule::null_lit => return DefaultValue::Null,
            _ => {}
        }
    }
    DefaultValue::Null
}

fn parse_constraint(
    pair: pest::iterators::Pair<Rule>,
) -> Result<Constraint, Vec<TirBaseError>> {
    // Capture location before consuming `pair` via into_inner().
    let (line, col) = pair.line_col();
    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::primary_key_constraint => {
                let cols = parse_column_list(inner);
                return Ok(Constraint::PrimaryKey(cols));
            }
            Rule::unique_constraint => {
                let cols = parse_column_list(inner);
                return Ok(Constraint::Unique(cols));
            }
            _ => {}
        }
    }
    Err(vec![TirBaseError::SchemaParseError {
        line: line as u32,
        col: col as u32,
        description: "unrecognised constraint".to_string(),
    }])
}

fn parse_column_list(pair: pest::iterators::Pair<Rule>) -> Vec<String> {
    let mut cols = Vec::new();
    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::column_list {
            for col in inner.into_inner() {
                if col.as_rule() == Rule::ident {
                    cols.push(col.as_str().to_string());
                }
            }
        }
    }
    cols
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::printer::print;

    // ─── Helpers ──────────────────────────────────────────────────────────────

    fn full_schema_src() -> &'static str {
        r#"schema {
  version = "1.0.0"

  table users {
    compaction = aggressive(500)

    id     TEXT    NOT NULL
    name   TEXT    NOT NULL
    age    INTEGER
    active BOOLEAN DEFAULT true
    score  REAL    DEFAULT 0.0

    PRIMARY KEY (id)
    UNIQUE (name)
  }

  table audit_log {
    compaction = none

    entry BLOB NOT NULL
  }
}"#
    }

    // ─── Happy-path parsing ───────────────────────────────────────────────────

    #[test]
    fn parse_full_schema_success() {
        let schema = parse(full_schema_src()).expect("should parse");
        assert_eq!(schema.version, "1.0.0");
        assert_eq!(schema.tables.len(), 2);

        let users = &schema.tables[0];
        assert_eq!(users.name, "users");
        assert_eq!(users.fields.len(), 5);

        let id_field = &users.fields[0];
        assert_eq!(id_field.name, "id");
        assert_eq!(id_field.field_type, FieldType::Text);
        assert!(!id_field.nullable);
        assert_eq!(id_field.default, None);

        let score_field = &users.fields[4];
        assert_eq!(score_field.field_type, FieldType::Real);
        assert_eq!(score_field.default, Some(DefaultValue::Real(0.0)));

        let active_field = &users.fields[3];
        assert_eq!(active_field.field_type, FieldType::Boolean);
        assert_eq!(active_field.default, Some(DefaultValue::Boolean(true)));

        assert_eq!(users.constraints.len(), 2);
        assert_eq!(
            users.constraints[0],
            Constraint::PrimaryKey(vec!["id".to_string()])
        );
        assert_eq!(
            users.constraints[1],
            Constraint::Unique(vec!["name".to_string()])
        );

        let audit = &schema.tables[1];
        assert_eq!(audit.name, "audit_log");
        assert_eq!(audit.compaction_policy, CompactionPolicy::None);
    }

    #[test]
    fn parse_compaction_aggressive() {
        let src = r#"schema {
  version = "1.0.0"
  table t {
    compaction = aggressive(1000)
    id TEXT NOT NULL
  }
}"#;
        let schema = parse(src).expect("should parse");
        assert_eq!(
            schema.tables[0].compaction_policy,
            CompactionPolicy::Aggressive { threshold: 1000 }
        );
    }

    #[test]
    fn parse_default_integer() {
        let src = r#"schema {
  version = "2.0.0"
  table t {
    compaction = none
    count INTEGER DEFAULT 42
  }
}"#;
        let schema = parse(src).expect("should parse");
        assert_eq!(
            schema.tables[0].fields[0].default,
            Some(DefaultValue::Integer(42))
        );
    }

    #[test]
    fn parse_default_string() {
        let src = r#"schema {
  version = "2.0.0"
  table t {
    compaction = none
    label TEXT DEFAULT "hello world"
  }
}"#;
        let schema = parse(src).expect("should parse");
        assert_eq!(
            schema.tables[0].fields[0].default,
            Some(DefaultValue::Text("hello world".to_string()))
        );
    }

    #[test]
    fn parse_default_null() {
        let src = r#"schema {
  version = "2.0.0"
  table t {
    compaction = none
    tag TEXT DEFAULT null
  }
}"#;
        let schema = parse(src).expect("should parse");
        assert_eq!(schema.tables[0].fields[0].default, Some(DefaultValue::Null));
    }

    #[test]
    fn parse_default_false() {
        let src = r#"schema {
  version = "2.0.0"
  table t {
    compaction = none
    enabled BOOLEAN DEFAULT false
  }
}"#;
        let schema = parse(src).expect("should parse");
        assert_eq!(
            schema.tables[0].fields[0].default,
            Some(DefaultValue::Boolean(false))
        );
    }

    // ─── Parse error coverage ─────────────────────────────────────────────────

    #[test]
    fn parse_error_has_line_and_col() {
        // Missing closing brace — syntax error
        let src = "schema { version = \"1.0.0\" table bad { compaction = none";
        let errs = parse(src).expect_err("should fail");
        assert!(!errs.is_empty());
        if let TirBaseError::SchemaParseError { line, col, description } = &errs[0] {
            assert!(*line >= 1, "line={line}");
            assert!(*col >= 1, "col={col}");
            assert!(!description.is_empty(), "description empty");
        } else {
            panic!("expected SchemaParseError");
        }
    }

    #[test]
    fn parse_error_missing_version() {
        let src = r#"schema { table t { compaction = none id TEXT } }"#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn parse_error_invalid_field_type() {
        let src = r#"schema { version = "1.0.0" table t { compaction = none id BADTYPE } }"#;
        assert!(parse(src).is_err());
    }

    // ─── Parse-print-parse round-trip ─────────────────────────────────────────

    #[test]
    fn parse_print_parse_round_trip() {
        let schema1 = parse(full_schema_src()).expect("first parse");
        let printed = print(&schema1);
        let schema2 = parse(&printed).expect("second parse");
        assert_eq!(schema1, schema2, "round-trip structural equality");
    }

    #[test]
    fn parse_print_parse_minimal_schema() {
        let src = r#"schema {
  version = "0.1.0"
  table events {
    compaction = none
    id TEXT NOT NULL
  }
}"#;
        let schema1 = parse(src).expect("first parse");
        let printed = print(&schema1);
        let schema2 = parse(&printed).expect("second parse");
        assert_eq!(schema1, schema2);
    }

    // ─── Hash determinism ─────────────────────────────────────────────────────

    #[test]
    fn hash_determinism_same_structure_different_order() {
        // Same schema, tables declared in different order.
        let src_a = r#"schema {
  version = "1.0.0"
  table users {
    compaction = none
    id TEXT NOT NULL
    name TEXT
  }
  table posts {
    compaction = none
    body TEXT
    id TEXT NOT NULL
  }
}"#;
        let src_b = r#"schema {
  version = "1.0.0"
  table posts {
    compaction = none
    id TEXT NOT NULL
    body TEXT
  }
  table users {
    compaction = none
    name TEXT
    id TEXT NOT NULL
  }
}"#;
        let s_a = parse(src_a).expect("parse a");
        let s_b = parse(src_b).expect("parse b");
        assert_eq!(
            s_a.identifier_hash(),
            s_b.identifier_hash(),
            "hash must be order-independent"
        );
    }

    #[test]
    fn hash_inequality_different_field_types() {
        let src_a = r#"schema {
  version = "1.0.0"
  table t {
    compaction = none
    id TEXT NOT NULL
  }
}"#;
        let src_b = r#"schema {
  version = "1.0.0"
  table t {
    compaction = none
    id INTEGER NOT NULL
  }
}"#;
        let s_a = parse(src_a).expect("parse a");
        let s_b = parse(src_b).expect("parse b");
        assert_ne!(
            s_a.identifier_hash(),
            s_b.identifier_hash(),
            "different types must produce different hashes"
        );
    }

    #[test]
    fn hash_inequality_different_table_names() {
        let src_a = r#"schema {
  version = "1.0.0"
  table foo {
    compaction = none
    id TEXT
  }
}"#;
        let src_b = r#"schema {
  version = "1.0.0"
  table bar {
    compaction = none
    id TEXT
  }
}"#;
        let s_a = parse(src_a).expect("parse a");
        let s_b = parse(src_b).expect("parse b");
        assert_ne!(s_a.identifier_hash(), s_b.identifier_hash());
    }

    // ─── Version path lookup ──────────────────────────────────────────────────

    #[test]
    fn version_path_next_step_lookup() {
        use crate::migration::version_path::SchemaVersionPath;

        let src_v1 = r#"schema {
  version = "1.0.0"
  table t { compaction = none id TEXT NOT NULL }
}"#;
        let src_v2 = r#"schema {
  version = "2.0.0"
  table t { compaction = none id TEXT NOT NULL name TEXT }
}"#;
        let src_v3 = r#"schema {
  version = "3.0.0"
  table t { compaction = none id TEXT NOT NULL name TEXT age INTEGER }
}"#;

        let h1 = parse(src_v1).unwrap().identifier_hash();
        let h2 = parse(src_v2).unwrap().identifier_hash();
        let h3 = parse(src_v3).unwrap().identifier_hash();

        let path = SchemaVersionPath::new(vec![h1, h2, h3]);

        assert_eq!(path.next_version(&h1), Some(&h2), "v1 → v2");
        assert_eq!(path.next_version(&h2), Some(&h3), "v2 → v3");
        assert_eq!(path.next_version(&h3), None, "v3 is latest");
        assert_eq!(path.current_version(), Some(&h3));
        assert!(path.is_valid_step(&h1, &h2));
        assert!(!path.is_valid_step(&h1, &h3), "non-adjacent step is invalid");
    }
}
