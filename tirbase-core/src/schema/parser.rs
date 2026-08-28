//! Schema definition parser — parses TirBase schema definition documents into
//! `Schema` objects with structured error reporting (Req 20.1–20.2).
//!
//! Implementation uses the `pest` parsing expression grammar library.
//! The grammar is defined in `schema/tirbase.pest` (Task 6).

#![allow(dead_code, unused_variables, unused_imports)]

use crate::errors::TirBaseError;
use crate::schema::Schema;

/// Parse a TirBase schema definition document into a `Schema` object (Req 20.1).
///
/// On success: returns the parsed `Schema`.
/// On failure: returns `Err(TirBaseError::SchemaParseError)` for each error,
///             with line number, column number, and description (Req 20.2).
pub fn parse(source: &str) -> Result<Schema, Vec<TirBaseError>> {
    todo!("Task 6: implement pest-based parser")
}
