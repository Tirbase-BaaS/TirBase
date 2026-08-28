//! Schema pretty-printer — formats a `Schema` object into a conforming
//! schema definition document (Req 20.3).

#![allow(dead_code, unused_variables)]

use crate::schema::Schema;

/// Format a `Schema` object into a TirBase schema definition document (Req 20.3).
///
/// The output round-trips through the parser without information loss:
///   parse(print(schema)) == schema  (Property 18)
pub fn print(schema: &Schema) -> String {
    todo!("Task 6: implement schema pretty-printer")
}
