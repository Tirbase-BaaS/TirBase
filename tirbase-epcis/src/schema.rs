// SPDX-License-Identifier: Apache-2.0

//! Validation against the vendored official EPCIS 2.0 JSON Schema.
//!
//! `schema/epcis-json-schema.json` is the published GS1 artifact
//! (`https://ref.gs1.org/standards/epcis/2.0.0/epcis-json-schema.json`), vendored
//! verbatim with its notice in `schema/NOTICE`. `Schema::epcis_20()` parses it
//! and [`Schema::validate`] checks a document against it.
//!
//! The checker implements the JSON Schema draft-07 keywords this schema actually
//! uses: `$ref` (local `#/definitions/...`), `type`, `enum`, `const`,
//! `required`, `properties`, `propertyNames`, `additionalProperties`, `items`,
//! `minItems`, `maxItems`, `uniqueItems`, `pattern`, `format` (`uri`,
//! `date-time`), `anyOf`, `allOf`, `oneOf`, `not`, and `if`/`then`. A keyword the
//! schema does not use is ignored rather than guessed at.

use std::collections::BTreeSet;

use serde_json::Value;

/// The vendored official schema, byte for byte.
pub const EPCIS_JSON_SCHEMA: &str = include_str!("../schema/epcis-json-schema.json");

/// The `$id` the vendored schema declares.
pub const EPCIS_JSON_SCHEMA_ID: &str =
    "https://ref.gs1.org/standards/epcis/2.0.0/epcis-json-schema.json";

/// One failed assertion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    /// JSON path of the offending value.
    pub path: String,
    /// What the schema expected.
    pub message: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// A parsed JSON Schema.
#[derive(Debug, Clone)]
pub struct Schema {
    root: Value,
}

impl Schema {
    /// The vendored EPCIS 2.0 schema.
    pub fn epcis_20() -> Result<Self, String> {
        let root: Value = serde_json::from_str(EPCIS_JSON_SCHEMA)
            .map_err(|error| format!("vendored EPCIS schema is not valid JSON: {error}"))?;
        Ok(Self { root })
    }

    /// The schema document.
    pub fn root(&self) -> &Value {
        &self.root
    }

    /// Validate `document`, returning every violation in a stable order.
    pub fn validate(&self, document: &Value) -> Vec<Violation> {
        let mut violations = Vec::new();
        self.check(document, &self.root, "$", &mut violations);
        violations.sort();
        violations.dedup();
        violations
    }

    fn check(&self, value: &Value, schema: &Value, path: &str, out: &mut Vec<Violation>) {
        let Some(object) = schema.as_object() else {
            return;
        };

        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            match self.resolve(reference) {
                Some(resolved) => self.check(value, resolved, path, out),
                None => out.push(Violation {
                    path: path.to_string(),
                    message: format!("unresolvable $ref {reference}"),
                }),
            }
        }

        if let Some(expected) = object.get("type") {
            if !matches_type(value, expected) {
                out.push(Violation {
                    path: path.to_string(),
                    message: format!(
                        "expected type {}, got {}",
                        render_expected(expected),
                        kind_name(value)
                    ),
                });
                return;
            }
        }

        if let Some(values) = object.get("enum").and_then(Value::as_array) {
            if !values.iter().any(|candidate| candidate == value) {
                out.push(Violation {
                    path: path.to_string(),
                    message: format!("value {value} is not one of the allowed values"),
                });
            }
        }
        if let Some(expected) = object.get("const") {
            if expected != value {
                out.push(Violation {
                    path: path.to_string(),
                    message: format!("value must be {expected}"),
                });
            }
        }

        if let (Some(required), Some(entries)) = (object.get("required"), value.as_object()) {
            for key in required.as_array().into_iter().flatten() {
                if let Some(key) = key.as_str() {
                    if !entries.contains_key(key) {
                        out.push(Violation {
                            path: format!("{path}.{key}"),
                            message: "required property is missing".to_string(),
                        });
                    }
                }
            }
        }

        if let Some(entries) = value.as_object() {
            if let Some(names) = object.get("propertyNames") {
                for key in entries.keys() {
                    self.check(
                        &Value::String(key.clone()),
                        names,
                        &format!("{path}.{key}"),
                        out,
                    );
                }
            }
            let declared = object.get("properties").and_then(Value::as_object);
            if let Some(declared) = declared {
                for (key, subschema) in declared {
                    if let Some(child) = entries.get(key) {
                        self.check(child, subschema, &format!("{path}.{key}"), out);
                    }
                }
            }
            match object.get("additionalProperties") {
                Some(Value::Bool(false)) => {
                    for key in entries.keys() {
                        let known = declared.is_some_and(|declared| declared.contains_key(key));
                        if !known {
                            out.push(Violation {
                                path: format!("{path}.{key}"),
                                message: "property is not allowed by the schema".to_string(),
                            });
                        }
                    }
                }
                Some(Value::Object(_)) => {
                    let subschema = object.get("additionalProperties").expect("object");
                    for (key, child) in entries {
                        let known = declared.is_some_and(|declared| declared.contains_key(key));
                        if !known {
                            self.check(child, subschema, &format!("{path}.{key}"), out);
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(items) = value.as_array() {
            if let Some(subschema) = object.get("items").filter(|items| items.is_object()) {
                for (index, child) in items.iter().enumerate() {
                    self.check(child, subschema, &format!("{path}[{index}]"), out);
                }
            }
            if let Some(minimum) = object.get("minItems").and_then(Value::as_u64) {
                if (items.len() as u64) < minimum {
                    out.push(Violation {
                        path: path.to_string(),
                        message: format!("needs at least {minimum} items"),
                    });
                }
            }
            if let Some(maximum) = object.get("maxItems").and_then(Value::as_u64) {
                if (items.len() as u64) > maximum {
                    out.push(Violation {
                        path: path.to_string(),
                        message: format!("allows at most {maximum} items"),
                    });
                }
            }
            if object.get("uniqueItems") == Some(&Value::Bool(true)) {
                let mut seen = BTreeSet::new();
                for child in items {
                    let rendered = serde_json::to_string(child).unwrap_or_default();
                    if !seen.insert(rendered) {
                        out.push(Violation {
                            path: path.to_string(),
                            message: "items must be unique".to_string(),
                        });
                    }
                }
            }
        }

        if let (Some(pattern), Some(text)) = (
            object.get("pattern").and_then(Value::as_str),
            value.as_str(),
        ) {
            match regex::Regex::new(pattern) {
                Ok(regex) => {
                    if !regex.is_match(text) {
                        out.push(Violation {
                            path: path.to_string(),
                            message: format!("does not match {pattern}"),
                        });
                    }
                }
                Err(error) => out.push(Violation {
                    path: path.to_string(),
                    message: format!("schema pattern {pattern} is not supported: {error}"),
                }),
            }
        }

        if let (Some(format), Some(text)) =
            (object.get("format").and_then(Value::as_str), value.as_str())
        {
            let ok = match format {
                "uri" => is_uri(text),
                "date-time" => is_date_time(text),
                _ => true,
            };
            if !ok {
                out.push(Violation {
                    path: path.to_string(),
                    message: format!("is not a valid {format}"),
                });
            }
        }

        if let Some(branches) = object.get("allOf").and_then(Value::as_array) {
            for branch in branches {
                self.check(value, branch, path, out);
            }
        }
        if let Some(branches) = object.get("anyOf").and_then(Value::as_array) {
            let failures: Vec<Vec<Violation>> = branches
                .iter()
                .map(|branch| {
                    let mut scratch = Vec::new();
                    self.check(value, branch, path, &mut scratch);
                    scratch
                })
                .collect();
            if failures.iter().all(|scratch| !scratch.is_empty()) {
                out.push(Violation {
                    path: path.to_string(),
                    message: "value does not match any allowed form".to_string(),
                });
            }
        }
        if let Some(branches) = object.get("oneOf").and_then(Value::as_array) {
            let matches = branches
                .iter()
                .filter(|branch| {
                    let mut scratch = Vec::new();
                    self.check(value, branch, path, &mut scratch);
                    scratch.is_empty()
                })
                .count();
            if matches != 1 {
                out.push(Violation {
                    path: path.to_string(),
                    message: format!("value must match exactly one form, matched {matches}"),
                });
            }
        }
        if let Some(branch) = object.get("not") {
            let mut scratch = Vec::new();
            self.check(value, branch, path, &mut scratch);
            if scratch.is_empty() {
                out.push(Violation {
                    path: path.to_string(),
                    message: "value matches a forbidden form".to_string(),
                });
            }
        }
        if let Some(condition) = object.get("if") {
            let mut scratch = Vec::new();
            self.check(value, condition, path, &mut scratch);
            if scratch.is_empty() {
                if let Some(then) = object.get("then") {
                    self.check(value, then, path, out);
                }
            } else if let Some(otherwise) = object.get("else") {
                self.check(value, otherwise, path, out);
            }
        }
    }

    fn resolve(&self, reference: &str) -> Option<&Value> {
        let name = reference.strip_prefix("#/definitions/")?;
        self.root.get("definitions")?.get(name)
    }
}

/// Validate a document against the vendored EPCIS 2.0 schema.
pub fn validate_document(document: &Value) -> Vec<Violation> {
    match Schema::epcis_20() {
        Ok(schema) => schema.validate(document),
        Err(error) => vec![Violation {
            path: "$".to_string(),
            message: error,
        }],
    }
}

fn matches_type(value: &Value, expected: &Value) -> bool {
    match expected {
        Value::String(name) => type_name_matches(value, name),
        Value::Array(names) => names
            .iter()
            .filter_map(Value::as_str)
            .any(|name| type_name_matches(value, name)),
        _ => true,
    }
}

fn type_name_matches(value: &Value, name: &str) -> bool {
    match name {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn kind_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn render_expected(expected: &Value) -> String {
    match expected {
        Value::String(name) => name.clone(),
        other => other.to_string(),
    }
}

fn is_uri(value: &str) -> bool {
    let Some(colon) = value.find(':') else {
        return false;
    };
    let scheme = &value[..colon];
    !scheme.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+-.".contains(character))
        && value.len() > colon + 1
}

fn is_date_time(value: &str) -> bool {
    // RFC 3339 date-time: YYYY-MM-DDThh:mm:ss[.fraction](Z|+hh:mm|-hh:mm)
    let bytes = value.as_bytes();
    bytes.len() >= 20
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && matches!(bytes.get(10), Some(b'T') | Some(b't'))
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && value[..4]
            .chars()
            .all(|character| character.is_ascii_digit())
        && value[5..7]
            .chars()
            .all(|character| character.is_ascii_digit())
        && value[8..10]
            .chars()
            .all(|character| character.is_ascii_digit())
        && (value.ends_with('Z')
            || value.ends_with('z')
            || value[value.len() - 6..]
                .chars()
                .next()
                .is_some_and(|sign| sign == '+' || sign == '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vendored_schema_is_the_official_document() {
        let root: Value = serde_json::from_str(EPCIS_JSON_SCHEMA).expect("json");
        assert_eq!(root["$id"], EPCIS_JSON_SCHEMA_ID);
        assert_eq!(root["$schema"], "http://json-schema.org/draft-07/schema#");
        for definition in [
            "ObjectEvent",
            "AggregationEvent",
            "TransformationEvent",
            "AssociationEvent",
        ] {
            assert!(
                root["definitions"][definition].is_object(),
                "{definition} missing from the vendored schema"
            );
        }
    }

    #[test]
    fn a_missing_required_field_and_an_unknown_property_are_reported() {
        let schema = Schema::epcis_20().expect("schema");
        let document = serde_json::json!({
            "@context": ["https://ref.gs1.org/standards/epcis/2.0.0/epcis-context.jsonld"],
            "type": "EPCISDocument",
            "schemaVersion": "2.0",
            "creationDate": "2026-02-02T02:40:00.000Z",
            "epcisBody": {"eventList": [{
                "type": "ObjectEvent",
                "eventTimeZoneOffset": "+00:00",
                "action": "ADD",
                "surprise": true
            }]}
        });
        let violations = schema.validate(&document);
        assert!(
            violations
                .iter()
                .any(|violation| violation.path.ends_with(".eventTime")),
            "{violations:?}"
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.path.ends_with(".surprise")),
            "{violations:?}"
        );
    }

    #[test]
    fn uri_and_date_time_formats_are_checked() {
        assert!(is_uri("urn:tirbase:lot:LOT-A"));
        assert!(!is_uri("lot-a"));
        assert!(is_date_time("2026-02-02T02:40:00.000Z"));
        assert!(!is_date_time("2026-02-02 02:40:00"));
    }
}
