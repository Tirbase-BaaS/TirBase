// SPDX-License-Identifier: Apache-2.0

//! Mapping DSL.
//!
//! A mapping document is TOML that names the fields a vendor expects and where
//! each one comes from. It is applied against `{event, payload}` and produces a
//! nested JSON object, so the same document drives the HTTP body, the webhook
//! body, the MQTT payload and the SFTP file.
//!
//! ```toml
//! schema_version = 1
//!
//! [[field]]
//! target = "device.serial"
//! source = "payload.device_serial"
//! required = true
//! transform = "trim"
//!
//! [[field]]
//! target = "reading.value_c"
//! source = "payload.temperature_c"
//! default = 0
//! ```
//!
//! Sources are dot paths with optional array indexes (`payload.samples[0].c`).
//! Targets are dot paths without indexes. A missing source with a `default` uses
//! the default; without one it is either an error (`required = true`) or omitted.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Mapping document schema version.
pub const MAPPING_SCHEMA_VERSION: u32 = 1;

/// Longest accepted path in a mapping document.
pub const MAX_PATH_LEN: usize = 128;

/// A parsed mapping document, as written by an integrator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingDocument {
    /// Schema version; must be [`MAPPING_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Field mappings.
    pub field: Vec<MappingField>,
}

/// One field mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingField {
    /// Destination path in the produced object.
    pub target: String,
    /// Source path in `{event, payload}`.
    pub source: String,
    /// Fail the mapping when the source is absent and no default is set.
    #[serde(default)]
    pub required: bool,
    /// Value used when the source is absent.
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    /// Optional value transform.
    #[serde(default)]
    pub transform: Option<Transform>,
}

/// Supported value transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transform {
    /// Leave the value alone.
    Identity,
    /// Trim surrounding whitespace on strings.
    Trim,
    /// Lower-case strings.
    Lowercase,
    /// Upper-case strings.
    Uppercase,
    /// Convert numbers or numeric strings to a string.
    String,
}

impl Transform {
    /// Apply the transform to one JSON value.
    pub fn apply(self, value: serde_json::Value) -> serde_json::Value {
        match self {
            Transform::Identity => value,
            Transform::Trim => match value {
                serde_json::Value::String(text) => {
                    serde_json::Value::String(text.trim().to_string())
                }
                other => other,
            },
            Transform::Lowercase => match value {
                serde_json::Value::String(text) => serde_json::Value::String(text.to_lowercase()),
                other => other,
            },
            Transform::Uppercase => match value {
                serde_json::Value::String(text) => serde_json::Value::String(text.to_uppercase()),
                other => other,
            },
            Transform::String => match value {
                serde_json::Value::String(text) => serde_json::Value::String(text),
                serde_json::Value::Number(number) => serde_json::Value::String(number.to_string()),
                serde_json::Value::Bool(flag) => serde_json::Value::String(flag.to_string()),
                other => other,
            },
        }
    }
}

/// A compiled mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    fields: Vec<MappingField>,
}

impl Mapping {
    /// Compile a TOML document, validating it before it can be used.
    pub fn from_toml(text: &str) -> Result<Self, MappingError> {
        let document: MappingDocument =
            toml::from_str(text).map_err(|error| MappingError::Toml(error.to_string()))?;
        Self::from_document(document)
    }

    /// Compile a parsed document.
    pub fn from_document(document: MappingDocument) -> Result<Self, MappingError> {
        if document.schema_version != MAPPING_SCHEMA_VERSION {
            return Err(MappingError::UnsupportedVersion {
                found: document.schema_version,
                supported: MAPPING_SCHEMA_VERSION,
            });
        }
        if document.field.is_empty() {
            return Err(MappingError::Invalid {
                field: "field".to_string(),
                detail: "a mapping must define at least one field".to_string(),
            });
        }
        let mut targets = BTreeSet::new();
        for (index, field) in document.field.iter().enumerate() {
            validate_target(index, &field.target)?;
            validate_source(index, &field.source)?;
            if !targets.insert(field.target.as_str()) {
                return Err(MappingError::Invalid {
                    field: format!("field[{index}].target"),
                    detail: format!("duplicate target {:?}", field.target),
                });
            }
            if field.required && field.default.is_some() {
                return Err(MappingError::Invalid {
                    field: format!("field[{index}]"),
                    detail: "a required field cannot also carry a default".to_string(),
                });
            }
        }
        Ok(Self {
            fields: document.field,
        })
    }

    /// The compiled fields.
    pub fn fields(&self) -> &[MappingField] {
        &self.fields
    }

    /// Apply the mapping to `{event, payload}` and produce the vendor object.
    pub fn apply(&self, context: &serde_json::Value) -> Result<serde_json::Value, MappingError> {
        let mut output = serde_json::Value::Object(serde_json::Map::new());
        for field in &self.fields {
            let value = match resolve(context, &field.source) {
                Some(value) => value.clone(),
                None => match field.default.as_ref() {
                    Some(default) => default.clone(),
                    None if field.required => {
                        return Err(MappingError::MissingSource {
                            target: field.target.clone(),
                            source: field.source.clone(),
                        })
                    }
                    None => continue,
                },
            };
            let value = field.transform.unwrap_or(Transform::Identity).apply(value);
            insert(&mut output, &field.target, value)?;
        }
        Ok(output)
    }
}

/// Resolve a dot path with optional array indexes.
pub fn resolve<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        let (name, indexes) = split_indexes(segment)?;
        if !name.is_empty() {
            current = current.get(name)?;
        }
        for index in indexes {
            current = current.get(index)?;
        }
    }
    Some(current)
}

/// Split `name[0][2]` into its name and its indexes.
fn split_indexes(segment: &str) -> Option<(&str, Vec<usize>)> {
    let Some(open) = segment.find('[') else {
        if segment.contains(']') {
            return None;
        }
        return Some((segment, Vec::new()));
    };
    let name = &segment[..open];
    let mut rest = &segment[open..];
    let mut indexes = Vec::new();
    while let Some(stripped) = rest.strip_prefix('[') {
        let close = stripped.find(']')?;
        let index: usize = stripped[..close].parse().ok()?;
        indexes.push(index);
        rest = &stripped[close + 1..];
    }
    if !rest.is_empty() {
        return None;
    }
    Some((name, indexes))
}

fn insert(
    output: &mut serde_json::Value,
    target: &str,
    value: serde_json::Value,
) -> Result<(), MappingError> {
    let segments: Vec<&str> = target.split('.').collect();
    let mut current = output;
    for (index, segment) in segments.iter().enumerate() {
        if index + 1 == segments.len() {
            let object = current
                .as_object_mut()
                .ok_or_else(|| MappingError::Invalid {
                    field: "target".to_string(),
                    detail: format!("target {target:?} collides with a scalar"),
                })?;
            object.insert((*segment).to_string(), value);
            return Ok(());
        }
        let object = current
            .as_object_mut()
            .ok_or_else(|| MappingError::Invalid {
                field: "target".to_string(),
                detail: format!("target {target:?} collides with a scalar"),
            })?;
        current = object
            .entry((*segment).to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    Ok(())
}

fn validate_target(index: usize, target: &str) -> Result<(), MappingError> {
    validate_path(index, "target", target)?;
    if target.contains('[') || target.contains(']') {
        return Err(MappingError::Invalid {
            field: format!("field[{index}].target"),
            detail: "targets may not contain array indexes".to_string(),
        });
    }
    Ok(())
}

fn validate_source(index: usize, source: &str) -> Result<(), MappingError> {
    validate_path(index, "source", source)?;
    if !source.starts_with("event") && !source.starts_with("payload") {
        return Err(MappingError::Invalid {
            field: format!("field[{index}].source"),
            detail: "source must start with `event` or `payload`".to_string(),
        });
    }
    if split_indexes(source.split('.').next().unwrap_or_default()).is_none() {
        return Err(MappingError::Invalid {
            field: format!("field[{index}].source"),
            detail: "malformed source path".to_string(),
        });
    }
    for segment in source.split('.') {
        if split_indexes(segment).is_none() {
            return Err(MappingError::Invalid {
                field: format!("field[{index}].source"),
                detail: format!("malformed source segment {segment:?}"),
            });
        }
    }
    Ok(())
}

fn validate_path(index: usize, kind: &str, path: &str) -> Result<(), MappingError> {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return Err(MappingError::Invalid {
            field: format!("field[{index}].{kind}"),
            detail: format!("must be 1..={MAX_PATH_LEN} characters"),
        });
    }
    if path.split('.').any(str::is_empty) {
        return Err(MappingError::Invalid {
            field: format!("field[{index}].{kind}"),
            detail: "must not contain empty segments".to_string(),
        });
    }
    Ok(())
}

/// Why a mapping document was refused or a mapping failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    /// The document is not valid TOML or does not match the schema.
    Toml(String),
    /// The schema version is not supported.
    UnsupportedVersion {
        /// Version found in the document.
        found: u32,
        /// Version this crate supports.
        supported: u32,
    },
    /// A field is invalid.
    Invalid {
        /// Offending field.
        field: String,
        /// Why it is invalid.
        detail: String,
    },
    /// A required source was absent.
    MissingSource {
        /// Target that would have received the value.
        target: String,
        /// Source that was absent.
        source: String,
    },
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MappingError::Toml(detail) => write!(f, "mapping document: {detail}"),
            MappingError::UnsupportedVersion { found, supported } => write!(
                f,
                "unsupported mapping schema version {found} (supported: {supported})"
            ),
            MappingError::Invalid { field, detail } => write!(f, "invalid {field}: {detail}"),
            MappingError::MissingSource { target, source } => {
                write!(f, "required source {source} for {target} is absent")
            }
        }
    }
}

impl std::error::Error for MappingError {}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &str = r#"
schema_version = 1

[[field]]
target = "device.serial"
source = "payload.device_serial"
required = true
transform = "trim"

[[field]]
target = "reading.value_c"
source = "payload.temperature_c"

[[field]]
target = "meta.gateway"
source = "payload.gateway"
default = "unknown"
transform = "lowercase"
"#;

    fn context() -> serde_json::Value {
        serde_json::json!({
            "event": { "event_id": "e-1", "tenant": "acme" },
            "payload": {
                "device_serial": "  SN-1 ",
                "temperature_c": 42,
                "gateway": "GW-A",
                "samples": [{ "c": 1 }, { "c": 2 }]
            }
        })
    }

    #[test]
    fn mapping_applies_defaults_transforms_and_nested_targets() {
        let mapping = Mapping::from_toml(DOCUMENT).expect("mapping");
        let output = mapping.apply(&context()).expect("apply");
        assert_eq!(
            output,
            serde_json::json!({
                "device": { "serial": "SN-1" },
                "reading": { "value_c": 42 },
                "meta": { "gateway": "gw-a" },
            })
        );
        assert_eq!(
            Mapping::from_toml(DOCUMENT).expect("stable").fields().len(),
            3
        );
    }

    #[test]
    fn mapping_refuses_unsafe_documents() {
        assert!(matches!(
            Mapping::from_toml("schema_version = 2\nfield = []"),
            Err(MappingError::UnsupportedVersion { .. })
        ));
        assert!(matches!(
            Mapping::from_toml(
                "schema_version = 1\n[[field]]\ntarget = \"a\"\nsource = \"payload.a\"\n\
                 [[field]]\ntarget = \"a\"\nsource = \"payload.b\""
            ),
            Err(MappingError::Invalid { .. })
        ));
        assert!(matches!(
            Mapping::from_toml(
                "schema_version = 1\n[[field]]\ntarget = \"a\"\nsource = \"secrets.token\""
            ),
            Err(MappingError::Invalid { .. })
        ));
        assert!(matches!(
            Mapping::from_toml(
                "schema_version = 1\n[[field]]\ntarget = \"a\"\nsource = \"payload.a\"\nrequired = true\ndefault = 1"
            ),
            Err(MappingError::Invalid { .. })
        ));
        assert!(matches!(
            Mapping::from_toml("schema_version = 1\nfield = []"),
            Err(MappingError::Invalid { .. })
        ));
        assert!(Mapping::from_toml("schema_version = 1\n[[field]]\ntarget = \"a\"").is_err());
    }

    #[test]
    fn missing_required_source_is_an_error_and_optional_is_omitted() {
        let mapping = Mapping::from_toml(DOCUMENT).expect("mapping");
        let mut context = context();
        context["payload"]
            .as_object_mut()
            .expect("object")
            .remove("temperature_c");
        let output = mapping.apply(&context).expect("optional is omitted");
        assert!(output["reading"].get("value_c").is_none());

        context["payload"]
            .as_object_mut()
            .expect("object")
            .remove("device_serial");
        assert!(matches!(
            mapping.apply(&context),
            Err(MappingError::MissingSource { .. })
        ));
    }

    #[test]
    fn resolver_reads_array_indexes() {
        let context = context();
        assert_eq!(
            resolve(&context, "payload.samples[1].c"),
            Some(&serde_json::json!(2))
        );
        assert_eq!(resolve(&context, "payload.samples[9].c"), None);
        assert_eq!(resolve(&context, "payload.samples[0"), None);
        assert_eq!(resolve(&context, ""), None);
    }
}
