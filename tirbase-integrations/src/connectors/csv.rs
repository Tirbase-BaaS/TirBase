// SPDX-License-Identifier: Apache-2.0

//! CSV connector: one idempotently named row file per event.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::connector::{
    validate_connector_common, AuthKind, Connector, ConnectorBuildError, ConnectorCapabilities,
    ConnectorHealth, ConnectorKind, DeliveryRequest, DeliveryResult, DEFAULT_MAX_PAYLOAD_BYTES,
};

/// A CSV drop connector.
pub struct CsvConnector {
    name: String,
    output_dir: PathBuf,
    columns: Vec<String>,
    max_payload_bytes: usize,
}

impl CsvConnector {
    /// Build a connector writing `columns` into `output_dir`.
    pub fn new(
        name: impl Into<String>,
        output_dir: impl Into<PathBuf>,
        columns: Vec<String>,
    ) -> Result<Self, ConnectorBuildError> {
        let name = name.into();
        validate_connector_common(&name, DEFAULT_MAX_PAYLOAD_BYTES)?;
        if columns.is_empty() {
            return Err(ConnectorBuildError::new(
                "columns",
                "at least one column is required",
            ));
        }
        let mut seen = BTreeSet::new();
        for column in &columns {
            if column.trim().is_empty()
                || !column.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
            {
                return Err(ConnectorBuildError::new(
                    "columns",
                    format!("invalid column name {column:?}"),
                ));
            }
            if !seen.insert(column.as_str()) {
                return Err(ConnectorBuildError::new(
                    "columns",
                    format!("duplicate column {column:?}"),
                ));
            }
        }
        let output_dir = output_dir.into();
        if output_dir.as_os_str().is_empty() {
            return Err(ConnectorBuildError::new("output_dir", "must not be empty"));
        }
        Ok(Self {
            name,
            output_dir,
            columns,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
        })
    }

    /// Restrict the accepted payload size.
    pub fn with_max_payload_bytes(mut self, max_payload_bytes: usize) -> Self {
        self.max_payload_bytes = max_payload_bytes.max(1);
        self
    }

    /// Where rows are written.
    pub fn output_dir(&self) -> &Path {
        &self.output_dir
    }

    /// The configured columns.
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// Render the row for one request.
    pub fn row(&self, request: &DeliveryRequest) -> String {
        let mut line = String::new();
        for (index, column) in self.columns.iter().enumerate() {
            if index > 0 {
                line.push(',');
            }
            let value = match column.as_str() {
                "event_id" => Some(request.event_id.clone()),
                "event_type" => Some(request.event_type.clone()),
                "tenant" => Some(request.tenant.clone()),
                "idempotency_key" => Some(request.idempotency_key.clone()),
                other => request.payload.get(other).map(scalar),
            };
            let value = value.unwrap_or_default();
            line.push_str(&escape_csv(&value));
        }
        line.push('\n');
        line
    }

    /// Deterministic file name for one idempotency key.
    pub fn file_name(&self, idempotency_key: &str) -> String {
        format!("{idempotency_key}.csv")
    }
}

fn scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn escape_csv(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

impl Connector for CsvConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ConnectorKind {
        ConnectorKind::Csv
    }

    fn capabilities(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            idempotent: true,
            auth: vec![AuthKind::None],
            max_payload_bytes: self.max_payload_bytes,
        }
    }

    fn deliver(&self, request: &DeliveryRequest) -> DeliveryResult {
        let row = self.row(request);
        let header = format!("{}\n", self.columns.join(","));
        if header.len() + row.len() > self.max_payload_bytes {
            return DeliveryResult::permanent(format!(
                "row of {} bytes exceeds the {}-byte ceiling",
                row.len(),
                self.max_payload_bytes
            ));
        }
        let contents = format!("{header}{row}");
        if let Err(error) = fs::create_dir_all(&self.output_dir) {
            return DeliveryResult::retryable(
                format!("cannot create {}: {error}", self.output_dir.display()),
                None,
            );
        }
        let path = self
            .output_dir
            .join(self.file_name(&request.idempotency_key));
        if path.exists() {
            return match fs::read_to_string(&path) {
                Ok(existing) if existing == contents => {
                    DeliveryResult::duplicate("row already written")
                }
                Ok(_) => DeliveryResult::permanent(
                    "a different row already exists for this idempotency key",
                ),
                Err(error) => DeliveryResult::retryable(
                    format!("cannot read {}: {error}", path.display()),
                    None,
                ),
            };
        }
        let temporary = path.with_extension("csv.part");
        if let Err(error) = fs::write(&temporary, contents.as_bytes()) {
            return DeliveryResult::retryable(
                format!("cannot write {}: {error}", temporary.display()),
                None,
            );
        }
        if let Err(error) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return DeliveryResult::retryable(
                format!("cannot commit {}: {error}", path.display()),
                None,
            );
        }
        DeliveryResult::delivered(format!("wrote {}", path.display()))
    }

    fn health(&self) -> ConnectorHealth {
        match fs::metadata(&self.output_dir) {
            Ok(metadata) if metadata.is_dir() => ConnectorHealth::healthy(format!(
                "drop directory {} ready",
                self.output_dir.display()
            )),
            Ok(_) => ConnectorHealth::unhealthy(format!(
                "{} exists but is not a directory",
                self.output_dir.display()
            )),
            Err(_) => ConnectorHealth::healthy(format!(
                "drop directory {} will be created on first delivery",
                self.output_dir.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escaping_is_rfc4180() {
        assert_eq!(escape_csv("plain"), "plain");
        assert_eq!(escape_csv("a,b"), "\"a,b\"");
        assert_eq!(escape_csv("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(escape_csv("a\nb"), "\"a\nb\"");
    }
}
