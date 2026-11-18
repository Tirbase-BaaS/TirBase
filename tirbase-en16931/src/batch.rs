// SPDX-License-Identifier: Apache-2.0

//! Batch export: register invoices in, validated e-invoices and a manifest out.
//!
//! The exporter is deterministic. It reads no clock, writes no timestamp, sorts
//! every collection, and derives each file name from the document number, so the
//! same input produces byte-identical files and a byte-identical `manifest.json`
//! on every run. Each written document is validated first; a document that fails
//! validation is reported in the manifest and **not** written, so a directory can
//! never contain an e-invoice that did not validate.
//!
//! ```
//! use tirbase_en16931::batch;
//! use tirbase_en16931::pos::PosInvoiceFile;
//! use tirbase_en16931::validate::Syntax;
//!
//! let file = PosInvoiceFile::from_json(r#"{"invoices": []}"#);
//! assert!(file.is_err());
//! let _ = (batch::FileNamer::stem("INV/1"), Syntax::Ubl);
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cii;
use crate::pos::PosInvoiceFile;
use crate::profiles::CountryProfile;
use crate::ubl;
use crate::validate::{validate_document, Syntax};
use crate::SPECIFICATION_ID;

/// Name of the manifest written into the output directory.
pub const MANIFEST_NAME: &str = "manifest.json";

/// Why a batch could not be exported.
#[derive(Debug)]
pub enum BatchError {
    /// The input was refused before any document was written.
    Input(String),
    /// A file could not be written.
    Io {
        /// Path that could not be written.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BatchError::Input(detail) => write!(f, "{detail}"),
            BatchError::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for BatchError {}

impl From<std::io::Error> for BatchError {
    fn from(source: std::io::Error) -> Self {
        BatchError::Io {
            path: PathBuf::from("<unknown>"),
            source,
        }
    }
}

/// File-name derivation for exported documents.
pub struct FileNamer;

impl FileNamer {
    /// A filesystem-safe stem for a document number.
    ///
    /// Letters, digits, `.`, `-` and `_` are kept; every other character becomes
    /// `-`. An empty stem becomes `document`.
    pub fn stem(number: &str) -> String {
        let stem: String = number
            .trim()
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                    character
                } else {
                    '-'
                }
            })
            .collect();
        if stem.is_empty() {
            "document".to_string()
        } else {
            stem
        }
    }

    /// The file name of a document in a syntax.
    pub fn file_name(number: &str, syntax: Syntax) -> String {
        format!("{}.{}.xml", Self::stem(number), syntax.id())
    }
}

/// One file an export wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportedFile {
    /// Syntax identifier.
    pub syntax: &'static str,
    /// File name inside the output directory.
    pub name: String,
    /// SHA-256 of the file contents, lower-case hex.
    pub sha256: String,
    /// Size in bytes.
    pub bytes: usize,
}

/// A document the export wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportedDocument {
    /// Document number.
    pub number: String,
    /// `invoice` or `credit_note`.
    pub document_type: &'static str,
    /// ISO 4217 currency.
    pub currency: String,
    /// Files written for it.
    pub files: Vec<ExportedFile>,
}

/// A document the export refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportFailure {
    /// Document number, or the position when the number is missing.
    pub number: String,
    /// Everything that was wrong.
    pub problems: Vec<String>,
}

/// The result of a batch export.
///
/// Serializing this value produces the manifest, so the manifest is exactly the
/// report a caller saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BatchReport {
    /// Generator identifier and version.
    pub generator: String,
    /// Specification identifier the documents were written against.
    pub specification: &'static str,
    /// Written documents, sorted by number.
    pub documents: Vec<ExportedDocument>,
    /// Refused documents, sorted by number.
    pub failures: Vec<ExportFailure>,
    /// Where the manifest was written.
    #[serde(skip)]
    pub manifest: PathBuf,
    /// Bytes written in total.
    #[serde(skip)]
    pub bytes: usize,
}

impl BatchReport {
    /// Whether every document in the batch was written.
    pub fn complete(&self) -> bool {
        self.failures.is_empty()
    }

    /// The manifest as JSON, with a trailing newline.
    pub fn manifest_json(&self) -> Result<String, BatchError> {
        let mut json = serde_json::to_string_pretty(self)
            .map_err(|error| BatchError::Input(format!("cannot render the manifest: {error}")))?;
        json.push('\n');
        Ok(json)
    }
}

/// Export every invoice in `file` into `output`.
///
/// The directory is created if needed. Files for a refused document are not
/// written; the reason is recorded in the manifest.
pub fn export(
    file: &PosInvoiceFile,
    output: &Path,
    formats: &[Syntax],
    profile: Option<&dyn CountryProfile>,
) -> Result<BatchReport, BatchError> {
    if formats.is_empty() {
        return Err(BatchError::Input(
            "no syntax was selected for export".to_string(),
        ));
    }
    let mut formats = formats.to_vec();
    formats.sort_unstable();
    formats.dedup();

    std::fs::create_dir_all(output).map_err(|source| BatchError::Io {
        path: output.to_path_buf(),
        source,
    })?;

    let mut documents = Vec::new();
    let mut failures = Vec::new();
    let mut bytes = 0usize;
    let mut stems: BTreeMap<String, String> = BTreeMap::new();
    let mut taken: BTreeSet<String> = BTreeSet::new();

    for (index, source) in file.invoices.iter().enumerate() {
        let label = if source.number.trim().is_empty() {
            format!("invoices[{index}]")
        } else {
            source.number.trim().to_string()
        };
        let stem = FileNamer::stem(&source.number);
        if let Some(previous) = stems.get(&stem) {
            failures.push(ExportFailure {
                number: label,
                problems: vec![format!(
                    "the file stem {stem:?} is already used by {previous:?}"
                )],
            });
            continue;
        }

        let invoice = match source.to_invoice() {
            Ok(invoice) => invoice,
            Err(problems) => {
                failures.push(ExportFailure {
                    number: label,
                    problems,
                });
                continue;
            }
        };

        let mut problems = Vec::new();
        if let Some(profile) = profile {
            for issue in profile.validate(&invoice) {
                if issue.fatal {
                    problems.push(format!("{} {}: {}", issue.rule, issue.path, issue.message));
                }
            }
        }
        if !problems.is_empty() {
            failures.push(ExportFailure {
                number: label,
                problems,
            });
            continue;
        }

        let mut files = Vec::new();
        for syntax in &formats {
            let document = match render(&invoice, *syntax, profile) {
                Ok(document) => document,
                Err(detail) => {
                    problems.push(format!("{}: {detail}", syntax.id()));
                    continue;
                }
            };
            let report = validate_document(&document, &invoice, *syntax);
            if !report.valid {
                problems.push(format!("{}: {}", syntax.id(), report.render()));
                continue;
            }
            let name = FileNamer::file_name(&invoice.number, *syntax);
            if !taken.insert(name.clone()) {
                problems.push(format!("the file name {name:?} is already used"));
                continue;
            }
            std::fs::write(output.join(&name), document.as_bytes()).map_err(|source| {
                BatchError::Io {
                    path: output.join(&name),
                    source,
                }
            })?;
            bytes += document.len();
            files.push(ExportedFile {
                syntax: syntax.id(),
                name,
                sha256: digest(document.as_bytes()),
                bytes: document.len(),
            });
        }
        if !problems.is_empty() {
            failures.push(ExportFailure {
                number: label,
                problems,
            });
            continue;
        }
        stems.insert(stem, invoice.number.clone());
        documents.push(ExportedDocument {
            number: invoice.number.clone(),
            document_type: match invoice.document_type {
                crate::model::DocumentType::Invoice => "invoice",
                crate::model::DocumentType::CreditNote => "credit_note",
            },
            currency: invoice.currency.clone(),
            files,
        });
    }

    documents.sort_by(|left, right| left.number.cmp(&right.number));
    failures.sort_by(|left, right| left.number.cmp(&right.number));

    let mut report = BatchReport {
        generator: format!("tirbase-en16931 {}", crate::VERSION),
        specification: SPECIFICATION_ID,
        documents,
        failures,
        manifest: output.join(MANIFEST_NAME),
        bytes,
    };
    let manifest = report.manifest_json()?;
    report.bytes += manifest.len();
    std::fs::write(&report.manifest, manifest.as_bytes()).map_err(|source| BatchError::Io {
        path: report.manifest.clone(),
        source,
    })?;
    Ok(report)
}

/// Serialize one invoice in one syntax, optionally under a country profile.
pub fn render(
    invoice: &crate::model::Invoice,
    syntax: Syntax,
    profile: Option<&dyn CountryProfile>,
) -> Result<String, String> {
    match (syntax, profile) {
        (Syntax::Ubl, None) => Ok(ubl::serialize(invoice)),
        (Syntax::Ubl, Some(profile)) => ubl::serialize_with(invoice, profile),
        (Syntax::Cii, None) => Ok(cii::serialize(invoice)),
        (Syntax::Cii, Some(profile)) => cii::serialize_with(invoice, profile),
    }
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stems_are_filesystem_safe() {
        assert_eq!(FileNamer::stem("INV/1"), "INV-1");
        assert_eq!(FileNamer::stem("a b:c"), "a-b-c");
        assert_eq!(FileNamer::stem("   "), "document");
        assert_eq!(FileNamer::stem("../../etc/passwd"), "..-..-etc-passwd");
        assert_eq!(FileNamer::file_name("INV-1", Syntax::Cii), "INV-1.cii.xml");
    }
}
