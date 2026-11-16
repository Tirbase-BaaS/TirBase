// SPDX-License-Identifier: Apache-2.0

//! `tirbase-epcis` — read a signed ledger bundle and write deterministic EPCIS
//! 2.0 output.
//!
//! ```text
//! tirbase-epcis --bundle DIR|bundle.json [--signature FILE] [--out DIR]
//!               [--format json|xml|both] [--creation-est N]
//!               [--verify --trusted-key HEX] [--fail-on-unsupported]
//! ```
//!
//! Exit codes: `0` success, `1` input or output error, `2` usage, `3` unsupported
//! entries with `--fail-on-unsupported`, `4` the generated JSON failed schema
//! validation.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tirbase_epcis::json::to_json;
use tirbase_epcis::mapping::map_bundle;
use tirbase_epcis::schema::validate_document;
use tirbase_epcis::xml::to_xml;
use tirbase_epcis::{parse_bundle, AdapterError};

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("tirbase-epcis: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(arguments: Vec<String>) -> Result<ExitCode, AdapterError> {
    let options = match Options::parse(&arguments) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("tirbase-epcis: {message}");
            eprintln!("{USAGE}");
            return Ok(ExitCode::from(2));
        }
    };

    let bundle_path = if options.bundle.is_dir() {
        options.bundle.join("bundle.json")
    } else {
        options.bundle.clone()
    };
    let bundle_json = std::fs::read_to_string(&bundle_path).map_err(|error| {
        AdapterError::InvalidBundle(format!("read {}: {error}", bundle_path.display()))
    })?;
    let bundle = parse_bundle(&bundle_json)?;

    if let Some(key) = options.trusted_key.as_deref() {
        let signature_path = options
            .signature
            .clone()
            .unwrap_or_else(|| defaults_dir(&bundle_path).join("bundle.sig"));
        let signature = std::fs::read_to_string(&signature_path).map_err(|error| {
            AdapterError::InvalidBundle(format!("read {}: {error}", signature_path.display()))
        })?;
        let verification = bundle.verify(signature.trim(), Some(key))?;
        eprintln!(
            "verified: {} ({}…)",
            verification.signer_did,
            &verification.public_key_hex[..verification.public_key_hex.len().min(16)]
        );
    }

    let mapped = map_bundle(&bundle, options.creation_est);
    let json = to_json(&mapped.document);
    let document: serde_json::Value = serde_json::from_str(&json)
        .map_err(|error| AdapterError::Json(format!("re-parse document: {error}")))?;
    let violations = validate_document(&document);
    for violation in &violations {
        eprintln!("schema: {violation}");
    }

    match options.output_dir.as_ref() {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|error| {
                AdapterError::InvalidBundle(format!("create {}: {error}", dir.display()))
            })?;
            if options.format.covers_json() {
                write_file(&dir.join("epcis.json"), &json)?;
            }
            if options.format.covers_xml() {
                write_file(&dir.join("epcis.xml"), &to_xml(&mapped.document))?;
            }
        }
        None => {
            if options.format.covers_json() {
                print!("{json}");
            }
            if options.format.covers_xml() {
                print!("{}", to_xml(&mapped.document));
            }
        }
    }

    for entry in &mapped.unsupported {
        eprintln!(
            "unsupported: seq {} {} ({}) — {}",
            entry.seq, entry.entry_id, entry.event_type, entry.reason
        );
    }
    let counts = mapped
        .document
        .counts()
        .into_iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!(
        "mapped {} events ({counts}), {} unsupported, {} schema violations",
        mapped.document.events.len(),
        mapped.unsupported.len(),
        violations.len()
    );

    if !violations.is_empty() {
        return Ok(ExitCode::from(4));
    }
    if options.fail_on_unsupported && !mapped.unsupported.is_empty() {
        return Ok(ExitCode::from(3));
    }
    Ok(ExitCode::from(0))
}

fn write_file(path: &Path, contents: &str) -> Result<(), AdapterError> {
    std::fs::write(path, contents)
        .map_err(|error| AdapterError::InvalidBundle(format!("write {}: {error}", path.display())))
}

fn defaults_dir(bundle_path: &Path) -> PathBuf {
    bundle_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

const USAGE: &str = "usage: tirbase-epcis --bundle DIR|bundle.json [--signature FILE] \
[--out DIR] [--format json|xml|both] [--creation-est N] \
[--verify --trusted-key HEX] [--fail-on-unsupported]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Xml,
    Both,
}

impl Format {
    fn covers_json(self) -> bool {
        matches!(self, Format::Json | Format::Both)
    }

    fn covers_xml(self) -> bool {
        matches!(self, Format::Xml | Format::Both)
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(Format::Json),
            "xml" => Some(Format::Xml),
            "both" => Some(Format::Both),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct Options {
    bundle: PathBuf,
    signature: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    format: Format,
    creation_est: Option<i64>,
    trusted_key: Option<String>,
    fail_on_unsupported: bool,
}

impl Options {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut options = Options {
            bundle: PathBuf::new(),
            signature: None,
            output_dir: None,
            format: Format::Json,
            creation_est: None,
            trusted_key: None,
            fail_on_unsupported: false,
        };
        let mut bundle = None;
        let mut index = 0;
        while index < arguments.len() {
            let argument = arguments[index].as_str();
            match argument {
                "--bundle" => bundle = Some(PathBuf::from(next(arguments, &mut index)?)),
                "--signature" => {
                    options.signature = Some(PathBuf::from(next(arguments, &mut index)?))
                }
                "--out" => options.output_dir = Some(PathBuf::from(next(arguments, &mut index)?)),
                "--format" => {
                    let value = next(arguments, &mut index)?;
                    options.format =
                        Format::parse(&value).ok_or_else(|| format!("unknown format {value}"))?;
                }
                "--creation-est" => {
                    let value = next(arguments, &mut index)?;
                    options.creation_est = Some(
                        value
                            .parse()
                            .map_err(|error| format!("--creation-est: {error}"))?,
                    );
                }
                "--trusted-key" => {
                    options.trusted_key = Some(next(arguments, &mut index)?);
                }
                "--verify" => {
                    if options.trusted_key.is_none() {
                        options.trusted_key = Some(String::new());
                    }
                }
                "--fail-on-unsupported" => options.fail_on_unsupported = true,
                "--help" | "-h" => return Err("help requested".to_string()),
                other => return Err(format!("unknown argument {other}")),
            }
            index += 1;
        }
        options.bundle = bundle.ok_or_else(|| "--bundle is required".to_string())?;
        if options.trusted_key.as_deref() == Some("") {
            return Err("--verify needs --trusted-key HEX".to_string());
        }
        Ok(options)
    }
}

fn next(arguments: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    arguments
        .get(*index)
        .cloned()
        .ok_or_else(|| format!("{} needs a value", arguments[*index - 1]))
}
