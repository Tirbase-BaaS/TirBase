// SPDX-License-Identifier: Apache-2.0

//! `en16931` — export and validate EN 16931 e-invoices from POS invoice data.
//!
//! The binary is a thin shell over the library: it reads a batch file of register
//! invoices, maps them onto the EN 16931 model, serializes UBL 2.1 and/or CII
//! D16B, validates every document, and writes the files plus a `manifest.json`
//! that records the SHA-256 of each one. It never writes a document that failed
//! validation.
//!
//! ```text
//! en16931 export --input batch.json --output out --format both
//! en16931 validate --input batch.json
//! en16931 validate --xml out/INV-1.ubl.xml --syntax ubl --input batch.json --number INV-1
//! en16931 version
//! ```

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use tirbase_en16931::batch;
use tirbase_en16931::pos::PosInvoiceFile;
use tirbase_en16931::profiles::{self, CountryProfile};
use tirbase_en16931::validate::{self, Syntax};
use tirbase_en16931::{SPECIFICATION_ID, VERSION};

const USAGE: &str = "\
en16931 — EN 16931 e-invoicing adapter

USAGE:
  en16931 export --input <batch.json> --output <dir> [--format ubl|cii|both] [--profile <id>]
  en16931 validate --input <batch.json> [--format ubl|cii|both] [--profile <id>]
  en16931 validate --xml <file> --syntax ubl|cii --input <batch.json> --number <number>
  en16931 version

The core adapter writes EN 16931 core documents only. It makes no national
fiscal claim; a country profile is a separate, closed module registered with
--profile.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("en16931: {message}");
            eprintln!();
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let Some((command, rest)) = args.split_first() else {
        return Err("no command given".to_string());
    };
    let flags = parse_flags(rest)?;
    match command.as_str() {
        "export" => export(&flags),
        "validate" => validate(&flags),
        "version" => version(),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command {other:?}")),
    }
}

fn parse_flags(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut flags = BTreeMap::new();
    let mut iter = args.iter();
    while let Some(argument) = iter.next() {
        let Some(name) = argument.strip_prefix("--") else {
            return Err(format!("unexpected argument {argument:?}"));
        };
        let Some(value) = iter.next() else {
            return Err(format!("--{name} needs a value"));
        };
        if flags.insert(name.to_string(), value.clone()).is_some() {
            return Err(format!("--{name} is given twice"));
        }
    }
    Ok(flags)
}

fn only(flags: &BTreeMap<String, String>, allowed: &[&str]) -> Result<(), String> {
    for name in flags.keys() {
        if !allowed.contains(&name.as_str()) {
            return Err(format!("unknown option --{name}"));
        }
    }
    Ok(())
}

fn required<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    flags
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("--{name} is required"))
}

fn export(flags: &BTreeMap<String, String>) -> Result<ExitCode, String> {
    only(flags, &["input", "output", "format", "profile"])?;
    let input = required(flags, "input")?;
    let output = required(flags, "output")?;
    let formats = formats(flags)?;
    let profile = profile(flags)?;
    let file = load(input)?;
    let report = batch::export(&file, Path::new(output), &formats, profile)
        .map_err(|error| error.to_string())?;
    let files: usize = report
        .documents
        .iter()
        .map(|document| document.files.len())
        .sum();
    println!(
        "wrote {} document(s), {} file(s), {} bytes into {}",
        report.documents.len(),
        files,
        report.bytes,
        Path::new(output).display()
    );
    println!(
        "manifest: {} ({} bytes)",
        report.manifest.display(),
        report.bytes
    );
    for failure in &report.failures {
        eprintln!("skipped {}:", failure.number);
        for problem in &failure.problems {
            eprintln!("  {problem}");
        }
    }
    if report.complete() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn validate(flags: &BTreeMap<String, String>) -> Result<ExitCode, String> {
    only(
        flags,
        &["input", "format", "profile", "xml", "syntax", "number"],
    )?;
    let input = required(flags, "input")?;
    let file = load(input)?;
    if let Some(xml_path) = flags.get("xml") {
        return validate_file(&file, xml_path, flags);
    }
    let formats = formats(flags)?;
    let profile = profile(flags)?;
    let mut documents = 0usize;
    let mut invalid = 0usize;
    for source in &file.invoices {
        let invoice = match source.to_invoice() {
            Ok(invoice) => invoice,
            Err(problems) => {
                invalid += 1;
                println!("{}: invalid input", source.number);
                for problem in problems {
                    println!("  {problem}");
                }
                continue;
            }
        };
        for syntax in &formats {
            documents += 1;
            let document = batch::render(&invoice, *syntax, profile)?;
            let report = validate::validate_document(&document, &invoice, *syntax);
            println!(
                "{} {} {}: {}",
                syntax.label(),
                invoice.number,
                syntax.id(),
                if report.valid { "valid" } else { "invalid" }
            );
            if !report.valid {
                invalid += 1;
                println!("{}", report.render());
            }
        }
    }
    println!("{documents} document(s) checked, {invalid} invalid");
    if invalid == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn validate_file(
    file: &PosInvoiceFile,
    xml_path: &str,
    flags: &BTreeMap<String, String>,
) -> Result<ExitCode, String> {
    let syntax = flags
        .get("syntax")
        .ok_or_else(|| "--xml needs --syntax".to_string())?;
    let syntax = Syntax::from_id(syntax)
        .ok_or_else(|| format!("--syntax must be ubl or cii, not {syntax:?}"))?;
    let number = required(flags, "number")?;
    let source = file
        .invoices
        .iter()
        .find(|invoice| invoice.number == number)
        .ok_or_else(|| format!("{number:?} is not in the batch"))?;
    let invoice = source
        .to_invoice()
        .map_err(|problems| problems.join("; "))?;
    let document =
        std::fs::read_to_string(xml_path).map_err(|error| format!("{xml_path}: {error}"))?;
    let report = validate::validate_document(&document, &invoice, syntax);
    println!(
        "{} {}: {}",
        syntax.label(),
        number,
        if report.valid { "valid" } else { "invalid" }
    );
    if !report.issues.is_empty() {
        println!("{}", report.render());
    }
    if report.valid {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn version() -> Result<ExitCode, String> {
    println!("tirbase-en16931 {VERSION}");
    println!("specification: {SPECIFICATION_ID}");
    println!("profiles: {}", profiles::ids().join(", "));
    Ok(ExitCode::SUCCESS)
}

fn formats(flags: &BTreeMap<String, String>) -> Result<Vec<Syntax>, String> {
    match flags.get("format").map(String::as_str) {
        None | Some("both") => Ok(vec![Syntax::Ubl, Syntax::Cii]),
        Some("ubl") => Ok(vec![Syntax::Ubl]),
        Some("cii") => Ok(vec![Syntax::Cii]),
        Some(other) => Err(format!("--format must be ubl, cii or both, not {other:?}")),
    }
}

fn profile(
    flags: &BTreeMap<String, String>,
) -> Result<Option<&'static dyn CountryProfile>, String> {
    let Some(id) = flags.get("profile") else {
        return Ok(None);
    };
    profiles::find(id).map(Some).ok_or_else(|| {
        format!(
            "no profile {id:?} is registered; available: {}",
            profiles::ids().join(", ")
        )
    })
}

fn load(path: &str) -> Result<PosInvoiceFile, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
    PosInvoiceFile::from_json(&text)
}
