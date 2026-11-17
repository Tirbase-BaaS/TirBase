// SPDX-License-Identifier: AGPL-3.0-only

//! Report rendering: CSV, JSON and a dependency-free PDF.
//!
//! Rendering is deterministic — the same report always produces the same bytes —
//! which is what lets an export manifest sign the body digest and a later
//! verifier recompute it. PDF uses the built-in Helvetica face only, so no font
//! file is embedded and no external library is linked.

use crate::reporting::{ExportFormat, Report, ReportError};

/// Render `report` in `format`.
pub fn render(report: &Report, format: ExportFormat) -> Result<Vec<u8>, ReportError> {
    match format {
        ExportFormat::Csv => Ok(render_csv(report).into_bytes()),
        ExportFormat::Json => serde_json::to_vec_pretty(report)
            .map_err(|error| ReportError::Export(format!("encode report JSON: {error}"))),
        ExportFormat::Pdf => Ok(render_pdf(report)),
    }
}

fn escape_csv(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn render_csv(report: &Report) -> String {
    let mut out = String::new();
    let mut header: Vec<String> = report
        .columns
        .iter()
        .map(|column| escape_csv(column))
        .collect();
    header.push("row_key".to_string());
    header.push("sources".to_string());
    out.push_str(&header.join(","));
    out.push('\n');
    for row in &report.rows {
        let mut cells: Vec<String> = report
            .columns
            .iter()
            .map(|column| {
                escape_csv(
                    row.cells
                        .get(column)
                        .map(String::as_str)
                        .unwrap_or_default(),
                )
            })
            .collect();
        cells.push(escape_csv(&row.key));
        cells.push(escape_csv(
            &row.sources
                .iter()
                .map(|source| format!("{}:{}", source.kind.as_str(), source.id))
                .collect::<Vec<_>>()
                .join("|"),
        ));
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

/// Escape a line for a PDF string literal and drop anything WinAnsi cannot show.
fn pdf_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars().take(120) {
        match character {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push(' '),
            character if (' '..='~').contains(&character) => out.push(character),
            _ => out.push('?'),
        }
    }
    out
}

fn render_pdf(report: &Report) -> Vec<u8> {
    const PAGE_WIDTH: i64 = 595;
    const PAGE_HEIGHT: i64 = 842;
    const MARGIN: i64 = 40;
    const LINE_HEIGHT: i64 = 11;
    const LINES_PER_PAGE: usize = 66;

    let mut lines: Vec<String> = Vec::new();
    lines.push(format!("TirBase report: {}", report.kind.as_str()));
    lines.push(format!("Report id: {}", report.report_id));
    lines.push(format!(
        "Tenant: {}   Generated: {}   By: {}",
        report.tenant, report.generated_est, report.generated_by
    ));
    if let Some((from, to)) = report.range {
        lines.push(format!("Range: {from} .. {to}"));
    }
    lines.push(format!(
        "Rows: {}   Content SHA-256: {}",
        report.rows.len(),
        report.content_sha256
    ));
    lines.push(format!(
        "ALCOA+: attributable={} legible={} contemporaneous={} original={} accurate={} complete={} consistent={} enduring={} available={}",
        report.alcoa.attributable.satisfied,
        report.alcoa.legible.satisfied,
        report.alcoa.contemporaneous.satisfied,
        report.alcoa.original.satisfied,
        report.alcoa.accurate.satisfied,
        report.alcoa.complete.satisfied,
        report.alcoa.consistent.satisfied,
        report.alcoa.enduring.satisfied,
        report.alcoa.available.satisfied,
    ));
    lines.push(String::new());
    lines.push(report.columns.join(" | "));
    lines.push("-".repeat(100));
    for row in &report.rows {
        let cells: Vec<&str> = report
            .columns
            .iter()
            .map(|column| {
                row.cells
                    .get(column)
                    .map(String::as_str)
                    .unwrap_or_default()
            })
            .collect();
        lines.push(cells.join(" | "));
    }

    let pages: Vec<&[String]> = lines.chunks(LINES_PER_PAGE).collect();
    let page_count = pages.len().max(1);

    // Object numbering: 1 catalog, 2 pages, 3 font, then (page, contents) pairs.
    let mut objects: Vec<String> = Vec::new();
    let kids: Vec<String> = (0..page_count)
        .map(|index| format!("{} 0 R", 4 + index * 2))
        .collect();
    objects.push("<< /Type /Catalog /Pages 2 0 R >>".to_string());
    objects.push(format!(
        "<< /Type /Pages /Kids [{}] /Count {page_count} >>",
        kids.join(" ")
    ));
    objects.push(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
            .to_string(),
    );
    for (index, page) in pages.iter().enumerate() {
        let content_id = 5 + index * 2;
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] \
             /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ));
        let mut stream = String::new();
        for (line_index, line) in page.iter().enumerate() {
            let y = PAGE_HEIGHT - MARGIN - (line_index as i64) * LINE_HEIGHT;
            stream.push_str(&format!(
                "BT /F1 8 Tf {MARGIN} {y} Td ({}) Tj ET\n",
                pdf_escape(line)
            ));
        }
        objects.push(format!(
            "<< /Length {} >>\nstream\n{stream}endstream",
            stream.len()
        ));
    }

    let mut document: Vec<u8> = Vec::new();
    document.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(document.len());
        document.extend_from_slice(format!("{} 0 obj\n{object}\nendobj\n", index + 1).as_bytes());
    }
    let xref_offset = document.len();
    document.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    document.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &offsets {
        document.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    document.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    document
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_escaping_is_safe_and_ascii() {
        assert_eq!(pdf_escape("a(b)c"), "a\\(b\\)c");
        assert_eq!(pdf_escape("back\\slash"), "back\\\\slash");
        assert_eq!(pdf_escape("caf\u{e9}"), "caf?");
        assert_eq!(pdf_escape("line\nbreak"), "line break");
    }

    #[test]
    fn csv_escaping_is_rfc4180() {
        assert_eq!(escape_csv("plain"), "plain");
        assert_eq!(escape_csv("a,b"), "\"a,b\"");
        assert_eq!(escape_csv("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
