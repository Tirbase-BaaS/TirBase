// SPDX-License-Identifier: AGPL-3.0-only

//! F-10 telemetry primitives: log redaction, trace context/export, and
//! structured audit helpers.
//!
//! # Redaction contract
//!
//! The gateway installs [`redacting_stdout`] as the tracing writer, so every
//! JSON log line passes through the redactor before it reaches stdout /
//! journald. The redactor removes:
//!
//! * PANs (13–19 digits with separators, Luhn-validated),
//! * PEM private-key blocks, 64+ hex-character secrets, bearer/JWT tokens,
//! * email addresses and E.164 phone numbers,
//! * precise location fields and other sensitive JSON keys.
//!
//! Redaction is deliberately structural rather than regex-heavy: it has no
//! external dependency, cannot be bypassed by logging a field twice, and is
//! covered by unit tests including a full JSON log line.
//!
//! # Traces
//!
//! [`Span`] creates a W3C-compatible 128-bit trace id and 64-bit span id. When
//! `TIRBASE_TRACE_EXPORT_PATH` is set, completed spans are appended as JSON
//! lines (one object per span, `resource.service.name=tirbase-gateway`). An
//! incoming `traceparent` header can be parsed with [`parse_traceparent`] and
//! attached with [`Span::with_parent`], so HTTP surfaces can preserve caller
//! trace context without pulling in the OpenTelemetry SDK.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing_subscriber::fmt::MakeWriter;

pub const REDACTED: &str = "[REDACTED]";

// ─── Redaction ───────────────────────────────────────────────────────────────

/// Redact sensitive values from an arbitrary log string.
pub fn redact_text(input: &str) -> String {
    let mut output = redact_pem_blocks(input);
    output = redact_prefixed_tokens(&output);
    output = redact_pans(&output);
    output = redact_emails(&output);
    output = redact_hex_secrets(&output);
    output = redact_phone_numbers(&output);
    output
}

/// Redact sensitive keys and values in a JSON value in place.
pub fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *child = serde_json::Value::String(REDACTED.to_string());
                } else {
                    redact_json(child);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json(item);
            }
        }
        serde_json::Value::String(text) => {
            *text = redact_text(text);
        }
        serde_json::Value::Number(number) => {
            let digits = number.to_string();
            if (13..=19).contains(&digits.len()) && luhn_valid(digits.as_bytes()) {
                *value = serde_json::Value::String(REDACTED.to_string());
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    const EXACT: &[&str] = &[
        "authorization",
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "private_key",
        "privatekey",
        "api_key",
        "apikey",
        "card_number",
        "cardnumber",
        "pan",
        "cvv",
        "cvc",
        "ssn",
        "email",
        "phone",
        "latitude",
        "longitude",
        "lat",
        "lon",
        "lng",
        "gps",
        "precise_location",
        "address",
        "date_of_birth",
        "dob",
    ];
    EXACT.contains(&key.as_str())
        || key.ends_with("_token")
        || key.ends_with("_secret")
        || key.ends_with("_password")
        || key.ends_with("_private_key")
        || key.ends_with("_card_number")
}

fn redact_pem_blocks(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;
    loop {
        let Some(rel_begin) = input[cursor..].find("-----BEGIN ") else {
            output.push_str(&input[cursor..]);
            break;
        };
        let begin = cursor + rel_begin;
        let header_end = input[begin..]
            .find('\n')
            .map(|rel| begin + rel)
            .unwrap_or(input.len());
        let header = &input[begin..header_end];
        if !header.to_ascii_uppercase().contains("PRIVATE KEY") {
            output.push_str(&input[cursor..header_end]);
            cursor = header_end;
            continue;
        }
        let Some(rel_end) = input[begin..].find("-----END ") else {
            output.push_str(&input[cursor..begin]);
            output.push_str(REDACTED);
            break;
        };
        let end_start = begin + rel_end;
        let end_line_end = input[end_start..]
            .find('\n')
            .map(|rel| end_start + rel + 1)
            .unwrap_or(input.len());
        output.push_str(&input[cursor..begin]);
        output.push_str(REDACTED);
        cursor = end_line_end;
    }
    output
}

fn redact_prefixed_tokens(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut spans = Vec::new();
    for needle in ["bearer ", "basic ", "token="] {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(needle) {
            let start = from + rel;
            let value_start = start + needle.len();
            let value_end = input[value_start..]
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '}'))
                .map(|i| value_start + i)
                .unwrap_or(input.len());
            let value = &input[value_start..value_end];
            if !value.is_empty() {
                spans.push((value_start, value_end));
            }
            from = value_end.max(start + needle.len());
        }
    }
    // JWT-shaped tokens.
    let bytes = input.as_bytes();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if &bytes[index..index + 3] == b"eyJ" {
            let end = input[index..]
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '}'))
                .map(|i| index + i)
                .unwrap_or(input.len());
            if end.saturating_sub(index) >= 20 {
                spans.push((index, end));
            }
            index = end.max(index + 3);
        } else {
            index += 1;
        }
    }
    replace_spans(input, &mut spans, REDACTED)
}

fn luhn_valid(digits: &[u8]) -> bool {
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    let parity = digits.len() % 2;
    for (index, digit) in digits.iter().enumerate() {
        let mut value = (*digit - b'0') as u32;
        if index % 2 == parity {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }
    sum % 10 == 0
}

fn redact_pans(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        let mut digits = Vec::new();
        let mut cursor = index;
        let mut last_digit = index;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'0'..=b'9' => {
                    digits.push(bytes[cursor]);
                    last_digit = cursor;
                    cursor += 1;
                }
                b' ' | b'-' if cursor + 1 < bytes.len() && bytes[cursor + 1].is_ascii_digit() => {
                    cursor += 1;
                }
                _ => break,
            }
        }
        if digits.len() >= 13 && digits.len() <= 19 && luhn_valid(&digits) {
            spans.push((start, last_digit + 1));
        }
        index = last_digit + 1;
    }
    replace_spans(input, &mut spans, REDACTED)
}

fn redact_emails(input: &str) -> String {
    let mut spans = Vec::new();
    for (at, _) in input.match_indices('@') {
        let start = input[..at]
            .rfind(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '(' | ',' | ';'))
            .map(|i| i + 1)
            .unwrap_or(0);
        let end = input[at + 1..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '>' | ')' | ',' | ';'))
            .map(|i| at + 1 + i)
            .unwrap_or(input.len());
        let local = &input[start..at];
        let domain = &input[at + 1..end];
        if local.len() >= 1 && domain.contains('.') && !domain.starts_with('.') {
            spans.push((start, end));
        }
    }
    replace_spans(input, &mut spans, REDACTED)
}

fn redact_hex_secrets(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_hexdigit() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
            index += 1;
        }
        if index - start >= 64 {
            spans.push((start, index));
        }
    }
    replace_spans(input, &mut spans, REDACTED)
}

fn redact_phone_numbers(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'+' || index + 1 >= bytes.len() || !bytes[index + 1].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        let mut count = 0;
        while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b' ') {
            if bytes[index].is_ascii_digit() {
                count += 1;
            }
            index += 1;
        }
        if (8..=15).contains(&count) {
            spans.push((start, index));
        }
    }
    replace_spans(input, &mut spans, REDACTED)
}

fn replace_spans(input: &str, spans: &mut Vec<(usize, usize)>, replacement: &str) -> String {
    if spans.is_empty() {
        return input.to_string();
    }
    spans.sort_unstable();
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    for (start, end) in spans.iter().copied() {
        if start < cursor || end <= start {
            continue;
        }
        output.push_str(&input[cursor..start]);
        output.push_str(replacement);
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

// ─── Redacting log writer ────────────────────────────────────────────────────

/// `MakeWriter` that buffers one formatted event and redacts it before the
/// inner writer sees a byte. Each event gets its own buffer, so partial writes
/// cannot leak a PAN across calls.
#[derive(Clone)]
pub struct RedactingMakeWriter<W> {
    inner: Arc<Mutex<W>>,
}

impl<W> RedactingMakeWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl<'a, W: Write + Send + 'a> MakeWriter<'a> for RedactingMakeWriter<W> {
    type Writer = RedactingWriter<W>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: Arc::clone(&self.inner),
            buffer: Vec::new(),
        }
    }
}

pub struct RedactingWriter<W: Write> {
    inner: Arc<Mutex<W>>,
    buffer: Vec<u8>,
}

impl<W: Write> RedactingWriter<W> {
    fn flush_buffer(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let raw = String::from_utf8_lossy(&self.buffer).into_owned();
        // Structured events get key-aware redaction as well as value-pattern
        // redaction. Falling back to text keeps non-JSON diagnostics covered.
        let mut redacted = match serde_json::from_str::<serde_json::Value>(raw.trim_end()) {
            Ok(mut value) => {
                redact_json(&mut value);
                serde_json::to_string(&value).unwrap_or_else(|_| redact_text(&raw))
            }
            Err(_) => redact_text(&raw),
        };
        if raw.ends_with('\n') && !redacted.ends_with('\n') {
            redacted.push('\n');
        }
        if let Ok(mut inner) = self.inner.lock() {
            let _ = inner.write_all(redacted.as_bytes());
            let _ = inner.flush();
        }
        self.buffer.clear();
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer();
        Ok(())
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        self.flush_buffer();
    }
}

/// Production log writer: JSON tracing output written to stdout after
/// redaction (systemd/journald captures stdout and stderr). A single instance
/// is installed in `main`; existing binary tests read stdout for boot markers.
pub fn redacting_stdout() -> RedactingMakeWriter<io::Stdout> {
    RedactingMakeWriter::new(io::stdout())
}

// ─── Trace context and span export ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub sampled: bool,
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if getrandom::getrandom(&mut buf).is_err() {
        // The gateway is already unusable without entropy; still avoid an empty
        // id so a span remains correlatable.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (index, byte) in buf.iter_mut().enumerate() {
            *byte = ((nanos >> ((index % 16) * 8)) & 0xff) as u8;
        }
    }
    hex::encode(buf)
}

/// Create a fresh root trace context (W3C `traceparent` compatible).
pub fn new_trace_context() -> TraceContext {
    TraceContext {
        trace_id: random_hex(16),
        span_id: random_hex(8),
        sampled: true,
    }
}

/// Parse a W3C `traceparent: 00-<32 hex>-<16 hex>-<flags>` header.
pub fn parse_traceparent(header: &str) -> Option<TraceContext> {
    let parts: Vec<&str> = header.trim().split('-').collect();
    if parts.len() != 4 || parts[0] != "00" {
        return None;
    }
    if parts[1].len() != 32 || parts[2].len() != 16 {
        return None;
    }
    if !parts[1].chars().all(|c| c.is_ascii_hexdigit())
        || !parts[2].chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }
    if parts[1].chars().all(|c| c == '0') || parts[2].chars().all(|c| c == '0') {
        return None;
    }
    let flags = u8::from_str_radix(parts[3], 16).ok()?;
    Some(TraceContext {
        trace_id: parts[1].to_ascii_lowercase(),
        span_id: parts[2].to_ascii_lowercase(),
        sampled: flags & 0x01 == 1,
    })
}

#[derive(Debug)]
struct TraceExporter {
    path: PathBuf,
    file: Mutex<Option<std::fs::File>>,
}

impl TraceExporter {
    fn new(path: PathBuf) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok();
        Self {
            path,
            file: Mutex::new(file),
        }
    }

    fn write(&self, span: &SpanRecord) {
        let mut guard = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
        }
        if let Some(file) = guard.as_mut() {
            let _ = writeln!(file, "{}", serde_json::to_string(span).unwrap_or_default());
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct SpanRecord {
    timestamp_unix_ms: u128,
    trace_id: String,
    span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_span_id: Option<String>,
    name: String,
    duration_ms: f64,
    status: String,
    attributes: BTreeMap<String, String>,
    resource: BTreeMap<String, String>,
}

static TRACE_EXPORTER: OnceLock<Option<Arc<TraceExporter>>> = OnceLock::new();

/// Install the trace exporter from `TIRBASE_TRACE_EXPORT_PATH` once.
pub fn init_trace_exporter_from_env() {
    let _ = TRACE_EXPORTER.get_or_init(|| {
        std::env::var_os("TIRBASE_TRACE_EXPORT_PATH")
            .filter(|path| !path.is_empty())
            .map(|path| Arc::new(TraceExporter::new(PathBuf::from(path))))
    });
}

/// Test/deployment helper for an explicit export path.
pub fn init_trace_exporter(path: PathBuf) {
    let exporter = Arc::new(TraceExporter::new(path));
    let _ = TRACE_EXPORTER.set(Some(exporter));
}

fn trace_exporter() -> Option<Arc<TraceExporter>> {
    TRACE_EXPORTER.get().cloned().flatten()
}

/// An in-process span. Finish it with [`Span::finish`]; dropping without
/// finishing still exports a span with status `unset`.
#[derive(Debug)]
pub struct Span {
    context: TraceContext,
    parent_span_id: Option<String>,
    name: String,
    started: Instant,
    started_unix_ms: u128,
    attributes: BTreeMap<String, String>,
    exporter: Option<Arc<TraceExporter>>,
    finished: bool,
}

impl Span {
    pub fn start(name: impl Into<String>) -> Self {
        let context = new_trace_context();
        Self::with_context(name, context, None)
    }

    pub fn with_context(
        name: impl Into<String>,
        context: TraceContext,
        parent_span_id: Option<String>,
    ) -> Self {
        Self {
            context,
            parent_span_id,
            name: name.into(),
            started: Instant::now(),
            started_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            attributes: BTreeMap::new(),
            exporter: trace_exporter(),
            finished: false,
        }
    }

    /// Start a span from an incoming `traceparent` when present.
    pub fn from_traceparent(name: impl Into<String>, traceparent: Option<&str>) -> Self {
        match traceparent.and_then(parse_traceparent) {
            Some(parent) => {
                let mut context = new_trace_context();
                context.trace_id = parent.trace_id.clone();
                context.sampled = parent.sampled;
                Self::with_context(name, context, Some(parent.span_id))
            }
            None => Self::start(name),
        }
    }

    pub fn trace_id(&self) -> &str {
        &self.context.trace_id
    }

    pub fn span_id(&self) -> &str {
        &self.context.span_id
    }

    pub fn set_attr(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    pub fn finish(mut self, status: &str) {
        self.finish_inner(status);
    }

    fn finish_inner(&mut self, status: &str) {
        if self.finished {
            return;
        }
        self.finished = true;
        let Some(exporter) = self.exporter.clone() else {
            return;
        };
        let mut resource = BTreeMap::new();
        resource.insert("service.name".to_string(), "tirbase-gateway".to_string());
        resource.insert(
            "service.version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
        exporter.write(&SpanRecord {
            timestamp_unix_ms: self.started_unix_ms,
            trace_id: self.context.trace_id.clone(),
            span_id: self.context.span_id.clone(),
            parent_span_id: self.parent_span_id.clone(),
            name: self.name.clone(),
            duration_ms: self.started.elapsed().as_secs_f64() * 1000.0,
            status: status.to_string(),
            attributes: self.attributes.clone(),
            resource,
        });
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        self.finish_inner("unset");
    }
}

/// Emit a structured audit event in the JSON log. The security event log
/// remains the authoritative audit ledger; this is the correlated operational
/// copy that ships with logs/traces.
pub fn audit(action: &str, outcome: &str, attributes: &[(&str, &str)]) {
    tracing::info!(
        audit = true,
        action,
        outcome,
        attributes = ?attributes,
        "audit event"
    );
}

/// Duration helper for callers that measure with `Instant`.
pub fn elapsed(start: Instant) -> Duration {
    start.elapsed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redacted(input: &str) -> String {
        redact_text(input)
    }

    #[test]
    fn pan_detection_requires_luhn_and_redacts_separators() {
        // Visa test PAN.
        let out = redacted(r#"{"card":"4111 1111 1111 1111"}"#);
        assert!(!out.contains("4111"), "{out}");
        assert!(out.contains(REDACTED), "{out}");

        // 16 digits that fail Luhn are not silently described as a PAN, but a
        // sensitive JSON key is still redacted by redact_json.
        let mut value = serde_json::json!({"card_number": "1234567890123456"});
        redact_json(&mut value);
        assert_eq!(value["card_number"], REDACTED);
    }

    #[test]
    fn private_keys_bearer_tokens_emails_and_phones_are_redacted() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----";
        let out = redacted(pem);
        assert!(!out.contains("MIIEvQ"), "{out}");
        assert!(out.contains(REDACTED), "{out}");

        let out = redacted("Authorization: Bearer abcdefghijklmnopqrstuvwxyz");
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz"), "{out}");

        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
        let out = redacted(jwt);
        assert!(!out.contains("eyJhbGci"), "{out}");

        let out = redacted("contact ops@example.com or +44 7700 900123");
        assert!(!out.contains("ops@example.com"), "{out}");
        assert!(!out.contains("7700"), "{out}");

        let hex_key = "ab".repeat(32);
        let out = redacted(&format!("seed={hex_key}"));
        assert!(!out.contains(&hex_key), "{out}");
    }

    #[test]
    fn json_redaction_covers_personal_and_location_data() {
        let mut value = serde_json::json!({
            "tenant": "acme",
            "card": {"pan": "4111111111111111", "cvv": "123"},
            "customer": {"email": "a@b.co", "phone": "+15551234567"},
            "location": {"latitude": 51.5, "longitude": -0.12, "address": "1 Main St"},
            "note": "ship to 4111 1111 1111 1111",
            "numeric_card": 4111111111111111u64
        });
        redact_json(&mut value);
        assert_eq!(value["tenant"], "acme");
        assert_eq!(value["card"]["pan"], REDACTED);
        assert_eq!(value["card"]["cvv"], REDACTED);
        assert_eq!(value["customer"]["email"], REDACTED);
        assert_eq!(value["location"]["latitude"], REDACTED);
        assert_eq!(value["location"]["address"], REDACTED);
        assert!(!value["note"].as_str().unwrap().contains("4111"));
        assert_eq!(value["numeric_card"], REDACTED);
    }

    #[test]
    fn redacting_writer_cleans_a_full_json_log_line() {
        let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = RedactingMakeWriter::new(Shared(Arc::clone(&buffer))).make_writer();
        writer
            .write_all(
                br#"{"level":"INFO","pan":"4111-1111-1111-1111","email":"ops@example.com","msg":"ok"}
"#,
            )
            .unwrap();
        drop(writer);
        let logged = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(!logged.contains("4111"), "{logged}");
        assert!(!logged.contains("ops@example.com"), "{logged}");
        assert!(logged.contains("\"level\":\"INFO\""), "{logged}");
    }

    #[test]
    fn traceparent_round_trips_and_invalid_context_is_rejected() {
        let parent = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("valid traceparent");
        assert_eq!(parent.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(parent.span_id, "00f067aa0ba902b7");
        assert!(parent.sampled);
        assert!(
            parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_none()
        );
        assert!(parse_traceparent("garbage").is_none());
    }

    #[test]
    fn span_export_writes_correlated_json() {
        let dir = std::env::temp_dir().join(format!(
            "tirbase-trace-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("traces.jsonl");
        init_trace_exporter(path.clone());
        let mut span = Span::from_traceparent(
            "vertical.request",
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        span.set_attr("vertical", "cold-chain");
        span.finish("ok");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\""));
        assert!(body.contains("\"parent_span_id\":\"00f067aa0ba902b7\""));
        assert!(body.contains("\"name\":\"vertical.request\""));
        assert!(body.contains("\"status\":\"ok\""));
        let _ = std::fs::remove_dir_all(dir);
    }
}
