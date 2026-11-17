// SPDX-License-Identifier: Apache-2.0

//! Mock vendor server and HTTP contract fixture.
//!
//! A real HTTP server on a loopback port that enforces the authentication and
//! idempotency rules a vendor is supposed to enforce, records every request, and
//! can inject failures. Tests (and integrators) point a connector at
//! [`MockVendorServer::base_url`] and assert what the vendor saw.
//!
//! It speaks enough HTTP/1.1 for a single request per connection: no chunked
//! bodies, no keep-alive, no TLS.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::auth::{
    constant_time_eq, hex_lower, hmac_sha256, DEFAULT_SIGNATURE_HEADER, DEFAULT_TIMESTAMP_HEADER,
};

/// One request the mock received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockRequest {
    /// Method.
    pub method: String,
    /// Path (query string retained).
    pub path: String,
    /// Lower-cased header names.
    pub headers: BTreeMap<String, String>,
    /// Body, decoded as UTF-8.
    pub body: String,
}

impl MockRequest {
    /// A header value by lower-case name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// How the mock vendor authenticates and behaves.
#[derive(Debug, Clone)]
pub struct MockVendorConfig {
    /// Required `(header, value)` API key.
    pub api_key: Option<(String, String)>,
    /// Required bearer token.
    pub bearer_token: Option<String>,
    /// Required HMAC-SHA256 webhook secret.
    pub hmac_secret: Option<String>,
    /// Clock used to check HMAC skew; `None` skips only the skew check.
    pub hmac_now_est: Option<i64>,
    /// Tolerated HMAC skew.
    pub hmac_tolerance_secs: i64,
    /// Accepted OAuth2 client `(id, secret)`.
    pub oauth_client: Option<(String, String)>,
    /// Number of data requests to reject with `503` before accepting.
    pub fail_first: usize,
}

impl Default for MockVendorConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            bearer_token: None,
            hmac_secret: None,
            hmac_now_est: None,
            hmac_tolerance_secs: 300,
            oauth_client: None,
            fail_first: 0,
        }
    }
}

impl MockVendorConfig {
    /// Require an API key header.
    pub fn with_api_key(mut self, header: impl Into<String>, value: impl Into<String>) -> Self {
        self.api_key = Some((header.into(), value.into()));
        self
    }

    /// Require a bearer token.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Require HMAC-SHA256 signatures.
    pub fn with_hmac_secret(mut self, secret: impl Into<String>) -> Self {
        self.hmac_secret = Some(secret.into());
        self
    }

    /// Accept OAuth2 client credentials at `/oauth/token`.
    pub fn with_oauth_client(
        mut self,
        client_id: impl Into<String>,
        secret: impl Into<String>,
    ) -> Self {
        self.oauth_client = Some((client_id.into(), secret.into()));
        self
    }

    /// Reject the first `count` authenticated data requests with `503`.
    pub fn with_fail_first(mut self, count: usize) -> Self {
        self.fail_first = count;
        self
    }
}

/// Why the mock server could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockError {
    detail: String,
}

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mock vendor server: {}", self.detail)
    }
}

impl std::error::Error for MockError {}

struct MockState {
    config: MockVendorConfig,
    requests: Mutex<Vec<MockRequest>>,
    records: Mutex<BTreeMap<String, usize>>,
    failures: AtomicUsize,
    shutdown: AtomicBool,
}

/// A loopback mock vendor.
pub struct MockVendorServer {
    address: SocketAddr,
    state: Arc<MockState>,
    handle: Option<JoinHandle<()>>,
}

impl MockVendorServer {
    /// Start a server with `config`.
    pub fn start(config: MockVendorConfig) -> Result<Self, MockError> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(io_error)?;
        let address = listener.local_addr().map_err(io_error)?;
        let state = Arc::new(MockState {
            failures: AtomicUsize::new(config.fail_first),
            config,
            requests: Mutex::new(Vec::new()),
            records: Mutex::new(BTreeMap::new()),
            shutdown: AtomicBool::new(false),
        });
        let accept_state = Arc::clone(&state);
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if accept_state.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(stream) => {
                        let connection_state = Arc::clone(&accept_state);
                        std::thread::spawn(move || {
                            handle_connection(stream, connection_state);
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            state,
            handle: Some(handle),
        })
    }

    /// Origin of the mock, e.g. `http://127.0.0.1:49321`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Data endpoint URL.
    pub fn events_url(&self) -> String {
        format!("{}/api/events", self.base_url())
    }

    /// Webhook endpoint URL.
    pub fn webhook_url(&self) -> String {
        format!("{}/webhook", self.base_url())
    }

    /// Every request received, oldest first.
    pub fn requests(&self) -> Vec<MockRequest> {
        self.state
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Requests whose path starts with `path_prefix`.
    pub fn requests_for(&self, path_prefix: &str) -> Vec<MockRequest> {
        self.requests()
            .into_iter()
            .filter(|request| request.path.starts_with(path_prefix))
            .collect()
    }

    /// Distinct downstream records created.
    pub fn record_count(&self) -> usize {
        self.state
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Whether a record exists for `idempotency_key`.
    pub fn has_record(&self, idempotency_key: &str) -> bool {
        self.state
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(idempotency_key)
    }

    /// Replace the failure budget.
    pub fn set_failures(&self, count: usize) {
        self.state.failures.store(count, Ordering::SeqCst);
    }

    /// Stop injecting failures.
    pub fn clear_failures(&self) {
        self.set_failures(0);
    }

    /// Stop the accept loop and join it.
    pub fn stop(&mut self) {
        if self.handle.is_none() {
            return;
        }
        self.state.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(500));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MockVendorServer {
    fn drop(&mut self) {
        self.stop();
    }
}

impl std::fmt::Debug for MockVendorServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockVendorServer")
            .field("base_url", &self.base_url())
            .finish()
    }
}

fn io_error(error: std::io::Error) -> MockError {
    MockError {
        detail: error.to_string(),
    }
}

fn handle_connection(mut stream: TcpStream, state: Arc<MockState>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    let responses = respond(&state, &request);
    state
        .requests
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(request);
    write_response(&mut stream, responses.0, &responses.1);
}

fn respond(state: &MockState, request: &MockRequest) -> (u16, String) {
    if request.method == "GET" && request.path == "/health" {
        return (200, r#"{"status":"ok"}"#.to_string());
    }
    if request.method == "POST" && request.path == "/oauth/token" {
        return oauth_token(state, &request.body);
    }
    if request.method == "POST" && (request.path == "/api/events" || request.path == "/webhook") {
        if let Some(rejection) = authorize(state, request) {
            return rejection;
        }
        if state
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return (503, r#"{"error":"injected failure"}"#.to_string());
        }
        let key = request
            .header("idempotency-key")
            .unwrap_or_default()
            .to_string();
        let mut records = state
            .records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next = records.get(&key).copied().unwrap_or(0) + 1;
        records.insert(key.clone(), next);
        if next > 1 {
            return (
                409,
                format!(r#"{{"duplicate":true,"id":"{key}","count":{next}}}"#),
            );
        }
        return (
            201,
            format!(r#"{{"duplicate":false,"id":"{key}","count":{next}}}"#),
        );
    }
    (404, r#"{"error":"not found"}"#.to_string())
}

fn oauth_token(state: &MockState, body: &str) -> (u16, String) {
    let Some((expected_id, expected_secret)) = state.config.oauth_client.as_ref() else {
        return (404, r#"{"error":"oauth disabled"}"#.to_string());
    };
    let mut client_id = None;
    let mut client_secret = None;
    let mut grant_type = None;
    for pair in body.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        match name {
            "client_id" => client_id = Some(percent_decode(value)),
            "client_secret" => client_secret = Some(percent_decode(value)),
            "grant_type" => grant_type = Some(percent_decode(value)),
            _ => {}
        }
    }
    let matches = grant_type.as_deref() == Some("client_credentials")
        && client_id.as_deref() == Some(expected_id.as_str())
        && client_secret
            .as_deref()
            .map(|secret| constant_time_eq(secret.as_bytes(), expected_secret.as_bytes()))
            .unwrap_or(false);
    if !matches {
        return (401, r#"{"error":"invalid_client"}"#.to_string());
    }
    (
        200,
        format!(
            r#"{{"access_token":"mock-token-{expected_id}","token_type":"Bearer","expires_in":3600}}"#
        ),
    )
}

fn authorize(state: &MockState, request: &MockRequest) -> Option<(u16, String)> {
    if let Some((header, expected)) = state.config.api_key.as_ref() {
        let presented = request.header(header).unwrap_or_default();
        if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
            return Some((401, r#"{"error":"invalid api key"}"#.to_string()));
        }
    }
    if let Some(expected) = state.config.bearer_token.as_ref() {
        let presented = request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
            return Some((401, r#"{"error":"invalid bearer token"}"#.to_string()));
        }
    }
    if let Some(secret) = state.config.hmac_secret.as_ref() {
        let timestamp = request
            .header(DEFAULT_TIMESTAMP_HEADER)
            .and_then(|value| value.parse::<i64>().ok());
        let signature = request.header(DEFAULT_SIGNATURE_HEADER).unwrap_or_default();
        let Some(timestamp) = timestamp else {
            return Some((401, r#"{"error":"missing timestamp"}"#.to_string()));
        };
        if let Some(now_est) = state.config.hmac_now_est {
            if now_est.saturating_sub(timestamp).abs() > state.config.hmac_tolerance_secs {
                return Some((401, r#"{"error":"stale timestamp"}"#.to_string()));
            }
        }
        let mut message = Vec::new();
        message.extend_from_slice(timestamp.to_string().as_bytes());
        message.push(b'.');
        message.extend_from_slice(request.body.as_bytes());
        let expected = format!(
            "sha256={}",
            hex_lower(&hmac_sha256(secret.as_bytes(), &message))
        );
        if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
            return Some((401, r#"{"error":"bad signature"}"#.to_string()));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_request(stream: &mut TcpStream) -> Option<MockRequest> {
    let mut buffer = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 2048];
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_header_end(&buffer) {
            break position;
        }
        if buffer.len() > 64 * 1024 {
            return None;
        }
    };

    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 2048];
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Some(MockRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn write_response(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding_handles_encoded_credentials() {
        assert_eq!(percent_decode("client%20id"), "client id");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
    }
}
