// SPDX-License-Identifier: Apache-2.0

//! Authentication for connectors: API keys, OAuth2 client credentials, mutual
//! TLS and HMAC webhook signatures.
//!
//! Secrets are held in [`SecretString`], which zeroizes on drop and prints as
//! `***` in `Debug`/`Display`; nothing here logs or stores a credential in
//! plaintext. HMAC-SHA256 is implemented in-crate (RFC 2104 over `sha2`) so the
//! crate keeps a small dependency surface.

use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use reqwest::blocking::{Client, RequestBuilder};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Domain-separation context for HMAC-signed webhook bodies.
pub const CONTEXT_HMAC_SIGNATURE: &str = "TirBase/v1/IntegrationHmac";

/// Default timestamp header for signed webhooks.
pub const DEFAULT_TIMESTAMP_HEADER: &str = "x-tirbase-timestamp";

/// Default signature header for signed webhooks.
pub const DEFAULT_SIGNATURE_HEADER: &str = "x-tirbase-signature";

/// Default tolerated clock skew for signed webhooks, in seconds.
pub const DEFAULT_HMAC_TOLERANCE_SECS: i64 = 300;

/// Minimum lead time before a cached OAuth2 token is refreshed, in seconds.
pub const TOKEN_REFRESH_MARGIN_SECS: i64 = 30;

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// A secret string that never appears in logs or debug output.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wrap a secret.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Borrow the secret for a request. Callers must not log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(***)")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

/// HMAC-SHA256 (RFC 2104) over `sha2`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] = key_block[index] ^ 0x36;
        opad[index] = key_block[index] ^ 0x5c;
    }
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    outer.update(opad);
    outer.update(inner_digest);
    let result = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Lower-case hex.
pub fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Constant-time byte comparison.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

// ---------------------------------------------------------------------------
// HMAC webhooks
// ---------------------------------------------------------------------------

/// HMAC-SHA256 request signing for webhooks.
#[derive(Clone)]
pub struct HmacWebhook {
    secret: SecretString,
    timestamp_header: String,
    signature_header: String,
    tolerance_secs: i64,
}

impl fmt::Debug for HmacWebhook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacWebhook")
            .field("secret", &"***")
            .field("timestamp_header", &self.timestamp_header)
            .field("signature_header", &self.signature_header)
            .field("tolerance_secs", &self.tolerance_secs)
            .finish()
    }
}

impl HmacWebhook {
    /// Sign with `secret` using the default headers and tolerance.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: SecretString::new(secret),
            timestamp_header: DEFAULT_TIMESTAMP_HEADER.to_string(),
            signature_header: DEFAULT_SIGNATURE_HEADER.to_string(),
            tolerance_secs: DEFAULT_HMAC_TOLERANCE_SECS,
        }
    }

    /// Override the timestamp and signature header names.
    pub fn with_headers(
        mut self,
        timestamp_header: impl Into<String>,
        signature_header: impl Into<String>,
    ) -> Self {
        self.timestamp_header = timestamp_header.into().to_ascii_lowercase();
        self.signature_header = signature_header.into().to_ascii_lowercase();
        self
    }

    /// Override the tolerated clock skew.
    pub fn with_tolerance(mut self, tolerance_secs: i64) -> Self {
        self.tolerance_secs = tolerance_secs.max(0);
        self
    }

    /// The timestamp header name.
    pub fn timestamp_header(&self) -> &str {
        &self.timestamp_header
    }

    /// The signature header name.
    pub fn signature_header(&self) -> &str {
        &self.signature_header
    }

    /// Signature for `body` at `timestamp_est`: `sha256=<hex>` over
    /// `"<timestamp>.<body>"`.
    pub fn sign(&self, timestamp_est: i64, body: &[u8]) -> String {
        let mut message = Vec::with_capacity(body.len() + 24);
        message.extend_from_slice(timestamp_est.to_string().as_bytes());
        message.push(b'.');
        message.extend_from_slice(body);
        format!(
            "sha256={}",
            hex_lower(&hmac_sha256(self.secret.expose().as_bytes(), &message))
        )
    }

    /// Whether `timestamp_est` is within the tolerated skew of `now_est`.
    pub fn timestamp_is_fresh(&self, timestamp_est: i64, now_est: i64) -> bool {
        now_est.saturating_sub(timestamp_est).abs() <= self.tolerance_secs
    }

    /// Verify a signature from a peer.
    pub fn verify(
        &self,
        timestamp_est: i64,
        body: &[u8],
        signature: &str,
        now_est: i64,
    ) -> Result<(), AuthError> {
        if !self.timestamp_is_fresh(timestamp_est, now_est) {
            return Err(AuthError::TimestampSkew {
                timestamp_est,
                now_est,
                tolerance_secs: self.tolerance_secs,
            });
        }
        let expected = self.sign(timestamp_est, body);
        if constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
            Ok(())
        } else {
            Err(AuthError::SignatureMismatch)
        }
    }
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

/// A static API key sent in a header.
#[derive(Clone)]
pub struct ApiKey {
    header: String,
    value: SecretString,
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("header", &self.header)
            .field("value", &"***")
            .finish()
    }
}

impl ApiKey {
    /// Build an API key auth, validating the header name.
    pub fn new(header: impl Into<String>, value: impl Into<String>) -> Result<Self, AuthError> {
        let header = header.into().to_ascii_lowercase();
        if header.is_empty()
            || !header.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(AuthError::Config(format!(
                "invalid API key header name {header:?}"
            )));
        }
        let value = SecretString::new(value);
        if value.is_empty() {
            return Err(AuthError::Config("API key value is empty".to_string()));
        }
        Ok(Self { header, value })
    }

    /// Header name.
    pub fn header(&self) -> &str {
        &self.header
    }
}

// ---------------------------------------------------------------------------
// OAuth2 client credentials
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct TokenState {
    token: Option<SecretString>,
    expires_est: i64,
}

/// An OAuth2 client-credentials token source with an in-memory cache.
pub struct OAuth2Client {
    token_url: String,
    client_id: String,
    client_secret: SecretString,
    scope: Option<String>,
    http: Client,
    state: Mutex<TokenState>,
}

impl fmt::Debug for OAuth2Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2Client")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"***")
            .field("scope", &self.scope)
            .finish()
    }
}

impl OAuth2Client {
    /// Build a client using a dedicated HTTP client.
    pub fn new(
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        scope: Option<String>,
        http: Client,
    ) -> Result<Self, AuthError> {
        let token_url = token_url.into();
        if !token_url.starts_with("http://") && !token_url.starts_with("https://") {
            return Err(AuthError::Config(format!(
                "token URL {token_url:?} must be http(s)"
            )));
        }
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(AuthError::Config("client_id is empty".to_string()));
        }
        let client_secret = SecretString::new(client_secret);
        if client_secret.is_empty() {
            return Err(AuthError::Config("client_secret is empty".to_string()));
        }
        Ok(Self {
            token_url,
            client_id,
            client_secret,
            scope,
            http,
            state: Mutex::new(TokenState::default()),
        })
    }

    /// Build a client with a default 30-second-timeout HTTP client.
    pub fn with_default_client(
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        scope: Option<String>,
    ) -> Result<Self, AuthError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| AuthError::Http(error.to_string()))?;
        Self::new(token_url, client_id, client_secret, scope, http)
    }

    /// The token endpoint.
    pub fn token_url(&self) -> &str {
        &self.token_url
    }

    /// A valid access token at `now_est`, fetching one when the cache is empty
    /// or near expiry.
    pub fn access_token(&self, now_est: i64) -> Result<String, AuthError> {
        {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(token) = state.token.as_ref() {
                if now_est < state.expires_est {
                    return Ok(token.expose().to_string());
                }
            }
        }

        let mut body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            urlencode(&self.client_id),
            urlencode(self.client_secret.expose())
        );
        if let Some(scope) = self.scope.as_ref() {
            body.push_str("&scope=");
            body.push_str(&urlencode(scope));
        }

        let response = self
            .http
            .post(&self.token_url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body)
            .send()
            .map_err(|error| AuthError::Http(error.to_string()))?;
        let status = response.status().as_u16();
        let text = response
            .text()
            .map_err(|error| AuthError::Http(error.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(AuthError::Status {
                status,
                detail: truncate(&text, 160),
            });
        }
        let parsed: serde_json::Value = serde_json::from_str(&text)
            .map_err(|error| AuthError::Config(format!("token response is not JSON: {error}")))?;
        let access_token = parsed
            .get("access_token")
            .and_then(|value| value.as_str())
            .ok_or_else(|| AuthError::Config("token response has no access_token".to_string()))?
            .to_string();
        if access_token.is_empty() {
            return Err(AuthError::Config(
                "token response has an empty access_token".to_string(),
            ));
        }
        let expires_in = parsed
            .get("expires_in")
            .and_then(|value| value.as_u64())
            .unwrap_or(3_600) as i64;
        let expires_est = now_est
            .saturating_add(expires_in)
            .saturating_sub(TOKEN_REFRESH_MARGIN_SECS);

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.token = Some(SecretString::new(access_token.clone()));
        state.expires_est = expires_est;
        Ok(access_token)
    }
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

// ---------------------------------------------------------------------------
// Mutual TLS
// ---------------------------------------------------------------------------

/// Client certificate material for mutual TLS.
///
/// Debug output reports lengths only; the PEM bytes are never printed.
#[derive(Clone)]
pub struct MutualTls {
    ca_pem: Vec<u8>,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

impl fmt::Debug for MutualTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutualTls")
            .field("ca_pem_bytes", &self.ca_pem.len())
            .field("cert_pem_bytes", &self.cert_pem.len())
            .field("key_pem_bytes", &"***")
            .finish()
    }
}

impl MutualTls {
    /// Build from PEM bytes.
    pub fn new(
        ca_pem: impl Into<Vec<u8>>,
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            ca_pem: ca_pem.into(),
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
        }
    }

    /// Build a reqwest client that presents the certificate and trusts only the
    /// supplied CA.
    ///
    /// Fails closed: malformed PEM or a missing key is an error, never a
    /// silently unauthenticated client.
    pub fn client_builder(&self, timeout: Duration) -> Result<Client, AuthError> {
        if self.ca_pem.is_empty() || self.cert_pem.is_empty() || self.key_pem.is_empty() {
            return Err(AuthError::InvalidMaterial(
                "CA, certificate and key PEM are all required for mutual TLS".to_string(),
            ));
        }
        let ca = reqwest::Certificate::from_pem(&self.ca_pem)
            .map_err(|error| AuthError::InvalidMaterial(format!("CA PEM: {error}")))?;

        let mut identity_pem = self.cert_pem.clone();
        if !identity_pem.ends_with(b"\n") {
            identity_pem.push(b'\n');
        }
        identity_pem.extend_from_slice(&self.key_pem);
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .map_err(|error| AuthError::InvalidMaterial(format!("client identity PEM: {error}")))?;

        Client::builder()
            .timeout(timeout)
            .add_root_certificate(ca)
            .identity(identity)
            .build()
            .map_err(|error| AuthError::InvalidMaterial(format!("TLS client: {error}")))
    }
}

// ---------------------------------------------------------------------------
// Auth selection
// ---------------------------------------------------------------------------

/// Authentication a connector applies to each request.
#[derive(Clone)]
pub enum Auth {
    /// No authentication.
    None,
    /// Static API key header.
    ApiKey(ApiKey),
    /// Static bearer token.
    Bearer(SecretString),
    /// OAuth2 client credentials, refreshed on demand.
    OAuth2(std::sync::Arc<OAuth2Client>),
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Auth::None => f.write_str("Auth::None"),
            Auth::ApiKey(_) => f.write_str("Auth::ApiKey(***)"),
            Auth::Bearer(_) => f.write_str("Auth::Bearer(***)"),
            Auth::OAuth2(_) => f.write_str("Auth::OAuth2(***)"),
        }
    }
}

impl Auth {
    /// Apply authentication to a request builder.
    pub fn apply(
        &self,
        builder: RequestBuilder,
        now_est: i64,
    ) -> Result<RequestBuilder, AuthError> {
        match self {
            Auth::None => Ok(builder),
            Auth::ApiKey(key) => Ok(builder.header(key.header.as_str(), key.value.expose())),
            Auth::Bearer(token) => Ok(builder.bearer_auth(token.expose())),
            Auth::OAuth2(client) => {
                let token = client.access_token(now_est)?;
                Ok(builder.bearer_auth(token))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why authentication failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The transport failed.
    Http(String),
    /// The peer returned a non-success status.
    Status {
        /// HTTP status.
        status: u16,
        /// Truncated response body.
        detail: String,
    },
    /// Configuration is unusable.
    Config(String),
    /// Certificate material is unusable.
    InvalidMaterial(String),
    /// A webhook timestamp is outside the tolerated skew.
    TimestampSkew {
        /// Timestamp presented by the caller.
        timestamp_est: i64,
        /// Current instant.
        now_est: i64,
        /// Tolerated skew.
        tolerance_secs: i64,
    },
    /// A webhook signature did not match.
    SignatureMismatch,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Http(detail) => write!(f, "auth transport: {detail}"),
            AuthError::Status { status, detail } => {
                write!(f, "auth endpoint returned {status}: {detail}")
            }
            AuthError::Config(detail) => write!(f, "auth config: {detail}"),
            AuthError::InvalidMaterial(detail) => write!(f, "TLS material: {detail}"),
            AuthError::TimestampSkew {
                timestamp_est,
                now_est,
                tolerance_secs,
            } => write!(
                f,
                "webhook timestamp {timestamp_est} outside ±{tolerance_secs}s of {now_est}"
            ),
            AuthError::SignatureMismatch => write!(f, "webhook signature mismatch"),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        hex_lower(bytes)
    }

    #[test]
    fn hmac_matches_rfc4231_vectors() {
        // RFC 4231 test case 1.
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test case 2.
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6 (key longer than the block size).
        let key = [0xaa; 131];
        assert_eq!(
            hex(&hmac_sha256(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn signatures_bind_the_timestamp_and_reject_skew() {
        let webhook = HmacWebhook::new("s3cret").with_tolerance(30);
        let signature = webhook.sign(1_000, b"{\"a\":1}");
        assert!(signature.starts_with("sha256="));
        webhook
            .verify(1_000, b"{\"a\":1}", &signature, 1_010)
            .expect("fresh signature");
        assert_eq!(
            webhook
                .verify(1_000, b"{\"a\":1}", &signature, 1_500)
                .expect_err("stale"),
            AuthError::TimestampSkew {
                timestamp_est: 1_000,
                now_est: 1_500,
                tolerance_secs: 30
            }
        );
        assert_eq!(
            webhook
                .verify(1_000, b"{\"a\":2}", &signature, 1_000)
                .expect_err("tampered body"),
            AuthError::SignatureMismatch
        );
        // Moving the timestamp invalidates the signature too.
        assert_eq!(
            webhook
                .verify(1_001, b"{\"a\":1}", &signature, 1_001)
                .expect_err("timestamp is signed"),
            AuthError::SignatureMismatch
        );
    }

    #[test]
    fn secrets_are_redacted_everywhere() {
        let secret = SecretString::new("super-secret-token");
        assert!(!format!("{secret:?}").contains("super-secret"));
        assert!(!format!("{secret}").contains("super-secret"));
        let key = ApiKey::new("x-api-key", "key-value-123").expect("key");
        assert!(!format!("{key:?}").contains("key-value-123"));
        assert_eq!(key.header(), "x-api-key");
        let webhook = HmacWebhook::new("webhook-secret");
        assert!(!format!("{webhook:?}").contains("webhook-secret"));
        let auth = Auth::Bearer(SecretString::new("bearer-secret"));
        assert!(!format!("{auth:?}").contains("bearer-secret"));
    }

    #[test]
    fn mutual_tls_fails_closed_on_bad_material() {
        let good = MutualTls::new(b"ca", b"cert", b"key");
        assert!(!format!("{good:?}").contains("key\""));
        let result = good.client_builder(Duration::from_secs(5));
        assert!(matches!(result, Err(AuthError::InvalidMaterial(_))));
        let empty = MutualTls::new(b"".to_vec(), b"".to_vec(), b"".to_vec());
        assert!(matches!(
            empty.client_builder(Duration::from_secs(5)),
            Err(AuthError::InvalidMaterial(_))
        ));
    }

    #[test]
    fn api_key_header_names_are_validated() {
        assert!(ApiKey::new("bad header", "v").is_err());
        assert!(ApiKey::new("x-key", "").is_err());
        assert!(ApiKey::new("x-key", "v").is_ok());
        assert!(matches!(
            OAuth2Client::with_default_client("ftp://token", "id", "secret", None),
            Err(AuthError::Config(_))
        ));
    }

    #[test]
    fn constant_time_comparison_is_exact() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
