// SPDX-License-Identifier: AGPL-3.0-only

//! MQTT 3.1.1 bridge driver and TLS-only transport (CLAIM-34.2, PV-10.7, CC-07).
//!
//! The low-level [`MqttTlsClient`] performs a real `rustls` handshake and speaks
//! MQTT 3.1.1 packets over the resulting TLS stream. There is no public
//! plaintext connect path, and a plaintext TCP server is rejected because the
//! TLS handshake fails.
//!
//! [`MqttBridgeClient`] is the sensor bridge on top of that transport. It adds
//! the properties the bridge contract requires:
//!
//! * **TLS only.** The bridge constructor takes [`MqttTlsTrust`] — a set of CA
//!   roots — and builds its own `rustls::ClientConfig` from it. No public API
//!   accepts a caller-supplied verifier, so certificate verification cannot be
//!   turned off through the bridge (see `docs/drivers/mqtt_sensor_bridge.md`).
//! * **Per-device credentials.** [`MqttDeviceCredentials`] are sent in the
//!   CONNECT packet only. `Debug` redacts the password and it is never logged.
//! * **Allowlisted topics.** Subscriptions are built from
//!   [`MqttTopicAllowlist`]; wildcard filters require an explicit opt-in and are
//!   rejected by default. Incoming messages on any other topic are rejected
//!   even if a broker sends them.
//! * **Bounded payloads.** Packet bodies are rejected from the MQTT remaining
//!   length *before* allocation, then the payload is checked against
//!   [`MqttBridgeConfig::max_payload_bytes`] and the schema in
//!   [`parse_sensor_payload`].
//! * **Replay protection.** [`MqttReplayGuard`] rejects a repeated or
//!   out-of-order `seq` per device and timestamps outside a bounded window.
//! * **Bounded outage.** Every read carries a deadline computed from the
//!   caller-supplied [`MqttClockFn`]; an unresponsive broker produces
//!   [`MqttBridgeError::Timeout`] instead of blocking a device read forever.
//!
//! The wire schema is documented in `docs/drivers/mqtt_sensor_bridge.md` and
//! summarised on [`MqttSensorReading`].

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use tirbase_driver_api::driver_trait::DriverError;
use tirbase_types::{FixedPointValue, UNIT_DEG_C, UNIT_PERCENT};

// The pure MQTT packet codec lives in the Apache-2.0 `tirbase-driver-api`
// crate. Re-exported here for compatibility.
pub use tirbase_driver_api::mqtt_codec::*;

/// Caller-supplied monotonic millisecond clock shared with the other drivers.
pub type MqttClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Default accepted payload size for one sensor message.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 512;
/// Hard ceiling for `MqttBridgeConfig::max_payload_bytes`.
pub const MAX_PAYLOAD_BYTES_LIMIT: usize = 4096;
/// Maximum device identifier length in the payload schema.
pub const MAX_DEVICE_ID_LEN: usize = 64;
/// Maximum number of allowlisted subscriptions.
pub const MAX_TOPIC_ALLOWLIST_ENTRIES: usize = 64;
/// Default timestamp window accepted by the replay guard (5 minutes).
pub const DEFAULT_REPLAY_WINDOW_MS: u64 = 300_000;
/// Clock skew tolerated on the "newer than now" side.
pub const MAX_FUTURE_SKEW_MS: u64 = 60_000;
/// Maximum tracked devices in the replay guard.
pub const MAX_REPLAY_ENTRIES: usize = 1024;
/// Schema version carried in the `v` field.
pub const MQTT_SENSOR_SCHEMA_VERSION: u8 = 1;

/// Connection security / protocol error.
#[derive(Debug)]
pub enum MqttError {
    PlainTextRejected {
        uri: String,
    },
    InvalidUri(String),
    Io(io::Error),
    Tls(String),
    Protocol(String),
    /// Inbound packet is larger than the configured limit; rejected from the
    /// remaining-length header before the body is allocated.
    PayloadTooLarge {
        len: usize,
        max: usize,
    },
}

impl fmt::Display for MqttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MqttError::PlainTextRejected { uri } => write!(
                f,
                "plain-text MQTT connection rejected for '{uri}'; use mqtts:// and TLS"
            ),
            MqttError::InvalidUri(m) => write!(f, "invalid MQTT URI: {m}"),
            MqttError::Io(e) => write!(f, "mqtt io error: {e}"),
            MqttError::Tls(m) => write!(f, "mqtt TLS error: {m}"),
            MqttError::Protocol(m) => write!(f, "mqtt protocol error: {m}"),
            MqttError::PayloadTooLarge { len, max } => {
                write!(f, "mqtt packet of {len} bytes exceeds limit {max}")
            }
        }
    }
}

impl std::error::Error for MqttError {}

impl From<io::Error> for MqttError {
    fn from(e: io::Error) -> Self {
        MqttError::Io(e)
    }
}

impl From<DriverError> for MqttError {
    fn from(e: DriverError) -> Self {
        MqttError::Protocol(e.to_string())
    }
}

/// Public marker kept for compatibility with existing tests/callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttSecurityError;
impl fmt::Display for MqttSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "plain-text MQTT/TLS validation failed")
    }
}
impl std::error::Error for MqttSecurityError {}

/// Configuration for an MQTT bridge endpoint. Only TLS endpoints are accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttConnectConfig {
    pub uri: String,
    pub client_id: String,
    pub tls_configured: bool,
}

impl MqttConnectConfig {
    /// Validates URI/TLS intent. Does not replace a real handshake.
    pub fn validate_tls_required(&self) -> Result<(), MqttError> {
        let lower = self.uri.trim().to_ascii_lowercase();
        if lower.starts_with("mqtt://") || lower.starts_with("tcp://") || lower.starts_with("ws://")
        {
            return Err(MqttError::PlainTextRejected {
                uri: self.uri.clone(),
            });
        }
        if !self.tls_configured
            && !(lower.starts_with("mqtts://")
                || lower.starts_with("ssl://")
                || lower.starts_with("tcps://")
                || lower.starts_with("wss://"))
        {
            return Err(MqttError::Tls(
                "MQTT TLS configuration is required (use mqtts://)".into(),
            ));
        }
        Ok(())
    }
}

/// Marker proving the endpoint passed TLS-only validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsValidatedEndpoint {
    pub uri: String,
    pub client_id: String,
}

pub fn connect_tls_only(config: &MqttConnectConfig) -> Result<TlsValidatedEndpoint, MqttError> {
    config.validate_tls_required()?;
    Ok(TlsValidatedEndpoint {
        uri: config.uri.clone(),
        client_id: config.client_id.clone(),
    })
}

/// Parse `mqtts://host:port` (or `ssl://`/`tcps://`) into host/port.
pub fn parse_mqtts_uri(uri: &str) -> Result<(String, u16), MqttError> {
    let lower = uri.trim().to_ascii_lowercase();
    if lower.starts_with("mqtt://") || lower.starts_with("tcp://") || lower.starts_with("ws://") {
        return Err(MqttError::PlainTextRejected {
            uri: uri.to_string(),
        });
    }
    let rest = uri
        .trim()
        .strip_prefix("mqtts://")
        .or_else(|| uri.trim().strip_prefix("ssl://"))
        .or_else(|| uri.trim().strip_prefix("tcps://"))
        .ok_or_else(|| MqttError::InvalidUri("expected mqtts://, ssl://, or tcps://".into()))?;
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| MqttError::InvalidUri(format!("invalid port '{p}'")))?,
        ),
        None => (rest.to_string(), 8883),
    };
    if host.is_empty() {
        return Err(MqttError::InvalidUri("missing host".into()));
    }
    Ok((host, port))
}

/// Install rustls ring crypto provider if not already installed (test/CLI helper).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a rustls client config that trusts `roots` (for tests/custom CAs) plus
/// webpki roots when `include_webpki` is true.
pub fn client_config_with_roots(
    extra_roots: impl IntoIterator<Item = rustls::pki_types::CertificateDer<'static>>,
    include_webpki: bool,
) -> Result<Arc<ClientConfig>, MqttError> {
    let mut roots = RootCertStore::empty();
    if include_webpki {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    for cert in extra_roots {
        roots
            .add(cert)
            .map_err(|e| MqttError::Tls(format!("add root: {e}")))?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Bridge TLS trust
// ---------------------------------------------------------------------------

/// CA roots the bridge is allowed to trust.
///
/// This is the only TLS input the bridge accepts. It holds roots, never a
/// verifier: there is no "skip verification" switch, so the bridge always
/// performs full certificate and hostname verification against the configured
/// roots. Keeping the config construction here (rather than taking a
/// `rustls::ClientConfig`) is what makes that a property of the public API
/// instead of a convention.
#[derive(Debug, Clone, Default)]
pub struct MqttTlsTrust {
    extra_roots: Vec<CertificateDer<'static>>,
    include_webpki_roots: bool,
}

impl MqttTlsTrust {
    /// Trust only the compiled-in webpki roots (public brokers).
    pub fn webpki() -> Self {
        Self {
            extra_roots: Vec::new(),
            include_webpki_roots: true,
        }
    }

    /// Trust only the supplied CA certificates (private brokers, tests).
    pub fn with_roots(roots: impl IntoIterator<Item = CertificateDer<'static>>) -> Self {
        Self {
            extra_roots: roots.into_iter().collect(),
            include_webpki_roots: false,
        }
    }

    /// Trust the supplied CA certificates plus the webpki roots.
    pub fn with_roots_and_webpki(roots: impl IntoIterator<Item = CertificateDer<'static>>) -> Self {
        Self {
            extra_roots: roots.into_iter().collect(),
            include_webpki_roots: true,
        }
    }

    /// Whether the compiled-in webpki roots are trusted.
    pub fn includes_webpki_roots(&self) -> bool {
        self.include_webpki_roots
    }

    /// Number of additionally supplied CA roots.
    pub fn extra_root_count(&self) -> usize {
        self.extra_roots.len()
    }

    /// Build the client configuration used for one bridge connection.
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, MqttError> {
        if self.extra_roots.is_empty() && !self.include_webpki_roots {
            return Err(MqttError::Tls(
                "MQTT bridge requires at least one trusted CA root".into(),
            ));
        }
        client_config_with_roots(self.extra_roots.clone(), self.include_webpki_roots)
    }
}

// ---------------------------------------------------------------------------
// Per-device credentials
// ---------------------------------------------------------------------------

/// Username/password pair presented on behalf of one device.
///
/// The password is only ever written into the CONNECT packet. `Debug` prints
/// `<redacted>` and the value is not retained in any error or log line.
#[derive(Clone)]
pub struct MqttDeviceCredentials {
    username: String,
    password: String,
}

impl MqttDeviceCredentials {
    /// Validate and store a device credential pair.
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, MqttBridgeError> {
        let username = username.into();
        let password = password.into();
        if username.is_empty() || password.is_empty() {
            return Err(MqttBridgeError::InvalidConfig(
                "MQTT credentials must be non-empty",
            ));
        }
        if username.len() > u16::MAX as usize || password.len() > u16::MAX as usize {
            return Err(MqttBridgeError::InvalidConfig(
                "MQTT credentials must fit an MQTT string field",
            ));
        }
        if username.chars().any(char::is_control) || password.chars().any(char::is_control) {
            return Err(MqttBridgeError::InvalidConfig(
                "MQTT credentials must not contain control characters",
            ));
        }
        Ok(Self { username, password })
    }

    /// Username sent in CONNECT.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Password sent in CONNECT. Deliberately crate-private to keep secrets out
    /// of other crates' logs; the bridge reads it when building CONNECT.
    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for MqttDeviceCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MqttDeviceCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Topic allowlist
// ---------------------------------------------------------------------------

/// Whether `filter` matches `topic` using MQTT `+` (one level) and `#`
/// (remaining levels, last position only) wildcards.
///
/// Exact equality is checked first, so a literal topic that happens to contain
/// no wildcard characters always matches itself.
pub fn mqtt_topic_matches(filter: &str, topic: &str) -> bool {
    if filter == topic {
        return true;
    }
    let filter_levels: Vec<&str> = filter.split('/').collect();
    let topic_levels: Vec<&str> = topic.split('/').collect();
    let mut index = 0;
    while index < filter_levels.len() {
        match filter_levels[index] {
            "#" => return index + 1 == filter_levels.len(),
            "+" => {
                if topic_levels.len() <= index {
                    return false;
                }
            }
            level => {
                if topic_levels.get(index) != Some(&level) {
                    return false;
                }
            }
        }
        index += 1;
    }
    topic_levels.len() == filter_levels.len()
}

fn validate_topic_filter(filter: &str, allow_wildcards: bool) -> Result<(), MqttBridgeError> {
    if filter.is_empty() || filter.len() > MAX_TOPIC_LEN {
        return Err(MqttBridgeError::InvalidConfig(
            "MQTT topic filter must be 1..=512 bytes",
        ));
    }
    if filter.chars().any(char::is_control) {
        return Err(MqttBridgeError::InvalidConfig(
            "MQTT topic filter must not contain control characters",
        ));
    }
    if !allow_wildcards && (filter.contains('#') || filter.contains('+')) {
        return Err(MqttBridgeError::WildcardTopicRejected(filter.to_string()));
    }
    for (index, level) in filter.split('/').enumerate() {
        if level.contains('#') && level != "#" {
            return Err(MqttBridgeError::WildcardTopicRejected(filter.to_string()));
        }
        if level.contains('+') && level != "+" {
            return Err(MqttBridgeError::WildcardTopicRejected(filter.to_string()));
        }
        let _ = index;
    }
    if filter.contains('#') && !filter.ends_with('#') {
        return Err(MqttBridgeError::WildcardTopicRejected(filter.to_string()));
    }
    Ok(())
}

/// Topics this bridge may subscribe to and accept.
///
/// Exact filters only by default. Wildcards require [`Self::with_wildcards`],
/// which is an explicit, reviewed choice at the call site: a wildcard
/// subscription lets any publisher on the broker inject readings, so it is
/// never the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttTopicAllowlist {
    filters: Vec<String>,
    allow_wildcards: bool,
}

impl MqttTopicAllowlist {
    /// Build an exact-match allowlist. Wildcard filters are rejected.
    pub fn exact(
        filters: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, MqttBridgeError> {
        Self::build(filters, false)
    }

    /// Build an allowlist that may contain wildcard filters.
    pub fn with_wildcards(
        filters: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, MqttBridgeError> {
        Self::build(filters, true)
    }

    fn build(
        filters: impl IntoIterator<Item = impl Into<String>>,
        allow_wildcards: bool,
    ) -> Result<Self, MqttBridgeError> {
        let mut out = Vec::new();
        for filter in filters {
            let filter = filter.into();
            validate_topic_filter(&filter, allow_wildcards)?;
            if out.contains(&filter) {
                return Err(MqttBridgeError::InvalidConfig(
                    "duplicate MQTT topic filter in allowlist",
                ));
            }
            out.push(filter);
        }
        if out.is_empty() {
            return Err(MqttBridgeError::InvalidConfig(
                "MQTT topic allowlist must not be empty",
            ));
        }
        if out.len() > MAX_TOPIC_ALLOWLIST_ENTRIES {
            return Err(MqttBridgeError::InvalidConfig(
                "MQTT topic allowlist exceeds the entry limit",
            ));
        }
        Ok(Self {
            filters: out,
            allow_wildcards,
        })
    }

    /// Whether this allowlist permits wildcard filters.
    pub fn allows_wildcards(&self) -> bool {
        self.allow_wildcards
    }

    /// The configured topic filters, in subscription order.
    pub fn filters(&self) -> &[String] {
        &self.filters
    }

    /// Whether an inbound topic is allowed.
    pub fn allows(&self, topic: &str) -> bool {
        self.filters.iter().any(|filter| {
            filter == topic || (self.allow_wildcards && mqtt_topic_matches(filter, topic))
        })
    }
}

// ---------------------------------------------------------------------------
// Payload schema
// ---------------------------------------------------------------------------

/// A schema violation in a sensor payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    /// Payload exceeds the configured byte limit.
    TooLarge { len: usize, max: usize },
    /// Empty payload.
    Empty,
    /// Payload is not valid UTF-8.
    NotUtf8,
    /// Fields are not `key=value` pairs separated by `;`.
    Malformed,
    /// More than the six allowed fields.
    TooManyFields,
    /// Field not defined by the schema.
    UnknownField(String),
    /// Field appears more than once.
    DuplicateField(String),
    /// Required field is absent.
    MissingField(&'static str),
    /// `v` values other than `1`.
    UnsupportedVersion(String),
    /// `device` is empty, too long, or contains disallowed characters.
    InvalidDeviceId,
    /// `seq` or `ts` is not a decimal integer.
    InvalidInteger(&'static str),
    /// `seq` is zero or a value is outside its physical range.
    OutOfRange(&'static str),
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadError::TooLarge { len, max } => {
                write!(f, "payload of {len} bytes exceeds limit {max}")
            }
            PayloadError::Empty => write!(f, "payload is empty"),
            PayloadError::NotUtf8 => write!(f, "payload is not valid UTF-8"),
            PayloadError::Malformed => write!(f, "payload is not a key=value field list"),
            PayloadError::TooManyFields => write!(f, "payload has more than six fields"),
            PayloadError::UnknownField(field) => write!(f, "unknown payload field '{field}'"),
            PayloadError::DuplicateField(field) => write!(f, "duplicate payload field '{field}'"),
            PayloadError::MissingField(field) => write!(f, "missing payload field '{field}'"),
            PayloadError::UnsupportedVersion(version) => {
                write!(f, "unsupported payload schema version '{version}'")
            }
            PayloadError::InvalidDeviceId => write!(f, "invalid device identifier"),
            PayloadError::InvalidInteger(field) => write!(f, "field '{field}' is not an integer"),
            PayloadError::OutOfRange(field) => write!(f, "field '{field}' is out of range"),
        }
    }
}

impl std::error::Error for PayloadError {}

/// One validated sensor message.
///
/// # Schema (version 1)
///
/// Six `key=value` fields separated by `;`, ASCII, in any order:
///
/// ```text
/// v=1;device=<id>;seq=<u64>;ts=<unix-ms>;temp_mc=<i64>;rh_cp=<u32>
/// ```
///
/// | Field | Meaning | Constraint |
/// |---|---|---|
/// | `v` | schema version | exactly `1` |
/// | `device` | device identifier | 1..=64 of `[A-Za-z0-9._:-]` |
/// | `seq` | per-device sequence number | decimal `u64`, `>= 1`, strictly increasing |
/// | `ts` | source timestamp | decimal Unix milliseconds |
/// | `temp_mc` | temperature, milli-°C | −100,000..=200,000 |
/// | `rh_cp` | relative humidity, centi-%RH | 0..=10,000 |
///
/// Unknown, duplicate, truncated, non-UTF-8, and oversized payloads are
/// rejected with [`PayloadError`] before any value reaches the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttSensorReading {
    /// Device identifier from the payload (not the topic).
    pub device_id: String,
    /// Schema version that produced this reading (always 1 today).
    pub schema_version: u8,
    /// Per-device sequence number used for replay protection.
    pub sequence: u64,
    /// Source timestamp in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Temperature in milli-°C (`UNIT_DEG_C`, exponent −3).
    pub temperature: FixedPointValue,
    /// Relative humidity in centi-%RH (`UNIT_PERCENT`, exponent −2).
    pub humidity: FixedPointValue,
    /// QoS the message arrived with.
    pub qos: MqttQoS,
}

impl MqttSensorReading {
    /// Encode this reading in the version 1 schema (canonical field order).
    pub fn encode(&self) -> Vec<u8> {
        format!(
            "v={};device={};seq={};ts={};temp_mc={};rh_cp={}",
            self.schema_version,
            self.device_id,
            self.sequence,
            self.timestamp_ms,
            self.temperature.mantissa,
            self.humidity.mantissa
        )
        .into_bytes()
    }
}

fn is_device_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')
}

fn parse_decimal_u64(field: &'static str, value: &str) -> Result<u64, PayloadError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PayloadError::InvalidInteger(field));
    }
    value
        .parse::<u64>()
        .map_err(|_| PayloadError::InvalidInteger(field))
}

/// Parse and validate one sensor payload.
///
/// `max_payload_bytes` is re-checked here so a caller cannot bypass the bridge
/// limit by calling the parser directly.
pub fn parse_sensor_payload(
    payload: &[u8],
    max_payload_bytes: usize,
    qos: MqttQoS,
) -> Result<MqttSensorReading, MqttBridgeError> {
    if payload.len() > max_payload_bytes {
        return Err(MqttBridgeError::PayloadTooLarge {
            len: payload.len(),
            max: max_payload_bytes,
        });
    }
    if payload.is_empty() {
        return Err(PayloadError::Empty.into());
    }
    let text = std::str::from_utf8(payload).map_err(|_| PayloadError::NotUtf8)?;

    let mut version: Option<&str> = None;
    let mut device: Option<&str> = None;
    let mut sequence: Option<u64> = None;
    let mut timestamp: Option<u64> = None;
    let mut temperature: Option<i64> = None;
    let mut humidity: Option<u32> = None;

    let mut fields = 0usize;
    for segment in text.split(';') {
        fields += 1;
        if fields > 6 {
            return Err(PayloadError::TooManyFields.into());
        }
        let (key, value) = segment.split_once('=').ok_or(PayloadError::Malformed)?;
        if key.is_empty() || value.is_empty() || value.contains('=') {
            return Err(PayloadError::Malformed.into());
        }
        let slot_taken = match key {
            "v" => version.replace(value).is_some(),
            "device" => device.replace(value).is_some(),
            "seq" => {
                if sequence.is_some() {
                    true
                } else {
                    sequence = Some(parse_decimal_u64("seq", value)?);
                    false
                }
            }
            "ts" => {
                if timestamp.is_some() {
                    true
                } else {
                    timestamp = Some(parse_decimal_u64("ts", value)?);
                    false
                }
            }
            "temp_mc" => {
                if temperature.is_some() {
                    true
                } else {
                    let parsed = value
                        .parse::<i64>()
                        .map_err(|_| PayloadError::InvalidInteger("temp_mc"))?;
                    temperature = Some(parsed);
                    false
                }
            }
            "rh_cp" => {
                if humidity.is_some() {
                    true
                } else {
                    let parsed = value
                        .parse::<u32>()
                        .map_err(|_| PayloadError::InvalidInteger("rh_cp"))?;
                    humidity = Some(parsed);
                    false
                }
            }
            _ => return Err(PayloadError::UnknownField(key.to_string()).into()),
        };
        if slot_taken {
            return Err(PayloadError::DuplicateField(key.to_string()).into());
        }
    }

    let version = version.ok_or(PayloadError::MissingField("v"))?;
    if version != "1" {
        return Err(PayloadError::UnsupportedVersion(version.to_string()).into());
    }
    let device_id = device.ok_or(PayloadError::MissingField("device"))?;
    if device_id.is_empty()
        || device_id.len() > MAX_DEVICE_ID_LEN
        || !device_id.chars().all(is_device_id_char)
    {
        return Err(PayloadError::InvalidDeviceId.into());
    }
    let sequence = sequence.ok_or(PayloadError::MissingField("seq"))?;
    if sequence == 0 {
        return Err(PayloadError::OutOfRange("seq").into());
    }
    let timestamp_ms = timestamp.ok_or(PayloadError::MissingField("ts"))?;
    let temp_mc = temperature.ok_or(PayloadError::MissingField("temp_mc"))?;
    if !(-100_000..=200_000).contains(&temp_mc) {
        return Err(PayloadError::OutOfRange("temp_mc").into());
    }
    let rh_cp = humidity.ok_or(PayloadError::MissingField("rh_cp"))?;
    if rh_cp > 10_000 {
        return Err(PayloadError::OutOfRange("rh_cp").into());
    }

    Ok(MqttSensorReading {
        device_id: device_id.to_string(),
        schema_version: MQTT_SENSOR_SCHEMA_VERSION,
        sequence,
        timestamp_ms,
        temperature: FixedPointValue::new(temp_mc, -3, UNIT_DEG_C),
        humidity: FixedPointValue::new(i64::from(rh_cp), -2, UNIT_PERCENT),
        qos,
    })
}

// ---------------------------------------------------------------------------
// Replay protection
// ---------------------------------------------------------------------------

/// Why a message was rejected as replayed or stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// `seq` is not greater than the last accepted value for this device.
    DuplicateSequence { device_id: String, sequence: u64 },
    /// Timestamp is older than the replay window.
    StaleTimestamp {
        device_id: String,
        timestamp_ms: u64,
    },
    /// Timestamp is further in the future than the allowed clock skew.
    FutureTimestamp {
        device_id: String,
        timestamp_ms: u64,
    },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplayError::DuplicateSequence {
                device_id,
                sequence,
            } => write!(f, "replayed sequence {sequence} from device '{device_id}'"),
            ReplayError::StaleTimestamp {
                device_id,
                timestamp_ms,
            } => write!(
                f,
                "stale timestamp {timestamp_ms} from device '{device_id}' is outside the replay window"
            ),
            ReplayError::FutureTimestamp {
                device_id,
                timestamp_ms,
            } => write!(
                f,
                "timestamp {timestamp_ms} from device '{device_id}' is too far in the future"
            ),
        }
    }
}

impl std::error::Error for ReplayError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayWatermark {
    sequence: u64,
    timestamp_ms: u64,
}

/// Per-device replay window.
///
/// A message is accepted only when its timestamp is inside
/// `[now - window, now + MAX_FUTURE_SKEW_MS]` and its `seq` is strictly greater
/// than the last accepted `seq` for that device. State is bounded to
/// `max_entries` devices; when full, the device with the oldest timestamp is
/// evicted deterministically.
#[derive(Debug, Clone)]
pub struct MqttReplayGuard {
    window_ms: u64,
    max_entries: usize,
    watermarks: BTreeMap<String, ReplayWatermark>,
}

impl MqttReplayGuard {
    /// Create a guard. `window_ms` is clamped to at least 1 ms and
    /// `max_entries` to `1..=MAX_REPLAY_ENTRIES`.
    pub fn new(window_ms: u64, max_entries: usize) -> Self {
        Self {
            window_ms: window_ms.max(1),
            max_entries: max_entries.clamp(1, MAX_REPLAY_ENTRIES),
            watermarks: BTreeMap::new(),
        }
    }

    /// Timestamp window in milliseconds.
    pub fn window_ms(&self) -> u64 {
        self.window_ms
    }

    /// Number of tracked devices.
    pub fn tracked_devices(&self) -> usize {
        self.watermarks.len()
    }

    /// Last accepted sequence for a device, if any.
    pub fn last_sequence(&self, device_id: &str) -> Option<u64> {
        self.watermarks.get(device_id).map(|mark| mark.sequence)
    }

    /// Validate and record one message.
    pub fn observe(
        &mut self,
        device_id: &str,
        sequence: u64,
        timestamp_ms: u64,
        now_ms: u64,
    ) -> Result<(), ReplayError> {
        if timestamp_ms.saturating_add(self.window_ms) < now_ms {
            return Err(ReplayError::StaleTimestamp {
                device_id: device_id.to_string(),
                timestamp_ms,
            });
        }
        if timestamp_ms > now_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
            return Err(ReplayError::FutureTimestamp {
                device_id: device_id.to_string(),
                timestamp_ms,
            });
        }
        if let Some(mark) = self.watermarks.get(device_id) {
            if sequence <= mark.sequence {
                return Err(ReplayError::DuplicateSequence {
                    device_id: device_id.to_string(),
                    sequence,
                });
            }
        }
        if !self.watermarks.contains_key(device_id) && self.watermarks.len() >= self.max_entries {
            if let Some(evict) = self
                .watermarks
                .iter()
                .min_by_key(|(id, mark)| (mark.timestamp_ms, (*id).clone()))
                .map(|(id, _)| id.clone())
            {
                self.watermarks.remove(&evict);
            }
        }
        self.watermarks.insert(
            device_id.to_string(),
            ReplayWatermark {
                sequence,
                timestamp_ms,
            },
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bridge configuration and errors
// ---------------------------------------------------------------------------

/// Bridge-level failure.
#[derive(Debug)]
pub enum MqttBridgeError {
    /// URI, credentials, limits, or topic configuration is invalid.
    InvalidConfig(&'static str),
    /// TLS handshake or trust configuration failed.
    Tls(String),
    /// Socket I/O failed (reset, refused, broken pipe).
    Io(io::Error),
    /// Malformed or unexpected MQTT packet.
    Protocol(String),
    /// Broker rejected CONNECT (bad credentials or not authorised).
    CredentialsRejected,
    /// Deadline expired: broker did not answer within the read budget.
    Timeout,
    /// Inbound topic is not in the allowlist.
    TopicNotAllowed(String),
    /// Wildcards are not permitted in this allowlist.
    WildcardTopicRejected(String),
    /// Inbound packet or payload exceeds the configured limit.
    PayloadTooLarge { len: usize, max: usize },
    /// Payload schema violation.
    InvalidPayload(PayloadError),
    /// Message replayed or outside the timestamp window.
    Replay(ReplayError),
}

impl fmt::Display for MqttBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MqttBridgeError::InvalidConfig(reason) => {
                write!(f, "invalid MQTT bridge config: {reason}")
            }
            MqttBridgeError::Tls(reason) => write!(f, "MQTT bridge TLS error: {reason}"),
            MqttBridgeError::Io(error) => write!(f, "MQTT bridge io error: {error}"),
            MqttBridgeError::Protocol(reason) => write!(f, "MQTT bridge protocol error: {reason}"),
            MqttBridgeError::CredentialsRejected => {
                write!(f, "MQTT bridge credentials rejected by broker")
            }
            MqttBridgeError::Timeout => write!(f, "MQTT bridge deadline expired"),
            MqttBridgeError::TopicNotAllowed(topic) => {
                write!(f, "MQTT topic '{topic}' is not allowlisted")
            }
            MqttBridgeError::WildcardTopicRejected(topic) => {
                write!(f, "MQTT wildcard filter '{topic}' is not permitted")
            }
            MqttBridgeError::PayloadTooLarge { len, max } => {
                write!(f, "MQTT payload of {len} bytes exceeds limit {max}")
            }
            MqttBridgeError::InvalidPayload(error) => write!(f, "MQTT payload rejected: {error}"),
            MqttBridgeError::Replay(error) => write!(f, "MQTT message rejected: {error}"),
        }
    }
}

impl std::error::Error for MqttBridgeError {}

impl From<PayloadError> for MqttBridgeError {
    fn from(error: PayloadError) -> Self {
        match error {
            PayloadError::TooLarge { len, max } => MqttBridgeError::PayloadTooLarge { len, max },
            other => MqttBridgeError::InvalidPayload(other),
        }
    }
}

impl From<ReplayError> for MqttBridgeError {
    fn from(error: ReplayError) -> Self {
        MqttBridgeError::Replay(error)
    }
}

impl From<MqttError> for MqttBridgeError {
    fn from(error: MqttError) -> Self {
        match error {
            MqttError::Tls(reason) => MqttBridgeError::Tls(reason),
            MqttError::Io(error) => match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => MqttBridgeError::Timeout,
                _ => MqttBridgeError::Io(error),
            },
            MqttError::Protocol(reason) => MqttBridgeError::Protocol(reason),
            MqttError::PayloadTooLarge { len, max } => {
                MqttBridgeError::PayloadTooLarge { len, max }
            }
            MqttError::PlainTextRejected { uri } => {
                tracing::warn!(adapter = "mqtt", %uri, "plain-text endpoint rejected");
                MqttBridgeError::InvalidConfig(
                    "plain-text MQTT endpoints are rejected; use mqtts://",
                )
            }
            MqttError::InvalidUri(reason) => MqttBridgeError::Protocol(reason),
        }
    }
}

/// Configuration for one bridged sensor endpoint.
#[derive(Debug, Clone)]
pub struct MqttBridgeConfig {
    /// Broker URI. Only `mqtts://`, `ssl://`, or `tcps://` are accepted.
    pub uri: String,
    /// MQTT client identifier (1..=128 bytes).
    pub client_id: String,
    /// Per-device username/password sent in CONNECT.
    pub credentials: MqttDeviceCredentials,
    /// Topics the bridge subscribes to and accepts.
    pub topics: MqttTopicAllowlist,
    /// Maximum accepted payload bytes. Clamped by [`Self::validate`] to
    /// `1..=MAX_PAYLOAD_BYTES_LIMIT`.
    pub max_payload_bytes: usize,
    /// Timestamp window for replay rejection.
    pub replay_window_ms: u64,
    /// Maximum devices tracked by the replay guard.
    pub max_replay_entries: usize,
    /// QoS requested in SUBSCRIBE and accepted for inbound PUBLISH.
    pub subscribe_qos: MqttQoS,
    /// Budget for TCP connect, TLS handshake, CONNACK, and SUBACK.
    pub connect_timeout: Duration,
    /// Budget for one inbound read.
    pub io_timeout: Duration,
}

impl MqttBridgeConfig {
    /// Defaults with an exact-match allowlist and QoS 1.
    pub fn new(
        uri: impl Into<String>,
        client_id: impl Into<String>,
        credentials: MqttDeviceCredentials,
        topics: MqttTopicAllowlist,
    ) -> Self {
        Self {
            uri: uri.into(),
            client_id: client_id.into(),
            credentials,
            topics,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            replay_window_ms: DEFAULT_REPLAY_WINDOW_MS,
            max_replay_entries: MAX_REPLAY_ENTRIES,
            subscribe_qos: MqttQoS::AtLeastOnce,
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
        }
    }

    /// Validate every configured bound before any socket is opened.
    pub fn validate(&self) -> Result<(), MqttBridgeError> {
        parse_mqtts_uri(&self.uri).map_err(|error| match error {
            MqttError::PlainTextRejected { .. } => MqttBridgeError::InvalidConfig(
                "plain-text MQTT endpoints are rejected; use mqtts://",
            ),
            MqttError::InvalidUri(_) => {
                MqttBridgeError::InvalidConfig("broker URI must be mqtts://host:port")
            }
            other => other.into(),
        })?;
        if self.client_id.is_empty() || self.client_id.len() > 128 {
            return Err(MqttBridgeError::InvalidConfig(
                "MQTT client id must be 1..=128 bytes",
            ));
        }
        if self.client_id.chars().any(char::is_control) {
            return Err(MqttBridgeError::InvalidConfig(
                "MQTT client id must not contain control characters",
            ));
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes > MAX_PAYLOAD_BYTES_LIMIT {
            return Err(MqttBridgeError::InvalidConfig(
                "max payload bytes must be 1..=4096",
            ));
        }
        if self.replay_window_ms == 0 {
            return Err(MqttBridgeError::InvalidConfig(
                "replay window must be positive",
            ));
        }
        if self.max_replay_entries == 0 || self.max_replay_entries > MAX_REPLAY_ENTRIES {
            return Err(MqttBridgeError::InvalidConfig(
                "replay entries must be 1..=1024",
            ));
        }
        if self.connect_timeout.is_zero() || self.connect_timeout > Duration::from_secs(30) {
            return Err(MqttBridgeError::InvalidConfig(
                "connect timeout must be 1ms..=30s",
            ));
        }
        if self.io_timeout.is_zero() || self.io_timeout > Duration::from_secs(30) {
            return Err(MqttBridgeError::InvalidConfig(
                "io timeout must be 1ms..=30s",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TLS transport
// ---------------------------------------------------------------------------

pub type TlsTcpStream = StreamOwned<ClientConnection, TcpStream>;

/// Real MQTT 3.1.1 client over TLS. No public plaintext connect path exists.
#[derive(Debug)]
pub struct MqttTlsClient {
    stream: TlsTcpStream,
    codec: MqttBridgeCodec,
    next_packet_id: u16,
}

impl MqttTlsClient {
    /// Connect to an `mqtts://` endpoint and perform TLS handshake + MQTT CONNECT.
    /// Connecting to a plaintext TCP server fails at TLS handshake (CLAIM-34.2).
    ///
    /// This low-level entry point accepts a caller-built `ClientConfig` for the
    /// gateway smoke profile and tests. Sensor integrations should use
    /// [`MqttBridgeClient::connect`], which builds the configuration from
    /// [`MqttTlsTrust`] CA roots and therefore cannot opt out of verification.
    /// Configurations must come from [`client_config_with_roots`].
    pub fn connect_mqtts(
        uri: &str,
        client_id: &str,
        tls_config: Arc<ClientConfig>,
        io_timeout: Duration,
    ) -> Result<Self, MqttError> {
        Self::open(uri, client_id, None, tls_config, io_timeout)
    }

    /// Connect with per-device username/password credentials.
    pub fn connect_mqtts_with_credentials(
        uri: &str,
        client_id: &str,
        username: &str,
        password: &str,
        tls_config: Arc<ClientConfig>,
        io_timeout: Duration,
    ) -> Result<Self, MqttError> {
        Self::open(
            uri,
            client_id,
            Some((username, password)),
            tls_config,
            io_timeout,
        )
    }

    fn open(
        uri: &str,
        client_id: &str,
        credentials: Option<(&str, &str)>,
        tls_config: Arc<ClientConfig>,
        io_timeout: Duration,
    ) -> Result<Self, MqttError> {
        let _span = tracing::info_span!(
            "adapter.mqtt.connect",
            audit = true,
            adapter = "mqtt",
            client_id
        )
        .entered();
        let (host, port) = parse_mqtts_uri(uri)?;
        let addr = (host.as_str(), port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| MqttError::InvalidUri(format!("no address for {host}:{port}")))?;
        let tcp = TcpStream::connect_timeout(&addr, io_timeout)?;
        tcp.set_read_timeout(Some(io_timeout))?;
        tcp.set_write_timeout(Some(io_timeout))?;
        tcp.set_nodelay(true)?;
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| MqttError::Tls(format!("invalid server name '{host}': {e}")))?;
        let conn = ClientConnection::new(tls_config, server_name)
            .map_err(|e| MqttError::Tls(format!("tls client: {e}")))?;
        let mut stream = StreamOwned::new(conn, tcp);
        // Completing handshake by writing/flushing if needed happens on first I/O.
        let codec = MqttBridgeCodec::new();
        let connect = match credentials {
            Some((username, password)) => {
                codec.encode_connect_with_credentials(client_id, username, password)?
            }
            None => codec.encode_connect(client_id)?,
        };
        stream.write_all(&connect)?;
        stream.flush()?;
        let ack = read_packet(&mut stream, io_timeout)?;
        codec.decode_connack(&ack)?;
        Ok(Self {
            stream,
            codec,
            next_packet_id: 1,
        })
    }

    /// Subscribe to one exact topic filter and wait for the SUBACK.
    pub fn subscribe(
        &mut self,
        topic: &str,
        qos: MqttQoS,
        timeout: Duration,
    ) -> Result<u16, MqttError> {
        let _span = tracing::info_span!(
            "adapter.mqtt.subscribe",
            audit = true,
            adapter = "mqtt",
            topic,
            qos = qos as u8
        )
        .entered();
        let pid = self.alloc_packet_id();
        let pkt = self.codec.encode_subscribe(topic, qos, pid)?;
        self.stream.write_all(&pkt)?;
        self.stream.flush()?;
        let ack = read_packet(&mut self.stream, timeout)?;
        self.codec.decode_suback(&ack, pid)?;
        Ok(pid)
    }

    pub fn publish_qos0(&mut self, topic: &str, payload: &[u8]) -> Result<(), MqttError> {
        let _span = tracing::info_span!(
            "adapter.mqtt.publish",
            audit = true,
            adapter = "mqtt",
            qos = 0,
            topic,
            payload_len = payload.len()
        )
        .entered();
        let pkt = self
            .codec
            .encode_publish(topic, payload, MqttQoS::AtMostOnce, None)
            .map_err(|e| MqttError::Protocol(e.to_string()))?;
        self.stream.write_all(&pkt)?;
        self.stream.flush()?;
        Ok(())
    }

    pub fn publish_qos1(
        &mut self,
        topic: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<u16, MqttError> {
        let _span = tracing::info_span!(
            "adapter.mqtt.publish",
            audit = true,
            adapter = "mqtt",
            qos = 1,
            topic,
            payload_len = payload.len()
        )
        .entered();
        let pid = self.alloc_packet_id();
        let pkt = self
            .codec
            .encode_publish(topic, payload, MqttQoS::AtLeastOnce, Some(pid))
            .map_err(|e| MqttError::Protocol(e.to_string()))?;
        self.stream.write_all(&pkt)?;
        self.stream.flush()?;
        let ack = read_packet(&mut self.stream, timeout)?;
        let ack_pid = self
            .codec
            .decode_puback(&ack)
            .map_err(|e| MqttError::Protocol(e.to_string()))?;
        if ack_pid != pid {
            return Err(MqttError::Protocol(format!(
                "PUBACK packet id mismatch: expected {pid}, got {ack_pid}"
            )));
        }
        Ok(pid)
    }

    fn alloc_packet_id(&mut self) -> u16 {
        let pid = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);
        pid
    }
}

fn read_packet<R: Read>(r: &mut R, _timeout: Duration) -> Result<Vec<u8>, MqttError> {
    let mut head = [0u8; 1];
    r.read_exact(&mut head)?;
    let mut rem = Vec::new();
    let mut multiplier = 1usize;
    let mut value = 0usize;
    loop {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        rem.push(b[0]);
        value += ((b[0] & 127) as usize) * multiplier;
        if (b[0] & 128) == 0 {
            break;
        }
        multiplier *= 128;
        if rem.len() > 4 {
            return Err(MqttError::Protocol("remaining length too large".into()));
        }
    }
    let mut body = vec![0u8; value];
    r.read_exact(&mut body)?;
    let mut out = Vec::with_capacity(1 + rem.len() + body.len());
    out.push(head[0]);
    out.extend_from_slice(&rem);
    out.extend_from_slice(&body);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Sensor bridge client
// ---------------------------------------------------------------------------

/// One inbound PUBLISH as received from the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceivedPublish {
    topic: String,
    payload: Vec<u8>,
    qos: MqttQoS,
    packet_id: Option<u16>,
}

fn deadline_remaining_ms(deadline_ms: u64, clock: &MqttClockFn) -> Result<u64, MqttBridgeError> {
    let now = clock();
    if now >= deadline_ms {
        return Err(MqttBridgeError::Timeout);
    }
    Ok((deadline_ms - now).max(1))
}

fn map_read_error(error: io::Error) -> MqttBridgeError {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => MqttBridgeError::Timeout,
        _ => MqttBridgeError::Io(error),
    }
}

fn read_exact_bounded(
    stream: &mut TlsTcpStream,
    buf: &mut [u8],
    deadline_ms: u64,
    clock: &MqttClockFn,
) -> Result<(), MqttBridgeError> {
    let remaining = deadline_remaining_ms(deadline_ms, clock)?;
    stream
        .sock
        .set_read_timeout(Some(Duration::from_millis(remaining)))
        .map_err(MqttBridgeError::Io)?;
    stream.read_exact(buf).map_err(map_read_error)
}

/// Read one MQTT packet with an overall deadline and a hard size bound.
///
/// The remaining length is checked against `max_remaining` *before* the body
/// buffer is allocated, so an oversized or hostile packet header cannot make
/// the bridge allocate unbounded memory.
fn read_packet_bounded(
    stream: &mut TlsTcpStream,
    max_remaining: usize,
    deadline_ms: u64,
    clock: &MqttClockFn,
) -> Result<Vec<u8>, MqttBridgeError> {
    let mut head = [0u8; 1];
    read_exact_bounded(stream, &mut head, deadline_ms, clock)?;
    let mut length_bytes = Vec::new();
    let mut multiplier = 1usize;
    let mut value = 0usize;
    loop {
        let mut byte = [0u8; 1];
        read_exact_bounded(stream, &mut byte, deadline_ms, clock)?;
        length_bytes.push(byte[0]);
        value = value.saturating_add(((byte[0] & 127) as usize).saturating_mul(multiplier));
        if (byte[0] & 128) == 0 {
            break;
        }
        multiplier = multiplier.saturating_mul(128);
        if length_bytes.len() > 4 {
            return Err(MqttBridgeError::Protocol(
                "MQTT remaining length too large".into(),
            ));
        }
    }
    if value > max_remaining {
        return Err(MqttBridgeError::PayloadTooLarge {
            len: value,
            max: max_remaining,
        });
    }
    let mut body = vec![0u8; value];
    read_exact_bounded(stream, &mut body, deadline_ms, clock)?;
    let mut out = Vec::with_capacity(1 + length_bytes.len() + body.len());
    out.push(head[0]);
    out.extend_from_slice(&length_bytes);
    out.extend_from_slice(&body);
    Ok(out)
}

/// TLS-only sensor bridge that subscribes to allowlisted topics and validates
/// every reading before it leaves the driver.
///
/// Each [`Self::read_reading`] call is bounded by the configured
/// `io_timeout`; there is no background thread, reconnect loop, or unbounded
/// wait. A broker outage therefore surfaces as [`MqttBridgeError::Timeout`] or
/// [`MqttBridgeError::Io`] on the read path and never stalls for longer than
/// the budget.
pub struct MqttBridgeClient {
    transport: MqttTlsClient,
    topics: MqttTopicAllowlist,
    max_payload_bytes: usize,
    max_packet_bytes: usize,
    max_inbound_qos: MqttQoS,
    replay: MqttReplayGuard,
    io_timeout: Duration,
    clock: MqttClockFn,
}

impl fmt::Debug for MqttBridgeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MqttBridgeClient")
            .field("topics", &self.topics.filters())
            .field("max_payload_bytes", &self.max_payload_bytes)
            .field("max_inbound_qos", &self.max_inbound_qos)
            .field("io_timeout", &self.io_timeout)
            .field("tracked_devices", &self.replay.tracked_devices())
            .finish_non_exhaustive()
    }
}

impl MqttBridgeClient {
    /// Connect, authenticate with per-device credentials, and subscribe to the
    /// allowlisted topics.
    ///
    /// TLS verification is performed against `trust`; the bridge builds the
    /// rustls configuration itself. No retry loop is entered here: if the
    /// broker is down, the call fails within `connect_timeout`.
    pub fn connect(
        config: &MqttBridgeConfig,
        trust: &MqttTlsTrust,
        clock: MqttClockFn,
    ) -> Result<Self, MqttBridgeError> {
        config.validate()?;
        let tls_config = trust.client_config()?;
        let mut transport = MqttTlsClient::connect_mqtts_with_credentials(
            &config.uri,
            &config.client_id,
            config.credentials.username(),
            config.credentials.password(),
            tls_config,
            config.connect_timeout,
        )?;
        for topic in config.topics.filters() {
            transport.subscribe(topic, config.subscribe_qos, config.connect_timeout)?;
        }
        let max_packet_bytes = config
            .max_payload_bytes
            .saturating_add(MAX_TOPIC_LEN)
            .saturating_add(8);
        Ok(Self {
            transport,
            topics: config.topics.clone(),
            max_payload_bytes: config.max_payload_bytes,
            max_packet_bytes,
            max_inbound_qos: config.subscribe_qos,
            replay: MqttReplayGuard::new(config.replay_window_ms, config.max_replay_entries),
            io_timeout: config.io_timeout,
            clock,
        })
    }

    /// Topics this bridge subscribed to.
    pub fn subscribed_topics(&self) -> &[String] {
        self.topics.filters()
    }

    /// Maximum accepted payload bytes.
    pub fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    /// Last accepted sequence for a device.
    pub fn last_sequence(&self, device_id: &str) -> Option<u64> {
        self.replay.last_sequence(device_id)
    }

    /// Read the next valid reading, using the configured `io_timeout`.
    ///
    /// Control packets are consumed and ignored. A PUBLISH on a non-allowlisted
    /// topic, an oversized payload, a schema violation, or a replay is returned
    /// as a typed error; the connection stays open and the caller can retry.
    pub fn read_reading(&mut self) -> Result<MqttSensorReading, MqttBridgeError> {
        self.read_reading_with_timeout(self.io_timeout)
    }

    /// Read the next valid reading with an explicit deadline budget.
    pub fn read_reading_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<MqttSensorReading, MqttBridgeError> {
        if timeout.is_zero() {
            return Err(MqttBridgeError::Timeout);
        }
        let deadline_ms = self.clock.as_ref()()
            .saturating_add(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX));
        loop {
            let packet = read_packet_bounded(
                &mut self.transport.stream,
                self.max_packet_bytes,
                deadline_ms,
                &self.clock,
            )?;
            let packet_type = packet.first().map(|byte| byte & 0xF0).unwrap_or(0);
            match packet_type {
                0x30 => {
                    let publish = decode_inbound_publish(&self.transport.codec, &packet)?;
                    self.acknowledge(&publish)?;
                    // Bound the payload independently of the packet budget.
                    if publish.payload.len() > self.max_payload_bytes {
                        return Err(MqttBridgeError::PayloadTooLarge {
                            len: publish.payload.len(),
                            max: self.max_payload_bytes,
                        });
                    }
                    if publish.qos as u8 > self.max_inbound_qos as u8 {
                        return Err(MqttBridgeError::Protocol(format!(
                            "inbound QoS {} exceeds subscribed QoS {}",
                            publish.qos as u8, self.max_inbound_qos as u8
                        )));
                    }
                    // Topic and payload are validated after the protocol ACK:
                    // the broker must not redeliver a message the bridge has
                    // already decided to reject.
                    if !self.topics.allows(&publish.topic) {
                        return Err(MqttBridgeError::TopicNotAllowed(publish.topic));
                    }
                    let reading = parse_sensor_payload(
                        &publish.payload,
                        self.max_payload_bytes,
                        publish.qos,
                    )?;
                    self.replay.observe(
                        &reading.device_id,
                        reading.sequence,
                        reading.timestamp_ms,
                        self.clock.as_ref()(),
                    )?;
                    tracing::debug!(
                        target: "adapter.mqtt.reading",
                        device = %reading.device_id,
                        sequence = reading.sequence,
                        timestamp_ms = reading.timestamp_ms,
                        qos = reading.qos as u8,
                        "adapter.mqtt.reading accepted"
                    );
                    return Ok(reading);
                }
                // PUBACK / PINGRESP / SUBACK for traffic we did not originate in
                // this read path: ignore and keep waiting inside the deadline.
                _ => continue,
            }
        }
    }

    fn acknowledge(&mut self, publish: &ReceivedPublish) -> Result<(), MqttBridgeError> {
        if publish.qos == MqttQoS::AtLeastOnce {
            if let Some(packet_id) = publish.packet_id {
                let ack = self.transport.codec.encode_puback(packet_id);
                self.transport
                    .stream
                    .write_all(&ack)
                    .map_err(MqttBridgeError::Io)?;
                self.transport.stream.flush().map_err(MqttBridgeError::Io)?;
            }
        }
        Ok(())
    }
}

fn decode_inbound_publish(
    codec: &MqttBridgeCodec,
    packet: &[u8],
) -> Result<ReceivedPublish, MqttBridgeError> {
    let (topic, payload, qos, packet_id) = codec
        .decode_publish(packet)
        .map_err(|error| MqttBridgeError::Protocol(error.to_string()))?;
    Ok(ReceivedPublish {
        topic,
        payload,
        qos,
        packet_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(seq: u64, ts: u64) -> MqttSensorReading {
        MqttSensorReading {
            device_id: "coldroom-1".into(),
            schema_version: 1,
            sequence: seq,
            timestamp_ms: ts,
            temperature: FixedPointValue::new(4512, -3, UNIT_DEG_C),
            humidity: FixedPointValue::new(5560, -2, UNIT_PERCENT),
            qos: MqttQoS::AtLeastOnce,
        }
    }

    #[test]
    fn plain_text_mqtt_uri_is_rejected() {
        let cfg = MqttConnectConfig {
            uri: "mqtt://broker.local:1883".into(),
            client_id: "c1".into(),
            tls_configured: false,
        };
        assert!(matches!(
            connect_tls_only(&cfg),
            Err(MqttError::PlainTextRejected { .. })
        ));
    }

    #[test]
    fn tcp_plain_text_is_rejected() {
        let err = parse_mqtts_uri("tcp://127.0.0.1:1883").unwrap_err();
        assert!(matches!(err, MqttError::PlainTextRejected { .. }));
    }

    #[test]
    fn mqtts_uri_parses() {
        let (h, p) = parse_mqtts_uri("mqtts://localhost:8883").unwrap();
        assert_eq!(h, "localhost");
        assert_eq!(p, 8883);
    }

    // -- payload schema -----------------------------------------------------

    #[test]
    fn payload_roundtrip() {
        let encoded = reading(7, 1_700_000_000_000).encode();
        let parsed =
            parse_sensor_payload(&encoded, DEFAULT_MAX_PAYLOAD_BYTES, MqttQoS::AtLeastOnce)
                .expect("valid payload");
        assert_eq!(parsed, reading(7, 1_700_000_000_000));
        assert_eq!(parsed.temperature.mantissa, 4512);
        assert_eq!(parsed.temperature.exponent, -3);
        assert_eq!(parsed.humidity.unit_id, UNIT_PERCENT);
    }

    #[test]
    fn payload_fields_may_be_reordered() {
        let parsed = parse_sensor_payload(
            b"rh_cp=5000;temp_mc=-18300;ts=1700000000000;seq=2;device=probe:3;v=1",
            DEFAULT_MAX_PAYLOAD_BYTES,
            MqttQoS::AtMostOnce,
        )
        .expect("reordered fields are valid");
        assert_eq!(parsed.device_id, "probe:3");
        assert_eq!(parsed.temperature.mantissa, -18_300);
        assert_eq!(parsed.humidity.mantissa, 5_000);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let payload = vec![b'a'; 64];
        let err = parse_sensor_payload(&payload, 16, MqttQoS::AtMostOnce).unwrap_err();
        assert!(matches!(
            err,
            MqttBridgeError::PayloadTooLarge { len: 64, max: 16 }
        ));
    }

    #[test]
    fn schema_violations_are_typed() {
        let max = DEFAULT_MAX_PAYLOAD_BYTES;
        let cases: &[(&[u8], PayloadError)] = &[
            (b"", PayloadError::Empty),
            (
                b"v=1;device=a;seq=1;ts=1;temp_mc=0",
                PayloadError::MissingField("rh_cp"),
            ),
            (
                b"v=2;device=a;seq=1;ts=1;temp_mc=0;rh_cp=0",
                PayloadError::UnsupportedVersion("2".into()),
            ),
            (
                b"v=1;device=a b;seq=1;ts=1;temp_mc=0;rh_cp=0",
                PayloadError::InvalidDeviceId,
            ),
            (
                b"v=1;device=a;seq=0;ts=1;temp_mc=0;rh_cp=0",
                PayloadError::OutOfRange("seq"),
            ),
            (
                b"v=1;device=a;seq=x;ts=1;temp_mc=0;rh_cp=0",
                PayloadError::InvalidInteger("seq"),
            ),
            (
                b"v=1;device=a;seq=1;ts=1;temp_mc=0;rh_cp=10001",
                PayloadError::OutOfRange("rh_cp"),
            ),
            (
                b"v=1;device=a;seq=1;ts=1;temp_mc=300001;rh_cp=0",
                PayloadError::OutOfRange("temp_mc"),
            ),
            (
                b"v=1;device=a;seq=1;ts=1;temp_mc=0;rh_cp=0;evil=1",
                PayloadError::TooManyFields,
            ),
            (
                b"v=1;device=a;seq=1;ts=1;temp_mc=0;rh_cp=0;x=1",
                PayloadError::TooManyFields,
            ),
            (
                b"v=1;device=a;device=b;seq=1;ts=1;temp_mc=0;rh_cp=0",
                PayloadError::DuplicateField("device".into()),
            ),
            (
                b"v=1;device=a;seq=1;ts=1;temp_mc=0;rh_cp=",
                PayloadError::Malformed,
            ),
            (
                b"v=1;device=a;seq=1;ts=1;temp_mc=0;rh_cp",
                PayloadError::Malformed,
            ),
            // A trailing separator is a seventh (empty) field, so the bounded
            // field count rejects it before parsing.
            (
                b"v=1;device=a;seq=1;ts=1;temp_mc=0;rh_cp=0;",
                PayloadError::TooManyFields,
            ),
            (b"v=1=device=a", PayloadError::Malformed),
        ];
        for (payload, expected) in cases {
            let err = parse_sensor_payload(payload, max, MqttQoS::AtMostOnce)
                .expect_err("payload must be rejected");
            assert_eq!(
                err.to_string(),
                MqttBridgeError::from(expected.clone()).to_string(),
                "payload {:?}",
                String::from_utf8_lossy(payload)
            );
        }
    }

    #[test]
    fn non_utf8_payload_is_rejected() {
        let err = parse_sensor_payload(&[0xff, 0xfe], 16, MqttQoS::AtMostOnce).unwrap_err();
        assert!(matches!(
            err,
            MqttBridgeError::InvalidPayload(PayloadError::NotUtf8)
        ));
    }

    #[test]
    fn unknown_field_is_named() {
        // Six known fields plus an unknown one trips the field cap first; a
        // five-field payload exercises the unknown-key path directly.
        let err = parse_sensor_payload(
            b"v=1;device=a;seq=1;ts=1;evil=1",
            DEFAULT_MAX_PAYLOAD_BYTES,
            MqttQoS::AtMostOnce,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            MqttBridgeError::InvalidPayload(PayloadError::UnknownField(ref field)) if field == "evil"
        ));
    }

    // -- replay guard -------------------------------------------------------

    #[test]
    fn replay_guard_rejects_duplicate_and_older_sequences() {
        let mut guard = MqttReplayGuard::new(60_000, 8);
        guard.observe("dev", 5, 10_000, 10_000).expect("first");
        assert!(matches!(
            guard.observe("dev", 5, 10_000, 10_000),
            Err(ReplayError::DuplicateSequence { .. })
        ));
        assert!(matches!(
            guard.observe("dev", 4, 10_000, 10_000),
            Err(ReplayError::DuplicateSequence { .. })
        ));
        guard.observe("dev", 6, 10_001, 10_001).expect("newer");
        assert_eq!(guard.last_sequence("dev"), Some(6));
    }

    #[test]
    fn replay_guard_rejects_stale_and_future_timestamps() {
        let mut guard = MqttReplayGuard::new(60_000, 8);
        assert!(matches!(
            guard.observe("dev", 1, 1_000, 200_000),
            Err(ReplayError::StaleTimestamp { .. })
        ));
        assert!(matches!(
            guard.observe("dev", 1, 400_000, 200_000),
            Err(ReplayError::FutureTimestamp { .. })
        ));
        guard
            .observe("dev", 1, 200_000, 200_000)
            .expect("in window");
    }

    #[test]
    fn replay_guard_is_bounded() {
        let mut guard = MqttReplayGuard::new(60_000, 2);
        guard.observe("a", 1, 100, 100).unwrap();
        guard.observe("b", 1, 200, 200).unwrap();
        guard.observe("c", 1, 300, 300).unwrap();
        assert_eq!(guard.tracked_devices(), 2);
        // The oldest watermark (device a) was evicted.
        assert_eq!(guard.last_sequence("a"), None);
        assert_eq!(guard.last_sequence("c"), Some(1));
    }

    #[test]
    fn replay_guard_keeps_devices_independent() {
        let mut guard = MqttReplayGuard::new(60_000, 8);
        guard.observe("a", 10, 100, 100).unwrap();
        guard.observe("b", 1, 100, 100).unwrap();
        assert_eq!(guard.last_sequence("a"), Some(10));
        assert_eq!(guard.last_sequence("b"), Some(1));
    }

    // -- topic allowlist ----------------------------------------------------

    #[test]
    fn allowlist_is_exact_by_default() {
        let list = MqttTopicAllowlist::exact([
            "tirbase/devices/coldroom-1/reading",
            "tirbase/devices/coldroom-2/reading",
        ])
        .unwrap();
        assert!(list.allows("tirbase/devices/coldroom-1/reading"));
        assert!(!list.allows("tirbase/devices/coldroom-3/reading"));
        assert!(!list.allows("tirbase/devices/coldroom-1/reading/extra"));
    }

    #[test]
    fn wildcard_filters_are_rejected_by_default() {
        assert!(matches!(
            MqttTopicAllowlist::exact(["tirbase/devices/+/reading"]),
            Err(MqttBridgeError::WildcardTopicRejected(_))
        ));
        assert!(matches!(
            MqttTopicAllowlist::exact(["tirbase/#"]),
            Err(MqttBridgeError::WildcardTopicRejected(_))
        ));
    }

    #[test]
    fn wildcard_filters_require_explicit_opt_in() {
        let list = MqttTopicAllowlist::with_wildcards(["tirbase/devices/+/reading"]).unwrap();
        assert!(list.allows_wildcards());
        assert!(list.allows("tirbase/devices/coldroom-9/reading"));
        assert!(!list.allows("tirbase/devices/coldroom-9/command"));
        assert!(!list.allows("tirbase/devices/coldroom-9/nested/reading"));
    }

    #[test]
    fn malformed_wildcard_filters_are_rejected() {
        assert!(MqttTopicAllowlist::with_wildcards(["tirbase/de#vices"]).is_err());
        assert!(MqttTopicAllowlist::with_wildcards(["tirbase/#/reading"]).is_err());
        assert!(MqttTopicAllowlist::with_wildcards(["tirbase/dev+ices"]).is_err());
        assert!(MqttTopicAllowlist::with_wildcards(Vec::<String>::new()).is_err());
    }

    #[test]
    fn topic_matcher_handles_multi_level_wildcard() {
        assert!(mqtt_topic_matches("tirbase/#", "tirbase"));
        assert!(mqtt_topic_matches("tirbase/#", "tirbase/a/b"));
        assert!(!mqtt_topic_matches("tirbase/#", "other/a"));
        assert!(mqtt_topic_matches("a/+/c", "a/b/c"));
        assert!(!mqtt_topic_matches("a/+/c", "a/b/d"));
        assert!(!mqtt_topic_matches("a/+/c", "a/c"));
    }

    // -- config and TLS -----------------------------------------------------

    fn credentials() -> MqttDeviceCredentials {
        MqttDeviceCredentials::new("device-coldroom-1", "s3cret").unwrap()
    }

    fn config() -> MqttBridgeConfig {
        MqttBridgeConfig::new(
            "mqtts://127.0.0.1:8883",
            "bridge-1",
            credentials(),
            MqttTopicAllowlist::exact(["tirbase/devices/coldroom-1/reading"]).unwrap(),
        )
    }

    #[test]
    fn config_rejects_plaintext_brokers() {
        let mut config = config();
        config.uri = "mqtt://127.0.0.1:1883".into();
        assert!(matches!(
            config.validate(),
            Err(MqttBridgeError::InvalidConfig(_))
        ));
    }

    #[test]
    fn config_rejects_unbounded_limits() {
        let mut payload = config();
        payload.max_payload_bytes = MAX_PAYLOAD_BYTES_LIMIT + 1;
        assert!(payload.validate().is_err());
        payload.max_payload_bytes = 0;
        assert!(payload.validate().is_err());

        let mut timeouts = config();
        timeouts.io_timeout = Duration::from_secs(31);
        assert!(timeouts.validate().is_err());
        timeouts.io_timeout = Duration::from_secs(1);
        timeouts.connect_timeout = Duration::ZERO;
        assert!(timeouts.validate().is_err());
    }

    #[test]
    fn credentials_debug_redacts_password() {
        let debug = format!("{:?}", credentials());
        assert!(debug.contains("device-coldroom-1"));
        assert!(!debug.contains("s3cret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn credentials_reject_empty_and_control_characters() {
        assert!(MqttDeviceCredentials::new("", "pass").is_err());
        assert!(MqttDeviceCredentials::new("user", "").is_err());
        assert!(MqttDeviceCredentials::new("us\ner", "pass").is_err());
    }

    #[test]
    fn tls_trust_requires_at_least_one_root() {
        let empty = MqttTlsTrust::default();
        assert!(empty.client_config().is_err());
        assert!(MqttTlsTrust::webpki().client_config().is_ok());
    }

    #[test]
    fn bridge_source_contains_no_verifier_bypass() {
        // Needles are assembled at runtime so this test's own source does not
        // contain the literal tokens it searches for.
        let source = include_str!("mqtt.rs");
        let needles = [
            concat!("with_custom_", "certificate_verifier"),
            concat!("danger", "ous()"),
            concat!("ServerCert", "Verifier"),
        ];
        for needle in needles {
            assert!(
                !source.contains(needle),
                "bridge source must not reference {needle}"
            );
        }
    }
}
