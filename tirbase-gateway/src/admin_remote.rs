//! Remote admin listener with mandatory mutual TLS (PV-11.2).
//!
//! The local admin API is authenticated by kernel peer credentials on a Unix
//! socket. Remote admin is a **separate, explicitly configured** TCP listener
//! that only accepts clients presenting a certificate chaining to the
//! configured client CA. There is no plaintext or optional-client-cert mode:
//! a missing or untrusted client certificate fails the TLS handshake before any
//! request bytes are read.
//!
//! Requests use a deliberately small HTTP/1.1 surface (one request per
//! connection, `Content-Length` bounded) and are translated into the same JSON
//! command envelope as the local socket. Privileged operations additionally
//! require a scoped Biscuit token (`Authorization: Bearer <hex>`), because a
//! client certificate proves transport identity but not an admin role.

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

use crate::admin::{dispatch_http_request, AdminCaller, AdminState};

/// Largest remote admin request body accepted (1 MiB).
pub const MAX_REMOTE_ADMIN_BODY: usize = 1024 * 1024;

/// Load a mutual-TLS server configuration from PEM files.
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: &Path,
) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(cert_path)
        .with_context(|| format!("load remote admin server cert {}", cert_path.display()))?;
    let key = load_private_key(key_path)
        .with_context(|| format!("load remote admin server key {}", key_path.display()))?;
    let client_cas = load_certs(client_ca_path).with_context(|| {
        format!(
            "load remote admin client CA bundle {}",
            client_ca_path.display()
        )
    })?;
    if client_cas.is_empty() {
        bail!("remote admin client CA bundle is empty; remote admin is mTLS-only");
    }
    let mut roots = rustls::RootCertStore::empty();
    for ca in client_cas {
        roots
            .add(ca)
            .context("remote admin client CA certificate is not usable as a trust anchor")?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| anyhow::anyhow!("build client-certificate verifier: {error}"))?;
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|error| anyhow::anyhow!("remote admin TLS server config: {error}"))?;
    Ok(Arc::new(config))
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        bail!("no PEM certificates found");
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?.context("no PEM private key found")
}

/// Bind the remote admin listener. This is only called when
/// [`crate::config::GatewayConfig::admin_remote_addr`] and all mTLS material are
/// configured.
pub async fn run_remote_admin_listener(
    addr: std::net::SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    state: Option<Arc<AdminState>>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(server_config);
    tracing::info!(%addr, "remote admin mTLS listener bound");
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls) => {
                    if let Err(error) = serve_remote_admin(tls, state).await {
                        tracing::warn!(%peer, %error, "remote admin request failed");
                    }
                }
                Err(error) => {
 // Fail closed: without a valid client certificate no request
 // bytes are processed at all.
                    tracing::warn!(%peer, %error, "remote admin TLS handshake rejected");
                }
            }
        });
    }
}

async fn serve_remote_admin(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    state: Option<Arc<AdminState>>,
) -> Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let (header_end, content_length) = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before request headers completed");
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.len() > MAX_REMOTE_ADMIN_BODY + 8192 {
            bail!("remote admin request headers exceed limit");
        }
        if let Some(position) = find_header_end(&buffer) {
            let headers = String::from_utf8_lossy(&buffer[..position]);
            let content_length = parse_content_length(&headers).unwrap_or(0);
            if content_length > MAX_REMOTE_ADMIN_BODY {
                let response = http_response(
                    413,
                    "Payload Too Large",
                    "{\"status\":413,\"error\":\"request body too large\"}",
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
                return Ok(());
            }
            break (position, content_length);
        }
    };

    let header_text = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let token = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("authorization") {
                value.trim().strip_prefix("Bearer ").map(ToOwned::to_owned)
            } else {
                None
            }
        })
        .and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

    if token.is_none() {
        let response = http_response(
            401,
            "Unauthorized",
            "{\"status\":401,\"code\":\"ADMIN_CREDENTIAL_REQUIRED\",\"error\":\"remote admin requires a scoped Biscuit credential\"}",
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
        return Ok(());
    }

    let mut body_bytes = buffer[header_end + 4..].to_vec();
    while body_bytes.len() < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body_bytes.extend_from_slice(&chunk[..n]);
    }
    body_bytes.truncate(content_length);
    let body = if content_length == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(&body_bytes).to_string())
    };

    let now_est = state
        .as_ref()
        .and_then(|state| {
            let ratchet = state.ratchet.as_ref()?;
            let time_source = state.time_source.as_ref()?;
            let guard = ratchet.lock().ok()?;
            Some(guard.now_est(time_source.as_ref()))
        })
        .unwrap_or_else(|| tirbase_core::traits::wall_hint_secs().unwrap_or_default());
    let caller = AdminCaller::Remote {
        biscuit_token_hex: token,
    };
    let (status, response_body) = dispatch_http_request(
        &method,
        &path,
        body.as_deref(),
        state.as_deref(),
        now_est,
        &caller,
    );
    let response = http_response(status, reason_phrase(status), &response_body);
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> Option<usize> {
    headers.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    })
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

fn http_response(status: u16, reason: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
