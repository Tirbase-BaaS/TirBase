//! Task 36.2 (PV-11.2): remote admin listener requires mutual TLS.
//!
//! Spawns the real gateway binary with `admin_remote_*` configured, then:
//! * a client certificate signed by the configured CA reaches `/admin/mode`;
//! * a client with no certificate fails the TLS handshake;
//! * a client certificate signed by another CA fails the handshake;
//! * a client with a valid certificate but no Bearer credential is refused;
//! * cross-issuer status requires an Auditor/PolicyAuthority credential.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::{json, Value};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::trust_root::{
    AuthorizedRoleSigner, RolePolicy, TrustRootRecord, TrustRootSignature,
};
use tirbase_types::CommandRole;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tb36-remote-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct TestPki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
    other_client_cert_pem: String,
    other_client_key_pem: String,
    ca_der: CertificateDer<'static>,
    client_cert_der: CertificateDer<'static>,
    client_key_der: PrivateKeyDer<'static>,
    other_client_cert_der: CertificateDer<'static>,
    other_client_key_der: PrivateKeyDer<'static>,
}

fn build_pki() -> TestPki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["tirbase-test-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let client_key = KeyPair::generate().unwrap();
    let client_params = CertificateParams::new(vec!["tirbase-admin".to_string()]).unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    // A second, untrusted CA for the negative case.
    let other_ca_key = KeyPair::generate().unwrap();
    let mut other_ca_params = CertificateParams::new(vec!["tirbase-other-ca".to_string()]).unwrap();
    other_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let other_ca_cert = other_ca_params.self_signed(&other_ca_key).unwrap();
    let other_client_key = KeyPair::generate().unwrap();
    let other_client_params = CertificateParams::new(vec!["other-admin".to_string()]).unwrap();
    let other_client_cert = other_client_params
        .signed_by(&other_client_key, &other_ca_cert, &other_ca_key)
        .unwrap();

    TestPki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
        other_client_cert_pem: other_client_cert.pem(),
        other_client_key_pem: other_client_key.serialize_pem(),
        ca_der: ca_cert.der().clone(),
        client_cert_der: client_cert.der().clone(),
        client_key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
        other_client_cert_der: other_client_cert.der().clone(),
        other_client_key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            other_client_key.serialize_der(),
        )),
    }
}

fn trust_root(ca: &InMemoryKeyProvider, pa: &InMemoryKeyProvider) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: pa.did().to_string(),
                public_key: pa.public_key_bytes().to_vec(),
            }],
        ),
    );
    let mut record = TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![ca.public_key_bytes().to_vec()],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    };
    record.signatures.push(TrustRootSignature {
        signer_did: ca.did().to_string(),
        signature: ca.sign(&record.signing_bytes()).unwrap(),
    });
    record
}

struct Gateway {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
    remote_addr: std::net::SocketAddr,
    pki: TestPki,
    logs: Arc<Mutex<Vec<String>>>,
}

impl Gateway {
    fn start(tag: &str) -> Gateway {
        let dir = temp_dir(tag);
        let pki = build_pki();
        let ca = InMemoryKeyProvider::generate().unwrap();
        let pa = InMemoryKeyProvider::generate().unwrap();
        std::fs::write(
            dir.join("trust-root.json"),
            serde_json::to_string(&trust_root(&ca, &pa)).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("enrollment-root-ca.hex"),
            hex::encode(ca.secret_seed()),
        )
        .unwrap();
        std::fs::write(dir.join("ca.pem"), &pki.ca_pem).unwrap();
        std::fs::write(dir.join("server.pem"), &pki.server_cert_pem).unwrap();
        std::fs::write(dir.join("server.key"), &pki.server_key_pem).unwrap();
        let profile_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../profiles/cold_room.toml");
        let remote_port = free_port();
        let config_path = dir.join("gateway.toml");
        std::fs::write(
            &config_path,
            format!(
                "key_path = {key:?}\n\
                 counter_db_path = {primary:?}\n\
                 derived_db_path = {derived:?}\n\
                 admin_socket = {sock:?}\n\
                 admin_enabled = true\n\
                 health_addr = \"127.0.0.1:{health}\"\n\
                 metrics_addr = \"127.0.0.1:{metrics}\"\n\
                 checkpoint_interval_secs = 3600\n\
                 trust_root_path = {trust:?}\n\
                 enrollment_root_ca_private_key_path = {seed:?}\n\
                 target_id = \"cold-room-1\"\n\
                 envelope_profile_path = {profile:?}\n\
                 admin_remote_addr = \"127.0.0.1:{remote_port}\"\n\
                 admin_remote_cert_path = {server_cert:?}\n\
                 admin_remote_key_path = {server_key:?}\n\
                 admin_remote_client_ca_path = {client_ca:?}\n",
                key = dir.join("device-key.json"),
                primary = dir.join("primary.db"),
                derived = dir.join("derived.db"),
                sock = dir.join("admin.sock"),
                health = free_port(),
                metrics = free_port(),
                trust = dir.join("trust-root.json"),
                seed = dir.join("enrollment-root-ca.hex"),
                profile = profile_path,
                server_cert = dir.join("server.pem"),
                server_key = dir.join("server.key"),
                client_ca = dir.join("ca.pem"),
            ),
        )
        .unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"))
            .arg(&config_path)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn gateway");
        let logs = Arc::new(Mutex::new(Vec::new()));
        let stdout = child.stdout.take().unwrap();
        let sink = logs.clone();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });
        let socket = dir.join("admin.sock");
        let deadline = Instant::now() + Duration::from_secs(40);
        while Instant::now() < deadline {
            if socket.exists()
                && logs
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|l| l.contains("tirbase-gateway started"))
            {
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!(
                    "gateway exited during boot ({status}); logs:\n{}",
                    logs.lock().unwrap().join("\n")
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(socket.exists(), "admin socket missing");
        Gateway {
            child,
            dir,
            socket,
            remote_addr: format!("127.0.0.1:{remote_port}").parse().unwrap(),
            pki,
            logs,
        }
    }

    fn local_cmd(&self, command: Value) -> Value {
        let mut stream = UnixStream::connect(&self.socket).expect("connect admin socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(format!("{command}\n").as_bytes()).unwrap();
        let mut body = String::new();
        stream.read_to_string(&mut body).unwrap();
        serde_json::from_str(body.trim()).unwrap()
    }

    fn mint(&self, did: &str, role: &str) -> String {
        let response = self.local_cmd(json!({
            "cmd":"mint",
            "payload":{"did":did,"role":role,"ttl_secs":3600}
        }));
        assert_eq!(response["status"], 200, "mint: {response}");
        response["token_hex"].as_str().unwrap().to_string()
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn client_config(
    ca_der: CertificateDer<'static>,
    cert: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let config = match cert {
        Some((cert, key)) => builder.with_client_auth_cert(vec![cert], key).unwrap(),
        None => builder.with_no_client_auth(),
    };
    Arc::new(config)
}

fn http_request(
    gateway: &Gateway,
    config: Arc<rustls::ClientConfig>,
    request: &str,
) -> Result<String, String> {
    let server_name = ServerName::try_from("localhost").unwrap();
    let conn = rustls::ClientConnection::new(config, server_name).map_err(|e| e.to_string())?;
    let sock = TcpStream::connect(gateway.remote_addr).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut tls = rustls::StreamOwned::new(conn, sock);
    tls.write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    tls.flush().map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            // The server sends `Connection: close` and drops the TCP socket
            // without a TLS close_notify; a received response is still valid.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                if body.is_empty() {
                    return Err(error.to_string());
                }
                break;
            }
        }
    }
    if body.is_empty() {
        return Err("empty TLS response".into());
    }
    Ok(String::from_utf8_lossy(&body).to_string())
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

#[test]
fn remote_admin_requires_mtls_and_privileged_status_credential() {
    let gateway = Gateway::start("mtls");
    let auditor_token = gateway.mint("did:key:remote-auditor", "Auditor");

    // Valid client certificate + Bearer credential.
    let config = client_config(
        gateway.pki.ca_der.clone(),
        Some((
            gateway.pki.client_cert_der.clone(),
            gateway.pki.client_key_der.clone_key(),
        )),
    );
    let response = http_request(
        &gateway,
        config.clone(),
        &format!(
            "GET /admin/mode HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {auditor_token}\r\n\r\n"
        ),
    )
    .expect("mTLS request succeeds");
    assert!(
        status_line(&response).contains(" 200 "),
        "mTLS mode request: {response}"
    );
    assert!(response.contains("\"mode\":\"Normal\""), "{response}");

    // No client certificate: handshake must fail before a request is served.
    let no_cert = client_config(gateway.pki.ca_der.clone(), None);
    let result = http_request(
        &gateway,
        no_cert,
        &format!("GET /admin/mode HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {auditor_token}\r\n\r\n"),
    );
    assert!(
        result.is_err() || result.as_deref().unwrap_or("").is_empty(),
        "connection without a client certificate must be rejected: {result:?}"
    );

    // Client certificate from an untrusted CA: handshake must fail.
    let wrong_ca = client_config(
        gateway.pki.ca_der.clone(),
        Some((
            gateway.pki.other_client_cert_der.clone(),
            gateway.pki.other_client_key_der.clone_key(),
        )),
    );
    let result = http_request(
        &gateway,
        wrong_ca,
        &format!("GET /admin/mode HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {auditor_token}\r\n\r\n"),
    );
    assert!(
        result.is_err() || result.as_deref().unwrap_or("").is_empty(),
        "untrusted client certificate must be rejected: {result:?}"
    );

    // Valid certificate but no Bearer credential: 401.
    let response = http_request(
        &gateway,
        config.clone(),
        "GET /admin/mode HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .expect("server answers 401 over the established tunnel");
    assert!(
        status_line(&response).contains(" 401 "),
        "missing credential: {response}"
    );

    // Cross-issuer Guard status requires Auditor/PolicyAuthority.  A
    // CommandIssuer token asking about another issuer is refused.
    let issuer_token = gateway.mint("did:key:remote-issuer", "CommandIssuer");
    let response = http_request(
        &gateway,
        config.clone(),
        &format!(
            "GET /admin/status/did:key:someone-else HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {issuer_token}\r\n\r\n"
        ),
    )
    .expect("status request");
    assert!(
        status_line(&response).contains(" 403 "),
        "cross-issuer status without Auditor must be refused: {response}"
    );
    assert!(
        response.contains("CROSS_ISSUER_STATUS_REQUIRES_AUDITOR"),
        "{response}"
    );

    // The issuer may query its own state freely.
    let response = http_request(
        &gateway,
        config,
        &format!(
            "GET /admin/status/did:key:remote-issuer HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {issuer_token}\r\n\r\n"
        ),
    )
    .expect("self status request");
    assert!(
        status_line(&response).contains(" 200 "),
        "self status: {response}"
    );
    assert!(response.contains("\"self_query\":true"), "{response}");
}

fn _assert_paths(_: &Path) {}
