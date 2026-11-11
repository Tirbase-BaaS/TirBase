//! Task 36.6/36.8a–36.8f: outbound-only cloud channel over real TLS.
//!
//! The gateway is spawnpointed as the real binary; a mock cloud endpoint
//! terminates TLS with a client-certificate verifier.  The tests cover:
//! * outbound-only connection (the gateway never listens on the cloud port);
//! * offline boot notification replayed on reconnect (36.8c);
//! * challenge nonce issuance and rejection feedback (36.8d/36.8e);
//! * per-connection inbound rate limit (36.8f);
//! * reconnect after a drop (36.8a);
//! * client-certificate rotation without disrupting the active connection
//!   (36.8f);
//! * connection refused when the device certificate is not trusted (36.8b).

#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::CertificateDer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::trust_root::{
    AuthorizedRoleSigner, RolePolicy, TrustRootRecord, TrustRootSignature,
};
use tirbase_types::CommandRole;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tb36-cloud-{tag}-{}-{n}", std::process::id()));
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

struct Pki {
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
    client_cert2_pem: String,
    client_key2_pem: String,
    other_cert_pem: String,
    other_key_pem: String,
}

fn build_pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["tb36-cloud-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let make_client = |name: &str| {
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![name.to_string()]).unwrap();
        let cert = params.signed_by(&key, &ca_cert, &ca_key).unwrap();
        (cert.pem(), key.serialize_pem())
    };
    let (client_cert_pem, client_key_pem) = make_client("device-1");
    let (client_cert2_pem, client_key2_pem) = make_client("device-1-rotated");

    let other_ca_key = KeyPair::generate().unwrap();
    let other_ca_cert = CertificateParams::new(vec!["other-ca".to_string()])
        .unwrap()
        .self_signed(&other_ca_key)
        .unwrap();
    let other_key = KeyPair::generate().unwrap();
    let other_cert = CertificateParams::new(vec!["rogue-device".to_string()])
        .unwrap()
        .signed_by(&other_key, &other_ca_cert, &other_ca_key)
        .unwrap();

    Pki {
        ca_pem: ca_cert.pem(),
        ca_der: ca_cert.der().clone(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem,
        client_key_pem,
        client_cert2_pem,
        client_key2_pem,
        other_cert_pem: other_cert.pem(),
        other_key_pem: other_key.serialize_pem(),
    }
}

fn trusted_client_ca(der: &CertificateDer<'static>) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    roots
}

fn server_config(pki: &Pki) -> Arc<rustls::ServerConfig> {
    let certs: Vec<_> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(pki.server_cert_pem.as_bytes()))
            .collect::<Result<_, _>>()
            .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(pki.server_key_pem.as_bytes()))
        .unwrap()
        .unwrap();
    let verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(trusted_client_ca(&pki.ca_der)))
            .build()
            .unwrap();
    Arc::new(
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

#[derive(Default)]
struct MockState {
    messages: Mutex<Vec<Value>>,
    peer_cert_hashes: Mutex<Vec<String>>,
    connections: AtomicU64,
}

struct MockCloud {
    state: Arc<MockState>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockCloud {
    fn start(addr: std::net::SocketAddr, config: Arc<rustls::ServerConfig>) -> Self {
        let state = Arc::new(MockState::default());
        let stop = Arc::new(AtomicBool::new(false));
        let shared = state.clone();
        let stopping = stop.clone();
        let handle = thread::spawn(move || {
            let listener = TcpListener::bind(addr).expect("bind mock cloud");
            listener.set_nonblocking(true).unwrap();
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let config = config.clone();
                        let shared = shared.clone();
                        thread::spawn(move || serve_connection(stream, config, shared));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => break,
                }
            }
        });
        MockCloud {
            state,
            stop,
            handle: Some(handle),
        }
    }

    fn messages(&self) -> Vec<Value> {
        self.state.messages.lock().unwrap().clone()
    }

    fn connection_count(&self) -> u64 {
        self.state.connections.load(Ordering::Relaxed)
    }

    fn peer_hash(&self, index: usize) -> Option<String> {
        self.state
            .peer_cert_hashes
            .lock()
            .unwrap()
            .get(index)
            .cloned()
    }
}

impl Drop for MockCloud {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_connection(stream: TcpStream, config: Arc<rustls::ServerConfig>, state: Arc<MockState>) {
    let conn = match rustls::ServerConnection::new(config) {
        Ok(conn) => conn,
        Err(_) => return,
    };
    let index = state.connections.fetch_add(1, Ordering::Relaxed);
    let mut tls = rustls::StreamOwned::new(conn, stream);
    tls.sock
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    tls.sock
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut buffer = String::new();
    let mut chunk = [0u8; 8192];
    let started = tirbase_core::traits::monotonic_now();
    let mut scripted = false;
    let mut hello_seen = false;

    while tirbase_core::traits::monotonic_now().saturating_sub(started) < 8_000_000 {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.push_str(&String::from_utf8_lossy(&chunk[..n]));
                while let Some(position) = buffer.find('\n') {
                    let line: String = buffer.drain(..=position).collect();
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(value) = serde_json::from_str::<Value>(line) {
                        if value["type"] == "hello" {
                            hello_seen = true;
                            let der = tls
                                .conn
                                .peer_certificates()
                                .and_then(|certs| certs.first().cloned());
                            if let Some(der) = der {
                                let mut hasher = Sha256::new();
                                hasher.update(der.as_ref());
                                state
                                    .peer_cert_hashes
                                    .lock()
                                    .unwrap()
                                    .push(hex::encode(hasher.finalize()));
                            }
                        }
                        state.messages.lock().unwrap().push(value);
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }

        if hello_seen && !scripted && index == 0 {
            scripted = true;
            // 36.8e: challenge request for a critical parameter while the
            // gateway has no authenticated time beacon (Unverified freshness).
            let _ = writeln!(
                tls,
                "{}",
                json!({
                    "type":"challenge_request",
                    "request_id": 77,
                    "issuer_did": "did:key:cloud-issuer",
                    "target_id": "cold-room-1",
                    "param": "setpoint_c",
                    "command_hash_hex": "ab".repeat(32)
                })
            );
            let _ = tls.flush();
            // 36.8d: a command that cannot be authorized produces coarse
            // rejection feedback.
            let _ = writeln!(
                tls,
                "{}",
                json!({
                    "type":"command",
                    "id":"cmd-1",
                    "command":{
                        "issuer_did":"did:key:cloud-issuer",
                        "role":"CommandIssuer",
                        "target_id":"cold-room-1",
                        "param":"setpoint_c",
                        "desired_state":{"mantissa":40,"exponent":-1,"unit_id":1},
                        "sequence_number":1,
                        "idempotency_key":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
                        "expiry_est":1900000000,
                        "policy_version":1,
                        "enrollment_epoch":0,
                        "challenge_nonce":null,
                        "co_signatures":[],
                        "signature":{"Ed25519":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
                    }
                })
            );
            let _ = tls.flush();
            // 36.8f: flood beyond the configured 3 messages/second.
            for i in 0..10 {
                let _ = writeln!(
                    tls,
                    "{}",
                    json!({
                        "type":"command",
                        "id":format!("flood-{i}"),
                        "command":{
                            "issuer_did":"did:key:cloud-issuer",
                            "role":"CommandIssuer",
                            "target_id":"cold-room-1",
                            "param":"setpoint_c",
                            "desired_state":{"mantissa":40,"exponent":-1,"unit_id":1},
                            "sequence_number":i+2,
                            "idempotency_key":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
                            "expiry_est":1900000000,
                            "policy_version":1,
                            "enrollment_epoch":0,
                            "challenge_nonce":null,
                            "co_signatures":[],
                            "signature":{"Ed25519":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
                        }
                    })
                );
            }
            let _ = tls.flush();
        }

        // Connection 0 is deliberately short-lived so the gateway reconnects.
        if index == 0 && tirbase_core::traits::monotonic_now().saturating_sub(started) > 2_000_000 {
            break;
        }
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
    logs: Arc<Mutex<Vec<String>>>,

}

impl Gateway {
    fn start(tag: &str, pki: &Pki, cloud_port: u16, use_other_cert: bool) -> Gateway {
        let dir = temp_dir(tag);
        let ca = InMemoryKeyProvider::generate().unwrap();
        let pa = InMemoryKeyProvider::generate().unwrap();
        std::fs::write(
            dir.join("trust-root.json"),
            serde_json::to_string(&trust_root(&ca, &pa)).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("ca.pem"), &pki.ca_pem).unwrap();
        let (cert_pem, key_pem) = if use_other_cert {
            (&pki.other_cert_pem, &pki.other_key_pem)
        } else {
            (&pki.client_cert_pem, &pki.client_key_pem)
        };
        std::fs::write(dir.join("device.pem"), cert_pem).unwrap();
        std::fs::write(dir.join("device.key"), key_pem).unwrap();
        let profile_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../profiles/cold_room.toml");
        let config_path = dir.join("gateway.toml");
        std::fs::write(
            &config_path,
            format!(
                "key_path = {key:?}\n\
                 counter_db_path = {primary:?}\n\
                 derived_db_path = {derived:?}\n\
                 admin_socket = {sock:?}\n\
                 admin_enabled = false\n\
                 health_addr = \"127.0.0.1:{health}\"\n\
                 metrics_addr = \"127.0.0.1:{metrics}\"\n\
                 checkpoint_interval_secs = 3600\n\
                 trust_root_path = {trust:?}\n\
                 target_id = \"cold-room-1\"\n\
                 envelope_profile_path = {profile:?}\n\
                 cloud_endpoint = \"127.0.0.1:{cloud_port}\"\n\
                 cloud_ca_cert_path = {ca:?}\n\
                 cloud_device_cert_path = {device:?}\n\
                 cloud_device_key_path = {device_key:?}\n\
                 cloud_queue_depth = 16\n\
                 cloud_rate_limit_per_sec = 3\n\
                 cloud_reconnect_initial_secs = 1\n\
                 cloud_max_reconnect_delay_secs = 2\n",
                key = dir.join("device-key.json"),
                primary = dir.join("primary.db"),
                derived = dir.join("derived.db"),
                sock = dir.join("admin.sock"),
                health = free_port(),
                metrics = free_port(),
                trust = dir.join("trust-root.json"),
                profile = profile_path,
                ca = dir.join("ca.pem"),
                device = dir.join("device.pem"),
                device_key = dir.join("device.key"),
                cloud_port = cloud_port,
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

        let deadline = tirbase_core::traits::monotonic_now() + 40_000_000;
        while tirbase_core::traits::monotonic_now() < deadline {
            if logs
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
        Gateway {
            child,
            dir,
            logs,
        }
    }

    fn log_text(&self) -> String {
        self.logs.lock().unwrap().join("\n")
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wait_until(deadline: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = tirbase_core::traits::monotonic_now();
    while tirbase_core::traits::monotonic_now().saturating_sub(start) < deadline.as_micros() as u64 {
        if check() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn cloud_channel_is_outbound_tls_only_with_queue_reconnect_feedback_and_rate_limit() {
    let pki = build_pki();
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = server_config(&pki);

    // The endpoint is deliberately down while the gateway boots, so the boot
    // notification must be retained by the offline queue.
    let gateway = Gateway::start("outbound", &pki, port, false);

    // No inbound cloud listener: the gateway never binds the cloud port, so the
    // port stays free for the cloud endpoint to bind.
    assert!(
        TcpListener::bind(addr).is_ok(),
        "36.6: gateway must not open an inbound listener on the cloud port"
    );

    let server = MockCloud::start(addr, config);

    let saw_boot = wait_until(Duration::from_secs(20), || {
        server
            .messages()
            .iter()
            .any(|m| m["type"] == "result" && m["id"] == "boot")
    });
    assert!(
        saw_boot,
        "36.8c: boot notification queued while offline must be replayed on reconnect; messages={:?}\nlogs:\n{}",
        server.messages(),
        gateway.log_text()
    );

    let saw_nonce = wait_until(Duration::from_secs(10), || {
        server
            .messages()
            .iter()
            .any(|m| m["type"] == "challenge_nonce" && m["request_id"] == 77)
    });
    assert!(
        saw_nonce,
        "36.8e: challenge nonce must be issued over the cloud channel; messages={:?}",
        server.messages()
    );
    let nonce = server
        .messages()
        .into_iter()
        .find(|m| m["type"] == "challenge_nonce")
        .unwrap();
    assert_eq!(nonce["nonce_hex"].as_str().unwrap().len(), 64);
    assert_eq!(nonce["command_hash_hex"], "ab".repeat(32));

    let saw_rejection = wait_until(Duration::from_secs(10), || {
        server
            .messages()
            .iter()
            .any(|m| m["type"] == "result" && m["id"] == "cmd-1" && m["accepted"] == false)
    });
    assert!(
        saw_rejection,
        "36.8d: coarse rejection must be delivered to the remote issuer; messages={:?}\nlogs:\n{}",
        server.messages(),
        gateway.log_text()
    );
    let rejection = server
        .messages()
        .into_iter()
        .find(|m| m["id"] == "cmd-1")
        .unwrap();
    assert!(
        rejection["code"].is_string(),
        "rejection carries a coarse code: {rejection}"
    );

    let saw_rate_limit = wait_until(Duration::from_secs(10), || {
        server.messages().iter().any(|m| m["type"] == "rate_limit")
    });
    assert!(
        saw_rate_limit,
        "36.8f: per-connection rate limit must trigger on a flood; messages={:?}",
        server.messages()
    );

    // 36.8a: the mock closes connection 0; the gateway must reconnect.
    let reconnected = wait_until(Duration::from_secs(20), || server.connection_count() >= 2);
    assert!(
        reconnected,
        "36.8a: gateway must reconnect after a drop (connections={})\nlogs:\n{}",
        server.connection_count(),
        gateway.log_text()
    );

    // 36.8f: certificate files are re-read on reconnect.  Rotate while the
    // connection used it, then force another reconnect and verify the peer
    // certificate changed without the gateway process restarting.
    std::fs::write(gateway.dir.join("device.pem"), &pki.client_cert2_pem).unwrap();
    std::fs::write(gateway.dir.join("device.key"), &pki.client_key2_pem).unwrap();
    let rotated = wait_until(Duration::from_secs(25), || {
        server.connection_count() >= 3
            && server.peer_hash(0).is_some()
            && server
                .peer_hash(server.connection_count().saturating_sub(1) as usize)
                .map(|hash| Some(hash) != server.peer_hash(0))
                .unwrap_or(false)
    });
    assert!(
        rotated,
        "36.8f: rotated certificate must be used on the next connection (certs={:?}, connections={})",
        server.state.peer_cert_hashes.lock().unwrap(),
        server.connection_count()
    );
}

#[test]
fn cloud_channel_rejects_untrusted_device_certificate() {
    let pki = build_pki();
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = server_config(&pki);
    let server = MockCloud::start(addr, config);

    // Device certificate signed by an unrelated CA: the cloud endpoint must
    // reject the TLS session and never receive a device hello.
    let _gateway = Gateway::start("untrusted", &pki, port, true);
    thread::sleep(Duration::from_secs(4));
    let messages = server.messages();
    assert!(
        !messages.iter().any(|m| m["type"] == "hello"),
        "36.8b: an untrusted device certificate must not establish an authenticated session; messages={messages:?}"
    );
}
