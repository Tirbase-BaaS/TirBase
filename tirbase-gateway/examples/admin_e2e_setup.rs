// SPDX-License-Identifier: AGPL-3.0-only

//! Prepare a real gateway deployment for the TypeScript admin-SDK e2e test.
//!
//! The generated `@tirbase/gateway-admin-sdk` client speaks the HTTP admin
//! surface, which in production is the mTLS remote listener. This tool writes
//! everything that listener and the gateway binary need into a directory:
//!
//! * a test PKI (CA, server cert with `localhost`/`127.0.0.1` SANs, client
//!   cert for mTLS),
//! * a signed trust root (PolicyAuthority / RevocationManager / 2-of-2
//!   TimeAnchor) and the root CA seed used by the `mint` endpoint,
//! * the `gateway.toml` enabling the Unix admin socket **and** the remote
//!   admin listener,
//! * a PolicyAuthority-signed `CommandMessage` body for `POST /admin/simulate`.
//!
//! It prints one JSON object describing the prepared deployment. The Node test
//! then spawns the real `tirbase-gateway` binary with that config and drives
//! `GatewayAdminClient` against it. No gateway behaviour is simulated here.
//!
//! Usage:
//!   cargo run -q -p tirbase-gateway --example admin_e2e_setup -- <dir>

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use serde_json::json;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::sign_command;
use tirbase_guard::trust_root::{
    AuthorizedRoleSigner, RolePolicy, TrustRootRecord, TrustRootSignature,
};
use tirbase_types::command::CommandMessage;
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId};

const TARGET: &str = "cold-room-1";
const CRITICAL_PARAM: &str = "setpoint_c";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind loopback")
        .local_addr()
        .expect("local addr")
        .port()
}

fn role_policy(threshold: u8, signers: &[&InMemoryKeyProvider]) -> RolePolicy {
    RolePolicy::new(
        threshold,
        signers
            .iter()
            .map(|signer| AuthorizedRoleSigner {
                did: signer.did().to_string(),
                public_key: signer.public_key_bytes().to_vec(),
            })
            .collect(),
    )
}

fn trust_root(
    ca: &InMemoryKeyProvider,
    pa: &InMemoryKeyProvider,
    rm: &InMemoryKeyProvider,
    ta1: &InMemoryKeyProvider,
    ta2: &InMemoryKeyProvider,
) -> TrustRootRecord {
    let mut roles = BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        role_policy(1, &[pa]),
    );
    roles.insert(
        CommandRole::RevocationManager,
        role_policy(1, &[rm]),
    );
    roles.insert(CommandRole::TimeAnchor, role_policy(2, &[ta1, ta2]));
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
        signature: ca.sign(&record.signing_bytes()).expect("sign trust root"),
    });
    record
}

struct TestPki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

fn build_pki() -> TestPki {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params =
        CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("ca params");
    // Distinct distinguished names keep the chain unambiguous: identical
    // subject/issuer DNs would make the leaf look self-signed to verifiers.
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "tirbase-admin-e2e-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let server_key = KeyPair::generate().expect("server key");
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("server params");
    server_params
        .distinguished_name
        .push(DnType::CommonName, "tirbase-admin-e2e-server");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert");

    let client_key = KeyPair::generate().expect("client key");
    let mut client_params =
        CertificateParams::new(vec!["tirbase-admin-client".to_string()]).expect("client params");
    client_params
        .distinguished_name
        .push(DnType::CommonName, "tirbase-admin-e2e-client");
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("client cert");

    TestPki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap_or_else(|e| {
        panic!("write {}: {e}", path.display());
    });
}

fn main() {
    let dir = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: admin_e2e_setup <directory>");
        std::process::exit(2);
    });
    std::fs::create_dir_all(&dir).expect("create dir");

    let pki = build_pki();
    write(&dir.join("ca.pem"), &pki.ca_pem);
    write(&dir.join("server.pem"), &pki.server_cert_pem);
    write(&dir.join("server.key"), &pki.server_key_pem);
    write(&dir.join("client.pem"), &pki.client_cert_pem);
    write(&dir.join("client.key"), &pki.client_key_pem);

    let ca = InMemoryKeyProvider::generate().expect("root ca");
    let pa = InMemoryKeyProvider::generate().expect("policy authority");
    let rm = InMemoryKeyProvider::generate().expect("revocation manager");
    let ta1 = InMemoryKeyProvider::generate().expect("time anchor 1");
    let ta2 = InMemoryKeyProvider::generate().expect("time anchor 2");

    write(
        &dir.join("trust-root.json"),
        &serde_json::to_string(&trust_root(&ca, &pa, &rm, &ta1, &ta2)).expect("trust root json"),
    );
    write(
        &dir.join("enrollment-root-ca.hex"),
        &hex::encode(ca.secret_seed()),
    );

    let profile_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../profiles/cold_room.toml");
    let remote_port = free_port();
    let config_path = dir.join("gateway.toml");
    write(
        &config_path,
        &format!(
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
             admin_events_view_days = 7\n\
             target_id = \"{target}\"\n\
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
            target = TARGET,
            profile = profile_path,
            server_cert = dir.join("server.pem"),
            server_key = dir.join("server.key"),
            client_ca = dir.join("ca.pem"),
        ),
    );

    // A PolicyAuthority-signed command for the `simulate` dry-run endpoint —
    // the only signature-bearing request body the test can produce without
    // re-implementing the guard's canonical encoding in JavaScript.
    let issuer = InMemoryKeyProvider::generate().expect("issuer");
    let mut command = CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: TargetId::new(TARGET),
        param: CRITICAL_PARAM.into(),
        desired_state: FixedPointValue::new(40, -1, 1),
        sequence_number: 1,
        idempotency_key: [3u8; 16],
        expiry_est: 1_800,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: Vec::new(),
        signature: DeviceSignature::Ed25519([0; 64]),
    };
    sign_command(&mut command, &issuer).expect("sign command");

    println!(
        "{}",
        serde_json::to_string(&json!({
            "configPath": config_path,
            "socketPath": dir.join("admin.sock"),
            "remoteAddr": format!("127.0.0.1:{remote_port}"),
            "caCertPath": dir.join("ca.pem"),
            "clientCertPath": dir.join("client.pem"),
            "clientKeyPath": dir.join("client.key"),
            "targetId": TARGET,
            "simulateBody": { "command": command },
        }))
        .expect("serialise setup")
    );
}
