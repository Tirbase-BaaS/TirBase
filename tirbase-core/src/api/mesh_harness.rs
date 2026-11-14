// SPDX-License-Identifier: AGPL-3.0-only

//! Reusable two-device real-mesh test harness (native tests only).
//!
//! These helpers were extracted verbatim from `api::real_mesh_tests` so later
//! workstreams can build genuine two-Swarm loopback scenarios without
//! duplicating the setup. Every helper drives **production** code paths:
//!
//! - `CoreHandle::init` — constructs the real Swarm and both background loops
//! - `CoreHandle::dial_peer` — the production dial path used by discovery
//! - `CoreHandle::spawn_inbound_drain_loop` — the identical drain loop `init`
//!   spawns in production builds (test builds make init's own instance inert
//!   so exact-count unit tests stay deterministic)
//! - `CoreHandle::read` — the ordinary public read path over the SQL projection
//!
//! No mock transport, no `inject_inbound`, no test-only branch sits on the
//! path these helpers set up.

#![cfg(all(test, feature = "native"))]

use super::*;
use std::env;
use std::net::TcpListener;
use std::time::Duration;

/// Temp-file SQLite path for a device's store.
pub(crate) fn tmp_path(suffix: &str) -> String {
    let mut p = env::temp_dir();
    p.push(format!("tirbase_mesh_test_{suffix}.db"));
    p.to_str().unwrap().to_string()
}

/// Remove a device's store, identity file and WAL/SHM sidecars.
pub(crate) fn cleanup(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{path}.identity.json"));
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

/// Reserve a free loopback TCP port for a transport listen address.
///
/// The listener is dropped before `CoreHandle::init` binds it, so there is
/// a tiny reuse window; reserving both ports up front (before either
/// handle inits) keeps that window to microseconds per port.
pub(crate) fn reserve_loopback_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    l.local_addr().expect("local addr").port()
}

/// Deployment baseline for a loopback mesh device (K=1, M=N=1, no schema,
/// no anchor). Tests that need quorum/diversity/schema behaviour clone it
/// and override the relevant fields.
pub(crate) fn mesh_deployment() -> DeploymentConfig {
    DeploymentConfig {
        revocation_m: 1,
        revocation_n: 1,
        biscuit_ttl_secs: 3600,
        extended_ttl_accepted_risk: false,
        root_ca_keys: vec![],
        migration_ca_public_key: None,
        update_signer_public_key: None,
        schema_version_path: vec![],
        schema_definitions: vec![],
        anchor_attested_location: false,
        beacon_public_keys: vec![],
        spatial_diversity_min: 1,
        max_single_sector_fraction: 0.7,
        quorum_k: 1,
        quorum_n: 1,
        saturate_lease_duration_secs: 3600,
        mesh_mtu: 0,
        mesh_ble_enabled: false,
        beacon_signal_loss_threshold_secs: 300,
    }
}

/// Minimal deployment config for a loopback mesh device (K=1, M=N=1,
/// no schema, no anchor). Quorum/diversity-sensitive tests use
/// [`mesh_config_with`] instead.
pub(crate) fn mesh_config(path: &str, port: u16) -> InitConfig {
    mesh_config_with(path, port, mesh_deployment())
}

/// Build a loopback mesh `InitConfig` with a caller-chosen deployment
/// (quorum K/N, spatial diversity, revocation thresholds, schema).
pub(crate) fn mesh_config_with(path: &str, port: u16, deployment: DeploymentConfig) -> InitConfig {
    InitConfig {
        storage_path: path.to_string(),
        listen_addr: format!("/ip4/127.0.0.1/tcp/{port}"),
        deployment,
    }
}

/// Initialise a handle on its own loopback port with a real Swarm (the
/// production `CoreHandle::init` path spawns the Swarm polling task) and
/// start the production inbound drain loop at accelerated cadence.
///
/// Test builds make `init`'s own drain loop inert so count-based unit tests
/// stay deterministic, so the test drives the accelerated loop explicitly —
/// the identical loop, same cadence knob the production build uses.
pub(crate) async fn init_mesh_handle(suffix: &str, port: u16) -> Arc<CoreHandle> {
    let path = tmp_path(suffix);
    cleanup(&path);
    init_mesh_handle_with_deployment(suffix, port, mesh_config(&path, port).deployment).await
}

/// Same as [`init_mesh_handle`] but with a caller-chosen deployment config
/// (quorum K/N, spatial diversity, revocation thresholds, schema).
pub(crate) async fn init_mesh_handle_with_deployment(
    suffix: &str,
    port: u16,
    deployment: DeploymentConfig,
) -> Arc<CoreHandle> {
    let path = tmp_path(suffix);
    cleanup(&path);
    let handle = CoreHandle::init(mesh_config_with(&path, port, deployment))
        .await
        .expect("init must succeed with a real Swarm");
    CoreHandle::spawn_inbound_drain_loop(&handle, Duration::from_millis(10));
    handle
}

/// Same as [`init_mesh_handle`] but with a caller-chosen storage path
/// (used by tests that reopen a device's store).
pub(crate) async fn init_mesh_handle_on_path(
    suffix: &str,
    port: u16,
    path: &str,
) -> Arc<CoreHandle> {
    let _ = suffix;
    let handle = CoreHandle::init(mesh_config(path, port))
        .await
        .expect("init must succeed with a real Swarm");
    CoreHandle::spawn_inbound_drain_loop(&handle, Duration::from_millis(10));
    handle
}

/// Dial `from` → `to`'s listen address via the production
/// `CoreHandle::dial_peer` path and wait until the connection is recorded
/// (the Swarm polling task's `ConnectionEstablished` arm populates the
/// peer table, so `mesh_status()` reports it).
pub(crate) async fn connect_peers(from: &Arc<CoreHandle>, target_addr: &str) {
    let addr: libp2p::Multiaddr = target_addr.parse().expect("valid multiaddr");
    from.dial_peer(addr).await.expect("dial_peer must succeed");

    let mut attempts = 0u32;
    loop {
        if from.mesh_status().peer_count >= 1 {
            return;
        }
        attempts += 1;
        assert!(
            attempts < 500,
            "explicit dial never established a connection (mesh_status stayed disconnected for 5s)"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Dial `from` → `target_addr` and wait until the connection is recorded,
/// asserting the mesh reaches `expected_peers` connected peers in total.
///
pub(crate) async fn connect_peers_until(
    from: &Arc<CoreHandle>,
    target_addr: &str,
    expected_peers: u32,
) {
    let addr: libp2p::Multiaddr = target_addr.parse().expect("valid multiaddr");
    from.dial_peer(addr).await.expect("dial_peer must succeed");

    let deadline = crate::traits::monotonic_now() + 5_000_000;
    loop {
        if from.mesh_status().peer_count >= expected_peers {
            return;
        }
        assert!(
            crate::traits::monotonic_now() < deadline,
            "mesh only reached {} of {expected_peers} peers within 5s",
            from.mesh_status().peer_count
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Poll `handle.read(table, key)` until the row's data equals `expected`
/// or `timeout` elapses.
///
/// Polling for a bare successful read is not enough across multiple round
/// trips — a row written by an earlier round trip already reads successfully
/// with stale data.
pub(crate) async fn wait_for_data(
    handle: &CoreHandle,
    table: &str,
    key: &str,
    expected: &serde_json::Value,
    timeout: Duration,
) -> QueryResult {
    let deadline = crate::traits::monotonic_now() + timeout.as_micros() as u64;
    loop {
        match handle.read(table, key).await {
            Ok(res) if &res.data == expected => return res,
            _ => {
                assert!(
                    crate::traits::monotonic_now() < deadline,
                    "row {table}/{key} never projected the expected data on the receiving device within {timeout:?}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}
