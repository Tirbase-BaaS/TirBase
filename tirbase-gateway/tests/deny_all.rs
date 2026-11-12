//! (PV-11.5): deny-all until a signed EnvelopeProfile is installed.
//!
//! A gateway configured with a command endpoint but no signed profile must not
//! open the command ingress socket at all, and must report the deny-all posture
//! at boot. The administrative socket remains available so an operator can
//! install a profile.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tb36-deny-{tag}-{}-{n}", std::process::id()));
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

struct Running {
    child: Child,
    dir: std::path::PathBuf,
    logs: Arc<Mutex<Vec<String>>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn no_profile_means_no_command_socket_and_a_deny_all_boot_event() {
    let dir = temp_dir("noprofile");
    let command_port = free_port();
    let config = dir.join("gateway.toml");
    std::fs::write(
        &config,
        format!(
            "key_path = {:?}\n\
             counter_db_path = {:?}\n\
             derived_db_path = {:?}\n\
             admin_socket = {:?}\n\
             admin_enabled = true\n\
             health_addr = \"127.0.0.1:{}\"\n\
             metrics_addr = \"127.0.0.1:{}\"\n\
             checkpoint_interval_secs = 3600\n\
             local_admin_command_addr = \"127.0.0.1:{command_port}\"\n",
            dir.join("device-key.json"),
            dir.join("primary.db"),
            dir.join("derived.db"),
            dir.join("admin.sock"),
            free_port(),
            free_port(),
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_tirbase-gateway"))
        .arg(&config)
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
    let running = Running { child, dir, logs };
    assert!(socket.exists(), "admin socket must still serve operators");

    let text = running.logs.lock().unwrap().join("\n");
    assert!(
        text.contains("deny-all command posture active"),
        "boot must report deny-all without a profile:\n{text}"
    );

 // 36.5 wiring mutation: no command ingress socket may be opened.
    let refused = TcpStream::connect(("127.0.0.1", command_port)).is_err();
    assert!(
        refused,
        "command ingress socket must not exist without an installed profile"
    );

 // The admin API stays available and reports the unconfigured state.
    let mut stream = UnixStream::connect(&socket).expect("admin socket");
    stream
        .write_all(b"{\"cmd\":\"simulate\",\"payload\":{\"command\":{}}}\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(
        !response.contains("\"status\":501"),
        "admin API must remain wired: {response}"
    );
}

#[test]
fn cloud_inbound_listener_is_a_configuration_error() {
    let dir = temp_dir("cloud-listen");
    let config = dir.join("gateway.toml");
    std::fs::write(
        &config,
        format!(
            "key_path = {:?}\n\
             cloud_listen_addr = \"0.0.0.0:4443\"\n",
            dir.join("device-key.json"),
        ),
    )
    .unwrap();
    let result = tirbase_gateway::config::load_config_from_toml_path(&config);
    assert!(
        result.is_err(),
        "36.6: cloud inbound listener configuration must be rejected (outbound-only cloud ingress)"
    );
}
