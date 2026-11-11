//! CLAIM-33.5/33.6/33.7 (PV-4.21, PV-10.4, S24, S35): real out-of-process
//! driver child supervision.
//!
//! Production callers exercised here:
//! * `tirbase_drivers::{create_driver_socketpair, verify_peercred,
//!   send_fd_via_scm_rights}` through `DriverProxy::spawn_child`
//! * `apply_child_sandbox` inside the spawned driver child, before parsing
//! * `DriverLifecycle` / `apply_restart_decision` through
//!   `SupervisedDriver::restart_after_crash`
//!
//! The child is the real `driver-isolation-child` binary (a separate process
//! reached over the inherited socketpair), never an in-process `Write` wrapper.
//! Linux (CI) additionally asserts the sandbox is actually in force: a
//! post-sandbox filesystem open and `socket(2)` both fail.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_drivers::lifecycle::{DriverCrashSupervisor, DriverLifecycle};
use tirbase_drivers::DriverRestartDecision;
use tirbase_guard::driver_proxy::{ChildDriverConfig, SupervisedDriver};
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::{sign_command, single_target_guard, DeviceTransport, IngressSource};
use tirbase_types::command::{CoSignature, CommandMessage};
use tirbase_types::{CommandRole, DeviceSignature, Did, FixedPointValue, TargetId, UNIT_PERCENT};

fn child_bin() -> String {
    env!("CARGO_BIN_EXE_driver-isolation-child").to_string()
}

fn fpv(mantissa: i64) -> FixedPointValue {
    FixedPointValue::new(mantissa, -1, UNIT_PERCENT)
}

fn target() -> TargetId {
    TargetId::new("pump-1")
}

fn device_id() -> String {
    "did:key:zDeviceLocal".to_string()
}

fn make_command(issuer: &InMemoryKeyProvider, sequence_number: u64) -> CommandMessage {
    CommandMessage {
        issuer_did: Did::new(issuer.did()),
        role: CommandRole::CommandIssuer,
        target_id: target(),
        param: "speed".to_string(),
        desired_state: fpv(500),
        sequence_number,
        idempotency_key: [sequence_number as u8; 16],
        expiry_est: 9_999_999_999,
        policy_version: 1,
        enrollment_epoch: 0,
        challenge_nonce: None,
        co_signatures: Vec::<CoSignature>::new(),
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}

/// Guard-owned device endpoint whose fd is handed to the child via SCM_RIGHTS.
fn make_device_transport() -> DeviceTransport {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind device");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    DeviceTransport::connect_modbus_tcp(
        &addr.to_string(),
        Duration::from_secs(1),
        Some(Duration::from_secs(1)),
    )
    .expect("connect device transport")
}

fn config(device_fd: Option<RawFd>, extra_args: Vec<String>) -> ChildDriverConfig {
    let caps = tirbase_drivers::isolation::KernelIsolationCaps::detect();
    let mut args = vec!["--sandboxed-driver".to_string()];
    args.extend(extra_args);
    ChildDriverConfig {
        program: PathBuf::from(child_bin()),
        args,
        device_fd,
        // Test-only explicit opt-in mirrors the signed config flag on hosts
        // without landlock; seccomp is still required and asserted below.
        degraded_isolation_opt_in: !caps.supports_landlock(),
        expected_peer_uid: None,
        capture_output: true,
    }
}

fn fast_lifecycle() -> DriverLifecycle {
    DriverLifecycle::new(Duration::from_millis(50), Duration::from_millis(200), 5)
}

/// Collects child stdout lines and lets the test wait for a marker.
fn collect_stdout(driver: &mut SupervisedDriver) -> Receiver<String> {
    let stdout = driver.take_stdout().expect("child stdout piped");
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

fn wait_for(rx: &Receiver<String>, needle: &str, timeout: Duration) -> Vec<String> {
    let deadline = tirbase_core::traits::monotonic_now() + timeout.as_micros() as u64;
    let mut seen = Vec::new();
    loop {
        let left_micros = deadline.saturating_sub(tirbase_core::traits::monotonic_now());
        if left_micros == 0 {
            panic!("timed out waiting for {needle:?}; child output so far: {seen:#?}");
        }
        let left = Duration::from_micros(left_micros);
        match rx.recv_timeout(left.min(Duration::from_millis(200))) {
            Ok(line) => {
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return seen;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("child stdout closed before {needle:?}; output so far: {seen:#?}")
            }
        }
    }
}

fn drain(rx: &Receiver<String>) -> Vec<String> {
    let mut seen = Vec::new();
    while let Ok(line) = rx.recv_timeout(Duration::from_secs(5)) {
        seen.push(line);
    }
    seen
}

/// Admitted actuation through the sole `ActuationPermit` issuer.
fn dispatch_admitted(driver: &mut SupervisedDriver, sequence_number: u64) {
    let issuer = InMemoryKeyProvider::generate().unwrap();
    let registry = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
    registry.ensure_enrolled(&device_id(), 1_000).unwrap();
    let guard = single_target_guard(registry, target(), device_id());
    let mut cmd = make_command(&issuer, sequence_number);
    sign_command(&mut cmd, &issuer).expect("sign");
    guard
        .admit(&cmd, IngressSource::Mesh, driver.proxy_mut(), b"PING")
        .expect("admitted command dispatched to the real driver child");
}

fn unique_marker() -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "tirbase-driver-crash-once-{}-{n}",
        std::process::id()
    ))
}

#[derive(Default)]
struct RecordingSupervisor {
    events: Mutex<Vec<(u32, bool)>>,
}

impl DriverCrashSupervisor for RecordingSupervisor {
    fn on_driver_restart(&self, attempt: u32, _backoff: Duration) {
        self.events.lock().unwrap().push((attempt, false));
    }
    fn on_driver_escalate_lockdown(&self, attempts: u32) {
        self.events.lock().unwrap().push((attempts, true));
    }
}

/// [CLAIM-33.5 + CLAIM-33.6] The spawned child is a real process: it receives
/// the device fd, applies its sandbox, probes it, and only then serves frames.
#[test]
fn real_child_applies_sandbox_and_serves_admitted_frames() {
    let transport = make_device_transport();
    let mut driver = SupervisedDriver::start_with_lifecycle(
        config(Some(transport.as_raw_fd()), Vec::new()),
        fast_lifecycle(),
    )
    .expect("spawn real driver child");

    assert!(driver.child_pid() > 0);
    #[cfg(target_os = "linux")]
    {
        let (uid, pid) = driver
            .peer_credentials()
            .expect("SO_PEERCRED verified before the first write");
        assert_eq!(uid, unsafe { libc::geteuid() });
        assert!(pid > 0);
    }

    let rx = collect_stdout(&mut driver);
    let ready = wait_for(&rx, "READY", Duration::from_secs(15));

    if cfg!(target_os = "linux") {
        assert!(
            ready.iter().any(|l| l.contains("SANDBOX:APPLIED")),
            "sandbox must be applied in the child: {ready:#?}"
        );
        assert!(
            ready.iter().any(|l| l.contains("NET_PROBE:BLOCKED")),
            "seccomp must block socket(2) after sandboxing: {ready:#?}"
        );
        if tirbase_drivers::isolation::KernelIsolationCaps::detect().supports_landlock() {
            assert!(
                ready.iter().any(|l| l.contains("FS_PROBE:BLOCKED")),
                "landlock must block filesystem opens after sandboxing: {ready:#?}"
            );
        }
    } else {
        // Non-Linux dev hosts cannot enforce Linux seccomp/landlock; the child
        // reports the platform limitation explicitly instead of pretending.
        assert!(
            ready.iter().any(|l| l.contains("SANDBOX:UNAVAILABLE")),
            "non-Linux child must report explicit sandbox status: {ready:#?}"
        );
    }

    // Dispatch through the guard-owned permit path and read the echo back.
    dispatch_admitted(&mut driver, 1);
    let mut buf = [0u8; 16];
    let n = driver
        .receive_with_timeout(&mut buf, Duration::from_secs(5))
        .expect("driver child echoes the frame");
    assert_eq!(&buf[..n], b"PING");
    assert_eq!(driver.consecutive_crashes(), 0);
}

/// [CLAIM-33.7] A crashing child is restarted with backoff through the
/// supervision path, and the decision is reported to supervisor accounting.
#[test]
fn crashed_child_is_restarted_with_backoff() {
    let marker = unique_marker();
    let _ = std::fs::remove_file(&marker);
    let transport = make_device_transport();
    let mut driver = SupervisedDriver::start_with_lifecycle(
        config(
            Some(transport.as_raw_fd()),
            vec!["--crash-once".to_string(), marker.to_string_lossy().into()],
        ),
        fast_lifecycle(),
    )
    .expect("spawn real driver child");

    let first_pid = driver.child_pid();
    let rx = collect_stdout(&mut driver);

    // The first child exits non-zero before applying its sandbox.
    let deadline = tirbase_core::traits::monotonic_now() + 10_000_000;
    let mut status = None;
    while tirbase_core::traits::monotonic_now() < deadline {
        if let Some(exit) = driver.try_wait().expect("try_wait") {
            status = Some(exit);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = status.expect("first driver child must crash");
    assert!(!status.success(), "first child should crash: {status:?}");
    let crashing_output = drain(&rx);
    assert!(
        crashing_output
            .iter()
            .any(|l| l.contains("CRASH_BEFORE_SANDBOX")),
        "crash must come from the real child process: {crashing_output:#?}"
    );

    let supervisor = RecordingSupervisor::default();
    let decision = driver
        .restart_after_crash(&supervisor)
        .expect("restart after crash");
    assert_eq!(
        decision,
        DriverRestartDecision::Restart {
            attempt: 1,
            backoff: Duration::from_millis(50),
        }
    );
    assert_eq!(
        supervisor.events.lock().unwrap().as_slice(),
        &[(1, false)],
        "restart decision must reach supervisor accounting"
    );
    assert_eq!(driver.consecutive_crashes(), 1);
    assert_ne!(
        driver.child_pid(),
        first_pid,
        "a new child process must run"
    );

    // The respawned child is real and sandboxed (marker present -> no crash).
    let rx = collect_stdout(&mut driver);
    let ready = wait_for(&rx, "READY", Duration::from_secs(15));
    if cfg!(target_os = "linux") {
        assert!(
            ready.iter().any(|l| l.contains("SANDBOX:APPLIED")),
            "restarted child must sandbox itself: {ready:#?}"
        );
    }
    assert_eq!(
        driver.consecutive_crashes(),
        1,
        "accounting is reset only after a stable period"
    );

    driver.note_stable();
    assert_eq!(driver.consecutive_crashes(), 0);
    let _ = std::fs::remove_file(&marker);
}
