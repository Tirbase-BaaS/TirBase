//! S35 / CLAIM-34.8: real child-process driver isolation test.
//!
//! Production caller: guard-owned DeviceTransport + tirbase-drivers SCM_RIGHTS,
//! plus driver child sandbox init. This test spawns a real child process, inherits
//! a socketpair fd, passes a device fd via SCM_RIGHTS, and verifies the child
//! receives it. On Linux it also verifies post-sandbox SCM_RIGHTS is blocked and
//! the child reports a `SecurityEvent(SandboxViolation/SCMRightsAttempt)`-shaped
//! reason.

#![cfg(unix)]

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

use tirbase_core::events::{ReasonCode, SecurityEvent, SecurityEventCategory, Severity};
use tirbase_drivers::{create_driver_socketpair, send_fd_via_scm_rights};
use tirbase_guard::{DeviceTransport, GuardDeviceTransport};

fn child_bin() -> String {
    env!("CARGO_BIN_EXE_driver-isolation-child").to_string()
}

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
    .expect("connect modbus tcp device transport")
}

#[test]
fn test_scm_rights_blocked() {
 // Part A (required by S35 Test ID): real child process receives device fd via SCM_RIGHTS.
    let transport = make_device_transport();
    assert!(transport.as_raw_fd() >= 0);
    let pair = create_driver_socketpair().expect("socketpair");
    let child = Command::new(child_bin())
        .arg("--recv-apply-sandbox-attempt-scm-rights")
        .arg("--socket-fd")
        .arg(pair.child_fd.to_string())
        .arg("--close-fd")
        .arg(pair.parent_fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn driver isolation child");

 // Parent must close its copy of child_fd after spawn.
    unsafe {
        libc::close(pair.child_fd);
    }

    let guard = GuardDeviceTransport::new(transport);
    guard
        .pass_device_fd_with(pair.parent_fd, |sock, devfd| {
            send_fd_via_scm_rights(sock, devfd).map_err(|e| std::io::Error::other(e.to_string()))
        })
        .expect("guard must pass device fd to real child via SCM_RIGHTS");

    let out = child.wait_with_output().expect("wait child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!(
        "child stdout:\n{stdout}\nchild stderr:\n{stderr}\nstatus={}",
        out.status
    );

    assert!(
        stdout.contains("SANDBOX:"),
        "child must report sandbox status (stdout={stdout}, stderr={stderr})"
    );

    if cfg!(target_os = "linux") {
        assert!(
            stdout.contains("SCM_RIGHTS_ATTEMPT:BLOCKED"),
            "Linux child must not be able to pass fds via SCM_RIGHTS after sandbox: {stdout}"
        );
        assert!(
            stdout.contains("reason=SCMRightsAttempt") || stdout.contains("SCMRightsAttempt"),
            "child must report SCMRightsAttempt security event reason: {stdout}"
        );
 // Production path emits/records SecurityEvent; this verifies the canonical
 // reason/category used by the event catalog and S35.
        let ev = SecurityEvent::new(
            SecurityEventCategory::Driver,
            Severity::High,
            ReasonCode::SCMRightsAttempt,
        )
        .with_detail("sandbox_blocked_scm_rights");
        assert_eq!(ev.reason_code.as_str(), "SCMRightsAttempt");
        assert_eq!(ev.category.as_str(), "Driver");
        assert!(
            out.status.success(),
            "Linux sandbox child should exit 0 after blocked attempt: {stdout}\n{stderr}"
        );
    } else {
 // Non-Linux dev hosts cannot enforce Linux seccomp/landlock; verify real
 // child fd passing and explicit platform status.
        assert!(
            stdout.contains("UNAVAILABLE:") || stdout.contains("SCM_RIGHTS_ATTEMPT:"),
            "non-Linux child must report explicit sandbox status: {stdout}"
        );
    }

    unsafe {
        libc::close(pair.parent_fd);
    }
}

// Wiring mutation check (34.8): omitting SCM_RIGHTS passing prevents child receive.
#[test]
fn wiring_mutation_not_passing_scm_rights_breaks_child_receive() {
    let pair = create_driver_socketpair().expect("socketpair");
    let child = Command::new(child_bin())
        .arg("--recv-and-report")
        .arg("--socket-fd")
        .arg(pair.child_fd.to_string())
        .arg("--close-fd")
        .arg(pair.parent_fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");
 // Parent must close its copy of child_fd; otherwise peer close isn't observed.
    unsafe {
        libc::close(pair.child_fd);
    }
 // Intentionally do NOT send SCM_RIGHTS; close parent side so child sees EOF/error.
    unsafe {
        libc::close(pair.parent_fd);
    }
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("RECV_ERR") || !out.status.success(),
        "without SCM_RIGHTS fd handoff, child must not report RECEIVED_OK: {stdout}"
    );
    assert!(!stdout.contains("RECEIVED_OK"), "{stdout}");
}
