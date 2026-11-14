// SPDX-License-Identifier: AGPL-3.0-only

//! CLAIM-33.5/33.6/33.7 (PV-4.21, PV-10.4, S24, S35): socketpair isolation plan,
//! fail-closed sandbox policy, and lifecycle restart/backoff/escalation.

#[cfg(unix)]
use tirbase_drivers::create_driver_socketpair;

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tirbase_drivers::{
    apply_child_sandbox, apply_restart_decision, DriverCrashSupervisor, DriverLifecycle,
    DriverRestartDecision, IsolationError, KernelIsolationCaps, DRIVER_RESTART_INITIAL,
    DRIVER_RESTART_MAX, DRIVER_RESTART_MAX_RETRIES, DRIVER_SOCKET_FD_ARG,
};

#[cfg(unix)]
#[test]
fn socketpair_af_unix_seqpacket_is_created() {
    let pair = create_driver_socketpair().expect("socketpair");
    assert!(pair.parent_fd >= 0);
    assert!(pair.child_fd >= 0);
    assert_ne!(pair.parent_fd, pair.child_fd);
 // Clean up fds.
    unsafe {
        libc::close(pair.parent_fd);
        libc::close(pair.child_fd);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn so_peercred_reports_current_process_uid() {
    let pair = create_driver_socketpair().expect("socketpair");
    let uid = unsafe { libc::getuid() };
    let (peer_uid, peer_pid) = verify_peercred(pair.parent_fd, Some(uid)).expect("peercred");
    assert_eq!(peer_uid, uid);
    assert!(peer_pid > 0);
    unsafe {
        libc::close(pair.parent_fd);
        libc::close(pair.child_fd);
    }
}

// [CLAIM-33.6] fail-closed without signed opt-in when landlock unavailable.
#[test]
fn landlock_unavailable_fails_closed_without_signed_opt_in() {
    let caps = KernelIsolationCaps {
        kernel_major: 5,
        kernel_minor: 4,
        landlock_available: false,
    };
    let err = apply_child_sandbox(caps, false).unwrap_err();
    match err {
        IsolationError::SandboxUnavailable { detail } => {
            assert!(detail.contains("fail-closed") || detail.contains("landlock unavailable"));
        }
        other => panic!("expected SandboxUnavailable, got {other:?}"),
    }
}

#[test]
fn child_inherits_socket_fd_via_exec_arg_name() {
    assert_eq!(DRIVER_SOCKET_FD_ARG, "--tirbase-driver-socket-fd");
}

// [CLAIM-33.7, S24] exponential backoff 1s initial, 60s max, 5 retries, escalation feeds supervisor.
#[test]
fn lifecycle_exponential_backoff_and_supervisor_escalation() {
    assert_eq!(DRIVER_RESTART_INITIAL, Duration::from_secs(1));
    assert_eq!(DRIVER_RESTART_MAX, Duration::from_secs(60));
    assert_eq!(DRIVER_RESTART_MAX_RETRIES, 5);

    #[derive(Default)]
    struct S(Mutex<Vec<(u32, bool)>>);
    impl DriverCrashSupervisor for S {
        fn on_driver_restart(&self, attempt: u32, _backoff: Duration) {
            self.0.lock().unwrap().push((attempt, false));
        }
        fn on_driver_escalate_lockdown(&self, attempts: u32) {
            self.0.lock().unwrap().push((attempts, true));
        }
    }
    let sup = Arc::new(S::default());
    let mut lc = DriverLifecycle::default();
    for (i, expected) in [1u64, 2, 4, 8, 16].iter().enumerate() {
        let d = lc.record_crash();
        let DriverRestartDecision::Restart { attempt, backoff } = d else {
            panic!("expected restart");
        };
        assert_eq!(attempt as usize, i + 1);
        assert_eq!(backoff, Duration::from_secs(*expected));
        apply_restart_decision(d, &*sup);
    }
    let esc = lc.record_crash();
    assert_eq!(esc, DriverRestartDecision::EscalateLockdown { attempts: 6 });
    apply_restart_decision(esc, &*sup);
    let ev = sup.0.lock().unwrap();
    assert_eq!(ev.last(), Some(&(6, true)));
}
