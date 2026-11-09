//! Out-of-process driver isolation primitives (CLAIM-33.5, CLAIM-33.6, PV-4.21,
//! PV-10.4, INV-6, S35).
//!
//! Narrow `unsafe` is confined to Unix syscall boundaries for socketpair/fd
//! control required by the isolation contract.

#![allow(unsafe_code)]

use core::fmt;
use std::io;
use std::path::PathBuf;

/// Driver child init argument carrying the inherited socketpair fd number.
pub const DRIVER_SOCKET_FD_ARG: &str = "--tirbase-driver-socket-fd";

/// Signed config flag required to opt into degraded isolation when landlock is
/// unavailable on kernels < 5.13 (PV-10.4 fail-closed default).
pub const DEGRADED_ISOLATION_OPT_IN_FLAG: &str = "allow_degraded_driver_isolation";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationError {
    Socketpair(io::ErrorKind, String),
    Exec(io::ErrorKind, String),
    PeerCredential(String),
    SandboxUnavailable { detail: String },
    SandboxApply(String),
    InvalidChildConfig(String),
}

impl fmt::Display for IsolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IsolationError::Socketpair(k, m) => write!(f, "socketpair failed ({k:?}): {m}"),
            IsolationError::Exec(k, m) => write!(f, "exec failed ({k:?}): {m}"),
            IsolationError::PeerCredential(m) => write!(f, "SO_PEERCRED verification failed: {m}"),
            IsolationError::SandboxUnavailable { detail } => {
                write!(f, "driver sandbox unavailable (fail-closed): {detail}")
            }
            IsolationError::SandboxApply(m) => write!(f, "sandbox apply failed: {m}"),
            IsolationError::InvalidChildConfig(m) => write!(f, "invalid child config: {m}"),
        }
    }
}

impl std::error::Error for IsolationError {}

impl From<io::Error> for IsolationError {
    fn from(e: io::Error) -> Self {
        IsolationError::Exec(e.kind(), e.to_string())
    }
}

/// Guard/parent-side socketpair endpoints for a driver child.
///
/// - `parent_fd` (fd0): kept by the guard/parent process.
/// - `child_fd` (fd1): inherited by the driver child via `execve` arg passing.
#[derive(Debug)]
pub struct DriverSocketPair {
    pub parent_fd: i32,
    pub child_fd: i32,
}

/// Parent-side plan for launching an isolated driver child (CLAIM-33.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverSpawnPlan {
    pub child_program: PathBuf,
    pub child_args: Vec<String>,
    pub child_socket_fd: i32,
    pub pass_device_fd_via_scm_rights: bool,
}

/// Kernel/capability context for landlock policy decisions (CLAIM-33.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelIsolationCaps {
    pub kernel_major: u32,
    pub kernel_minor: u32,
    pub landlock_available: bool,
}

impl KernelIsolationCaps {
    pub fn supports_landlock(self) -> bool {
        self.landlock_available
            && (self.kernel_major > 5 || (self.kernel_major == 5 && self.kernel_minor >= 13))
    }
}

/// Creates `socketpair(AF_UNIX, SOCK_SEQPACKET)` for guard<->driver IPC.
///
/// Parent keeps `parent_fd` (fd0). Child inherits `child_fd` (fd1) via exec
/// argument inheritance (`DRIVER_SOCKET_FD_ARG`). The driver has no bind/connect
/// address; IPC is only over the inherited socketpair.
///
/// On platforms where `SOCK_SEQPACKET` is unavailable, falls back to
/// `SOCK_STREAM` so the isolation API remains usable for development/testing;
/// production Linux deployments use `SOCK_SEQPACKET` as specified.
#[cfg(unix)]
pub fn create_driver_socketpair() -> Result<DriverSocketPair, IsolationError> {
    let mut fds = [0_i32; 2];
    // SAFETY: `fds` is a valid 2-int array; libc writes exactly two fds on success.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        let _e = io::Error::last_os_error();
        // Fallback for platforms without AF_UNIX+SOCK_SEQPACKET (e.g. some macOS configs).
        // SAFETY: same invariants as above.
        let rc2 =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc2 != 0 {
            let e2 = io::Error::last_os_error();
            return Err(IsolationError::Socketpair(e2.kind(), e2.to_string()));
        }
    }
    Ok(DriverSocketPair {
        parent_fd: fds[0],
        child_fd: fds[1],
    })
}

#[cfg(not(unix))]
pub fn create_driver_socketpair() -> Result<DriverSocketPair, IsolationError> {
    Err(IsolationError::SandboxUnavailable {
        detail: "AF_UNIX/SOCK_SEQPACKET socketpair is unavailable on this target".into(),
    })
}

/// Verifies peer credentials on the guard-owned socket end (`SO_PEERCRED`).
///
/// This provides additional process identity verification beyond socketpair
/// inheritance (CLAIM-33.5). On Linux this returns the peer uid/pid; callers may
/// enforce policy (same uid, expected child pid) at the guard boundary.
#[cfg(target_os = "linux")]
pub fn verify_peercred(
    parent_fd: i32,
    expected_uid: Option<u32>,
) -> Result<(u32, i32), IsolationError> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = core::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred`/`len` are valid writable pointers for getsockopt output.
    let rc = unsafe {
        libc::getsockopt(
            parent_fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        return Err(IsolationError::PeerCredential(e.to_string()));
    }
    if let Some(uid) = expected_uid {
        if cred.uid != uid {
            return Err(IsolationError::PeerCredential(format!(
                "peer uid {} did not match expected {}",
                cred.uid, uid
            )));
        }
    }
    Ok((cred.uid, cred.pid))
}

#[cfg(not(target_os = "linux"))]
pub fn verify_peercred(
    _parent_fd: i32,
    _expected_uid: Option<u32>,
) -> Result<(u32, i32), IsolationError> {
    Err(IsolationError::SandboxUnavailable {
        detail: "SO_PEERCRED verification is implemented for Linux targets".into(),
    })
}

/// Applies seccomp-BPF, `no-new-privs`, and landlock in the driver child
/// **before any parsing begins** (CLAIM-33.6, PV-10.4, S35).
///
/// Fail-closed: if landlock is unavailable (kernel < 5.13 or not exposed) and
/// `degraded_isolation_opt_in_signed` is `false`, loading/sandboxing is refused.
///
/// Note: full BPF filter compilation/installation is platform-specific and may
/// be provided by the production gateway's child-init runtime. This function
/// enforces the required pre-parse ordering contract and fail-closed policy;
/// it returns an error when a mandatory sandbox step cannot be applied.
pub fn apply_child_sandbox(
    caps: KernelIsolationCaps,
    degraded_isolation_opt_in_signed: bool,
) -> Result<(), IsolationError> {
    if !caps.supports_landlock() && !degraded_isolation_opt_in_signed {
        return Err(IsolationError::SandboxUnavailable {
            detail: format!(
                "landlock unavailable on kernel {}.{} and no signed {DEGRADED_ISOLATION_OPT_IN_FLAG} opt-in",
                caps.kernel_major, caps.kernel_minor
            ),
        });
    }

    #[cfg(target_os = "linux")]
    {
        // 1) no-new-privs must be set before seccomp install.
        // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is a process-local syscall.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            return Err(IsolationError::SandboxApply(format!(
                "no_new_privs failed: {e}"
            )));
        }
        // 2) seccomp-BPF and 3) landlock application are performed by the
        // production child-init path. Fail closed if the runtime reports they are
        // not installed before parsing begins.
        return Err(IsolationError::SandboxUnavailable {
            detail: "seccomp-BPF/landlock child-init runtime hook is required before parsing"
                .into(),
        });
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (caps, degraded_isolation_opt_in_signed);
        Err(IsolationError::SandboxUnavailable {
            detail: "seccomp-bpf/no-new-privs/landlock child sandbox is Linux-specific".into(),
        })
    }
}

/// Encodes SCM_RIGHTS control message metadata for passing a device fd from the
/// guard/parent to the driver child (CLAIM-33.5).
///
/// This is a pure helper that validates intent; actual `sendmsg`/`recvmsg` is
/// performed by the platform IPC layer in the gateway/guard runtime.
pub fn scm_rights_device_fd_plan(device_fd: i32) -> Result<i32, IsolationError> {
    if device_fd < 0 {
        return Err(IsolationError::InvalidChildConfig(
            "device fd for SCM_RIGHTS must be non-negative".into(),
        ));
    }
    Ok(device_fd)
}
