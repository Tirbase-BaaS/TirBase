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

    /// Detect the running kernel's isolation capabilities (CLAIM-33.6).
    ///
    /// `landlock_available` is true only when the kernel's active LSM list
    /// includes `landlock`. On non-Unix targets every capability is reported
    /// false so callers fail closed.
    #[cfg(unix)]
    pub fn detect() -> Self {
        // SAFETY: `uname` writes into a zeroed `utsname`; the pointer is valid.
        let mut uts: libc::utsname = unsafe { core::mem::zeroed() };
        let release = if unsafe { libc::uname(&mut uts) } == 0 {
            // SAFETY: `release` is a NUL-terminated C string owned by `uts`.
            unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        };
        let mut parts = release.split('.');
        let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = parts
            .next()
            .and_then(|s| {
                s.trim_end_matches(|c: char| !c.is_ascii_digit())
                    .parse()
                    .ok()
            })
            .unwrap_or(0);
        let landlock_available = std::fs::read_to_string("/sys/kernel/security/lsm")
            .map(|lsm| lsm.split(',').any(|entry| entry.trim() == "landlock"))
            .unwrap_or(false);
        Self {
            kernel_major: major,
            kernel_minor: minor,
            landlock_available,
        }
    }

    /// Non-Unix targets have no landlock; report every capability as absent.
    #[cfg(not(unix))]
    pub fn detect() -> Self {
        Self {
            kernel_major: 0,
            kernel_minor: 0,
            landlock_available: false,
        }
    }
}

#[cfg(all(test, unix))]
mod detect_tests {
    use super::*;

    #[test]
    fn detect_reports_a_kernel_version() {
        let caps = KernelIsolationCaps::detect();
        assert!(caps.kernel_major > 0, "unexpected caps: {caps:?}");
        // supports_landlock is never true unless landlock is actually present.
        assert!(!caps.supports_landlock() || caps.landlock_available);
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
/// `degraded_isolation_opt_in_signed` is `false`, the child is refused. When
/// the signed opt-in is present the child still installs `no_new_privs` and the
/// seccomp-BPF filter, and only the landlock layer is skipped.
///
/// On Linux this performs the real syscalls, in order:
///
/// 1. `prctl(PR_SET_NO_NEW_PRIVS, 1)` — required before seccomp and landlock.
/// 2. `seccomp(SECCOMP_SET_MODE_FILTER)` — a deny-list filter that stops the
/// child from creating/connecting sockets, passing fds (`sendmsg`/
/// `sendmmsg`/`sendto`), tracing or executing another process. Denied
/// calls fail with `EPERM`.
/// 3. `landlock_create_ruleset` + `landlock_restrict_self` with an empty
/// ruleset, i.e. every handled filesystem access is denied. The driver is
/// a pure codec over the inherited socket/device fds and needs no
/// filesystem access after init.
///
/// The caller must invoke this in the driver child process, before parsing any
/// untrusted frame. Any step that cannot be applied returns an error so the
/// child can exit rather than run unsandboxed.
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

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        linux_sandbox::install(caps.supports_landlock())
    }

    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = (caps, degraded_isolation_opt_in_signed);
        Err(IsolationError::SandboxUnavailable {
            detail: "seccomp-bpf/no-new-privs/landlock child sandbox is only implemented for Linux x86_64/aarch64".into(),
        })
    }
}

/// Linux child-init sandbox implementation for [`apply_child_sandbox`].
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_sandbox {
    use super::IsolationError;
    use core::mem::size_of;
    use std::io;

    // ── seccomp-BPF constants ────────────────────────────────────────────────
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const EPERM_ERRNO: u32 = 1;
    /// `offsetof(struct seccomp_data, arch)`
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    /// `offsetof(struct seccomp_data, nr)`
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;

    // ── landlock constants ───────────────────────────────────────────────────
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    /// `LANDLOCK_ACCESS_FS_{EXECUTE,WRITE_FILE,READ_FILE,READ_DIR,REMOVE_DIR,
    /// REMOVE_FILE,MAKE_CHAR,MAKE_DIR,MAKE_REG,MAKE_SOCK,MAKE_FIFO,MAKE_BLOCK,
    /// MAKE_SYM}` — the ABI-1 rights.
    const LANDLOCK_ACCESS_FS_ABI1: u64 = (1 << 13) - 1;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13; // ABI 2
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14; // ABI 3
    const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15; // ABI 5

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jump(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt,
            jf,
            k,
        }
    }

    /// Syscalls the driver child never needs after init. Denying them stops
    /// network egress, fd passing via `SCM_RIGHTS`, process tracing and
    /// re-exec, so a compromised codec cannot escape its inherited fds.
    fn denied_syscalls() -> Vec<libc::c_long> {
        vec![
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
            libc::SYS_ptrace,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
        ]
    }

    /// Installs the deny-list seccomp-BPF filter (CLAIM-33.6).
    fn install_seccomp() -> Result<(), IsolationError> {
        let denied = denied_syscalls();
        let mut filter = Vec::with_capacity(4 + denied.len() * 2);
        // Reject a filter evaluated against a different ABI: kill the child
        // instead of silently matching the wrong syscall numbers.
        filter.push(stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET));
        filter.push(jump(AUDIT_ARCH, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
        filter.push(stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
        for nr in denied {
            let nr = nr as u32;
            filter.push(jump(nr, 0, 1));
            filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | EPERM_ERRNO));
        }
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: PR_SET_SECCOMP copies the `sock_fprog`/filter into the kernel;
        // both live on this stack frame for the duration of the call.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            )
        };
        if rc != 0 {
            let e = io::Error::last_os_error();
            return Err(IsolationError::SandboxApply(format!(
                "seccomp filter install failed: {e}"
            )));
        }
        Ok(())
    }

    /// Restricts the child to zero filesystem access (CLAIM-33.6).
    fn install_landlock() -> Result<(), IsolationError> {
        // SAFETY: querying the ABI version uses a null attribute pointer and a
        // zero size, which is the documented version-probe form.
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                core::ptr::null::<LandlockRulesetAttr>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if abi < 1 {
            let e = io::Error::last_os_error();
            return Err(IsolationError::SandboxApply(format!(
                "landlock ABI probe failed: {e}"
            )));
        }
        let abi = abi as u64;
        let mut handled = LANDLOCK_ACCESS_FS_ABI1;
        if abi >= 2 {
            handled |= LANDLOCK_ACCESS_FS_REFER;
        }
        if abi >= 3 {
            handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }
        if abi >= 5 {
            handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        }

        let attr = LandlockRulesetAttr {
            handled_access_fs: handled,
        };
        // SAFETY: `attr` is a valid `landlock_ruleset_attr` for the stated size;
        // the syscall only reads it.
        let ruleset_fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const LandlockRulesetAttr,
                size_of::<LandlockRulesetAttr>(),
                0u32,
            )
        };
        if ruleset_fd < 0 {
            let e = io::Error::last_os_error();
            return Err(IsolationError::SandboxApply(format!(
                "landlock_create_ruleset failed: {e}"
            )));
        }
        let ruleset_fd = ruleset_fd as libc::c_int;
        // No LANDLOCK_RULE_PATH_BENEATH rules are added: every handled access
        // is denied. Inherited fds keep working.
        // SAFETY: `ruleset_fd` is an owned ruleset fd from the call above.
        let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
        let err = io::Error::last_os_error();
        // SAFETY: closing the ruleset fd; it is not used afterwards.
        unsafe {
            libc::close(ruleset_fd);
        }
        if rc != 0 {
            return Err(IsolationError::SandboxApply(format!(
                "landlock_restrict_self failed: {err}"
            )));
        }
        Ok(())
    }

    pub(super) fn install(expect_landlock: bool) -> Result<(), IsolationError> {
        // 1) no-new-privs must be set before seccomp/landlock install.
        // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is a process-local syscall.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            return Err(IsolationError::SandboxApply(format!(
                "no_new_privs failed: {e}"
            )));
        }
        // 2) seccomp-BPF deny-list.
        install_seccomp()?;
        // 3) landlock, unless the signed opt-in accepted a degraded posture.
        if expect_landlock {
            install_landlock()?;
        }
        Ok(())
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

/// Send a device fd to a child over a Unix socket using `SCM_RIGHTS` (CLAIM-34.8, PV-10.4).
///
/// Narrow `unsafe` confined to the `sendmsg` syscall boundary.
#[cfg(unix)]
pub fn send_fd_via_scm_rights(socket_fd: i32, device_fd: i32) -> Result<(), IsolationError> {
    scm_rights_device_fd_plan(device_fd)?;
    if socket_fd < 0 {
        return Err(IsolationError::InvalidChildConfig(
            "socket fd for SCM_RIGHTS must be non-negative".into(),
        ));
    }
    let mut data = *b"F";
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    // Control buffer for one fd.
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut cbuf = vec![0u8; cmsg_space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = cbuf.len() as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(IsolationError::Socketpair(
                io::ErrorKind::Other,
                "CMSG_FIRSTHDR returned null".into(),
            ));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as _;
        let data_ptr = libc::CMSG_DATA(cmsg).cast::<i32>();
        std::ptr::write(data_ptr, device_fd);
        msg.msg_controllen = (*cmsg).cmsg_len as _;
    }
    let rc = unsafe { libc::sendmsg(socket_fd, &msg, 0) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        return Err(IsolationError::Socketpair(e.kind(), e.to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn send_fd_via_scm_rights(_socket_fd: i32, _device_fd: i32) -> Result<(), IsolationError> {
    Err(IsolationError::SandboxUnavailable {
        detail: "SCM_RIGHTS is unavailable on this target".into(),
    })
}

/// Receive a device fd over a Unix socket using `SCM_RIGHTS` (test/helper).
#[cfg(unix)]
pub fn recv_fd_via_scm_rights(socket_fd: i32) -> Result<i32, IsolationError> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut cbuf = vec![0u8; cmsg_space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = cbuf.len() as _;
    let rc = unsafe { libc::recvmsg(socket_fd, &mut msg, 0) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        return Err(IsolationError::Socketpair(e.kind(), e.to_string()));
    }
    if rc == 0 {
        return Err(IsolationError::PeerCredential(
            "socket closed before SCM_RIGHTS message".into(),
        ));
    }
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Err(IsolationError::PeerCredential(
                "missing SCM_RIGHTS control message".into(),
            ));
        }
        let data_ptr = libc::CMSG_DATA(cmsg).cast::<i32>();
        Ok(std::ptr::read(data_ptr))
    }
}

#[cfg(not(unix))]
pub fn recv_fd_via_scm_rights(_socket_fd: i32) -> Result<i32, IsolationError> {
    Err(IsolationError::SandboxUnavailable {
        detail: "SCM_RIGHTS is unavailable on this target".into(),
    })
}
