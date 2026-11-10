//! Test/production helper: driver child that receives a device fd via SCM_RIGHTS,
//! applies sandbox (Linux: no_new_privs+seccomp+landlock best-effort), and verifies
//! it cannot pass fds via SCM_RIGHTS after sandboxing (S35/CLAIM-34.8).

#[cfg(unix)]
fn main() {
    use std::os::unix::io::RawFd;

    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let mut sock_fd: RawFd = -1;
    let mut close_fds: Vec<RawFd> = Vec::new();
    let mut crash_once: Option<String> = None;
    let mut degraded_opt_in = false;
    let mut expect_device_fd = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket-fd" | "--tirbase-driver-socket-fd" => {
                sock_fd = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .expect("--socket-fd value");
            }
            "--close-fd" => {
                if let Some(fd) = args.next().and_then(|s| s.parse().ok()) {
                    close_fds.push(fd);
                }
            }
            "--crash-once" => {
                crash_once = args.next();
            }
            "--degraded-isolation-opt-in" => degraded_opt_in = true,
            "--expect-device-fd" => expect_device_fd = true,
            s if sock_fd < 0 => {
                // back-compat positional fd
                if let Ok(fd) = s.parse() {
                    sock_fd = fd;
                }
            }
            _ => {}
        }
    }
    for fd in close_fds {
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    if sock_fd < 0 {
        eprintln!("--socket-fd required");
        std::process::exit(2);
    }

    match mode.as_str() {
        "--recv-and-report" => recv_and_report(sock_fd),
        "--recv-apply-sandbox-attempt-scm-rights" => sandbox_then_attempt(sock_fd),
        "--sandboxed-driver" => sandboxed_driver(
            sock_fd,
            expect_device_fd,
            degraded_opt_in,
            crash_once.as_deref(),
        ),
        _ => {
            eprintln!("unknown mode: {mode}");
            std::process::exit(2);
        }
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("unix required");
    std::process::exit(3);
}

#[cfg(unix)]
fn recv_and_report(sock_fd: i32) {
    match tirbase_drivers::recv_fd_via_scm_rights(sock_fd) {
        Ok(fd) if fd >= 0 => {
            unsafe {
                libc::close(fd);
            }
            println!("RECEIVED_OK");
        }
        Ok(fd) => {
            println!("RECEIVED_BAD_FD:{fd}");
            std::process::exit(10);
        }
        Err(e) => {
            println!("RECV_ERR:{e}");
            std::process::exit(11);
        }
    }
}

#[cfg(unix)]
fn sandbox_then_attempt(sock_fd: i32) {
    // Receive device fd first (guard-owned fd handoff happens before/with init contract
    // in production; this child proves post-sandbox SCM_RIGHTS is blocked).
    let device_fd = match tirbase_drivers::recv_fd_via_scm_rights(sock_fd) {
        Ok(fd) => fd,
        Err(e) => {
            println!("RECV_ERR:{e}");
            std::process::exit(11);
        }
    };

    let sandbox = apply_linux_sandbox_before_parse();
    println!("SANDBOX:{sandbox}");

    // S35: after sandbox, child must not be able to pass fds via SCM_RIGHTS.
    let attempt = tirbase_drivers::send_fd_via_scm_rights(sock_fd, device_fd);
    unsafe {
        libc::close(device_fd);
    }
    match attempt {
        Ok(()) => {
            println!("SCM_RIGHTS_ATTEMPT:ALLOWED");
            if cfg!(target_os = "linux") {
                std::process::exit(20);
            }
        }
        Err(e) => {
            println!("SCM_RIGHTS_ATTEMPT:BLOCKED:{e}");
            println!(
                "SECURITY_EVENT:category=Driver,reason=SCMRightsAttempt,severity=High,detail=sandbox_blocked_scm_rights"
            );
        }
    }
}

#[cfg(all(unix, target_os = "linux"))]
fn apply_linux_sandbox_before_parse() -> String {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return format!("ERR:no_new_privs:{}", std::io::Error::last_os_error());
    }

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }
    const SECCOMP_SET_MODE_FILTER: i32 = 1;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const EPERM: u32 = 1;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
    const SYS_SENDMSG: u32 = if cfg!(target_arch = "x86_64") {
        46
    } else {
        211
    };
    const SYS_SENDMMSG: u32 = if cfg!(target_arch = "x86_64") {
        307
    } else {
        269
    };
    const ARCH: u32 = if cfg!(target_arch = "x86_64") {
        AUDIT_ARCH_X86_64
    } else {
        AUDIT_ARCH_AARCH64
    };

    let filter = [
        SockFilter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        },
        SockFilter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: ARCH,
        },
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        SockFilter {
            code: 0x15,
            jt: 2,
            jf: 0,
            k: SYS_SENDMSG,
        },
        SockFilter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: SYS_SENDMMSG,
        },
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | EPERM,
        },
    ];
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    let rc = unsafe { libc::prctl(libc::PR_SET_SECCOMP, SECCOMP_SET_MODE_FILTER, &prog) };
    if rc != 0 {
        return format!("ERR:seccomp:{}", std::io::Error::last_os_error());
    }

    let ll = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32,
        )
    };
    if ll < 0 {
        let e = std::io::Error::last_os_error();
        return format!("OK:no_new_privs+seccomp;landlock_unavailable:{e}");
    }
    unsafe {
        libc::close(ll as i32);
    }
    "OK:no_new_privs+seccomp+landlock_probe".to_string()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn apply_linux_sandbox_before_parse() -> String {
    "UNAVAILABLE:linux_seccomp_landlock_not_supported_on_this_platform".to_string()
}

/// Production driver-child mode (CLAIM-33.5/33.6/33.7): receive the guard-owned
/// device fd, apply the seccomp-BPF + landlock sandbox **before any frame is
/// parsed**, then serve the codec loop over the inherited socket only.
///
/// `--crash-once <path>` is a harness for the restart integration test: the
/// first child (marker absent) exits non-zero before sandboxing; the respawned
/// child (marker present) runs normally.
#[cfg(unix)]
fn sandboxed_driver(
    sock_fd: i32,
    expect_device_fd: bool,
    degraded_opt_in: bool,
    crash_once: Option<&str>,
) {
    // 1) Guard-owned device fd handoff completes before the sandbox is applied;
    // no command frame has been read at this point.
    let device_fd = if expect_device_fd {
        match tirbase_drivers::recv_fd_via_scm_rights(sock_fd) {
            Ok(fd) => Some(fd),
            Err(e) => {
                println!("RECV_ERR:{e}");
                std::process::exit(11);
            }
        }
    } else {
        None
    };

    if let Some(path) = crash_once {
        if !std::path::Path::new(path).exists() {
            let _ = std::fs::write(path, b"crashed");
            println!("CRASH_BEFORE_SANDBOX");
            std::process::exit(7);
        }
    }

    // 2) Sandbox first, parse later (CLAIM-33.6).
    #[cfg(all(
        unix,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let caps = tirbase_drivers::isolation::KernelIsolationCaps::detect();
        let landlock = caps.supports_landlock();
        match tirbase_drivers::apply_child_sandbox(caps, degraded_opt_in) {
            Ok(()) => println!("SANDBOX:APPLIED:landlock={landlock}"),
            Err(e) => {
                println!("SANDBOX:FAILED:{e}");
                std::process::exit(20);
            }
        }
        // Probe that the sandbox is really in force: filesystem open and
        // socket creation must both fail after the sandbox is applied.
        match std::fs::File::open("/etc/hostname") {
            Ok(f) => {
                drop(f);
                println!("FS_PROBE:ALLOWED");
            }
            Err(e) => println!("FS_PROBE:BLOCKED:{e}"),
        }
        let rc = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if rc >= 0 {
            unsafe {
                libc::close(rc);
            }
            println!("NET_PROBE:ALLOWED");
        } else {
            println!("NET_PROBE:BLOCKED:{}", std::io::Error::last_os_error());
        }
    }
    #[cfg(not(all(
        unix,
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = degraded_opt_in;
        println!("SANDBOX:UNAVAILABLE:linux_seccomp_landlock_not_supported_on_this_platform");
    }

    // 3) Codec loop over the inherited socket only.  No filesystem or network
    // syscall is needed from here on.
    println!("READY");
    loop {
        let mut buf = [0u8; 64];
        let n = unsafe { libc::recv(sock_fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        let frame = String::from_utf8_lossy(&buf[..n]).into_owned();
        println!("FRAME:{frame}");
        let sent = unsafe { libc::send(sock_fd, buf.as_ptr().cast(), n, 0) };
        if sent < 0 {
            break;
        }
    }
    if let Some(fd) = device_fd {
        unsafe {
            libc::close(fd);
        }
    }
}
