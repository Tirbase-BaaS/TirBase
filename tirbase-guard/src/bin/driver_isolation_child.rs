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
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket-fd" => {
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
