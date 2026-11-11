//! Scenario S35 — driver fd leakage (PV-4.21, PV-10.4).
//!
//! The driver child must be unable to pass file descriptors (including the
//! device fd) to any process.  The control is a seccomp-BPF deny-list installed
//! before the child parses any frame.  Because seccomp is Linux-only and this
//! crate forbids `unsafe`, the scenario verifies the production wiring
//! structurally *and* checks that the runtime isolation test exists:
//!
//! * `tirbase-drivers/src/isolation.rs` denies `sendmsg` (the `SCM_RIGHTS`
//!   send path) and installs `PR_SET_NO_NEW_PRIVS` before seccomp;
//! * `tirbase-guard/src/bin/driver_isolation_child.rs` calls
//!   `apply_child_sandbox` before entering its frame loop;
//! * `tirbase-guard/tests/driver_isolation.rs::test_scm_rights_blocked` runs the
//!   real child process and asserts the attempt is blocked on Linux.
//!
//! Removing any of those controls makes this scenario fail.

use std::path::Path;

fn read(root: &Path, relative: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(relative))
        .map_err(|error| format!("S35 read {relative}: {error}"))
}

fn before(haystack: &str, needle: &str, boundary: &str) -> bool {
    match (haystack.find(needle), haystack.find(boundary)) {
        (Some(needle_at), Some(boundary_at)) => needle_at < boundary_at,
        _ => false,
    }
}

/// S35 — the seccomp/SCM_RIGHTS barrier is wired before any child parsing.
pub fn run_s35(_seed: u64) -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "S35: workspace root".to_string())?
        .to_path_buf();

    let isolation = read(&root, "tirbase-drivers/src/isolation.rs")?;
    if !isolation.contains("libc::SYS_sendmsg") {
        return Err(
            "S35 FAIL: seccomp deny-list no longer blocks sendmsg (SCM_RIGHTS)".to_string(),
        );
    }
    if !isolation.contains("PR_SET_NO_NEW_PRIVS") {
        return Err("S35 FAIL: no-new-privs is not set before the seccomp filter".to_string());
    }
    if !isolation.contains("install_seccomp") {
        return Err("S35 FAIL: seccomp filter installation is missing".to_string());
    }

    let child = read(&root, "tirbase-guard/src/bin/driver_isolation_child.rs")?;
    if !child.contains("apply_child_sandbox") {
        return Err("S35 FAIL: driver child no longer applies the sandbox".to_string());
    }
    if !child.contains("apply_linux_sandbox_before_parse") {
        return Err("S35 FAIL: child sandbox-before-parse function is missing".to_string());
    }
    if !before(&child, "apply_child_sandbox", "libc::recv(sock_fd") {
        return Err(
            "S35 FAIL: driver child may parse frames before applying the sandbox".to_string(),
        );
    }

    let test = read(&root, "tirbase-guard/tests/driver_isolation.rs")?;
    if !test.contains("test_scm_rights_blocked") {
        return Err("S35 FAIL: runtime SCM_RIGHTS isolation test is missing".to_string());
    }
    if !test.contains("SCM_RIGHTS_ATTEMPT:BLOCKED") {
        return Err(
            "S35 FAIL: runtime test no longer asserts the sandboxed child blocks SCM_RIGHTS"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s35_driver_fd_leakage_blocked() {
        run_s35(1).expect("S35");
    }
}
