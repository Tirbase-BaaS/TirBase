//! Task 6.7b / CLAIM-6.7b: real TPM2 NV counter behaviour against swtpm.
//!
//! Starts a software TPM (`swtpm`) with a TCP TCTI, provisions the counter
//! index, and exercises read / increment / `set_if_greater` through the same
//! `Tpm2MonotonicCounter` the gateway selects with `--features tpm2`.
//!
//! Rollback detection and checkpoint-cadence wear-leveling are properties of
//! `HardwareCounterBinding`; this test proves the counter itself never moves
//! backwards, which is what makes that detection meaningful.

#![cfg(feature = "tpm2")]

use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tirbase_core::traits::MonotonicCounterTrait;
use tirbase_gateway::monotonic_counter::{
    provision_tpm2_counter_index, Tpm2MonotonicCounter,
};

const NV_INDEX: u32 = 0x0150_0002;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

struct Swtpm {
    child: Child,
    port: u16,
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_swtpm() -> Option<Swtpm> {
    let swtpm = Command::new("swtpm")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if !swtpm.success() {
        return None;
    }

    let dir = std::env::temp_dir().join(format!("tirbase-swtpm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let port = free_port();
    let ctrl = free_port();
    let child = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={}", dir.display()),
            "--server",
            &format!("type=tcp,port={port},bindaddr=127.0.0.1"),
            "--ctrl",
            &format!("type=tcp,port={ctrl},bindaddr=127.0.0.1"),
            "--flags",
            "not-need-init,startup-clear",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // swtpm serves a single TCTI client connection, so probing the port with a
    // throwaway TcpStream can steal it and make the TCTI fail to instantiate.
    // Give the daemon a moment instead, then confirm it is still running.
    let mut child = child;
    std::thread::sleep(Duration::from_millis(600));
    if child.try_wait().ok().flatten().is_some() {
        return None;
    }
    Some(Swtpm { child, port })
}

#[test]
#[ignore = "swtpm TCTI crashes on this macOS host: tctildr looks for libtss2-tcti-swtpm.so (Linux naming) and the symlink workaround SIGSEGVs; run on Linux CI with tpm2-tss installed"]
fn swtpm_nv_counter_is_monotonic_and_never_written_backwards() {
    let Some(swtpm) = start_swtpm() else {
        eprintln!("SKIP: swtpm not available");
        return;
    };
    std::env::set_var(
        "TIRBASE_TPM2_TCTI",
        format!("swtpm:host=127.0.0.1,port={}", swtpm.port),
    );

    provision_tpm2_counter_index(NV_INDEX).expect("define TPM2 NV counter index");
    let counter = Tpm2MonotonicCounter::new(NV_INDEX);

    let initial = counter.read().expect("read freshly defined counter");
    assert_eq!(initial, 0, "a freshly defined counter reads as zero");

    assert_eq!(counter.increment().expect("first increment"), 1);
    assert_eq!(counter.read().expect("read after increment"), 1);
    assert_eq!(counter.increment().expect("second increment"), 2);

    // set_if_greater only ever raises the counter.
    assert_eq!(
        counter.set_if_greater(10).expect("raise to 10"),
        10,
        "counter must advance to the requested floor"
    );
    assert_eq!(
        counter.set_if_greater(4).expect("lower request is a no-op"),
        10,
        "a lower value must never move the hardware counter backwards"
    );
    assert_eq!(counter.read().expect("final read"), 10);

    // The value survives a fresh TCTI connection (it lives in TPM NV, not in
    // process memory) — this is what rollback detection relies on.
    let reopened = Tpm2MonotonicCounter::new(NV_INDEX);
    assert_eq!(reopened.read().expect("read from new connection"), 10);

    let mut out = std::io::stderr();
    let _ = writeln!(out, "TPM2 NV counter verified against swtpm");
}
