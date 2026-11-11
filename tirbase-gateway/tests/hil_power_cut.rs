//! HIL power-cut failpoint tests (CLAIM-52.3, PV-27.2).
//!
//! Ignored by default; requires provisioned gateway hardware, real device/bus,
//! and a smart PDU. Fails closed when HIL environment is not configured.

#![cfg(unix)]

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn required_env(name: &str) -> String {
    match env::var(name) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => panic!(
            "HIL power-cut hardware not configured: set {name} (see docs/hil-test-procedure.md). \
             Requires smart PDU and provisioned lab hardware; not for public CI."
        ),
    }
}

fn run_power_cut_case(case: &str) -> String {
    let addr = required_env("HIL_POWER_HARNESS_ADDR");
    let pdu = required_env("HIL_PDU_CONTROL");
    let _serial = required_env("HIL_SERIAL");

    let mut stream = TcpStream::connect(&addr).unwrap_or_else(|e| {
        panic!(
            "HIL power harness unreachable at {addr}: {e}. \
             Smart PDU and lab harness must be provisioned."
        )
    });
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();

    let req = format!("CASE {case}\nPDU {pdu}\nEND\n");
    stream
        .write_all(req.as_bytes())
        .expect("write power harness request");
    stream.flush().ok();
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .expect("read power harness response");
    resp
}

fn assert_reconciled(resp: &str, case: &str) {
    let upper = resp.to_uppercase();
    assert!(
        upper.contains("RECONCILED") || upper.contains("CONSISTENT") || upper.contains("PASS"),
        "HIL {case} did not report reconciled/consistent recovery. Response: {resp}"
    );
    assert!(
        !upper.contains("STUCK_ACTUATING") && !upper.contains("DUPLICATE_ACTUATION"),
        "HIL {case} reported unsafe recovery state. Response: {resp}"
    );
}

#[test]
#[ignore = "requires provisioned HIL hardware + smart PDU (PV-27, CLAIM-52.3)"]
fn hil_power_cut_at_intent_actuating_boundary() {
    let resp = run_power_cut_case("POWER_CUT_AT_INTENT_ACTUATING");
    assert_reconciled(&resp, "POWER_CUT_AT_INTENT_ACTUATING");
}

#[test]
#[ignore = "requires provisioned HIL hardware + smart PDU (PV-27, CLAIM-52.3)"]
fn hil_power_cut_at_completion_boundary() {
    let resp = run_power_cut_case("POWER_CUT_AT_COMPLETION");
    assert_reconciled(&resp, "POWER_CUT_AT_COMPLETION");
}
