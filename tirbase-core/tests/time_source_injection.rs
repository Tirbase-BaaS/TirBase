// SPDX-License-Identifier: AGPL-3.0-only

//! Isolated process-wide `TimeSource` injection test (CLAIM-5.1).
//!
//! This lives in its own integration-test binary because it replaces the
//! process-wide time source. Other tests in the crate read the clock through
//! that same slot (for example when minting Biscuit tokens), so swapping it
//! from a lib-test thread would race with them; a separate test process keeps
//! the injection hermetic.

use std::sync::Arc;

use tirbase_core::traits::{
    install_time_source, monotonic_now, time_source, wall_hint, wall_hint_secs, TimeSource,
};

#[derive(Debug)]
struct FixedTimeSource {
    monotonic: u64,
    wall: i64,
    boot: u64,
}

impl TimeSource for FixedTimeSource {
    fn monotonic_now(&self) -> u64 {
        self.monotonic
    }

    fn wall_hint(&self) -> Option<i64> {
        Some(self.wall)
    }

    fn boot_id(&self) -> u64 {
        self.boot
    }
}

#[test]
fn injected_time_source_is_used_by_free_functions() {
    let fixed = Arc::new(FixedTimeSource {
        monotonic: 123_456,
        wall: 1_700_000_000_000_000,
        boot: 42,
    });
    install_time_source(fixed);

 // These free functions are what every core subsystem calls (PV-3.8).
    assert_eq!(monotonic_now(), 123_456);
    assert_eq!(wall_hint(), Some(1_700_000_000_000_000));
    assert_eq!(wall_hint_secs(), Some(1_700_000_000));
    assert_eq!(time_source().boot_id(), 42);
}
