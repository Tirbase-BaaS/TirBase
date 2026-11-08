//! Adversary / safety scenarios wired into tirbase-sim.
//!
//! Each scenario is a deterministic, self-contained test that exercises a
//! production caller path (guard/gateway components) and asserts the expected
//! system response.  `cargo test -p tirbase-sim` runs all wired scenarios.

pub mod s7_policy_loosening;
