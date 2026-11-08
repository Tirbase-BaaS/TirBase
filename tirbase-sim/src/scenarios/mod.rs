//! Adversarial scenario implementations (tirbase-sim, PV-12.8).
//!
//! Each scenario module is a self-contained proof that the corresponding
//! guard/lifecycle invariant holds. Scenario IDs map to
//! `docs/adversary-scenarios.md`.

pub mod s1_s2_s3;
pub mod s24_crash_loop;
pub mod s32_challenge_nonce_flood;
pub mod s7_policy_loosening;
