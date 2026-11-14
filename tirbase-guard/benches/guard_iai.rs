// SPDX-License-Identifier: AGPL-3.0-only

//! Instruction-count benchmarks for CI gating (CLAIM-40.3, PV-15.3).
//! Run with iai-callgrind-runner under valgrind in CI; regressions fail the job.

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

fn sample_profile() -> tirbase_types::envelope::EnvelopeProfile {
    use tirbase_types::envelope::{EnvelopeProfile, ParameterKind, ParameterSpec};
    use tirbase_types::{DeviceSignature, FixedPointValue};
    EnvelopeProfile {
        profile_id: [0u8; 16],
        version: 1,
        device_class: "cold_room".to_string(),
        parameters: vec![ParameterSpec {
            name: "temp".to_string(),
            unit_id: 1,
            canonical_exponent: -1,
            kind: ParameterKind::Range {
                min: FixedPointValue {
                    mantissa: -400,
                    exponent: -1,
                    unit_id: 1,
                },
                max: FixedPointValue {
                    mantissa: 300,
                    exponent: -1,
                    unit_id: 1,
                },
            },
            max_rate_per_sec: FixedPointValue {
                mantissa: 10,
                exponent: -1,
                unit_id: 1,
            },
            dwell_secs: 0,
            min_off_secs: 0,
            drift_window_secs: 60,
            max_delta_in_window: FixedPointValue {
                mantissa: 50,
                exponent: -1,
                unit_id: 1,
            },
            safe_default: FixedPointValue {
                mantissa: 40,
                exponent: -1,
                unit_id: 1,
            },
            tightening_floor: FixedPointValue {
                mantissa: -400,
                exponent: -1,
                unit_id: 1,
            },
            critical: false,
        }],
        cross_constraints: vec![],
        policy_loosen_m: 2,
        policy_loosen_n: 3,
        policy_timelock_secs: 60,
        policy_cancel_window_secs: 30,
        signature: DeviceSignature::Ed25519([0u8; 64]),
    }
}

#[library_benchmark]
fn guard_profile_signing_bytes() -> Vec<u8> {
    let p = sample_profile();
    tirbase_guard::envelope::profile_signing_bytes(black_box(&p))
}

#[library_benchmark]
fn ed25519_signature_verify() -> bool {
    let (secret, public) = tirbase_core::identity::keypair::generate_keypair().unwrap();
    let payload = b"tirbase-guard-iai";
    let sig = tirbase_core::identity::keypair::sign(&secret, payload).unwrap();
    tirbase_core::identity::keypair::verify(&public, black_box(payload), &sig).is_ok()
}

library_benchmark_group!(
    name = guard_iai_group;
    benchmarks = guard_profile_signing_bytes, ed25519_signature_verify
);
main!(library_benchmark_groups = guard_iai_group);
