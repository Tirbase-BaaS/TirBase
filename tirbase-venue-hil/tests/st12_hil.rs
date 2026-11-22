// SPDX-License-Identifier: AGPL-3.0-only

//! ST-12 acceptance tests: power loss at every stage, fail-safe/fail-secure
//! safety states, software hold-open prevention, emergency egress, clock jumps,
//! durability/event flooding and a reproducible evidence pack.

use tirbase_venue_gate::{FailMode, GatePosition};
use tirbase_venue_hil::{run_campaign, CaseKind, HilBench, LossStage, REFERENCE_SEED};

fn evidence_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/hil-evidence/st12")
}

#[test]
fn power_loss_at_every_stage_leaves_the_configured_safe_state() {
    for mode in [FailMode::FailSafe, FailMode::FailSecure] {
        for stage in LossStage::all() {
            let mut bench = HilBench::new(mode).expect("bench");
            match stage {
                LossStage::Idle => {}
                LossStage::ReaderTap => bench.reader_tap().expect("reader tap"),
                LossStage::PermitArmed => {
                    bench.present_card(0).expect("permit armed");
                }
                LossStage::Actuating => {
                    bench.present_card(0).expect("authorized");
                    let commands = bench.controller_mut().take_commands();
                    let at = bench.now_us();
                    for command in commands {
                        bench.turnstile_mut().apply(command, at);
                    }
                }
                LossStage::Passage => {
                    bench.present_card(0).expect("authorized");
                    bench.settle();
                    bench.passage().expect("passage");
                }
                LossStage::Reclosing => {
                    bench.present_card(0).expect("authorized");
                    bench.settle();
                    bench.passage().expect("passage");
                    bench.advance_controller(5_000_000);
                }
            }
            let record = bench.cut_power(stage);
            assert!(
                record.safe(),
                "{} at {} was not safe: {record:?}",
                mode.as_str(),
                stage.code()
            );
            assert_eq!(record.safe_state, mode.safe_state());
            assert!(!record.reader_powered);
            assert_eq!(bench.controller().queued_commands(), 0);
        }
    }
}

#[test]
fn a_stalled_controller_cannot_hold_a_fail_secure_gate_open() {
    let mut bench = HilBench::new(FailMode::FailSecure).expect("bench");
    bench.present_card(0).expect("authorized");
    bench.settle();
    bench.passage().expect("passage");
    assert_eq!(bench.turnstile().position(), GatePosition::Open);
    // The controller software stops refreshing the drive entirely.
    bench.advance_turnstile(13_000_000);
    assert_eq!(
        bench.turnstile().position(),
        GatePosition::Locked,
        "the actuator watchdog must spring the fail-secure lane"
    );
    // Once the controller ticks again, it accepts the locked feedback.
    bench.advance_controller(1);
    bench.settle();
    assert_eq!(bench.position(), GatePosition::Locked);
}

#[test]
fn fail_safe_releases_on_power_loss_and_fire_alarm_overrides_fail_secure() {
    let mut fail_safe = HilBench::new(FailMode::FailSafe).expect("bench");
    let record = fail_safe.cut_power(LossStage::Idle);
    assert_eq!(record.controller_position, GatePosition::Unlocked);
    assert_eq!(record.turnstile_position, GatePosition::Unlocked);
    assert_eq!(record.safe_state, fail_safe.safe_state());

    let mut fail_secure = HilBench::new(FailMode::FailSecure).expect("bench");
    fail_secure.fire_alarm();
    assert_eq!(fail_secure.position(), GatePosition::Open);
    assert_eq!(fail_secure.turnstile().position(), GatePosition::Open);
    assert!(fail_secure.present_card(0).is_err());
    fail_secure.clear_fire_alarm();
    assert_eq!(fail_secure.position(), GatePosition::Locked);
    assert_eq!(fail_secure.turnstile().position(), GatePosition::Locked);
}

#[test]
fn clock_jumps_are_ignored_by_gate_decisions() {
    let mut bench = HilBench::new(FailMode::FailSecure).expect("bench");
    bench.present_card(0).expect("authorized");
    bench.settle();
    let gate_time = bench.clock().gate_time_us();
    bench.clock_mut().jump_wall(-86_400_000_000);
    assert_eq!(bench.clock().gate_time_us(), gate_time);
    bench.advance(10_000_001);
    assert!(bench.controller().permit_id().is_none());
    assert_eq!(bench.position(), GatePosition::Locked);
}

#[test]
fn campaign_is_reproducible_and_covers_the_required_matrix() {
    let first = run_campaign(REFERENCE_SEED);
    assert!(first.passed, "campaign failed: {}", first.to_json());
    let second = run_campaign(REFERENCE_SEED);
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.to_json(), second.to_json());

    for kind in [
        CaseKind::Bench,
        CaseKind::PowerLoss,
        CaseKind::Brownout,
        CaseKind::NetworkLoss,
        CaseKind::ClockJump,
        CaseKind::SafetyState,
        CaseKind::EmergencyEgress,
        CaseKind::Durability,
    ] {
        assert!(
            first.cases.iter().any(|case| case.kind == kind),
            "campaign has no {kind:?} case"
        );
    }
    for mode in [FailMode::FailSafe, FailMode::FailSecure] {
        for stage in LossStage::all() {
            let id = format!("power_loss.{}.{}", mode.as_str(), stage.code());
            assert!(first.cases.iter().any(|case| case.id == id), "missing {id}");
        }
    }

    let directory = evidence_dir();
    std::fs::create_dir_all(&directory).expect("evidence dir");
    std::fs::write(directory.join("campaign.json"), first.to_json()).expect("campaign json");
    std::fs::write(directory.join("campaign.md"), first.to_markdown()).expect("campaign md");
}

#[test]
fn committed_evidence_matches_a_fresh_run() {
    let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/evidence/hil/st12-venue-gate-safety/campaign.json");
    if !committed.exists() {
        return;
    }
    let text = std::fs::read_to_string(&committed).expect("committed evidence");
    let committed: serde_json::Value = serde_json::from_str(&text).expect("committed json");
    let fresh = run_campaign(
        committed["seed"]
            .as_u64()
            .expect("committed pack carries a seed"),
    );
    assert_eq!(
        committed["digest"], fresh.digest,
        "the committed ST-12 evidence no longer matches the documented procedure"
    );
}
