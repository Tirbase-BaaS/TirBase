// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic ST-12 evidence campaign.
//!
//! Every case is a reproducible bench run with explicit time. The report hashes
//! its canonical case list, so the committed evidence pack can be checked
//! against a fresh run in CI.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use tirbase_venue_gate::{DriveCommand, FailMode, GatePosition, SafeState};

use crate::bench::{bench_summary, HilBench, LossStage};

/// Evidence schema.
pub const SCHEMA: &str = "tirbase.hil.st12.venue-gate-safety.v1";
/// Reference seed for the committed pack.
pub const REFERENCE_SEED: u64 = 12;

/// What a case verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    /// Bench composition and wiring.
    Bench,
    /// Power loss at an operating stage.
    PowerLoss,
    /// Shallow or deep supply brownout.
    Brownout,
    /// Reader back-office network loss.
    NetworkLoss,
    /// Wall-clock jump.
    ClockJump,
    /// Fail-safe/fail-secure safety state.
    SafetyState,
    /// Emergency egress / fire alarm.
    EmergencyEgress,
    /// Long-run or event-flood durability.
    Durability,
}

/// One campaign case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseOutcome {
    /// Stable case id.
    pub id: String,
    /// Category.
    pub kind: CaseKind,
    /// Pass/fail.
    pub passed: bool,
    /// Human-readable observation.
    pub detail: String,
}

/// Hash-sealed campaign document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignReport {
    /// Schema id.
    pub schema: String,
    /// Fixture seed.
    pub seed: u64,
    /// Cases in execution order.
    pub cases: Vec<CaseOutcome>,
    /// All cases passed.
    pub passed: bool,
    /// SHA-256 over the canonical case list.
    pub digest: String,
}

impl CampaignReport {
    /// Pretty JSON evidence.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("campaign serializes")
    }

    /// Markdown rendering for review.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# ST-12 venue gate HIL campaign\n\n");
        out.push_str(&format!(
            "Schema: `{}`  \nSeed: `{}`  \nDigest: `{}`  \nResult: **{}**\n\n",
            self.schema,
            self.seed,
            self.digest,
            if self.passed { "PASS" } else { "FAIL" }
        ));
        out.push_str("| Case | Kind | Result | Observation |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for case in &self.cases {
            out.push_str(&format!(
                "| `{}` | {:?} | {} | {} |\n",
                case.id,
                case.kind,
                if case.passed { "PASS" } else { "FAIL" },
                case.detail.replace('|', "\\|")
            ));
        }
        out
    }
}

/// Run the complete software bench campaign.
pub fn run_campaign(seed: u64) -> CampaignReport {
    let mut cases = Vec::new();
    cases.push(bench_case());
    for mode in [FailMode::FailSafe, FailMode::FailSecure] {
        for stage in LossStage::all() {
            cases.push(power_loss_case(mode, stage));
        }
        cases.push(brownout_case(mode, false));
        cases.push(brownout_case(mode, true));
        cases.push(fire_case(mode, false));
        cases.push(fire_case(mode, true));
        cases.push(stalled_controller_case(mode));
        cases.push(stuck_open_power_case(mode));
    }
    cases.push(network_without_cache_case());
    cases.push(network_with_cache_case());
    cases.push(network_loss_while_open_case());
    cases.push(clock_forward_case());
    cases.push(clock_backward_case());
    cases.push(long_run_case());
    cases.push(event_flood_case());

    let passed = cases.iter().all(|case| case.passed);
    let canonical = serde_json::to_vec(&cases).expect("cases serialize");
    let digest = hex::encode(Sha256::digest(&canonical));
    CampaignReport {
        schema: SCHEMA.to_string(),
        seed,
        cases,
        passed,
        digest,
    }
}

fn bench_case() -> CaseOutcome {
    let result = HilBench::new(FailMode::FailSecure);
    match result {
        Ok(bench) => {
            let detail = format!(
                "controller={} reader={} turnstile={} supply={}mV safe_state={}",
                bench.controller().gate_id(),
                bench.reader().reads(),
                bench.turnstile().position().as_str(),
                bench.power().voltage_mv(),
                bench.safe_state().as_str()
            );
            let passed = bench.controller().position() == GatePosition::Locked
                && bench.turnstile().position() == GatePosition::Locked
                && bench.power().is_powered()
                && bench.safe_state() == SafeState::Secured;
            CaseOutcome {
                id: "bench.composed".to_string(),
                kind: CaseKind::Bench,
                passed,
                detail,
            }
        }
        Err(error) => CaseOutcome {
            id: "bench.composed".to_string(),
            kind: CaseKind::Bench,
            passed: false,
            detail: error,
        },
    }
}

fn setup_stage(bench: &mut HilBench, stage: LossStage) -> Result<(), String> {
    match stage {
        LossStage::Idle => Ok(()),
        LossStage::ReaderTap => bench.reader_tap(),
        LossStage::PermitArmed => bench.present_card(0).map(|_| ()),
        LossStage::Actuating => {
            bench.present_card(0)?;
            let commands = bench.controller_mut().take_commands();
            let at = bench.now_us();
            for command in commands {
                bench.turnstile_mut().apply(command, at);
            }
            Ok(())
        }
        LossStage::Passage => {
            bench.present_card(0)?;
            bench.settle();
            bench.passage().map(|_| ())
        }
        LossStage::Reclosing => {
            bench.present_card(0)?;
            bench.settle();
            bench.passage()?;
            bench.advance_controller(5_000_000);
            Ok(())
        }
    }
}

fn power_loss_case(mode: FailMode, stage: LossStage) -> CaseOutcome {
    let id = format!("power_loss.{}.{}", mode.as_str(), stage.code());
    let mut bench = match HilBench::new(mode) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::PowerLoss, id, error),
    };
    if let Err(error) = setup_stage(&mut bench, stage) {
        return failed(CaseKind::PowerLoss, id, error);
    }
    let before = bench_summary(&bench);
    let record = bench.cut_power(stage);
    let queued_power_loss = bench.controller().queued_commands() > 0;
    let passed = record.safe()
        && record.safe_state == mode.safe_state()
        && record.safe_command == Some(mode.safe_state().drive_command())
        && !queued_power_loss;
    let detail = format!(
        "at {}: before={:?} supply={}mV; after controller={} turnstile={} safe={} command={:?}; queued={}",
        stage.code(),
        before,
        record.voltage_before_mv,
        record.controller_position.as_str(),
        record.turnstile_position.as_str(),
        record.safe_state.as_str(),
        record.safe_command.map(DriveCommand::as_str),
        queued_power_loss
    );
    CaseOutcome {
        id,
        kind: CaseKind::PowerLoss,
        passed,
        detail,
    }
}

fn brownout_case(mode: FailMode, deep: bool) -> CaseOutcome {
    let depth = if deep { "deep" } else { "shallow" };
    let id = format!("brownout.{}.{}", mode.as_str(), depth);
    let mut bench = match HilBench::new(mode) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::Brownout, id, error),
    };
    let setup = (|| -> Result<(), String> {
        bench.present_card(0)?;
        bench.settle();
        bench.passage()?;
        Ok(())
    })();
    if let Err(error) = setup {
        return failed(CaseKind::Brownout, id, error);
    }
    let millivolts = if deep { 16_000 } else { 20_000 };
    let record = bench.brownout(millivolts, LossStage::Passage);
    if deep {
        let Some(record) = record else {
            return failed(CaseKind::Brownout, id, "deep brownout did not cut power");
        };
        let passed = record.safe() && record.voltage_before_mv == millivolts;
        CaseOutcome {
            id,
            kind: CaseKind::Brownout,
            passed,
            detail: format!(
                "supply sagged to {millivolts}mV: controller={} turnstile={} safe={}",
                record.controller_position.as_str(),
                record.turnstile_position.as_str(),
                record.safe_state.as_str()
            ),
        }
    } else {
        if record.is_some() {
            return failed(
                CaseKind::Brownout,
                id,
                "shallow brownout cut the controller",
            );
        }
        let reader_offline = !bench.reader().backoffice_link();
        bench.advance_turnstile(13_000_000);
        let expected = match mode {
            FailMode::FailSecure => GatePosition::Locked,
            FailMode::FailSafe => GatePosition::Unlocked,
        };
        let passed = reader_offline && bench.turnstile().position() == expected;
        CaseOutcome {
            id,
            kind: CaseKind::Brownout,
            passed,
            detail: format!(
                "supply sagged to {millivolts}mV: reader_link={} turnstile={} (bounded drive, expected {})",
                if reader_offline { "offline" } else { "online" },
                bench.turnstile().position().as_str(),
                expected.as_str()
            ),
        }
    }
}

fn fire_case(mode: FailMode, while_unpowered: bool) -> CaseOutcome {
    let suffix = if while_unpowered {
        "after_power_cut"
    } else {
        "powered"
    };
    let id = format!("egress.{}.{}", mode.as_str(), suffix);
    let mut bench = match HilBench::new(mode) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::EmergencyEgress, id, error),
    };
    if while_unpowered {
        bench.cut_power(LossStage::Idle);
    }
    bench.fire_alarm();
    if while_unpowered {
        bench.restore_power();
    }
    let released = bench.position() == GatePosition::Open
        && bench.turnstile().position() == GatePosition::Open
        && bench.fire_alarm_active();
    let entry_refused = bench.present_card(0).is_err();
    bench.clear_fire_alarm();
    bench.settle();
    let resecured = bench.position() == GatePosition::Locked
        && bench.turnstile().position() == GatePosition::Locked
        && !bench.fire_alarm_active();
    CaseOutcome {
        id,
        kind: CaseKind::EmergencyEgress,
        passed: released && entry_refused && resecured,
        detail: format!(
            "fire input: released={released} entry_refused={entry_refused} re-secured={resecured} controller={} turnstile={}",
            bench.position().as_str(),
            bench.turnstile().position().as_str()
        ),
    }
}

fn stalled_controller_case(mode: FailMode) -> CaseOutcome {
    let id = format!("safety.stalled_controller.{}", mode.as_str());
    let mut bench = match HilBench::new(mode) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::SafetyState, id, error),
    };
    let setup = (|| -> Result<(), String> {
        bench.present_card(0)?;
        bench.settle();
        bench.passage()?;
        Ok(())
    })();
    if let Err(error) = setup {
        return failed(CaseKind::SafetyState, id, error);
    }
    // Simulate a controller software fault: no tick and no drive refresh.
    bench.advance_turnstile(13_000_000);
    let physical = bench.turnstile().position();
    let expected = match mode {
        FailMode::FailSecure => GatePosition::Locked,
        FailMode::FailSafe => GatePosition::Unlocked,
    };
    let passed = physical == expected;
    let detail = format!(
        "controller stalled for 13s; turnstile watchdog position={} expected={} (fail-safe remains open by design)",
        physical.as_str(),
        expected.as_str()
    );
    CaseOutcome {
        id,
        kind: CaseKind::SafetyState,
        passed,
        detail,
    }
}

fn stuck_open_power_case(mode: FailMode) -> CaseOutcome {
    let id = format!("safety.stuck_open_power_cut.{}", mode.as_str());
    let mut bench = match HilBench::new(mode) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::SafetyState, id, error),
    };
    bench.turnstile_mut().set_stuck_open(true);
    let setup = (|| -> Result<(), String> {
        bench.present_card(0)?;
        bench.settle();
        bench.passage()?;
        Ok(())
    })();
    if let Err(error) = setup {
        return failed(CaseKind::SafetyState, id, error);
    }
    // Even with the physical actuator reporting stuck open, removing power
    // must recover the configured safe state.
    let record = bench.cut_power(LossStage::Passage);
    let passed = record.safe();
    CaseOutcome {
        id,
        kind: CaseKind::SafetyState,
        passed,
        detail: format!(
            "stuck-open mechanism after power cut: controller={} turnstile={} safe={}",
            record.controller_position.as_str(),
            record.turnstile_position.as_str(),
            record.safe_state.as_str()
        ),
    }
}

fn network_without_cache_case() -> CaseOutcome {
    let id = "network.loss_without_cache".to_string();
    let mut bench = match HilBench::new(FailMode::FailSecure) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::NetworkLoss, id, error),
    };
    bench.lose_network();
    let denied = bench.present_card(0).is_err();
    let stayed_locked = bench.position() == GatePosition::Locked;
    bench.restore_network();
    let recovered = bench.present_card(0).is_ok();
    let passed = denied && stayed_locked && recovered;
    CaseOutcome {
        id,
        kind: CaseKind::NetworkLoss,
        passed,
        detail: format!(
            "back-office loss: denied={denied} stayed_locked={stayed_locked} online_recovered={recovered}"
        ),
    }
}

fn network_with_cache_case() -> CaseOutcome {
    let id = "network.loss_with_cache".to_string();
    let mut bench = match HilBench::new(FailMode::FailSecure) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::NetworkLoss, id, error),
    };
    if let Err(error) = bench.prime_cache(0) {
        return failed(CaseKind::NetworkLoss, id, error);
    }
    bench.lose_network();
    let decision = match bench.present_card(0) {
        Ok(decision) => decision,
        Err(error) => return failed(CaseKind::NetworkLoss, id, error),
    };
    bench.settle();
    let passed = decision.grant.offline
        && !bench.reader().backoffice_link()
        && bench.position() == GatePosition::Unlocked;
    CaseOutcome {
        id,
        kind: CaseKind::NetworkLoss,
        passed,
        detail: format!(
            "cached grant offline={} reader_link={} controller={}",
            decision.grant.offline,
            if bench.reader().backoffice_link() {
                "online"
            } else {
                "offline"
            },
            bench.position().as_str()
        ),
    }
}

fn network_loss_while_open_case() -> CaseOutcome {
    let id = "network.loss_while_open".to_string();
    let mut bench = match HilBench::new(FailMode::FailSecure) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::NetworkLoss, id, error),
    };
    let setup = (|| -> Result<(), String> {
        bench.present_card(0)?;
        bench.settle();
        bench.passage()?;
        Ok(())
    })();
    if let Err(error) = setup {
        return failed(CaseKind::NetworkLoss, id, error);
    }
    bench.lose_network();
    bench.advance(5_000_000);
    let passed = bench.position() == GatePosition::Locked
        && bench.turnstile().position() == GatePosition::Locked;
    CaseOutcome {
        id,
        kind: CaseKind::NetworkLoss,
        passed,
        detail: format!(
            "network lost with lane open; after open hold controller={} turnstile={}",
            bench.position().as_str(),
            bench.turnstile().position().as_str()
        ),
    }
}

fn clock_forward_case() -> CaseOutcome {
    let id = "clock.jump_forward".to_string();
    let mut bench = match HilBench::new(FailMode::FailSecure) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::ClockJump, id, error),
    };
    let setup = (|| -> Result<(), String> {
        bench.present_card(0)?;
        bench.settle();
        Ok(())
    })();
    if let Err(error) = setup {
        return failed(CaseKind::ClockJump, id, error);
    }
    bench.clock_mut().jump_wall(86_400_000_000);
    bench.advance(10_000_001);
    let passed = bench.controller().permit_id().is_none()
        && bench.position() == GatePosition::Locked
        && bench.clock().wall_jumps() == 1;
    CaseOutcome {
        id,
        kind: CaseKind::ClockJump,
        passed,
        detail: format!(
            "wall +1 day: permit={:?} gate_time_advanced_monotonically=10000001us position={}",
            bench.controller().permit_id(),
            bench.position().as_str()
        ),
    }
}

fn clock_backward_case() -> CaseOutcome {
    let id = "clock.jump_backward".to_string();
    let mut bench = match HilBench::new(FailMode::FailSecure) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::ClockJump, id, error),
    };
    let setup = (|| -> Result<(), String> {
        bench.present_card(0)?;
        bench.settle();
        bench.passage()?;
        Ok(())
    })();
    if let Err(error) = setup {
        return failed(CaseKind::ClockJump, id, error);
    }
    bench.clock_mut().jump_wall(-86_400_000_000);
    bench.advance(5_000_000);
    let passed = bench.position() == GatePosition::Locked
        && bench.turnstile().position() == GatePosition::Locked
        && bench.clock().wall_jumps() == 1;
    CaseOutcome {
        id,
        kind: CaseKind::ClockJump,
        passed,
        detail: format!(
            "wall -1 day: open hold still elapsed on monotonic time; controller={} turnstile={}",
            bench.position().as_str(),
            bench.turnstile().position().as_str()
        ),
    }
}

fn long_run_case() -> CaseOutcome {
    let id = "durability.long_run".to_string();
    let cycles = 600usize;
    let card_count = 600usize;
    let mut bench = match HilBench::with_options(FailMode::FailSecure, card_count, 256, 256) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::Durability, id, error),
    };
    let mut error = None;
    for cycle in 0..cycles {
        let step = (|| -> Result<(), String> {
            bench.present_card(cycle % card_count)?;
            bench.settle();
            bench.passage()?;
            bench.advance(5_000_000);
            if bench.position() != GatePosition::Locked
                || bench.turnstile().position() != GatePosition::Locked
            {
                return Err(format!("cycle {cycle} did not re-secure"));
            }
            Ok(())
        })();
        if let Err(step_error) = step {
            error = Some(step_error);
            break;
        }
    }
    if let Some(error) = error {
        return failed(CaseKind::Durability, id, error);
    }
    let audit = bench.controller().audit();
    let chain_ok = audit.verify().is_ok();
    let dropped = audit.dropped();
    let audit_entries = audit.len();
    let json = match bench.controller().audit_json() {
        Ok(json) => json,
        Err(error) => return failed(CaseKind::Durability, id, error.to_string()),
    };
    let mut restarted = match HilBench::with_options(FailMode::FailSecure, card_count, 256, 256) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::Durability, id, error),
    };
    if let Err(error) = restarted.controller_mut().restore_audit(&json) {
        return failed(CaseKind::Durability, id, error.to_string());
    }
    let restored_ok = restarted.controller().audit().verify().is_ok()
        && restarted.controller().audit().len() == audit_entries;
    let passed = chain_ok
        && restored_ok
        && dropped > 0
        && bench.controller().faults() == 0
        && bench.controller().position() == GatePosition::Locked;
    CaseOutcome {
        id,
        kind: CaseKind::Durability,
        passed,
        detail: format!(
            "cycles={cycles} cards={card_count} audit_entries={audit_entries} audit_dropped={dropped} chain_ok={chain_ok} restored={restored_ok} faults={}",
            bench.controller().faults()
        ),
    }
}

fn event_flood_case() -> CaseOutcome {
    let id = "durability.event_flood".to_string();
    let mut bench = match HilBench::with_options(FailMode::FailSecure, 1, 128, 64) {
        Ok(bench) => bench,
        Err(error) => return failed(CaseKind::Durability, id, error),
    };
    let rounds = 5_000u32;
    for _ in 0..rounds {
        let at = bench.now_us();
        bench.controller_mut().observe_tamper(at);
        if bench.controller_mut().clear_tamper(true, at + 1).is_err() {
            return failed(CaseKind::Durability, id, "authorised tamper reset failed");
        }
        bench.clock_mut().advance(2);
    }
    let health = bench.controller().health();
    let chain_ok = bench.controller().audit().verify().is_ok();
    let events_bounded = bench.controller().events().count() <= 64;
    let passed = chain_ok
        && events_bounded
        && health.events_dropped > 0
        && health.last_event_seq == u64::from(rounds) * 2
        && health.audit_dropped > 0
        && bench.controller().audit().len() <= 128;
    CaseOutcome {
        id,
        kind: CaseKind::Durability,
        passed,
        detail: format!(
            "rounds={rounds} last_event_seq={} events_dropped={} audit_entries={} audit_dropped={} chain_ok={chain_ok}",
            health.last_event_seq,
            health.events_dropped,
            health.audit_entries,
            health.audit_dropped
        ),
    }
}

fn failed(kind: CaseKind, id: String, detail: impl Into<String>) -> CaseOutcome {
    CaseOutcome {
        id,
        kind,
        passed: false,
        detail: detail.into(),
    }
}
