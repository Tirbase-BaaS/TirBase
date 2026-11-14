// SPDX-License-Identifier: AGPL-3.0-only

//! TirBase seeded deterministic simulator (PV-12.1).
//!
//! # Determinism
//!
//! Every source of randomness in the simulator is a [`rand_chacha::ChaCha8Rng`]
//! seeded from the scenario seed: ChaCha8 is a fixed, portable stream cipher, so
//! the same seed yields byte-identical transcripts on every platform and Rust
//! version (unlike `SmallRng` or thread/entropy RNGs). The virtual clock only
//! advances on [`sim::SimClock::tick`], and the thermal/battery models use the
//! `libm` crate for non-linear math. Together these guarantee that a failed
//! scenario is exactly reproducible from its printed seed.
//!
//! # Layout
//!
//! * [`network`] — fault-injecting virtual network: partition, delay, drop,
//! reorder, duplicate (CLAIM-38.3).
//! * [`sim`] — `SimClock`, `SimNode` (real `CommandGuard` + plant models), and
//! the seed-reporting scenario harness (CLAIM-38.2).
//! * [`models`] — first-order thermal and battery/inverter models (CLAIM-38.4,
//! CLAIM-38.5).
//! * [`invariants`] — per-tick INV-1..INV-16 checks (CLAIM-38.6).
//! * [`drivers`] — reference Modbus server and cold-room driver backends.
//! * [`runner`] — TOML scenario loader and seeded scenario runner (//! CLAIM-39.1).
//! * [`scenarios`] — the S1–S35 adversary scenario implementations
//! (CLAIM-39.2/39.3/39.4).
//!
//! # Seeded scenarios
//!
//! [`TirBaseSim::run_seeded_scenario`] executes one complete randomised scenario
//! for a seed; the CI integration test runs 1,000 of them per invocation
//! (PV-12.1). If a run fails, the seed is printed to stdout before the error is
//! returned, so re-running with that seed reproduces it (PV-12.2).
//!
//! [`runner::ScenarioRunner`] loads `tirbase-sim/scenarios/S*.toml`, executes
//! the registered S1–S35 scenarios for every configured seed, and prints the
//! failing scenario's seed before it exits.

#![forbid(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]
// HashMap is banned in guard/sim (PV-12): iteration order is not
// deterministic, which breaks seeded reproducibility. Use BTreeMap or IndexMap.
#![deny(clippy::disallowed_types)]

use rand::Rng;
use rand_chacha::ChaCha8Rng;

/// Deterministic device/reference driver backends (Modbus server, cold-room model).
pub mod drivers;
/// Per-tick invariant checks (INV-1..INV-16, CLAIM-17.1..17.8, CLAIM-38.6).
pub mod invariants;
/// Deterministic thermal and battery/inverter plant models (CLAIM-38.4/38.5).
pub mod models;
/// Fault-injecting virtual network (CLAIM-38.3).
pub mod network;
/// TOML adversary-scenario loader and seeded runner (CLAIM-39.1).
pub mod runner;
/// Adversary scenarios S1–S35 (39.4, CLAIM-39.2/39.3/39.4).
pub mod scenarios;
/// Virtual-time soak harness (72h simulated, fault injection — CLAIM-45.1).
pub mod soak;
/// Simulation runtime: `SimClock`, `SimNode`, scenario harness (CLAIM-38.2).
pub mod sim;

#[cfg(test)]
pub mod conformance;

pub use drivers::{ColdRoomThermalSim, ModbusServerHandle, ModbusSimServer};
pub use invariants::{
    assert_invariants_hold, InvariantChecker, InvariantId, InvariantViolation, SimState,
};
pub use models::{BatteryModel, ThermalModel};
pub use network::{
    DeliveredMessage, MessageId, NetworkError, NetworkFault, NodeId, SimNetwork,
    DEFAULT_LINK_DELAY_MS, MAX_DELAY_MS, MAX_DUPLICATE_COPIES, MIN_DELAY_MS,
};
pub use runner::{
    load_scenario_dir, load_scenario_file, RunnerError, ScenarioRunSummary, ScenarioRunner,
    ScenarioSpec, MIN_SEEDS_PER_RUN,
};
pub use sim::{
    install_faults, seeded_rng, ScenarioReport, SimClock, SimError, SimNode, TickGuard,
    DEFAULT_TICK_MS, SIM_EPOCH_SECS,
};
pub use soak::{
    run_ci_72h_soak, run_soak, SoakConfig, SoakError, SoakReport, DEFAULT_SOAK_TICK_MS,
    SOAK_DURATION_SECS,
};

/// Number of nodes in a default seeded scenario.
pub const DEFAULT_SCENARIO_NODES: usize = 3;
/// Number of messages broadcast per tick in a default seeded scenario.
pub const DEFAULT_SCENARIO_MESSAGES_PER_TICK: usize = 2;

/// Seeded, deterministic, virtual-time simulator (CLAIM-38.1/38.2, PV-12.1).
///
/// ```text
/// let mut sim = TirBaseSim::new(42);
/// sim.run(100).expect("scenario");
/// ```
pub struct TirBaseSim {
    seed: u64,
    rng: ChaCha8Rng,
    clock: SimClock,
    network: SimNetwork,
    nodes: Vec<SimNode>,
    invariant_checker: InvariantChecker,
    state: SimState,
    halted: Option<InvariantViolation>,
}

impl std::fmt::Debug for TirBaseSim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TirBaseSim")
            .field("seed", &self.seed)
            .field("clock", &self.clock)
            .field("nodes", &self.nodes)
            .field("in_flight", &self.network.in_flight())
            .field("halted", &self.halted.is_some())
            .finish_non_exhaustive()
    }
}

impl TirBaseSim {
 /// Create a three-node simulation at virtual time zero.
    pub fn new(seed: u64) -> Self {
        Self::with_nodes(seed, DEFAULT_SCENARIO_NODES)
    }

 /// Create a simulation with `node_count` nodes (at least one).
    pub fn with_nodes(seed: u64, node_count: usize) -> Self {
        let node_count = node_count.max(1);
        let nodes = (0..node_count)
            .map(|i| SimNode::new(NodeId::new(i as u16), seed))
            .collect();
        Self {
            seed,
            rng: seeded_rng(seed),
            clock: SimClock::new(0, DEFAULT_TICK_MS),
            network: SimNetwork::new(seed),
            nodes,
            invariant_checker: InvariantChecker::new(),
            state: SimState {
                seed,
                tick: 0,
                hash_chain_intact: true,
                triggering_state: format!("sim seed={seed}"),
                ..Default::default()
            },
            halted: None,
        }
    }

 /// Scenario seed (the value to print and reuse on failure).
    pub fn seed(&self) -> u64 {
        self.seed
    }

 /// Scenario RNG, seeded from [`TirBaseSim::seed`].
    pub fn rng(&mut self) -> &mut ChaCha8Rng {
        &mut self.rng
    }

 /// Virtual clock.
    pub fn clock(&self) -> &SimClock {
        &self.clock
    }

 /// Mutable virtual clock (advance/reboot in scenario scripts).
    pub fn clock_mut(&mut self) -> &mut SimClock {
        &mut self.clock
    }

 /// Virtual network.
    pub fn network(&self) -> &SimNetwork {
        &self.network
    }

 /// Mutable virtual network (install/heal faults in scenario scripts).
    pub fn network_mut(&mut self) -> &mut SimNetwork {
        &mut self.network
    }

 /// Simulated nodes.
    pub fn nodes(&self) -> &[SimNode] {
        &self.nodes
    }

 /// Mutable simulated nodes.
    pub fn nodes_mut(&mut self) -> &mut [SimNode] {
        &mut self.nodes
    }

 /// Invariant state observed so far. Scenarios may push observations before
 /// a tick; [`TirBaseSim::tick`] then checks INV-1..INV-16.
    pub fn state(&self) -> &SimState {
        &self.state
    }

 /// Mutable invariant state for scenario observations.
    pub fn state_mut(&mut self) -> &mut SimState {
        &mut self.state
    }

 /// The invariant that halted this scenario, if any.
    pub fn halted(&self) -> Option<&InvariantViolation> {
        self.halted.as_ref()
    }

 /// Install a network fault (validating PV-12.1 bounds).
    pub fn inject_fault(&mut self, fault: NetworkFault) -> Result<(), NetworkError> {
        self.network.add_fault(fault)
    }

 /// Broadcast `payload` from `src` to every other node at the current
 /// virtual time. Returns the number of messages accepted onto the wire.
    pub fn broadcast(&mut self, src: NodeId, payload: impl Into<Vec<u8>>) -> usize {
        let now = self.clock.now_ms();
        let payload: Vec<u8> = payload.into();
        let destinations: Vec<NodeId> = self
            .nodes
            .iter()
            .map(SimNode::id)
            .filter(|id| *id != src)
            .collect();
        let mut accepted = 0;
        for dst in destinations {
            accepted += self.network.send(now, src, dst, payload.clone()).len();
        }
        accepted
    }

 /// Advance one virtual tick: deliver due messages, step every node's plant
 /// models, and run the per-tick invariant checks (PV-23.2).
 ///
 /// A failing check halts the scenario immediately and returns
 /// [`SimError::Invariant`], which carries the seed.
    pub fn tick(&mut self) -> Result<(), SimError> {
        if let Some(violation) = &self.halted {
            return Err(SimError::Invariant {
                seed: self.seed,
                tick: self.state.tick,
                violation: violation.clone(),
            });
        }

        let now_ms = self.clock.tick();
        for message in self.network.deliver(now_ms) {
            if let Some(node) = self.nodes.iter_mut().find(|n| n.id() == message.dst) {
                node.record_delivery(message);
            }
        }
        for node in self.nodes.iter_mut() {
            node.step_to(now_ms);
        }

        self.state.tick = self.state.tick.saturating_add(1);
        if self.state.triggering_state.is_empty() {
            self.state.triggering_state = format!("tick={} now_ms={now_ms}", self.state.tick);
        }

        match TickGuard::new(self.seed).check(&self.invariant_checker, &self.state) {
            Ok(()) => Ok(()),
            Err(err) => {
                let SimError::Invariant { violation, .. } = &err;
                self.halted = Some(violation.clone());
                Err(err)
            }
        }
    }

 /// Run `ticks` virtual ticks, halting at the first invariant violation.
    pub fn run(&mut self, ticks: u64) -> Result<(), SimError> {
        for _ in 0..ticks {
            self.tick()?;
        }
        Ok(())
    }

 /// Order-sensitive digest of everything observable about this run.
    pub fn digest(&self) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        let mut mix = |value: u64| {
            hash ^= value;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        };
        mix(self.seed);
        mix(self.clock.now_ms());
        mix(self.clock.boot_id());
        mix(self.state.tick);
        mix(self.network.sent_messages());
        mix(self.network.delivered_messages());
        mix(self.network.dropped_messages());
        for node in &self.nodes {
            mix(node.fingerprint());
        }
        hash
    }

 /// Snapshot report for reproducibility assertions.
    pub fn report(&self) -> ScenarioReport {
        ScenarioReport {
            seed: self.seed,
            ticks: self.state.tick,
            digest: self.digest(),
            node_fingerprints: self.nodes.iter().map(SimNode::fingerprint).collect(),
            delivered_messages: self.network.delivered_messages(),
            dropped_messages: self.network.dropped_messages(),
        }
    }

 /// Run one complete randomised scenario for `seed`.
 ///
 /// Every run installs faults chosen from the scenario RNG (always at least
 /// one), broadcasts messages on a seeded schedule, and ends with the
 /// per-tick invariant checks. On failure the seed is printed to stdout
 /// before the error is returned (PV-12.2).
    pub fn run_seeded_scenario(seed: u64, ticks: u64) -> Result<ScenarioReport, SimError> {
        let mut out = std::io::stdout().lock();
        Self::run_seeded_scenario_to(seed, ticks, &mut out)
    }

 /// Like [`TirBaseSim::run_seeded_scenario`], but writes the failure report
 /// (including the reproducibility seed) to `out` instead of stdout. Tests
 /// use this to assert the seed is printed before the scenario exits.
    pub fn run_seeded_scenario_to(
        seed: u64,
        ticks: u64,
        out: &mut dyn std::io::Write,
    ) -> Result<ScenarioReport, SimError> {
        let mut sim = Self::new(seed);
        sim.install_randomised_faults();
        let node_ids: Vec<NodeId> = sim.nodes().iter().map(SimNode::id).collect();

        for _ in 0..ticks {
            for _ in 0..DEFAULT_SCENARIO_MESSAGES_PER_TICK {
                let src_index = sim.rng.gen_range(0..node_ids.len());
                let src = node_ids[src_index];
                let payload = sim.rng.gen::<u64>().to_le_bytes().to_vec();
                sim.broadcast(src, payload);
            }
            if let Err(err) = sim.tick() {
                let _ = writeln!(out, "scenario FAILED seed={seed}: {err}");
                return Err(err);
            }
        }
        Ok(sim.report())
    }

 /// Install one fault drawn from the scenario RNG.
    fn install_randomised_faults(&mut self) {
        let ids: Vec<NodeId> = self.nodes().iter().map(SimNode::id).collect();
        let src = ids[0];
        let dst = ids[1 % ids.len()];
 // Always exercise one fault so the scenario is meaningful; the exact
 // fault varies by seed.
        let fault = match self.rng.gen_range(0u8..5) {
            0 => NetworkFault::Partition { src, dst },
            1 => NetworkFault::Delay {
                src,
                dst,
                ms: self.rng.gen_range(MIN_DELAY_MS..=MAX_DELAY_MS),
            },
            2 => NetworkFault::Drop {
                src,
                dst,
                rate: self.rng.gen_range(0.0..=0.5),
            },
            3 => NetworkFault::Reorder { src, dst },
            _ => NetworkFault::Duplicate {
                src,
                dst,
                copies: self.rng.gen_range(1..=MAX_DUPLICATE_COPIES),
            },
        };
 // The values above are in range by construction.
        let _ = self.network.add_fault(fault);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_produces_identical_reports_and_transcripts() {
        let a = TirBaseSim::run_seeded_scenario(0x5EED, 64).expect("scenario a");
        let b = TirBaseSim::run_seeded_scenario(0x5EED, 64).expect("scenario b");
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_produce_different_trajectories() {
        let a = TirBaseSim::run_seeded_scenario(1, 32).expect("scenario 1");
        let b = TirBaseSim::run_seeded_scenario(2, 32).expect("scenario 2");
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn unseeded_rng_would_break_reproducibility() {
 // Sanity check for the wiring-mutation requirement: two independently
 // constructed runs share the seed and therefore the same transcript.
        let mut a = TirBaseSim::new(11);
        let mut b = TirBaseSim::new(11);
        a.run(8).unwrap();
        b.run(8).unwrap();
        assert_eq!(a.report(), b.report());
    }

    #[test]
    fn sim_halts_immediately_on_invariant_violation() {
        let mut sim = TirBaseSim::new(0xDEAD);
        sim.state_mut().hash_chain_intact = false;
        let err = sim.tick().expect_err("broken chain must halt");
        assert_eq!(err.seed(), 0xDEAD);
        assert!(sim.halted().is_some());
 // Subsequent ticks return the stored halt instead of continuing.
        assert!(sim.tick().is_err());
        assert_eq!(sim.state().tick, 1);
    }

    #[test]
    fn network_and_clock_advance_together() {
        let mut sim = TirBaseSim::new(3);
        sim.broadcast(NodeId::new(0), b"tick".to_vec());
        sim.run(2).unwrap();
        assert_eq!(sim.clock().now_ms(), 2 * DEFAULT_TICK_MS);
        assert!(sim.network().sent_messages() >= 2);
    }
}
