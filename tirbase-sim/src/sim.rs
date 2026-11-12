//! Simulation runtime: virtual clock, nodes, and seeded scenario harness
//! (CLAIM-38.2, PV-12.1).
//!
//! [`SimClock`] is the single source of simulated time. It advances only when
//! [`SimClock::tick`] (or [`SimClock::advance_ms`]) is called, and implements
//! [`TimeSource`] so guard code sees the same virtual time the simulator uses.
//!
//! [`SimNode`] couples a real [`CommandGuard`] with the deterministic thermal
//! and battery plant models. Each tick advances the node's models by the
//! virtual elapsed time and records deterministic state bits that feed the
//! determinism digest.
//!
//! Failing scenarios print the seed before exiting (PV-12.2), so any CI failure
//! can be reproduced with `TIRBASE_SIM_SEED`-style re-runs using that seed.

use std::fmt;
use std::sync::Arc;

use rand_chacha::ChaCha8Rng;
use tirbase_core::traits::TimeSource;
use tirbase_guard::epoch::{EpochRegistry, InMemoryEpochStore};
use tirbase_guard::guard::{CommandGuard, GuardConfig};
use tirbase_guard::node_mode::{NodeMode, NodeModeState};

use crate::invariants::{InvariantChecker, InvariantViolation, SimState};
use crate::models::{BatteryModel, ThermalModel};
use crate::network::{DeliveredMessage, NetworkFault, NodeId, SimNetwork};

/// Wall-clock epoch anchored to the start of a virtual run: 2025-01-01T00:00:00Z.
pub const SIM_EPOCH_SECS: i64 = 1_735_689_600;
/// Virtual time step used by [`SimClock::tick`]: 100 ms.
pub const DEFAULT_TICK_MS: u64 = 100;

/// Virtual clock driven exclusively by [`SimClock::tick`] (CLAIM-38.2).
///
/// No wall clock is ever read, so two runs with the same seed observe exactly
/// the same sequence of time values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimClock {
    now_ms: u64,
    tick_len_ms: u64,
    boot_id: u64,
}

impl SimClock {
 /// Create a clock at `start_ms` that advances by `tick_len_ms` per tick.
    pub fn new(start_ms: u64, tick_len_ms: u64) -> Self {
        Self {
            now_ms: start_ms,
            tick_len_ms: tick_len_ms.max(1),
            boot_id: 1,
        }
    }

 /// Virtual time in milliseconds since the simulation epoch.
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

 /// Virtual time in whole seconds.
    pub fn now_secs(&self) -> u64 {
        self.now_ms / 1_000
    }

 /// Virtual wall-clock time in Unix seconds (anchor + elapsed).
    pub fn wall_secs(&self) -> i64 {
        SIM_EPOCH_SECS + self.now_secs() as i64
    }

 /// Configured tick length in milliseconds.
    pub fn tick_len_ms(&self) -> u64 {
        self.tick_len_ms
    }

 /// Advance one tick and return the new virtual time in milliseconds.
    pub fn tick(&mut self) -> u64 {
        self.now_ms = self.now_ms.saturating_add(self.tick_len_ms);
        self.now_ms
    }

 /// Advance by an explicit duration.
    pub fn advance_ms(&mut self, ms: u64) -> u64 {
        self.now_ms = self.now_ms.saturating_add(ms);
        self.now_ms
    }

 /// Simulate a reboot. Monotonic time keeps increasing (as `CLOCK_BOOTTIME`
 /// does across a reboot on the same host in this model); only the boot id
 /// changes, which is what freshness logic keys off.
    pub fn reboot(&mut self) -> u64 {
        self.boot_id = self.boot_id.wrapping_add(1).max(1);
        self.now_ms
    }

 /// Current virtual boot identifier.
    pub fn boot_id(&self) -> u64 {
        self.boot_id
    }
}

impl Default for SimClock {
    fn default() -> Self {
        Self::new(0, DEFAULT_TICK_MS)
    }
}

impl TimeSource for SimClock {
    fn monotonic_now(&self) -> u64 {
        self.now_ms.saturating_mul(1_000)
    }

    fn wall_hint(&self) -> Option<i64> {
        Some(self.wall_secs().saturating_mul(1_000_000))
    }

    fn boot_id(&self) -> u64 {
        self.boot_id
    }
}

/// A simulated TirBase node: real guard + deterministic plant models.
pub struct SimNode {
    id: NodeId,
 /// The real command guard this node runs. Simulated commands go through
 /// the same admission machinery the gateway uses.
    guard: CommandGuard,
    thermal: ThermalModel,
    battery: BatteryModel,
    clock: SimClock,
    last_step_ms: u64,
    ticks: u64,
    received: Vec<DeliveredMessage>,
}

impl fmt::Debug for SimNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimNode")
            .field("id", &self.id)
            .field("ticks", &self.ticks)
            .field("received", &self.received.len())
            .finish_non_exhaustive()
    }
}

impl SimNode {
 /// Create a node in `Normal` mode with a fresh in-memory epoch store and
 /// models seeded from `seed` (each node domain-separates by its id).
    pub fn new(id: NodeId, seed: u64) -> Self {
        let node_seed = seed ^ ((id.as_u16() as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let epochs = Arc::new(EpochRegistry::new(Arc::new(InMemoryEpochStore::default())));
        let mode = NodeModeState::new(NodeMode::Normal);
        let guard = CommandGuard::with_mode(epochs, GuardConfig::default(), mode);
        Self {
            id,
            guard,
            thermal: ThermalModel::new(node_seed),
            battery: BatteryModel::new(node_seed),
            clock: SimClock::new(0, DEFAULT_TICK_MS),
            last_step_ms: 0,
            ticks: 0,
            received: Vec::new(),
        }
    }

 /// Node identifier.
    pub fn id(&self) -> NodeId {
        self.id
    }

 /// The real [`CommandGuard`] wrapped by this node.
    pub fn guard(&self) -> &CommandGuard {
        &self.guard
    }

 /// Shared mode state of the wrapped guard.
    pub fn mode_state(&self) -> Arc<NodeModeState> {
        Arc::clone(self.guard.node_mode())
    }

 /// Set the node's operational mode (Stage 1 reads this on admission).
    pub fn set_mode(&self, mode: NodeMode) -> NodeMode {
        self.guard.node_mode().set(mode)
    }

 /// Current operational mode.
    pub fn mode(&self) -> NodeMode {
        self.guard.node_mode().get()
    }

 /// Thermal plant model.
    pub fn thermal(&self) -> &ThermalModel {
        &self.thermal
    }

 /// Mutable thermal plant model (e.g. to change the setpoint).
    pub fn thermal_mut(&mut self) -> &mut ThermalModel {
        &mut self.thermal
    }

 /// Battery/inverter plant model.
    pub fn battery(&self) -> &BatteryModel {
        &self.battery
    }

 /// Mutable battery/inverter plant model (e.g. to set the load).
    pub fn battery_mut(&mut self) -> &mut BatteryModel {
        &mut self.battery
    }

 /// The node's virtual clock view.
    pub fn clock(&self) -> &SimClock {
        &self.clock
    }

 /// Messages delivered to this node, in delivery order.
    pub fn received(&self) -> &[DeliveredMessage] {
        &self.received
    }

 /// Number of tick steps this node has executed.
    pub fn ticks(&self) -> u64 {
        self.ticks
    }

 /// Record a delivery from the network.
    pub fn record_delivery(&mut self, message: DeliveredMessage) {
        if message.dst == self.id {
            self.received.push(message);
        }
    }

 /// Advance the node to virtual time `now_ms`, stepping the plant models by
 /// the elapsed whole seconds (at most one step per second to keep the
 /// physics independent of tick granularity).
    pub fn step_to(&mut self, now_ms: u64) {
        self.clock = SimClock::new(now_ms, DEFAULT_TICK_MS);
        let elapsed_s = now_ms.saturating_sub(self.last_step_ms) / 1_000;
        for _ in 0..elapsed_s {
            self.thermal.step();
            self.battery.step();
        }
        if elapsed_s > 0 {
            self.last_step_ms = self.last_step_ms.saturating_add(elapsed_s * 1_000);
        }
        self.ticks = self.ticks.saturating_add(1);
    }

 /// Deterministic state fingerprint for this node at the current instant.
    pub fn fingerprint(&self) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        let mut mix = |value: u64| {
            hash ^= value;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        };
        mix(self.id.as_u16() as u64);
        mix(self.clock.now_ms());
        mix(self.thermal.temperature_bits());
        mix(self.battery.soc_bits());
        mix(self.received.len() as u64);
        hash
    }
}

/// A failed scenario: always carries the seed needed to reproduce it (PV-12.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimError {
 /// A per-tick invariant failed and the scenario halted immediately.
    Invariant {
        seed: u64,
        tick: u64,
        violation: InvariantViolation,
    },
}

impl SimError {
 /// The reproducibility seed for this failure.
    pub fn seed(&self) -> u64 {
        match self {
            SimError::Invariant { seed, .. } => *seed,
        }
    }
}

impl fmt::Display for SimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimError::Invariant {
                seed,
                tick,
                violation,
            } => write!(f, "scenario FAILED seed={seed} tick={tick}: {violation}"),
        }
    }
}

impl std::error::Error for SimError {}

/// Seed a `ChaCha8Rng` the canonical way for every simulator entry point
/// (CLAIM-38.1). Callers must never substitute entropy-seeded RNGs, or the
/// determinism tests fail.
pub fn seeded_rng(seed: u64) -> ChaCha8Rng {
    <ChaCha8Rng as rand::SeedableRng>::seed_from_u64(seed)
}

/// Compact, comparable snapshot of one seeded scenario run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioReport {
    pub seed: u64,
    pub ticks: u64,
 /// Order-sensitive FNV-1a digest over clock time, node fingerprints,
 /// network counters, and the invariant state.
    pub digest: u64,
 /// Per-node state fingerprints at the end of the run.
    pub node_fingerprints: Vec<u64>,
    pub delivered_messages: u64,
    pub dropped_messages: u64,
}

/// Per-tick invariant checking context shared by the simulator and scenarios.
#[derive(Debug, Clone)]
pub struct TickGuard {
    seed: u64,
}

impl TickGuard {
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

 /// Check invariants for `state`, halting (and printing the seed,
 /// invariant ID, and triggering state) on the first violation.
    pub fn check(&self, checker: &InvariantChecker, state: &SimState) -> Result<(), SimError> {
        match checker.check_all(state) {
            Ok(()) => Ok(()),
            Err(violation) => {
 // PV-23.2 / PV-12.2: print the seed before the scenario exits.
                println!(
                    "tirbase-sim: seed={} invariant={} state={}",
                    self.seed, violation.invariant, violation.triggering_state
                );
                Err(SimError::Invariant {
                    seed: self.seed,
                    tick: state.tick,
                    violation,
                })
            }
        }
    }
}

/// Helper used by the scenario harness: apply one tick worth of network and
/// node activity, then run the per-tick invariant checks.
pub fn tick_nodes(
    clock: &mut SimClock,
    network: &mut SimNetwork,
    nodes: &mut [SimNode],
    checker: &InvariantChecker,
    state: &mut SimState,
) -> Result<(), SimError> {
    let now_ms = clock.tick();
    for message in network.deliver(now_ms) {
        if let Some(node) = nodes.iter_mut().find(|n| n.id() == message.dst) {
            node.record_delivery(message);
        }
    }
    for node in nodes.iter_mut() {
        node.step_to(now_ms);
    }
    state.tick = state.tick.saturating_add(1);
    if state.triggering_state.is_empty() {
        state.triggering_state = format!("tick={} now_ms={now_ms}", state.tick);
    }
    TickGuard::new(state.seed).check(checker, state)
}

/// Convenience for tests and scenarios: map a list of faults onto a network.
pub fn install_faults(
    network: &mut SimNetwork,
    faults: &[NetworkFault],
) -> Result<(), crate::network::NetworkError> {
    for fault in faults {
        network.add_fault(*fault)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_advances_only_on_tick() {
        let mut clock = SimClock::new(0, 100);
        assert_eq!(clock.now_ms(), 0);
        assert_eq!(clock.tick(), 100);
        assert_eq!(clock.tick(), 200);
        assert_eq!(clock.advance_ms(50), 250);
        assert_eq!(clock.now_secs(), 0);
    }

    #[test]
    fn clock_implements_timesource_deterministically() {
        let clock = SimClock::new(5_000, 100);
        assert_eq!(clock.monotonic_now(), 5_000_000);
        assert_eq!(clock.wall_hint(), Some((SIM_EPOCH_SECS + 5) * 1_000_000));
        assert_eq!(clock.boot_id(), 1);
    }

    #[test]
    fn node_wraps_real_guard_and_models() {
        let mut node = SimNode::new(NodeId::new(0), 99);
        assert_eq!(node.mode(), NodeMode::Normal);
        let before = node.thermal().temperature_bits();
        node.step_to(5_000);
        assert_eq!(node.ticks(), 1);
        assert_ne!(before, node.thermal().temperature_bits());
        assert_eq!(node.guard().node_mode().get(), NodeMode::Normal);
    }

    #[test]
    fn reboot_changes_boot_id_but_not_time() {
        let mut clock = SimClock::new(1_000, 100);
        let now = clock.now_ms();
        clock.reboot();
        assert_eq!(clock.now_ms(), now);
        assert_eq!(clock.boot_id(), 2);
    }

    #[test]
    fn failed_scenario_reports_its_seed() {
        let err = TickGuard::new(0xABCD)
            .check(
                &InvariantChecker::new(),
                &SimState {
                    seed: 0xABCD,
                    hash_chain_intact: false,
                    ..Default::default()
                },
            )
            .expect_err("broken hash chain must halt the scenario");
        assert_eq!(err.seed(), 0xABCD);
        assert!(err.to_string().contains("seed=43981"), "{err}");
    }
}
