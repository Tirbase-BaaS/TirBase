//! Virtual-time soak test harness (task 45.1 — CLAIM-45.1, PV-15.5).
//!
//! Runs 72h of simulated operation on the accelerated [`SimClock`] with
//! deterministic fault injection and per-tick invariant checking.  Because
//! time is virtual, the full 72h completes in seconds of wall-clock time and
//! fits comfortably within a 2-hour CI job.
//!
//! Production caller: `tirbase-sim/src/soak.rs` (invoked by CI via the
//! `soak_virtual_time_72h` integration test).

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::network::NetworkFault;
use crate::{NodeId, SimError, TirBaseSim};

/// 72 hours expressed in virtual seconds.
pub const SOAK_DURATION_SECS: u64 = 72 * 60 * 60;
/// Default virtual tick length for the soak (1 simulated second per tick).
pub const DEFAULT_SOAK_TICK_MS: u64 = 1_000;

/// Configuration for a virtual-time soak run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoakConfig {
    /// Scenario seed (printed on failure so the run is reproducible).
    pub seed: u64,
    /// Total simulated duration in seconds (72h for PV-15.5).
    pub duration_secs: u64,
    /// Virtual milliseconds advanced by each tick.
    pub tick_ms: u64,
    /// Number of simulated nodes.
    pub nodes: usize,
    /// Inject deterministic network faults during the run.
    pub fault_injection: bool,
}

impl Default for SoakConfig {
    fn default() -> Self {
        Self {
            seed: 0x50AC_0072,
            duration_secs: SOAK_DURATION_SECS,
            tick_ms: DEFAULT_SOAK_TICK_MS,
            nodes: 3,
            fault_injection: true,
        }
    }
}

impl SoakConfig {
    /// CI configuration: 72h simulated with fault injection.
    pub fn ci_72h(seed: u64) -> Self {
        Self {
            seed,
            ..Self::default()
        }
    }

    /// Total virtual ticks implied by this configuration (>= 1).
    pub fn total_ticks(&self) -> u64 {
        let total_ms = self.duration_secs.saturating_mul(1_000);
        total_ms.div_ceil(self.tick_ms.max(1)).max(1)
    }
}

/// Outcome of a completed soak run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoakReport {
    pub seed: u64,
    pub simulated_secs: u64,
    pub ticks: u64,
    pub faults_injected: u64,
    pub digest: u64,
}

/// Errors produced by the soak harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoakError {
    /// The underlying simulation violated an invariant.
    Simulation(SimError),
    /// The run did not cover the requested virtual duration.
    Incomplete { simulated_secs: u64, required_secs: u64 },
}

impl std::fmt::Display for SoakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SoakError::Simulation(err) => write!(f, "soak simulation error: {err}"),
            SoakError::Incomplete {
                simulated_secs,
                required_secs,
            } => write!(
                f,
                "soak incomplete: simulated {simulated_secs}s < required {required_secs}s"
            ),
        }
    }
}

impl std::error::Error for SoakError {}

impl From<SimError> for SoakError {
    fn from(err: SimError) -> Self {
        SoakError::Simulation(err)
    }
}

/// Run a virtual-time soak with `config`.
///
/// On failure the underlying [`SimError`] (and therefore the seed) is printed
/// before the error is returned, preserving PV-12.2 reproducibility.
pub fn run_soak(config: &SoakConfig) -> Result<SoakReport, SoakError> {
    let tick_ms = config.tick_ms.max(1);
    let mut sim = TirBaseSim::with_nodes(config.seed, config.nodes.max(1));
    // Align the sim clock tick length with the soak cadence.
    *sim.clock_mut() = crate::SimClock::new(0, tick_ms);

    let mut rng = ChaCha8Rng::seed_from_u64(config.seed ^ 0x5A0A_5A0A);
    let total_ticks = config.total_ticks();
    let mut faults_injected = 0u64;

    for tick in 0..total_ticks {
        if config.fault_injection {
            // Reconfigure faults at deterministic, sparse intervals so the
            // network experiences partitions/delay/drop/reorder/duplicate
            // churn without dominating the run.
            maybe_inject_faults(&mut sim, &mut rng, tick, &mut faults_injected);
        }
        if let Err(err) = sim.tick() {
            eprintln!(
                "soak FAILED seed={} tick={} simulated_secs={}: {err}",
                config.seed,
                tick,
                sim.clock().now_secs()
            );
            return Err(SoakError::Simulation(err));
        }
    }

    let simulated_secs = sim.clock().now_secs();
    if simulated_secs < config.duration_secs {
        return Err(SoakError::Incomplete {
            simulated_secs,
            required_secs: config.duration_secs,
        });
    }

    Ok(SoakReport {
        seed: config.seed,
        simulated_secs,
        ticks: total_ticks,
        faults_injected,
        digest: sim.report().digest,
    })
}

fn maybe_inject_faults(
    sim: &mut TirBaseSim,
    rng: &mut ChaCha8Rng,
    tick: u64,
    faults_injected: &mut u64,
) {
    // Refresh the fault set every 300 simulated ticks and otherwise leave the
    // network in its current (possibly faulted) state so scenarios exercise
    // sustained partitions/delays as well as churn.
    if tick % 300 != 0 {
        return;
    }
    let node_count = sim.nodes().len();
    if node_count < 2 {
        return;
    }
    // Heal prior directional faults between the chosen pair by reinstalling a
    // fresh schedule (faults are additive; a partition will still block, which
    // is the point — but we vary which pair is affected).
    let a = NodeId::new(rng.gen_range(0..node_count as u16));
    let mut b_idx = rng.gen_range(0..node_count as u16);
    if b_idx == a.as_u16() {
        b_idx = (b_idx + 1) % node_count as u16;
    }
    let b = NodeId::new(b_idx);

    let choice: u8 = rng.gen_range(0..5);
    let fault = match choice {
        0 => NetworkFault::Partition { src: a, dst: b },
        1 => NetworkFault::Delay {
            src: a,
            dst: b,
            ms: rng.gen_range(1..=30_000),
        },
        2 => NetworkFault::Drop {
            src: a,
            dst: b,
            rate: rng.gen_range(0.0..=1.0),
        },
        3 => NetworkFault::Reorder { src: a, dst: b },
        _ => NetworkFault::Duplicate {
            src: a,
            dst: b,
            copies: rng.gen_range(1..=5),
        },
    };
    // Invalid combinations are ignored; the soak must keep running.
    if sim.inject_fault(fault).is_ok() {
        *faults_injected = faults_injected.saturating_add(1);
    }
}

/// Convenience: run the CI 72h virtual-time soak with fault injection.
pub fn run_ci_72h_soak(seed: u64) -> Result<SoakReport, SoakError> {
    run_soak(&SoakConfig::ci_72h(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_covers_72h_in_virtual_time() {
        let cfg = SoakConfig::ci_72h(1);
        assert_eq!(cfg.duration_secs, 72 * 60 * 60);
        assert_eq!(cfg.total_ticks(), 72 * 60 * 60);
        assert!(cfg.fault_injection);
    }

    #[test]
    fn short_virtual_soak_runs_with_fault_injection() {
        let cfg = SoakConfig {
            seed: 7,
            duration_secs: 120,
            tick_ms: 1_000,
            nodes: 3,
            fault_injection: true,
        };
        let report = run_soak(&cfg).expect("short soak must complete");
        assert_eq!(report.seed, 7);
        assert!(report.simulated_secs >= 120);
        assert_eq!(report.ticks, 120);
    }

    #[test]
    fn same_seed_produces_same_soak_digest() {
        let cfg = SoakConfig {
            seed: 99,
            duration_secs: 60,
            tick_ms: 1_000,
            nodes: 3,
            fault_injection: true,
        };
        let a = run_soak(&cfg).unwrap();
        let b = run_soak(&cfg).unwrap();
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.faults_injected, b.faults_injected);
    }

    #[test]
    fn ci_72h_soak_completes_within_wall_clock_budget() {
        // CLAIM-45.1 / PV-15.5: 72h simulated via the accelerated virtual clock
        // with fault injection, completing well within the 2-hour CI wall-clock
        // limit.  A 1-second virtual tick keeps 259,200 steps fast in release
        // and comfortably under budget in debug on CI hardware.
        let start = std::time::Instant::now();
        let report = run_ci_72h_soak(0xCAFE_BABE).expect("72h virtual soak must pass");
        let elapsed = start.elapsed();
        assert_eq!(report.simulated_secs, SOAK_DURATION_SECS);
        assert_eq!(report.ticks, SOAK_DURATION_SECS);
        assert!(report.faults_injected > 0, "fault injection must be active");
        assert!(
            elapsed.as_secs() < 2 * 60 * 60,
            "72h virtual soak exceeded 2h wall-clock budget: {elapsed:?}"
        );
    }
}
