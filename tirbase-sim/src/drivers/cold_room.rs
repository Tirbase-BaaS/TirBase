// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical cold-room thermal model for simulation/conformance (CLAIM-34.3).
//!
//! `tirbase-sim` re-exports the canonical first-order thermal model from
//! `tirbase-drivers` so there is exactly one implementation and trajectories are
//! bit-identical across crates for the same seed/inputs.

pub use tirbase_drivers::cold_room_sim::{ColdRoomSimDriver, FirstOrderThermalModel};

/// Back-compat wrapper used by existing sim/conformance callers.
/// Delegates to the canonical [`FirstOrderThermalModel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdRoomThermalSim {
    inner: FirstOrderThermalModel,
}

impl ColdRoomThermalSim {
    pub fn new(seed: u64) -> Self {
        Self {
 // Canonical defaults match the reference cold-room device.
            inner: FirstOrderThermalModel::new(seed, 8_000, 22_000),
        }
    }

    pub fn step(&mut self) -> i64 {
        self.inner.step()
    }

    pub fn run_steps(&mut self, steps: usize) -> Vec<i64> {
        let mut out = Vec::with_capacity(steps);
        for _ in 0..steps {
            out.push(self.step());
        }
        out
    }

    pub fn temp_mdeg_c(&self) -> i64 {
        self.inner.temp_mdeg_c
    }

    pub fn setpoint_mdeg_c(&self) -> i64 {
        self.inner.setpoint_mdeg_c
    }

    pub fn compressor_on(&self) -> bool {
        self.inner.compressor_on
    }

    pub fn inner(&self) -> &FirstOrderThermalModel {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut FirstOrderThermalModel {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_identical_from_same_seed() {
        let mut a = ColdRoomThermalSim::new(42);
        let mut b = ColdRoomThermalSim::new(42);
        assert_eq!(a.run_steps(256), b.run_steps(256));
    }

    #[test]
    fn claim_34_3_cross_crate_canonical_model_bit_identical() {
        let seeds = [0u64, 1, 42, 0xC01D, 0xDEAD_BEEF];
        for seed in seeds {
            let mut via_drivers = FirstOrderThermalModel::new(seed, 8_000, 22_000);
            let mut via_sim = ColdRoomThermalSim::new(seed);
            for step in 0..512 {
                let a = via_drivers.step();
                let b = via_sim.step();
                assert_eq!(
                    a, b,
                    "canonical thermal model diverged at seed={seed} step={step}"
                );
            }
        }
    }
}
