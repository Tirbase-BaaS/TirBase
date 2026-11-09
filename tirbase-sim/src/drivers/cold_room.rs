//! First-order thermal cold-room model for conformance/simulation (CLAIM-34.3).
//! Deterministic integer arithmetic: bit-identical output from the same seed.

/// First-order thermal model state.
///
/// `T_{k+1} = T_k + (step_s * 1_000_000 / tau_s) / 1_000_000 * (T_target - T_k) + noise`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdRoomThermalSim {
    pub temp_mdeg_c: i64,
    pub ambient_mdeg_c: i64,
    pub setpoint_mdeg_c: i64,
    pub compressor_on: bool,
    pub tau_s: i64,
    pub cooling_mdeg_c: i64,
    pub step_s: i64,
    seed: u64,
    rng_state: u64,
}

impl ColdRoomThermalSim {
    pub fn new(seed: u64) -> Self {
        let mut s = Self {
            temp_mdeg_c: 8_000,
            ambient_mdeg_c: 22_000,
            setpoint_mdeg_c: 4_000,
            compressor_on: false,
            tau_s: 120,
            cooling_mdeg_c: 15_000,
            step_s: 1,
            seed,
            rng_state: seed.wrapping_add(0xA5A5_A5A5_1234_5678),
        };
        s.update_hysteresis();
        s
    }

    fn noise(&mut self) -> i64 {
        let mut x = self.rng_state ^ self.seed.rotate_left(9);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        ((v % 11) as i64) - 5
    }

    fn update_hysteresis(&mut self) {
        let hi = self.setpoint_mdeg_c.saturating_add(500);
        let lo = self.setpoint_mdeg_c.saturating_sub(500);
        if self.temp_mdeg_c > hi {
            self.compressor_on = true;
        } else if self.temp_mdeg_c < lo {
            self.compressor_on = false;
        }
    }

    pub fn step(&mut self) -> i64 {
        self.update_hysteresis();
        let cooling = if self.compressor_on {
            -self.cooling_mdeg_c
        } else {
            0
        };
        let target = self.ambient_mdeg_c.saturating_add(cooling);
        let delta = target.saturating_sub(self.temp_mdeg_c);
        let tau = self.tau_s.max(1);
        let numer = delta.saturating_mul(self.step_s).saturating_mul(1_000_000);
        let change = numer / tau / 1_000_000;
        let n = self.noise();
        self.temp_mdeg_c = self.temp_mdeg_c.saturating_add(change).saturating_add(n);
        self.temp_mdeg_c
    }

    pub fn run_steps(&mut self, steps: usize) -> Vec<i64> {
        let mut out = Vec::with_capacity(steps);
        for _ in 0..steps {
            out.push(self.step());
        }
        out
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
}
