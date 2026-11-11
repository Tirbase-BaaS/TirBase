//! Deterministic first-order thermal device model (task 38.4 — CLAIM-38.4,
//! PV-12.3).
//!
//! The cold-room model is a standard lumped-capacitance first-order system:
//!
//! ```text
//! T_{k+1} = T_target + (T_k - T_target) * e^(-dt / tau)
//! ```
//!
//! where `T_target` is the ambient temperature shifted by the compressor's
//! cooling effect. The exponential comes from the `libm` crate rather than the
//! platform `std` math library: `libm` is a pure-Rust implementation, so the
//! same seed and inputs produce bit-identical trajectories on x86_64, aarch64,
//! and any other target, which `std`'s libm-backed `f64` methods do not
//! guarantee (PV-12.3).
//!
//! The small process-noise term is drawn from a `ChaCha8Rng` seeded from the
//! model seed and composed with IEEE-754 additions only, so it introduces no
//! platform dependence either.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Default cold-room time constant in seconds.
pub const DEFAULT_TAU_S: f64 = 120.0;
/// Default cooling effect of the compressor in degrees Celsius.
pub const DEFAULT_COOLING_C: f64 = 15.0;
/// Default control step in seconds.
pub const DEFAULT_STEP_S: f64 = 1.0;
/// Hysteresis band around the setpoint in degrees Celsius.
pub const DEFAULT_HYSTERESIS_C: f64 = 0.5;

/// First-order thermal model of a refrigerated room (CLAIM-38.4).
#[derive(Debug, Clone)]
pub struct ThermalModel {
    /// Current air temperature in degrees Celsius.
    temp_c: f64,
    /// Ambient (outside) temperature in degrees Celsius.
    ambient_c: f64,
    /// Controller setpoint in degrees Celsius.
    setpoint_c: f64,
    /// Thermal time constant in seconds.
    tau_s: f64,
    /// Temperature drop the compressor can pull the room towards.
    cooling_c: f64,
    /// Simulation step size in seconds.
    dt_s: f64,
    /// Compressor state from the hysteresis controller.
    compressor_on: bool,
    rng: ChaCha8Rng,
}

impl ThermalModel {
    /// Create a model at 8 °C in a 22 °C ambient room with a 4 °C setpoint.
    pub fn new(seed: u64) -> Self {
        Self::with_initial(seed, 8.0, 22.0)
    }

    /// Create a model with explicit initial and ambient temperatures.
    pub fn with_initial(seed: u64, initial_c: f64, ambient_c: f64) -> Self {
        let mut model = Self {
            temp_c: initial_c,
            ambient_c,
            setpoint_c: 4.0,
            tau_s: DEFAULT_TAU_S,
            cooling_c: DEFAULT_COOLING_C,
            dt_s: DEFAULT_STEP_S,
            compressor_on: false,
            // Domain-separated from the scenario/network streams.
            rng: ChaCha8Rng::seed_from_u64(seed ^ 0x5448_4552_4D41_4C01),
        };
        model.update_compressor();
        model
    }

    /// Override the time constant (seconds); clamped to at least one second.
    pub fn with_time_constant(mut self, tau_s: f64) -> Self {
        self.tau_s = if tau_s.is_finite() && tau_s >= 1.0 {
            tau_s
        } else {
            1.0
        };
        self
    }

    /// Override the compressor cooling effect (degrees Celsius).
    pub fn with_cooling(mut self, cooling_c: f64) -> Self {
        self.cooling_c = if cooling_c.is_finite() {
            cooling_c.abs()
        } else {
            0.0
        };
        self
    }

    /// Override the control step (seconds); clamped to at least one second.
    pub fn with_step(mut self, dt_s: f64) -> Self {
        self.dt_s = if dt_s.is_finite() && dt_s >= 1.0 {
            dt_s
        } else {
            1.0
        };
        self
    }

    /// Set the controller setpoint (degrees Celsius) and re-evaluate the
    /// compressor hysteresis.
    pub fn set_setpoint_c(&mut self, setpoint_c: f64) {
        if setpoint_c.is_finite() {
            self.setpoint_c = setpoint_c;
        }
        self.update_compressor();
    }

    /// Ambient temperature in degrees Celsius.
    pub fn ambient_c(&self) -> f64 {
        self.ambient_c
    }

    /// Controller setpoint in degrees Celsius.
    pub fn setpoint_c(&self) -> f64 {
        self.setpoint_c
    }

    /// Current temperature in degrees Celsius.
    pub fn temperature_c(&self) -> f64 {
        self.temp_c
    }

    /// Bit pattern of the current temperature, for reproducibility checks.
    pub fn temperature_bits(&self) -> u64 {
        self.temp_c.to_bits()
    }

    /// Whether the compressor is currently energised.
    pub fn compressor_on(&self) -> bool {
        self.compressor_on
    }

    /// Advance one control step and return the new temperature.
    ///
    /// Uses `libm::exp` so the trajectory is bit-identical across platforms.
    pub fn step(&mut self) -> f64 {
        self.update_compressor();
        let target = self.ambient_c
            - if self.compressor_on {
                self.cooling_c
            } else {
                0.0
            };
        let decay = libm::exp(-self.dt_s / self.tau_s);
        let next = target + (self.temp_c - target) * decay;
        // Deterministic ±0.005 °C process noise (IEEE additions only).
        let noise = (self.rng.gen_range(0u32..=10) as f64) * 0.001 - 0.005;
        self.temp_c = next + noise;
        self.temp_c
    }

    /// Advance `steps` control steps and collect the temperature each step.
    pub fn run_steps(&mut self, steps: usize) -> Vec<f64> {
        let mut out = Vec::with_capacity(steps);
        for _ in 0..steps {
            out.push(self.step());
        }
        out
    }

    /// Advance `steps` control steps and collect the raw bit patterns.
    pub fn run_steps_bits(&mut self, steps: usize) -> Vec<u64> {
        let mut out = Vec::with_capacity(steps);
        for _ in 0..steps {
            out.push(self.step().to_bits());
        }
        out
    }

    fn update_compressor(&mut self) {
        if self.temp_c > self.setpoint_c + DEFAULT_HYSTERESIS_C {
            self.compressor_on = true;
        } else if self.temp_c < self.setpoint_c - DEFAULT_HYSTERESIS_C {
            self.compressor_on = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_is_bit_identical() {
        let mut a = ThermalModel::new(42);
        let mut b = ThermalModel::new(42);
        assert_eq!(a.run_steps_bits(512), b.run_steps_bits(512));
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = ThermalModel::new(1);
        let mut b = ThermalModel::new(2);
        assert_ne!(a.run_steps_bits(64), b.run_steps_bits(64));
    }

    #[test]
    fn golden_trajectory_is_stable_across_platforms() {
        // Golden values captured from the libm-based implementation. `libm` is
        // pure Rust, so these bit patterns must reproduce on every target;
        // substituting `std` float math can change them on another platform.
        let mut model = ThermalModel::new(0xC01D);
        let bits = model.run_steps_bits(8);
        assert_eq!(
            bits,
            vec![
                0x401f_f886_b00a_52d7,
                0x401f_f42f_af72_111b,
                0x401f_f0e8_0c01_41b7,
                0x401f_e98e_cce4_e72f,
                0x401f_e245_2a6e_f8a9,
                0x401f_db0b_0374_b3b3,
                0x401f_cfc7_a39d_0fcb,
                0x401f_c5a2_5646_60dd,
            ],
            "thermal golden trajectory changed; the model must use libm deterministically"
        );
    }

    #[test]
    fn compressor_hysteresis_and_setpoint_are_deterministic() {
        let mut model = ThermalModel::new(7);
        model.set_setpoint_c(2.0);
        assert!(model.compressor_on());
        let mut expected = model.clone();
        assert_eq!(model.run_steps_bits(64), expected.run_steps_bits(64));
    }
}
