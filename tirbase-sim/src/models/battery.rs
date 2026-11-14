// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic battery/inverter model for the energy-edge demo (//! CLAIM-38.5, PV-12.3).
//!
//! The pack is modelled as an energy reservoir with a state of charge (SoC), an
//! open-circuit voltage curve, ohmic sag, and a load-dependent inverter
//! efficiency:
//!
//! ```text
//! ocv = V_nominal * (0.85 + 0.15 * sqrt(soc))
//! current = P / ocv
//! terminal V = ocv - I * R_internal
//! efficiency = eta_max * (1 - e^(4 * |P| / P_max))
//! ```
//!
//! `sqrt` and `exp` come from the `libm` crate, not `std`. `libm` is pure Rust,
//! so identical seeds and loads produce bit-identical SoC/voltage/efficiency
//! trajectories across x86_64 and ARM (PV-12.3).

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Default usable pack energy in watt-hours.
pub const DEFAULT_CAPACITY_WH: f64 = 5_000.0;
/// Default nominal pack voltage in volts.
pub const DEFAULT_NOMINAL_V: f64 = 48.0;
/// Default pack internal resistance in ohms.
pub const DEFAULT_INTERNAL_RESISTANCE_OHM: f64 = 0.02;
/// Default inverter maximum AC output in watts.
pub const DEFAULT_MAX_POWER_W: f64 = 3_000.0;
/// Default peak inverter efficiency.
pub const DEFAULT_MAX_EFFICIENCY: f64 = 0.96;
/// Default control step in seconds.
pub const DEFAULT_STEP_S: f64 = 1.0;

/// Deterministic battery + inverter model (CLAIM-38.5).
#[derive(Debug, Clone)]
pub struct BatteryModel {
 /// State of charge in `0.0..=1.0`.
    soc: f64,
 /// Usable pack energy in watt-hours.
    capacity_wh: f64,
 /// Nominal pack voltage in volts.
    nominal_v: f64,
 /// Pack internal resistance in ohms.
    internal_resistance_ohm: f64,
 /// Inverter maximum AC output in watts.
    max_power_w: f64,
 /// Peak inverter efficiency in `0.0..=1.0`.
    max_efficiency: f64,
 /// Instantaneous DC power in watts: positive discharges, negative charges.
    power_w: f64,
 /// Control step in seconds.
    dt_s: f64,
 /// Deterministic measurement noise source.
    rng: ChaCha8Rng,
}

impl BatteryModel {
 /// Create a pack at 80 % SoC, idle.
    pub fn new(seed: u64) -> Self {
        Self {
            soc: 0.8,
            capacity_wh: DEFAULT_CAPACITY_WH,
            nominal_v: DEFAULT_NOMINAL_V,
            internal_resistance_ohm: DEFAULT_INTERNAL_RESISTANCE_OHM,
            max_power_w: DEFAULT_MAX_POWER_W,
            max_efficiency: DEFAULT_MAX_EFFICIENCY,
            power_w: 0.0,
            dt_s: DEFAULT_STEP_S,
 // Domain-separated from the scenario/network/thermal streams.
            rng: ChaCha8Rng::seed_from_u64(seed ^ 0x4241_5454_4552_5901),
        }
    }

 /// Override the pack capacity in watt-hours (clamped above zero).
    pub fn with_capacity_wh(mut self, capacity_wh: f64) -> Self {
        self.capacity_wh = if capacity_wh.is_finite() && capacity_wh > 0.0 {
            capacity_wh
        } else {
            DEFAULT_CAPACITY_WH
        };
        self
    }

 /// Override the initial state of charge (clamped to `0.0..=1.0`).
    pub fn with_soc(mut self, soc: f64) -> Self {
        self.soc = if soc.is_finite() {
            soc.clamp(0.0, 1.0)
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

 /// Set the DC power in watts (positive = discharge, negative = charge).
    pub fn set_power_w(&mut self, power_w: f64) {
        if power_w.is_finite() {
            self.power_w = power_w;
        }
    }

 /// Current DC power setpoint in watts.
    pub fn power_w(&self) -> f64 {
        self.power_w
    }

 /// Current state of charge in `0.0..=1.0`.
    pub fn soc(&self) -> f64 {
        self.soc
    }

 /// Bit pattern of the current state of charge.
    pub fn soc_bits(&self) -> u64 {
        self.soc.to_bits()
    }

 /// Open-circuit voltage at the current SoC (volts).
    pub fn open_circuit_voltage(&self) -> f64 {
        self.nominal_v * (0.85 + 0.15 * libm::sqrt(self.soc.clamp(0.0, 1.0)))
    }

 /// Terminal voltage at the current SoC and power setpoint (volts).
    pub fn terminal_voltage(&self) -> f64 {
        let ocv = self.open_circuit_voltage();
        let current = if ocv > 0.0 { self.power_w / ocv } else { 0.0 };
        ocv - current * self.internal_resistance_ohm
    }

 /// Inverter efficiency at the current load (dimensionless).
 ///
 /// Uses `libm::exp` for a deterministic load-dependent curve.
    pub fn efficiency(&self) -> f64 {
        let load = (self.power_w.abs() / self.max_power_w.max(1e-9)).clamp(0.0, 1.0);
        let curve = 1.0 - libm::exp(-4.0 * load);
        (self.max_efficiency * curve).max(0.0)
    }

 /// AC power delivered (discharge) or absorbed (charge) in watts.
    pub fn ac_power_w(&self) -> f64 {
        self.power_w * self.efficiency()
    }

 /// Advance one control step and return the new state of charge.
 ///
 /// The energy update uses IEEE-754 arithmetic only; the non-linear voltage
 /// and efficiency curves use `libm`.
    pub fn step(&mut self) -> f64 {
        let energy_wh = self.power_w * self.dt_s / 3_600.0;
        let next = self.soc - energy_wh / self.capacity_wh;
        self.soc = next.clamp(0.0, 1.0);
 // Deterministic ±0.0005 SoC measurement noise (IEEE additions only).
        let noise = (self.rng.gen_range(0u32..=10) as f64) * 0.0001 - 0.0005;
        self.soc = (self.soc + noise).clamp(0.0, 1.0);
        self.soc
    }

 /// Advance `steps` control steps and collect the SoC after each step.
    pub fn run_steps(&mut self, steps: usize) -> Vec<f64> {
        let mut out = Vec::with_capacity(steps);
        for _ in 0..steps {
            out.push(self.step());
        }
        out
    }

 /// Advance `steps` control steps and collect the raw SoC bits.
    pub fn run_steps_bits(&mut self, steps: usize) -> Vec<u64> {
        let mut out = Vec::with_capacity(steps);
        for _ in 0..steps {
            out.push(self.step().to_bits());
        }
        out
    }

 /// Bit patterns of `(soc, terminal_voltage, efficiency)` at this instant.
    pub fn state_bits(&self) -> [u64; 3] {
        [
            self.soc.to_bits(),
            self.terminal_voltage().to_bits(),
            self.efficiency().to_bits(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_is_bit_identical() {
        let mut a = BatteryModel::new(42);
        let mut b = BatteryModel::new(42);
        a.set_power_w(1_800.0);
        b.set_power_w(1_800.0);
        assert_eq!(a.run_steps_bits(512), b.run_steps_bits(512));
        assert_eq!(a.state_bits(), b.state_bits());
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = BatteryModel::new(1);
        let mut b = BatteryModel::new(2);
        a.set_power_w(900.0);
        b.set_power_w(900.0);
        assert_ne!(a.run_steps_bits(32), b.run_steps_bits(32));
    }

    #[test]
    fn golden_trajectory_is_stable_across_platforms() {
 // Golden SoC bits captured from the libm-based implementation; `libm`
 // is pure Rust so these must reproduce on every target.
        let mut model = BatteryModel::new(0xBA77_0000);
        model.set_power_w(2_000.0);
        assert_eq!(
            model.run_steps_bits(6),
            vec![
                0x3fe9_9a54_0375_76d5,
                0x3fe9_9899_480b_496a,
                0x3fe9_9af7_2015_d869,
                0x3fe9_96c7_3f65_a058,
                0x3fe9_9781_a941_7d93,
                0x3fe9_94f5_36bf_f746,
            ],
            "battery golden trajectory changed; the model must use libm deterministically"
        );
    }

    #[test]
    fn load_curves_are_monotonic_and_deterministically_labelled() {
        let mut model = BatteryModel::new(9);
        model.set_power_w(0.0);
        let idle_efficiency = model.efficiency();
        model.set_power_w(1_500.0);
        assert!(model.efficiency() > idle_efficiency);
        assert!(model.terminal_voltage() < model.open_circuit_voltage());
        assert_eq!(
            model.state_bits(),
            BatteryModel { ..model.clone() }.state_bits()
        );
    }
}
