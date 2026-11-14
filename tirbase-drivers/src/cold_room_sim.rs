// SPDX-License-Identifier: AGPL-3.0-only

//! Cold-room simulator driver backed by a first-order thermal model (CLAIM-34.3,
//! PV-10.7). The deterministic model lives in `tirbase-sim`; this module provides
//! a reusable pure model and a `DriverTrait` codec wrapper.

use tirbase_types::{FixedPointValue, TargetId, UNIT_DEG_C};

use crate::driver_trait::{
    ActuationPermitRef, DeviceModel, DriverError, DriverHealth, DriverResult, DriverTrait, Frame,
    ParameterDescriptor,
};

/// First-order thermal model:
/// `T_{k+1} = T_k + dt_s/tau_s * (T_ambient + cooling_effect - T_k)`
///
/// Integer fixed-point arithmetic (all internal state in millidegrees * 10^-3 C
/// represented as i64 scaled values) for deterministic, bit-identical output from
/// the same seed/inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstOrderThermalModel {
    /// Temperature in millidegrees Celsius (10^-3).
    pub temp_mdeg_c: i64,
    pub ambient_mdeg_c: i64,
    pub setpoint_mdeg_c: i64,
    pub compressor_on: bool,
    /// Time constant in seconds.
    pub tau_s: i64,
    /// Cooling effect in millidegrees when compressor is on.
    pub cooling_mdeg_c: i64,
    pub step_s: i64,
    seed: u64,
    rng_state: u64,
}

impl FirstOrderThermalModel {
    pub fn new(seed: u64, initial_mdeg_c: i64, ambient_mdeg_c: i64) -> Self {
        let mut m = Self {
            temp_mdeg_c: initial_mdeg_c,
            ambient_mdeg_c,
            setpoint_mdeg_c: 4000, // 4.0 C
            compressor_on: false,
            tau_s: 120,
            cooling_mdeg_c: 15_000,
            step_s: 1,
            seed,
            rng_state: seed ^ 0x9E37_79B9_7F4A_7C15,
        };
        m.update_compressor();
        m
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64* — deterministic, tiny, no deps.
        let mut x = self.rng_state.wrapping_add(self.seed.rotate_left(7));
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Advance one step. Returns current temperature in millidegrees.
    pub fn step(&mut self) -> i64 {
        self.update_compressor();
        let cooling = if self.compressor_on {
            -self.cooling_mdeg_c
        } else {
            0
        };
        let target = self.ambient_mdeg_c.saturating_add(cooling);
        let delta = target.saturating_sub(self.temp_mdeg_c);
        // dt/tau in fixed-point: step_s / tau_s, scaled by 1_000_000 for integer math.
        let tau = self.tau_s.max(1);
        let change = delta.saturating_mul(self.step_s).saturating_mul(1_000_000) / tau / 1_000_000;
        // Deterministic tiny process noise from seed (bounded ±5 mdeg).
        let noise = ((self.next_u64() % 11) as i64) - 5;
        self.temp_mdeg_c = self
            .temp_mdeg_c
            .saturating_add(change)
            .saturating_add(noise);
        self.temp_mdeg_c
    }

    pub fn set_setpoint_mdeg_c(&mut self, setpoint: i64) {
        self.setpoint_mdeg_c = setpoint;
        self.update_compressor();
    }

    pub fn set_compressor(&mut self, on: bool) {
        self.compressor_on = on;
    }

    fn update_compressor(&mut self) {
        // Simple hysteresis: on above setpoint+500 mdeg, off below setpoint-500 mdeg.
        if self.temp_mdeg_c > self.setpoint_mdeg_c.saturating_add(500) {
            self.compressor_on = true;
        } else if self.temp_mdeg_c < self.setpoint_mdeg_c.saturating_sub(500) {
            self.compressor_on = false;
        }
    }

    pub fn temperature_fpv(&self) -> FixedPointValue {
        // millidegrees -> exponent -3, unit degC
        FixedPointValue::new(self.temp_mdeg_c, -3, UNIT_DEG_C)
    }

    pub fn setpoint_fpv(&self) -> FixedPointValue {
        FixedPointValue::new(self.setpoint_mdeg_c, -3, UNIT_DEG_C)
    }
}

/// Pure codec wrapper exposing the cold-room model as a `DriverTrait`.
#[derive(Debug, Clone)]
pub struct ColdRoomSimDriver {
    pub model: FirstOrderThermalModel,
    pub target_id: TargetId,
}

impl ColdRoomSimDriver {
    pub fn new(seed: u64, target_id: impl Into<String>) -> Self {
        Self {
            model: FirstOrderThermalModel::new(seed, 8_000, 22_000),
            target_id: TargetId::new(target_id),
        }
    }
}

impl DriverTrait for ColdRoomSimDriver {
    fn capability_discovery(&self) -> DriverResult<DeviceModel> {
        DeviceModel::try_new(
            "cold_room_sim".into(),
            vec![
                ParameterDescriptor {
                    name: "temperature_c".into(),
                    unit_id: UNIT_DEG_C,
                    unit_label: "degC".into(),
                    range: [
                        FixedPointValue::new(-40_000, -3, UNIT_DEG_C),
                        FixedPointValue::new(30_000, -3, UNIT_DEG_C),
                    ],
                    writable: false,
                },
                ParameterDescriptor {
                    name: "setpoint_c".into(),
                    unit_id: UNIT_DEG_C,
                    unit_label: "degC".into(),
                    range: [
                        FixedPointValue::new(-30_000, -3, UNIT_DEG_C),
                        FixedPointValue::new(15_000, -3, UNIT_DEG_C),
                    ],
                    writable: true,
                },
                ParameterDescriptor {
                    name: "compressor_on".into(),
                    unit_id: 0,
                    unit_label: "bool".into(),
                    range: [FixedPointValue::new(0, 0, 0), FixedPointValue::new(1, 0, 0)],
                    writable: true,
                },
            ],
        )
        .map_err(|e| DriverError::Capability(e.to_string()))
    }

    fn encode_read(&self, param: &str) -> DriverResult<Frame> {
        match param {
            "temperature_c" | "setpoint_c" | "compressor_on" => Ok(format!("READ:{param}").into()),
            _ => Err(DriverError::UnsupportedParam(param.into())),
        }
    }

    fn decode_read_response(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        let s = std::str::from_utf8(frame)
            .map_err(|e| DriverError::InvalidFrame(format!("utf8: {e}")))?;
        let mut parts = s.splitn(3, ':');
        if parts.next() != Some("RESP") {
            return Err(DriverError::InvalidFrame("expected RESP".into()));
        }
        let param = parts
            .next()
            .ok_or_else(|| DriverError::InvalidFrame("missing param".into()))?;
        let val = parts
            .next()
            .ok_or_else(|| DriverError::InvalidFrame("missing value".into()))?;
        let mantissa: i64 = val
            .parse()
            .map_err(|e| DriverError::InvalidFrame(format!("mantissa: {e}")))?;
        let (exp, unit) = if param == "compressor_on" {
            (0, 0)
        } else {
            (-3, UNIT_DEG_C)
        };
        Ok(FixedPointValue::new(mantissa, exp, unit))
    }

    fn encode_actuation(&self, permit: &ActuationPermitRef) -> DriverResult<Frame> {
        Ok(format!(
            "ACT:{}:{}:{}:{}",
            permit.target_id.as_str(),
            permit.param,
            permit.value.mantissa,
            permit.value.exponent
        )
        .into_bytes())
    }

    fn decode_read_back(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        let s = std::str::from_utf8(frame)
            .map_err(|e| DriverError::InvalidFrame(format!("utf8: {e}")))?;
        let mut parts = s.splitn(3, ':');
        if parts.next() != Some("RB") {
            return Err(DriverError::InvalidFrame("expected RB".into()));
        }
        let _param = parts.next();
        let val = parts
            .next()
            .ok_or_else(|| DriverError::InvalidFrame("missing value".into()))?;
        let mantissa: i64 = val
            .parse()
            .map_err(|e| DriverError::InvalidFrame(format!("mantissa: {e}")))?;
        Ok(FixedPointValue::new(mantissa, -3, UNIT_DEG_C))
    }

    fn encode_health_check(&self) -> DriverResult<Frame> {
        Ok(b"HEALTH?".to_vec())
    }

    fn decode_health_response(&self, frame: &[u8]) -> DriverResult<DriverHealth> {
        Ok(DriverHealth {
            healthy: frame == b"HEALTH:OK",
            detail: String::from_utf8_lossy(frame).into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_seed_bit_identical() {
        let mut a = FirstOrderThermalModel::new(0xC01D, 8_000, 22_000);
        let mut b = FirstOrderThermalModel::new(0xC01D, 8_000, 22_000);
        for _ in 0..200 {
            assert_eq!(a.step(), b.step());
        }
    }
}
