// SPDX-License-Identifier: AGPL-3.0-only

//! F-13 device simulator catalogue (HIL/field-validation).
//!
//! These types are lightweight in-repo stand-ins used by `tirbase-sim` scenarios and
//! documentation. Full protocol fidelity (BACnet stack, BLE GATT peripheral, real ESC/POS
//! binary streams, etc.) may live in external lab harnesses; record the harness ID in
//! `docs/hil-lab-checklist.md` evidence manifests.
//!
//! | Kind | Intended use |
//! |------|----------------|
//! | Modbus | Covered by [`super::modbus_server::ModbusSimServer`] + driver tests |
//! | Bacnet | Building/energy device simulation (scaffold) |
//! | OneWire | Covered by [`super::onewire::SimOneWireBus`] + driver tests |
//! | CurrentLoop4_20MaAdc | Analog input via calibrated current source or simulator |
//! | BleGatt | Peripheral GATT services (scaffold) |
//! | EscPos | Receipt printer output capture (scaffold) |
//! | Scale | Weight readings with tolerance (scaffold) |
//! | Scanner | Barcode/QR decode events (scaffold) |
//! | GateController | Access/gate relay state machine (scaffold) |

use serde::{Deserialize, Serialize};

/// Logical device simulator kinds required by F-13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulatorKind {
    Modbus,
    Bacnet,
    OneWire,
    CurrentLoop4_20MaAdc,
    BleGatt,
    EscPos,
    Scale,
    Scanner,
    GateController,
}

/// Minimal descriptor for a configured simulator instance (for scenarios/evidence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatorDescriptor {
    pub kind: SimulatorKind,
    pub id: String,
    pub notes: Option<String>,
}

impl SimulatorDescriptor {
    pub fn new(kind: SimulatorKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
            notes: None,
        }
    }
}

/// 4–20 mA ADC simulator producing raw counts and injectable faults (CC-05).
///
/// Counts are `loop_ma / 24 mA × adc_full_scale`, so 4 mA and 20 mA sit inside
/// the scale. `set_open_loop`, `set_under_range`, and `set_over_range` model
/// loop faults; `set_noise` alternates counts around the nominal value, and
/// `set_stuck(true)` freezes the current counts until cleared.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sim4To20MaAdc {
    /// Loop current in milliamps (0.0..=24.0).
    pub loop_ma: f64,
    /// Full-scale ADC count (default 4095, a 12-bit converter).
    pub adc_full_scale: u32,
    /// Peak-to-peak injected noise in microamperes.
    pub noise_peak_to_peak_ua: i32,
    /// Whether the ADC is stuck at `stuck_counts`.
    pub stuck: bool,
    #[serde(skip)]
    stuck_counts: Option<u32>,
    #[serde(skip)]
    noise_phase: bool,
}

impl Default for Sim4To20MaAdc {
    fn default() -> Self {
        Self {
            loop_ma: 0.0,
            adc_full_scale: 4_095,
            noise_peak_to_peak_ua: 0,
            stuck: false,
            stuck_counts: None,
            noise_phase: false,
        }
    }
}

impl Sim4To20MaAdc {
    pub fn set_loop_ma(&mut self, ma: f64) {
        self.loop_ma = ma.clamp(0.0, 24.0);
    }

    /// Models a disconnected loop (0 mA) and clears any stuck state.
    pub fn set_open_loop(&mut self) {
        self.stuck = false;
        self.stuck_counts = None;
        self.loop_ma = 0.0;
    }

    /// Models a live loop below the 4 mA nominal (3.7 mA).
    pub fn set_under_range(&mut self) {
        self.stuck = false;
        self.stuck_counts = None;
        self.loop_ma = 3.7;
    }

    /// Models an over-range loop (22 mA).
    pub fn set_over_range(&mut self) {
        self.stuck = false;
        self.stuck_counts = None;
        self.loop_ma = 22.0;
    }

    /// Sets peak-to-peak noise in microamperes (negative values clamp to 0).
    pub fn set_noise(&mut self, peak_to_peak_ua: i32) {
        self.noise_peak_to_peak_ua = peak_to_peak_ua.max(0);
    }

    /// Freezes (or unfreezes) the ADC at its current counts.
    pub fn set_stuck(&mut self, stuck: bool) {
        if stuck {
            if self.stuck_counts.is_none() {
                self.stuck_counts = Some(self.nominal_counts());
            }
        } else {
            self.stuck_counts = None;
        }
        self.stuck = stuck;
    }

    /// Reads one ADC sample.
    pub fn read_counts(&mut self) -> u32 {
        if self.stuck {
            if let Some(counts) = self.stuck_counts {
                return counts;
            }
        }
        let mut counts = i64::from(self.nominal_counts());
        if self.noise_peak_to_peak_ua > 0 {
            let half = i64::from(self.noise_peak_to_peak_ua / 2);
            let full_scale = i64::from(self.adc_full_scale.max(1));
            let delta = half * full_scale / 24_000;
            counts += if self.noise_phase { delta } else { -delta };
            self.noise_phase = !self.noise_phase;
        }
        counts.clamp(0, i64::from(self.adc_full_scale)) as u32
    }

    /// Linear map from 4–20 mA to 0–100% of span (clamped).
    pub fn percent_of_span(&self) -> f64 {
        let ma = self.loop_ma.clamp(4.0, 20.0);
        (ma - 4.0) / 16.0 * 100.0
    }

    fn nominal_counts(&self) -> u32 {
        let full_scale = self.adc_full_scale.max(1);
        ((self.loop_ma.clamp(0.0, 24.0) / 24.0) * f64::from(full_scale))
            .round()
            .clamp(0.0, f64::from(full_scale)) as u32
    }
}

/// Stub: simple gate controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GateState {
    #[default]
    ClosedLocked,
    Opening,
    Open,
    Closing,
    Fault,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SimGateController {
    pub state: GateState,
}

impl SimGateController {
    pub fn command_open(&mut self) {
        self.state = match self.state {
            GateState::Fault => GateState::Fault,
            _ => GateState::Opening,
        };
    }

    pub fn command_close(&mut self) {
        self.state = match self.state {
            GateState::Fault => GateState::Fault,
            _ => GateState::Closing,
        };
    }

    pub fn step(&mut self) {
        self.state = match self.state {
            GateState::Opening => GateState::Open,
            GateState::Closing => GateState::ClosedLocked,
            other => other,
        };
    }
}
