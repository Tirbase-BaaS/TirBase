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
//! | OneWire | Temperature/ID chains (scaffold) |
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

/// Stub: 4–20 mA ADC simulator producing a scaled engineering value.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Sim4To20MaAdc {
    /// Raw loop current in milliamps (4.0..=20.0 typical).
    pub loop_ma: f64,
}

impl Sim4To20MaAdc {
    pub fn set_loop_ma(&mut self, ma: f64) {
        self.loop_ma = ma.clamp(0.0, 24.0);
    }

    /// Linear map from 4–20 mA to 0–100% of span (clamped).
    pub fn percent_of_span(&self) -> f64 {
        let ma = self.loop_ma.clamp(4.0, 20.0);
        (ma - 4.0) / 16.0 * 100.0
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
