// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic protocol simulators used by recorded-frame tests.
//!
//! Each simulator builds the exact bytes a field device/peer would emit, with
//! no sockets, clocks or randomness, so tests are byte-for-byte reproducible.

#[cfg(feature = "bacnet")]
pub use bacnet_sim::BacnetSim;
#[cfg(feature = "knx")]
pub use knx_sim::{KnxSim, KnxSimValue};
#[cfg(feature = "modbus")]
pub use modbus_sim::ModbusSim;
#[cfg(feature = "mqtt")]
pub use mqtt_sim::MqttSim;

#[cfg(feature = "bacnet")]
mod bacnet_sim {
    use tirbase_driver_api::{encode_read_property_ack, BacnetValue, ObjectIdentifier};

    /// BACnet/IP peer that answers a read with a recorded-shaped ACK.
    pub struct BacnetSim;

    impl BacnetSim {
        /// Encode a ReadProperty-ACK carrying `value` (invoke id 1).
        pub fn read_property_ack(object: ObjectIdentifier, value: BacnetValue) -> Vec<u8> {
            let _ = object;
            encode_read_property_ack(1, &value)
        }
    }
}

#[cfg(feature = "modbus")]
mod modbus_sim {
    use tirbase_driver_api::modbus_codec::build_rtu_frame;

    /// Modbus peer that answers FC03/FC04 reads.
    pub struct ModbusSim;

    impl ModbusSim {
        /// FC03 read-holding-registers response over TCP (transaction id 1).
        pub fn tcp_read_response(unit_id: u8, registers: &[u16]) -> Vec<u8> {
            let pdu = read_pdu(registers);
            let length = (pdu.len() + 1) as u16;
            let mut frame = Vec::with_capacity(7 + pdu.len());
            frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
            frame.extend_from_slice(&length.to_be_bytes());
            frame.push(unit_id);
            frame.extend_from_slice(&pdu);
            frame
        }

        /// FC03 read-holding-registers response over RTU (with CRC).
        pub fn rtu_read_response(unit_id: u8, registers: &[u16]) -> Vec<u8> {
            build_rtu_frame(unit_id, &read_pdu(registers))
        }
    }

    fn read_pdu(registers: &[u16]) -> Vec<u8> {
        let mut pdu = Vec::with_capacity(2 + registers.len() * 2);
        pdu.push(0x03);
        pdu.push((registers.len() * 2) as u8);
        for register in registers {
            pdu.extend_from_slice(&register.to_be_bytes());
        }
        pdu
    }
}

#[cfg(feature = "knx")]
mod knx_sim {
    use super::super::protocol::knx::KNXNET_IP_TUNNELING_REQUEST;

    /// Value emitted by the KNX simulator.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum KnxSimValue {
        /// DPT1 boolean.
        Bool(bool),
        /// DPT9 value in hundredths of the engineering unit (21.50 -> 2150).
        Dpt9Centi(i32),
    }

    /// KNX/IP peer that emits cEMI `L_Data.ind` group-value frames.
    pub struct KnxSim;

    impl KnxSim {
        /// Build a complete KNXnet/IP tunneling frame.
        pub fn group_value_indication(group_address: u16, value: KnxSimValue) -> Vec<u8> {
            let (data_length, high, low): (u8, u8, Option<u8>) = match value {
                KnxSimValue::Bool(flag) => (1u8, 0x80u8 | u8::from(flag), None),
                KnxSimValue::Dpt9Centi(centi) => {
                    let raw = encode_dpt9(centi);
                    (16u8, 0x80 | ((raw >> 8) as u8 & 0x3F), Some(raw as u8))
                }
            };
            let mut cemi = vec![0x29, 0x00, 0xBC, 0xE0, 0x00, 0x01];
            cemi.extend_from_slice(&group_address.to_be_bytes());
            cemi.push(data_length);
            cemi.push(0x00);
            cemi.push(high);
            if let Some(low) = low {
                cemi.push(low);
            }

            let total = 10 + cemi.len();
            let mut frame = Vec::with_capacity(total);
            frame.push(0x06);
            frame.push(0x10);
            frame.extend_from_slice(&KNXNET_IP_TUNNELING_REQUEST.to_be_bytes());
            frame.extend_from_slice(&(total as u16).to_be_bytes());
            frame.extend_from_slice(&[0x04, 0x01, 0x00, 0x00]);
            frame.extend_from_slice(&cemi);
            frame
        }
    }

    /// DPT9 encoder: pick the smallest exponent keeping the mantissa in 11 bits.
    pub fn encode_dpt9(centi: i32) -> u16 {
        let negative = centi < 0;
        let mut value = centi.unsigned_abs();
        let mut exponent = 0u16;
        while value > 0x07FF && exponent < 15 {
            value = value.div_ceil(2);
            exponent += 1;
        }
        let mut raw = (exponent << 11) | (value as u16 & 0x07FF);
        if negative {
            raw |= 0x8000;
        }
        raw
    }
}

#[cfg(feature = "mqtt")]
mod mqtt_sim {
    use tirbase_driver_api::mqtt_codec::{MqttBridgeCodec, MqttQoS};

    /// MQTT peer that emits QoS 0 PUBLISH frames.
    pub struct MqttSim;

    impl MqttSim {
        pub fn publish(topic: &str, payload: &[u8]) -> Vec<u8> {
            MqttBridgeCodec::new()
                .encode_publish(topic, payload, MqttQoS::AtMostOnce, None)
                .expect("simulator topic and payload are valid")
        }
    }
}
