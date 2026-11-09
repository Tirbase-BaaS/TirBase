//! Modbus TCP/RTU client codec and frame parsing (CLAIM-34.1, PV-10.7).
//!
//! Pure codec: builds request frames and decodes response frames for FC 03
//! (Read Holding Registers), FC 04 (Read Input Registers), FC 06 (Write Single
//! Register), and FC 16 (Write Multiple Registers). The guard/transport owns I/O;
//! this module performs no socket or serial operations.
//!
//! ## TCP framing (MBAP)
//! `transaction_id(u16) | protocol_id(u16=0) | length(u16) | unit_id(u8) | PDU`
//!
//! ## RTU framing
//! `unit_id(u8) | PDU | crc16(u16 LE)` — CRC over `unit_id + PDU`.

use tirbase_types::{FixedPointValue, UnitId};

use crate::driver_trait::{
    ActuationPermitRef, DeviceModel, DriverError, DriverHealth, DriverResult, DriverTrait, Frame,
    ParameterDescriptor,
};

/// Modbus function codes supported by this reference driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FunctionCode {
    ReadHoldingRegisters = 0x03,
    ReadInputRegisters = 0x04,
    WriteSingleRegister = 0x06,
    WriteMultipleRegisters = 0x10,
}

impl TryFrom<u8> for FunctionCode {
    type Error = DriverError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x03 => Ok(Self::ReadHoldingRegisters),
            0x04 => Ok(Self::ReadInputRegisters),
            0x06 => Ok(Self::WriteSingleRegister),
            0x10 => Ok(Self::WriteMultipleRegisters),
            _ => Err(DriverError::UnsupportedParam(format!(
                "unsupported Modbus function code 0x{v:02x}"
            ))),
        }
    }
}

/// Wire mode for framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireMode {
    Tcp,
    Rtu,
}

/// A Modbus TCP client codec bound to a unit id and register map parameters.
///
/// Register values are interpreted as signed 16-bit integers scaled into
/// `FixedPointValue`s via `(raw as i64 * scale_mantissa, scale_exponent, unit_id)`.
#[derive(Debug, Clone)]
pub struct ModbusTcpCodec {
    pub unit_id: u8,
    pub unit_type_id: UnitId,
    pub scale_mantissa: i64,
    pub scale_exponent: i8,
    pub holding_register: u16,
    pub input_register: u16,
    pub quantity: u16,
    next_transaction: u16,
}

impl ModbusTcpCodec {
    pub fn new(unit_id: u8, unit_type_id: UnitId) -> Self {
        Self {
            unit_id,
            unit_type_id,
            scale_mantissa: 1,
            scale_exponent: -1,
            holding_register: 0,
            input_register: 0,
            quantity: 1,
            next_transaction: 1,
        }
    }

    pub fn with_scale(mut self, scale_mantissa: i64, scale_exponent: i8) -> Self {
        self.scale_mantissa = scale_mantissa;
        self.scale_exponent = scale_exponent;
        self
    }

    pub fn with_registers(mut self, holding: u16, input: u16) -> Self {
        self.holding_register = holding;
        self.input_register = input;
        self
    }

    fn alloc_tid(&mut self) -> u16 {
        let t = self.next_transaction;
        self.next_transaction = self.next_transaction.wrapping_add(1).max(1);
        t
    }

    fn mbap(&self, transaction_id: u16, pdu_len: u16) -> [u8; 7] {
        let len = pdu_len + 1; // unit id + PDU
        [
            (transaction_id >> 8) as u8,
            transaction_id as u8,
            0,
            0, // protocol id
            (len >> 8) as u8,
            len as u8,
            self.unit_id,
        ]
    }

    fn raw_to_fpv(&self, raw: i16) -> FixedPointValue {
        FixedPointValue::new(
            (raw as i64).saturating_mul(self.scale_mantissa),
            self.scale_exponent,
            self.unit_type_id,
        )
    }

    fn fpv_to_raw(&self, value: &FixedPointValue) -> Result<i16, DriverError> {
        // Normalize to codec exponent by integer scaling when possible.
        let mut mantissa = value.mantissa;
        let mut exponent = value.exponent;
        while exponent < self.scale_exponent {
            mantissa = mantissa.saturating_mul(10);
            exponent += 1;
        }
        while exponent > self.scale_exponent {
            mantissa /= 10;
            exponent -= 1;
        }
        let scaled = if self.scale_mantissa == 0 {
            0
        } else {
            mantissa / self.scale_mantissa
        };
        i16::try_from(scaled)
            .map_err(|_| DriverError::Codec(format!("value {mantissa} out of i16 register range")))
    }

    /// Build FC 03 request (read holding registers).
    pub fn build_fc03(&mut self, address: u16, quantity: u16) -> Frame {
        let tid = self.alloc_tid();
        let pdu = [
            0x03,
            (address >> 8) as u8,
            address as u8,
            (quantity >> 8) as u8,
            quantity as u8,
        ];
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&self.mbap(tid, pdu.len() as u16));
        out.extend_from_slice(&pdu);
        out
    }

    /// Build FC 04 request (read input registers).
    pub fn build_fc04(&mut self, address: u16, quantity: u16) -> Frame {
        let tid = self.alloc_tid();
        let pdu = [
            0x04,
            (address >> 8) as u8,
            address as u8,
            (quantity >> 8) as u8,
            quantity as u8,
        ];
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&self.mbap(tid, pdu.len() as u16));
        out.extend_from_slice(&pdu);
        out
    }

    /// Build FC 06 request (write single register).
    pub fn build_fc06(&mut self, address: u16, value: u16) -> Frame {
        let tid = self.alloc_tid();
        let pdu = [
            0x06,
            (address >> 8) as u8,
            address as u8,
            (value >> 8) as u8,
            value as u8,
        ];
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&self.mbap(tid, pdu.len() as u16));
        out.extend_from_slice(&pdu);
        out
    }

    /// Build FC 16 request (write multiple registers).
    pub fn build_fc16(&mut self, address: u16, values: &[u16]) -> Frame {
        let tid = self.alloc_tid();
        let quantity = values.len() as u16;
        let byte_count = (values.len() * 2) as u8;
        let mut pdu = Vec::with_capacity(6 + values.len() * 2);
        pdu.extend_from_slice(&[
            0x10,
            (address >> 8) as u8,
            address as u8,
            (quantity >> 8) as u8,
            quantity as u8,
            byte_count,
        ]);
        for v in values {
            pdu.extend_from_slice(&v.to_be_bytes());
        }
        let mut out = Vec::with_capacity(7 + pdu.len());
        out.extend_from_slice(&self.mbap(tid, pdu.len() as u16));
        out.extend_from_slice(&pdu);
        out
    }
}

/// Parsed Modbus TCP ADU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModbusTcpAdu {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub pdu: Vec<u8>,
}

/// Parse a Modbus TCP ADU (MBAP + PDU). Returns a typed error on malformed input.
pub fn parse_tcp_adu(frame: &[u8]) -> DriverResult<ModbusTcpAdu> {
    if frame.len() < 8 {
        return Err(DriverError::InvalidFrame(
            "Modbus TCP frame shorter than MBAP+FC".into(),
        ));
    }
    let transaction_id = u16::from_be_bytes([frame[0], frame[1]]);
    let protocol_id = u16::from_be_bytes([frame[2], frame[3]]);
    if protocol_id != 0 {
        return Err(DriverError::InvalidFrame(format!(
            "Modbus TCP protocol id must be 0, got {protocol_id}"
        )));
    }
    let length = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    if length < 2 {
        return Err(DriverError::InvalidFrame(
            "Modbus TCP length must include unit id and function code".into(),
        ));
    }
    let expected = 6usize
        .checked_add(length)
        .ok_or_else(|| DriverError::InvalidFrame("Modbus TCP length overflow".into()))?;
    if frame.len() < expected {
        return Err(DriverError::InvalidFrame(format!(
            "Modbus TCP frame truncated: need {expected} bytes, got {}",
            frame.len()
        )));
    }
    let unit_id = frame[6];
    let pdu = frame[7..expected].to_vec();
    if pdu.is_empty() {
        return Err(DriverError::InvalidFrame("empty Modbus PDU".into()));
    }
    Ok(ModbusTcpAdu {
        transaction_id,
        unit_id,
        pdu,
    })
}

/// Parse a Modbus exception response PDU. Exception PDUs have high bit set on FC.
pub fn parse_exception(pdu: &[u8]) -> Option<(u8, u8)> {
    if pdu.len() >= 2 && (pdu[0] & 0x80) != 0 {
        Some((pdu[0] & 0x7f, pdu[1]))
    } else {
        None
    }
}

/// Decode FC 03/04 response PDU into register values.
pub fn decode_read_registers_response(pdu: &[u8], expected_fc: u8) -> DriverResult<Vec<u16>> {
    if let Some((fc, ex)) = parse_exception(pdu) {
        return Err(DriverError::Codec(format!(
            "Modbus exception FC 0x{fc:02x} code 0x{ex:02x}"
        )));
    }
    if pdu.len() < 2 || pdu[0] != expected_fc {
        return Err(DriverError::InvalidFrame(format!(
            "expected FC 0x{expected_fc:02x} response"
        )));
    }
    let byte_count = pdu[1] as usize;
    if pdu.len() < 2 + byte_count || byte_count % 2 != 0 {
        return Err(DriverError::InvalidFrame(
            "invalid Modbus read-register byte count".into(),
        ));
    }
    let mut regs = Vec::with_capacity(byte_count / 2);
    for chunk in pdu[2..2 + byte_count].chunks_exact(2) {
        regs.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    Ok(regs)
}

/// Decode FC 06 response (echo of address/value).
pub fn decode_write_single_response(pdu: &[u8], address: u16, value: u16) -> DriverResult<()> {
    if let Some((fc, ex)) = parse_exception(pdu) {
        return Err(DriverError::Codec(format!(
            "Modbus exception FC 0x{fc:02x} code 0x{ex:02x}"
        )));
    }
    if pdu.len() < 5 || pdu[0] != 0x06 {
        return Err(DriverError::InvalidFrame("expected FC 06 response".into()));
    }
    let a = u16::from_be_bytes([pdu[1], pdu[2]]);
    let v = u16::from_be_bytes([pdu[3], pdu[4]]);
    if a != address || v != value {
        return Err(DriverError::InvalidFrame(
            "FC 06 response did not echo address/value".into(),
        ));
    }
    Ok(())
}

/// Decode FC 16 response (address/quantity echo).
pub fn decode_write_multiple_response(pdu: &[u8], address: u16, quantity: u16) -> DriverResult<()> {
    if let Some((fc, ex)) = parse_exception(pdu) {
        return Err(DriverError::Codec(format!(
            "Modbus exception FC 0x{fc:02x} code 0x{ex:02x}"
        )));
    }
    if pdu.len() < 5 || pdu[0] != 0x10 {
        return Err(DriverError::InvalidFrame("expected FC 16 response".into()));
    }
    let a = u16::from_be_bytes([pdu[1], pdu[2]]);
    let q = u16::from_be_bytes([pdu[3], pdu[4]]);
    if a != address || q != quantity {
        return Err(DriverError::InvalidFrame(
            "FC 16 response did not echo address/quantity".into(),
        ));
    }
    Ok(())
}

/// Compute Modbus RTU CRC-16.
pub fn crc16_rtu(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Parse an RTU frame `unit_id + PDU + crc_lo + crc_hi`.
pub fn parse_rtu_frame(frame: &[u8]) -> DriverResult<(u8, Vec<u8>)> {
    if frame.len() < 4 {
        return Err(DriverError::InvalidFrame("RTU frame too short".into()));
    }
    let (body, crc_bytes) = frame.split_at(frame.len() - 2);
    let expected = u16::from_le_bytes([crc_bytes[0], crc_bytes[1]]);
    let actual = crc16_rtu(body);
    if actual != expected {
        return Err(DriverError::InvalidFrame(format!(
            "RTU CRC mismatch: expected 0x{expected:04x}, got 0x{actual:04x}"
        )));
    }
    Ok((body[0], body[1..].to_vec()))
}

/// Build an RTU frame.
pub fn build_rtu_frame(unit_id: u8, pdu: &[u8]) -> Frame {
    let mut out = Vec::with_capacity(1 + pdu.len() + 2);
    out.push(unit_id);
    out.extend_from_slice(pdu);
    let crc = crc16_rtu(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

impl DriverTrait for ModbusTcpCodec {
    fn capability_discovery(&self) -> DriverResult<DeviceModel> {
        DeviceModel::try_new(
            "modbus".into(),
            vec![
                ParameterDescriptor {
                    name: "holding".into(),
                    unit_id: self.unit_type_id,
                    unit_label: "register".into(),
                    range: [self.raw_to_fpv(i16::MIN), self.raw_to_fpv(i16::MAX)],
                    writable: true,
                },
                ParameterDescriptor {
                    name: "input".into(),
                    unit_id: self.unit_type_id,
                    unit_label: "register".into(),
                    range: [self.raw_to_fpv(i16::MIN), self.raw_to_fpv(i16::MAX)],
                    writable: false,
                },
            ],
        )
        .map_err(|e| DriverError::Capability(e.to_string()))
    }

    fn encode_read(&self, param: &str) -> DriverResult<Frame> {
        let mut c = self.clone();
        match param {
            "holding" => Ok(c.build_fc03(self.holding_register, self.quantity)),
            "input" => Ok(c.build_fc04(self.input_register, self.quantity)),
            _ => Err(DriverError::UnsupportedParam(param.into())),
        }
    }

    fn decode_read_response(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        let adu = parse_tcp_adu(frame)?;
        let fc = adu.pdu.first().copied().unwrap_or(0);
        let regs = decode_read_registers_response(&adu.pdu, fc)?;
        let raw = regs.first().copied().unwrap_or(0) as i16;
        Ok(self.raw_to_fpv(raw))
    }

    fn encode_actuation(&self, permit: &ActuationPermitRef) -> DriverResult<Frame> {
        let mut c = self.clone();
        let raw = self.fpv_to_raw(&permit.value)? as u16;
        // Default to FC 16 (multiple registers) for actuation; also supports single.
        Ok(c.build_fc16(self.holding_register, &[raw]))
    }

    fn decode_read_back(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        let adu = parse_tcp_adu(frame)?;
        match adu.pdu.first().copied().unwrap_or(0) {
            0x03 | 0x04 => {
                let regs = decode_read_registers_response(&adu.pdu, adu.pdu[0])?;
                Ok(self.raw_to_fpv(regs.first().copied().unwrap_or(0) as i16))
            }
            0x06 => {
                if adu.pdu.len() < 5 {
                    return Err(DriverError::InvalidFrame("short FC06".into()));
                }
                let v = u16::from_be_bytes([adu.pdu[3], adu.pdu[4]]) as i16;
                Ok(self.raw_to_fpv(v))
            }
            0x10 => {
                decode_write_multiple_response(&adu.pdu, self.holding_register, self.quantity)?;
                // FC16 echoes address/qty only; read-back callers should follow with a read.
                Ok(self.raw_to_fpv(0))
            }
            fc => Err(DriverError::InvalidFrame(format!(
                "unexpected read-back FC 0x{fc:02x}"
            ))),
        }
    }

    fn encode_health_check(&self) -> DriverResult<Frame> {
        let mut c = self.clone();
        Ok(c.build_fc03(self.holding_register, 1))
    }

    fn decode_health_response(&self, frame: &[u8]) -> DriverResult<DriverHealth> {
        match parse_tcp_adu(frame) {
            Ok(adu) => {
                let healthy = parse_exception(&adu.pdu).is_none()
                    && matches!(adu.pdu.first().copied(), Some(0x03 | 0x04));
                Ok(DriverHealth {
                    healthy,
                    detail: format!("fc=0x{:02x}", adu.pdu.first().copied().unwrap_or(0)),
                })
            }
            Err(e) => Ok(DriverHealth {
                healthy: false,
                detail: e.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_types::UNIT_DEG_C;

    #[test]
    fn fc03_roundtrip_frame() {
        let mut c = ModbusTcpCodec::new(1, UNIT_DEG_C);
        let req = c.build_fc03(10, 2);
        let adu = parse_tcp_adu(&req).unwrap();
        assert_eq!(adu.pdu[0], 0x03);
        assert_eq!(u16::from_be_bytes([adu.pdu[1], adu.pdu[2]]), 10);
        assert_eq!(u16::from_be_bytes([adu.pdu[3], adu.pdu[4]]), 2);
        let resp_pdu = [0x03u8, 4, 0, 42, 0, 43];
        let regs = decode_read_registers_response(&resp_pdu, 0x03).unwrap();
        assert_eq!(regs, vec![42, 43]);
    }

    #[test]
    fn fc04_roundtrip_frame() {
        let mut c = ModbusTcpCodec::new(1, UNIT_DEG_C);
        let req = c.build_fc04(5, 1);
        let adu = parse_tcp_adu(&req).unwrap();
        assert_eq!(adu.pdu[0], 0x04);
        let regs = decode_read_registers_response(&[0x04, 2, 0xFF, 0xF6], 0x04).unwrap();
        assert_eq!(regs[0] as i16, -10);
    }

    #[test]
    fn fc06_roundtrip_frame() {
        let mut c = ModbusTcpCodec::new(1, UNIT_DEG_C);
        let req = c.build_fc06(7, 123);
        let adu = parse_tcp_adu(&req).unwrap();
        assert_eq!(adu.pdu[0], 0x06);
        decode_write_single_response(&adu.pdu, 7, 123).unwrap();
    }

    #[test]
    fn fc16_roundtrip_frame() {
        let mut c = ModbusTcpCodec::new(1, UNIT_DEG_C);
        let req = c.build_fc16(7, &[1, 2, 3]);
        let adu = parse_tcp_adu(&req).unwrap();
        assert_eq!(adu.pdu[0], 0x10);
        decode_write_multiple_response(&[0x10, 0, 7, 0, 3], 7, 3).unwrap();
    }

    #[test]
    fn rtu_crc_roundtrip() {
        let frame = build_rtu_frame(1, &[0x03, 0x00, 0x00, 0x00, 0x01]);
        let (uid, pdu) = parse_rtu_frame(&frame).unwrap();
        assert_eq!(uid, 1);
        assert_eq!(pdu[0], 0x03);
    }
}
