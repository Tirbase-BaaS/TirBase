// SPDX-License-Identifier: Apache-2.0

//! Pure BACnet/IP read-only codec (CC-04).
//!
//! This module implements the wire format only: BVLC framing, NPDU, Who-Is /
//! I-Am discovery, and confirmed ReadProperty for analog/binary inputs and
//! values. It performs no I/O; the feature-gated UDP transport lives in
//! `tirbase_drivers::bacnet`.
//!
//! # Read-only by construction
//!
//! This is the read-only MVP. [`encode_write_property`] does not emit a frame:
//! it returns [`BacnetError::WriteRejected`]. Transports expose the same typed
//! error before touching a socket.
//!
//! # Bounds
//!
//! Every parser rejects frames longer than [`MAX_BVLC_LENGTH`] and APDUs
//! longer than [`MAX_APDU_LENGTH`]. Decoding object values never allocates more
//! than the supplied frame, and discovery caps the number of reported devices
//! at [`MAX_DISCOVERED_DEVICES`].

use core::fmt;

use tirbase_types::{FixedPointValue, UnitId};

/// BVLC type for BACnet/IP.
pub const BVLC_TYPE: u8 = 0x81;
/// BVLC function: Original-Unicast-NPDU.
pub const BVLC_ORIGINAL_UNICAST: u8 = 0x0A;
/// BVLC function: Original-Broadcast-NPDU.
pub const BVLC_ORIGINAL_BROADCAST: u8 = 0x0B;
/// IANA-assigned BACnet/IP UDP port.
pub const BACNET_IP_PORT: u16 = 47808;
/// Maximum accepted BVLC frame length (single UDP datagram, no fragmentation).
pub const MAX_BVLC_LENGTH: usize = 1500;
/// Maximum accepted APDU length.
pub const MAX_APDU_LENGTH: usize = 1024;
/// Upper bound on devices reported by one discovery pass.
pub const MAX_DISCOVERED_DEVICES: usize = 256;
/// Upper bound on retries for a discovery or read transaction.
pub const MAX_RETRIES: u8 = 3;

const NPDU_VERSION: u8 = 0x01;
const NPDU_NETWORK_LAYER_MESSAGE: u8 = 0x80;
const NPDU_DESTINATION_SPECIFIER: u8 = 0x20;
const NPDU_SOURCE_SPECIFIER: u8 = 0x08;

const SERVICE_I_AM: u8 = 0x00;
const SERVICE_WHO_IS: u8 = 0x08;
const SERVICE_READ_PROPERTY: u8 = 0x0C;
/// Confirmed service choice: WriteProperty (rejected by the read bridge).
pub const SERVICE_WRITE_PROPERTY: u8 = 0x0F;
/// Confirmed service choice: WritePropertyMultiple (rejected by the read bridge).
pub const SERVICE_WRITE_PROPERTY_MULTIPLE: u8 = 0x10;

const PDU_CONFIRMED_REQUEST: u8 = 0x00;
const PDU_UNCONFIRMED_REQUEST: u8 = 0x10;
const PDU_SIMPLE_ACK: u8 = 0x20;
const PDU_COMPLEX_ACK: u8 = 0x30;
const PDU_ERROR: u8 = 0x50;
const PDU_REJECT: u8 = 0x60;
const PDU_ABORT: u8 = 0x70;

/// BACnet object type codes accepted by the read bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectType {
    AnalogInput,
    AnalogOutput,
    AnalogValue,
    BinaryInput,
    BinaryOutput,
    BinaryValue,
    /// Device object, used by I-Am discovery.
    Device,
}

impl ObjectType {
    /// Wire code (10-bit object type field).
    pub const fn code(self) -> u16 {
        match self {
            Self::AnalogInput => 0,
            Self::AnalogOutput => 1,
            Self::AnalogValue => 2,
            Self::BinaryInput => 3,
            Self::BinaryOutput => 4,
            Self::BinaryValue => 5,
            Self::Device => 8,
        }
    }

    /// Decodes a wire code. Only the read-bridge object types are accepted.
    pub fn from_code(code: u16) -> Result<Self, BacnetError> {
        match code {
            0 => Ok(Self::AnalogInput),
            1 => Ok(Self::AnalogOutput),
            2 => Ok(Self::AnalogValue),
            3 => Ok(Self::BinaryInput),
            4 => Ok(Self::BinaryOutput),
            5 => Ok(Self::BinaryValue),
            8 => Ok(Self::Device),
            other => Err(BacnetError::UnsupportedObjectType(other)),
        }
    }

    /// Whether this object may be read by the read bridge.
    pub const fn is_readable(self) -> bool {
        !matches!(self, Self::Device)
    }

    /// Whether this object is an analog input/value family member.
    pub const fn is_analog(self) -> bool {
        matches!(
            self,
            Self::AnalogInput | Self::AnalogOutput | Self::AnalogValue
        )
    }

    /// Whether this object is a binary input/value family member.
    pub const fn is_binary(self) -> bool {
        matches!(
            self,
            Self::BinaryInput | Self::BinaryOutput | Self::BinaryValue
        )
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::AnalogInput => "analog-input",
            Self::AnalogOutput => "analog-output",
            Self::AnalogValue => "analog-value",
            Self::BinaryInput => "binary-input",
            Self::BinaryOutput => "binary-output",
            Self::BinaryValue => "binary-value",
            Self::Device => "device",
        };
        f.write_str(name)
    }
}

/// BACnet object identifier (type + 22-bit instance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectIdentifier {
    pub object_type: ObjectType,
    pub instance: u32,
}

/// Largest BACnet object instance.
pub const MAX_OBJECT_INSTANCE: u32 = 0x3F_FFFF;

impl ObjectIdentifier {
    /// Constructs an identifier, rejecting instances above 22 bits.
    pub fn new(object_type: ObjectType, instance: u32) -> Result<Self, BacnetError> {
        if instance > MAX_OBJECT_INSTANCE {
            return Err(BacnetError::InvalidObjectInstance(instance));
        }
        Ok(Self {
            object_type,
            instance,
        })
    }

    /// Convenience constructor for a device object.
    pub fn device(instance: u32) -> Result<Self, BacnetError> {
        Self::new(ObjectType::Device, instance)
    }

    /// Encodes the four-byte BACnet object identifier.
    pub fn encode(self) -> [u8; 4] {
        let raw = ((self.object_type.code() as u32) << 22) | (self.instance & MAX_OBJECT_INSTANCE);
        raw.to_be_bytes()
    }

    /// Decodes the four-byte BACnet object identifier.
    pub fn decode(bytes: &[u8]) -> Result<Self, BacnetError> {
        if bytes.len() != 4 {
            return Err(BacnetError::InvalidFrame(
                "object identifier must be four bytes".into(),
            ));
        }
        let raw = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let object_type = ObjectType::from_code((raw >> 22) as u16)?;
        Ok(Self {
            object_type,
            instance: raw & MAX_OBJECT_INSTANCE,
        })
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{}", self.object_type, self.instance)
    }
}

/// BACnet property identifier (22-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PropertyId(pub u32);

impl PropertyId {
    /// Present-Value, the value exposed by analog/binary objects.
    pub const PRESENT_VALUE: Self = Self(85);
    /// Object-Name.
    pub const OBJECT_NAME: Self = Self(77);
    /// Units.
    pub const UNITS: Self = Self(117);
    /// Status-Flags.
    pub const STATUS_FLAGS: Self = Self(111);

    /// Wire value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for PropertyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Decoded BACnet application value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BacnetValue {
    Real(f32),
    Double(f64),
    Unsigned(u64),
    Signed(i64),
    Enumerated(u32),
    Boolean(bool),
    Null,
}

impl BacnetValue {
    /// Numeric view used by analog objects.
    pub fn as_f64(self) -> Option<f64> {
        match self {
            Self::Real(value) => Some(f64::from(value)),
            Self::Double(value) => Some(value),
            Self::Unsigned(value) => Some(value as f64),
            Self::Signed(value) => Some(value as f64),
            Self::Enumerated(value) => Some(f64::from(value)),
            Self::Boolean(value) => Some(if value { 1.0 } else { 0.0 }),
            Self::Null => None,
        }
    }

    /// Boolean view used by binary objects (BACnet binary-present-value).
    pub fn as_bool(self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(value),
            Self::Enumerated(value) => Some(value != 0),
            Self::Unsigned(value) => Some(value != 0),
            Self::Real(value) => Some(value != 0.0),
            Self::Double(value) => Some(value != 0.0),
            Self::Signed(value) => Some(value != 0),
            Self::Null => None,
        }
    }

    /// Converts to a fixed-point value at `exponent` in `unit`.
    ///
    /// Returns `None` when the value is null, non-finite, or does not fit in
    /// `i64` after scaling.
    pub fn to_fixed_point(self, unit: UnitId, exponent: i8) -> Option<FixedPointValue> {
        let value = self.as_f64()?;
        if !value.is_finite() {
            return None;
        }
        let factor = 10f64.powi(-i32::from(exponent));
        let scaled = (value * factor).round();
        if scaled < i64::MIN as f64 || scaled > i64::MAX as f64 {
            return None;
        }
        Some(FixedPointValue::new(scaled as i64, exponent, unit))
    }
}

/// I-Am discovery response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IAm {
    pub device: ObjectIdentifier,
    pub max_apdu: u16,
    pub segmentation: u8,
    pub vendor_id: u16,
}

impl IAm {
    /// Builds an I-Am for a device instance.
    pub fn new(device_instance: u32, max_apdu: u16, segmentation: u8, vendor_id: u16) -> Self {
        Self {
            // Device instances are validated by the caller-facing encoders.
            device: ObjectIdentifier {
                object_type: ObjectType::Device,
                instance: device_instance & MAX_OBJECT_INSTANCE,
            },
            max_apdu,
            segmentation,
            vendor_id,
        }
    }
}

/// A decoded confirmed ReadProperty request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadPropertyRequest {
    pub invoke_id: u8,
    pub object: ObjectIdentifier,
    pub property: PropertyId,
}

/// A parsed BACnet message from a BVLC frame.
#[derive(Debug, Clone, PartialEq)]
pub enum BacnetMessage {
    WhoIs {
        low: u32,
        high: u32,
    },
    IAm(IAm),
    ReadProperty(ReadPropertyRequest),
    ReadPropertyAck {
        invoke_id: u8,
        value: BacnetValue,
    },
    SimpleAck {
        invoke_id: u8,
        service: u8,
    },
    Error {
        invoke_id: u8,
        service: u8,
        error_class: u32,
        error_code: u32,
    },
    Reject {
        invoke_id: u8,
        reason: u8,
    },
    Abort {
        invoke_id: u8,
        reason: u8,
    },
}

/// BVLC-level view of a datagram, with the APDU exposed for transports and
/// simulators. `npdu_control` is the NPDU control octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BvlcApdu<'a> {
    pub function: u8,
    pub npdu_control: u8,
    pub apdu: &'a [u8],
}

/// Typed BACnet codec error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BacnetError {
    /// A write was attempted. This MVP is read-only and never emits writes.
    WriteRejected {
        object: ObjectIdentifier,
        property: PropertyId,
    },
    InvalidFrame(String),
    ApduTooLarge {
        len: usize,
        max: usize,
    },
    UnsupportedObjectType(u16),
    InvalidObjectInstance(u32),
    UnsupportedService(u8),
    UnsupportedPdu(u8),
    UnsupportedValueType(u8),
    NetworkLayerMessage,
    NetworkLayerDestination,
    Reject {
        invoke_id: u8,
        reason: u8,
    },
    Abort {
        invoke_id: u8,
        reason: u8,
    },
    ErrorPdu {
        invoke_id: u8,
        error_class: u32,
        error_code: u32,
    },
    Timeout {
        operation: &'static str,
        limit_ms: u64,
    },
    DiscoveryLimit {
        max: usize,
    },
    /// Transport-level failure. The pure codec never constructs this variant.
    Transport(String),
    /// Requested property is not present on the object.
    PropertyNotPresent {
        object: ObjectIdentifier,
        property: PropertyId,
    },
}

impl fmt::Display for BacnetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriteRejected { object, property } => write!(
                f,
                "BACnet write rejected (read-only MVP): object {object}, property {property}"
            ),
            Self::InvalidFrame(message) => write!(f, "invalid BACnet frame: {message}"),
            Self::ApduTooLarge { len, max } => {
                write!(f, "BACnet frame too large: {len} bytes exceeds {max}")
            }
            Self::UnsupportedObjectType(code) => {
                write!(f, "unsupported BACnet object type {code}")
            }
            Self::InvalidObjectInstance(instance) => {
                write!(f, "invalid BACnet object instance {instance}")
            }
            Self::UnsupportedService(service) => {
                write!(f, "unsupported BACnet service 0x{service:02x}")
            }
            Self::UnsupportedPdu(pdu) => write!(f, "unsupported BACnet PDU type 0x{pdu:02x}"),
            Self::UnsupportedValueType(tag) => {
                write!(f, "unsupported BACnet application tag 0x{tag:02x}")
            }
            Self::NetworkLayerMessage => {
                write!(f, "BACnet network-layer messages are not supported")
            }
            Self::NetworkLayerDestination => {
                write!(
                    f,
                    "BACnet routed destination is not supported by the read bridge"
                )
            }
            Self::Reject { invoke_id, reason } => {
                write!(f, "BACnet reject: invoke {invoke_id}, reason {reason}")
            }
            Self::Abort { invoke_id, reason } => {
                write!(f, "BACnet abort: invoke {invoke_id}, reason {reason}")
            }
            Self::ErrorPdu {
                invoke_id,
                error_class,
                error_code,
            } => write!(
                f,
                "BACnet error: invoke {invoke_id}, class {error_class}, code {error_code}"
            ),
            Self::Timeout {
                operation,
                limit_ms,
            } => write!(f, "BACnet {operation} exceeded {limit_ms} ms timeout"),
            Self::DiscoveryLimit { max } => {
                write!(f, "BACnet discovery device limit must be 1..={max}")
            }
            Self::Transport(message) => write!(f, "BACnet transport error: {message}"),
            Self::PropertyNotPresent { object, property } => {
                write!(f, "object {object} has no property {property}")
            }
        }
    }
}

impl std::error::Error for BacnetError {}

impl From<BacnetError> for crate::driver_trait::DriverError {
    fn from(error: BacnetError) -> Self {
        use crate::driver_trait::DriverError;
        match error {
            BacnetError::WriteRejected { object, property } => DriverError::UnsupportedParam(
                format!("BACnet write rejected (read-only MVP): {object} property {property}"),
            ),
            BacnetError::Timeout {
                operation,
                limit_ms,
            } => DriverError::Timeout(crate::driver_trait::TimeoutError {
                operation,
                limit_ms,
            }),
            BacnetError::UnsupportedObjectType(_)
            | BacnetError::UnsupportedService(_)
            | BacnetError::PropertyNotPresent { .. } => {
                DriverError::UnsupportedParam(error.to_string())
            }
            BacnetError::InvalidFrame(_)
            | BacnetError::ApduTooLarge { .. }
            | BacnetError::InvalidObjectInstance(_)
            | BacnetError::UnsupportedPdu(_)
            | BacnetError::UnsupportedValueType(_)
            | BacnetError::NetworkLayerMessage
            | BacnetError::NetworkLayerDestination
            | BacnetError::DiscoveryLimit { .. } => DriverError::Codec(error.to_string()),
            BacnetError::Reject { reason, .. } => DriverError::Exception {
                function_code: 0x0C,
                exception_code: reason,
            },
            BacnetError::Abort { reason, .. } => DriverError::Exception {
                function_code: 0x0C,
                exception_code: reason,
            },
            BacnetError::ErrorPdu { error_class, .. } => DriverError::Exception {
                function_code: 0x0C,
                exception_code: error_class as u8,
            },
            BacnetError::Transport(_) => DriverError::Codec(error.to_string()),
        }
    }
}

/// Result alias for codec and transport operations.
pub type BacnetResult<T> = Result<T, BacnetError>;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encodes a global-broadcast Who-Is (DNET 0xFFFF, no DADR).
pub fn encode_who_is() -> Vec<u8> {
    // No instance limits means "all devices" (0..=4_194_303).
    let apdu = [PDU_UNCONFIRMED_REQUEST, SERVICE_WHO_IS];
    // Destination specifier present (0x20), global broadcast, hop count 0xFF.
    let npdu = [0x01, NPDU_DESTINATION_SPECIFIER, 0xFF, 0xFF, 0x00, 0xFF];
    encode_bvlc(BVLC_ORIGINAL_BROADCAST, &npdu, &apdu)
}

/// Encodes a directed (unicast) Who-Is. Used for bounded, address-specific
/// discovery; no broadcast is emitted.
pub fn encode_who_is_unicast() -> Vec<u8> {
    // The range is statically valid, so the encoder cannot fail.
    encode_who_is_range_unicast(0, MAX_OBJECT_INSTANCE).expect("global Who-Is range is valid")
}

/// Encodes a directed Who-Is limited to an inclusive device-instance range.
pub fn encode_who_is_range(low: u32, high: u32) -> BacnetResult<Vec<u8>> {
    let apdu = who_is_range_apdu(low, high)?;
    let npdu = [0x01, NPDU_DESTINATION_SPECIFIER, 0xFF, 0xFF, 0x00, 0xFF];
    Ok(encode_bvlc(BVLC_ORIGINAL_BROADCAST, &npdu, &apdu))
}

/// Encodes a directed, unicast Who-Is limited to an inclusive instance range.
pub fn encode_who_is_range_unicast(low: u32, high: u32) -> BacnetResult<Vec<u8>> {
    let apdu = who_is_range_apdu(low, high)?;
    Ok(encode_bvlc(BVLC_ORIGINAL_UNICAST, &[0x01, 0x00], &apdu))
}

fn who_is_range_apdu(low: u32, high: u32) -> BacnetResult<Vec<u8>> {
    if low > high || high > MAX_OBJECT_INSTANCE {
        return Err(BacnetError::InvalidFrame(format!(
            "invalid Who-Is range {low}..={high}"
        )));
    }
    let mut apdu = vec![PDU_UNCONFIRMED_REQUEST, SERVICE_WHO_IS];
    apdu.extend_from_slice(&encode_unsigned_24(low));
    apdu.extend_from_slice(&encode_unsigned_24(high));
    Ok(apdu)
}

/// Encodes a unicast I-Am response.
pub fn encode_i_am(i_am: &IAm) -> BacnetResult<Vec<u8>> {
    if i_am.device.object_type != ObjectType::Device {
        return Err(BacnetError::InvalidFrame(
            "I-Am object must be a device".into(),
        ));
    }
    let mut apdu = vec![PDU_UNCONFIRMED_REQUEST, SERVICE_I_AM];
    apdu.extend_from_slice(&encode_application_object_id(i_am.device));
    apdu.extend_from_slice(&encode_application_unsigned(u64::from(i_am.max_apdu)));
    apdu.extend_from_slice(&encode_application_enumerated(u32::from(i_am.segmentation)));
    apdu.extend_from_slice(&encode_application_unsigned(u64::from(i_am.vendor_id)));
    Ok(encode_bvlc(BVLC_ORIGINAL_UNICAST, &[0x01, 0x00], &apdu))
}

/// Encodes a confirmed ReadProperty request.
pub fn encode_read_property(
    invoke_id: u8,
    object: ObjectIdentifier,
    property: PropertyId,
) -> BacnetResult<Vec<u8>> {
    if !object.object_type.is_readable() {
        return Err(BacnetError::UnsupportedObjectType(
            object.object_type.code(),
        ));
    }
    let apdu = read_property_apdu(invoke_id, object, property);
    if apdu.len() > MAX_APDU_LENGTH {
        return Err(BacnetError::ApduTooLarge {
            len: apdu.len(),
            max: MAX_APDU_LENGTH,
        });
    }
    Ok(encode_bvlc(BVLC_ORIGINAL_UNICAST, &[0x01, 0x04], &apdu))
}

fn read_property_apdu(invoke_id: u8, object: ObjectIdentifier, property: PropertyId) -> Vec<u8> {
    let mut apdu = vec![PDU_CONFIRMED_REQUEST, invoke_id, SERVICE_READ_PROPERTY];
    apdu.extend_from_slice(&encode_context_object_id(0, object));
    apdu.extend_from_slice(&encode_context_unsigned(1, property.as_u32()));
    apdu
}

/// Encodes a ReadProperty-ACK carrying a present value.
pub fn encode_read_property_ack(invoke_id: u8, value: &BacnetValue) -> Vec<u8> {
    let mut apdu = vec![PDU_COMPLEX_ACK, invoke_id, SERVICE_READ_PROPERTY];
    apdu.push(0x3E); // context tag 3, opening
    apdu.extend_from_slice(&encode_application_value(value));
    apdu.push(0x3F); // context tag 3, closing
    encode_bvlc(BVLC_ORIGINAL_UNICAST, &[0x01, 0x00], &apdu)
}

/// Encodes a BACnet Error PDU.
pub fn encode_error_pdu(invoke_id: u8, service: u8, error_class: u32, error_code: u32) -> Vec<u8> {
    let mut apdu = vec![PDU_ERROR, invoke_id, service];
    apdu.extend_from_slice(&encode_application_enumerated(error_class));
    apdu.extend_from_slice(&encode_application_enumerated(error_code));
    encode_bvlc(BVLC_ORIGINAL_UNICAST, &[0x01, 0x00], &apdu)
}

/// Encodes a BACnet Reject PDU.
pub fn encode_reject(invoke_id: u8, reason: u8) -> Vec<u8> {
    encode_bvlc(
        BVLC_ORIGINAL_UNICAST,
        &[0x01, 0x00],
        &[PDU_REJECT, invoke_id, reason],
    )
}

/// Read-only MVP: WriteProperty is rejected before a frame is produced.
///
/// Always returns [`BacnetError::WriteRejected`].
pub fn encode_write_property(
    _invoke_id: u8,
    object: ObjectIdentifier,
    property: PropertyId,
    _value: &BacnetValue,
) -> BacnetResult<Vec<u8>> {
    Err(BacnetError::WriteRejected { object, property })
}

pub(crate) fn encode_bvlc(function: u8, npdu: &[u8], apdu: &[u8]) -> Vec<u8> {
    // The BVLC length field counts the NPDU and APDU, not the BVLC header.
    let length = npdu.len() + apdu.len();
    let mut out = Vec::with_capacity(4 + length);
    out.push(BVLC_TYPE);
    out.push(function);
    out.extend_from_slice(&(length as u16).to_be_bytes());
    out.extend_from_slice(npdu);
    out.extend_from_slice(apdu);
    out
}

fn encode_unsigned_24(value: u32) -> [u8; 3] {
    [
        ((value >> 16) & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        (value & 0xFF) as u8,
    ]
}

fn minimal_unsigned(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[first..].to_vec()
}

fn minimal_signed(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut first = 0;
    while first < 7 {
        let redundant = (bytes[first] == 0x00 && bytes[first + 1] & 0x80 == 0)
            || (bytes[first] == 0xFF && bytes[first + 1] & 0x80 != 0);
        if !redundant {
            break;
        }
        first += 1;
    }
    bytes[first..].to_vec()
}

fn encode_context_object_id(tag: u8, object: ObjectIdentifier) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(0x08 | (tag << 4) | 4);
    out.extend_from_slice(&object.encode());
    out
}

fn encode_context_unsigned(tag: u8, value: u32) -> Vec<u8> {
    let bytes = minimal_unsigned(u64::from(value));
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(0x08 | (tag << 4) | bytes.len() as u8);
    out.extend_from_slice(&bytes);
    out
}

fn encode_application_object_id(object: ObjectIdentifier) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(0xC4);
    out.extend_from_slice(&object.encode());
    out
}

/// Encodes an application/context tag header, using the extended-length form
/// when the payload is longer than four octets.
fn encode_tag_header(tag: u8, len: usize, context: bool) -> Vec<u8> {
    let class = if context { 0x08 } else { 0x00 };
    if len <= 4 {
        return vec![class | (tag << 4) | len as u8];
    }
    if len <= 253 {
        return vec![class | (tag << 4) | 0x05, len as u8];
    }
    let mut header = vec![class | (tag << 4) | 0x05, 254u8];
    header.extend_from_slice(&(len as u16).to_be_bytes());
    header
}

fn encode_application_unsigned(value: u64) -> Vec<u8> {
    let bytes = minimal_unsigned(value);
    let mut out = encode_tag_header(2, bytes.len(), false);
    out.extend_from_slice(&bytes);
    out
}

fn encode_application_enumerated(value: u32) -> Vec<u8> {
    let bytes = minimal_unsigned(u64::from(value));
    let mut out = encode_tag_header(9, bytes.len(), false);
    out.extend_from_slice(&bytes);
    out
}

/// Encodes a decoded value as an application-tagged BACnet value.
pub fn encode_application_value(value: &BacnetValue) -> Vec<u8> {
    match *value {
        BacnetValue::Null => vec![0x00],
        // A BACnet boolean carries its value in the tag's LVT field.
        BacnetValue::Boolean(flag) => vec![0x10 | u8::from(flag)],
        BacnetValue::Real(number) => {
            let mut out = vec![0x44];
            out.extend_from_slice(&number.to_bits().to_be_bytes());
            out
        }
        BacnetValue::Double(number) => {
            let mut out = encode_tag_header(5, 8, false);
            out.extend_from_slice(&number.to_bits().to_be_bytes());
            out
        }
        BacnetValue::Unsigned(number) => encode_application_unsigned(number),
        BacnetValue::Signed(number) => {
            let bytes = minimal_signed(number);
            let mut out = encode_tag_header(3, bytes.len(), false);
            out.extend_from_slice(&bytes);
            out
        }
        BacnetValue::Enumerated(number) => encode_application_enumerated(number),
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Parses BVLC + NPDU and exposes the APDU. Enforces BVLC/APDU bounds.
pub fn parse_bvlc(frame: &[u8]) -> BacnetResult<BvlcApdu<'_>> {
    if frame.len() > MAX_BVLC_LENGTH {
        return Err(BacnetError::ApduTooLarge {
            len: frame.len(),
            max: MAX_BVLC_LENGTH,
        });
    }
    if frame.len() < 4 {
        return Err(BacnetError::InvalidFrame("truncated BVLC header".into()));
    }
    if frame[0] != BVLC_TYPE {
        return Err(BacnetError::InvalidFrame(format!(
            "unexpected BVLC type 0x{:02x}",
            frame[0]
        )));
    }
    let function = frame[1];
    if !matches!(function, BVLC_ORIGINAL_UNICAST | BVLC_ORIGINAL_BROADCAST) {
        return Err(BacnetError::UnsupportedService(function));
    }
    // The BVLC length field counts everything after the four-byte BVLC header.
    let declared = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    if declared + 4 != frame.len() {
        return Err(BacnetError::InvalidFrame(format!(
            "BVLC length {declared} does not match datagram length {}",
            frame.len()
        )));
    }
    if declared < 3 {
        return Err(BacnetError::InvalidFrame("BVLC frame too short".into()));
    }
    let (npdu, apdu) = parse_npdu(&frame[4..])?;
    if apdu.len() > MAX_APDU_LENGTH {
        return Err(BacnetError::ApduTooLarge {
            len: apdu.len(),
            max: MAX_APDU_LENGTH,
        });
    }
    Ok(BvlcApdu {
        function,
        npdu_control: npdu,
        apdu,
    })
}

/// Parses an NPDU and returns `(control_octet, apdu)`.
pub fn parse_npdu(npdu: &[u8]) -> BacnetResult<(u8, &[u8])> {
    if npdu.len() < 2 {
        return Err(BacnetError::InvalidFrame("truncated NPDU".into()));
    }
    if npdu[0] != NPDU_VERSION {
        return Err(BacnetError::InvalidFrame(format!(
            "unsupported NPDU version 0x{:02x}",
            npdu[0]
        )));
    }
    let control = npdu[1];
    if control & NPDU_NETWORK_LAYER_MESSAGE != 0 {
        return Err(BacnetError::NetworkLayerMessage);
    }
    let mut pos = 2;
    if control & NPDU_DESTINATION_SPECIFIER != 0 {
        if npdu.len() < pos + 3 {
            return Err(BacnetError::InvalidFrame(
                "truncated NPDU destination".into(),
            ));
        }
        let dnet = [npdu[pos], npdu[pos + 1]];
        let dlen = npdu[pos + 2] as usize;
        pos += 3;
        if npdu.len() < pos + dlen + 1 {
            return Err(BacnetError::InvalidFrame(
                "truncated NPDU destination".into(),
            ));
        }
        pos += dlen;
        let hop_count = npdu[pos];
        pos += 1;
        // A routed destination (DNET != 0xFFFF or non-zero DADR) is outside
        // the read bridge's scope. Global broadcast frames carry no DADR.
        if dnet != [0xFF, 0xFF] || dlen != 0 {
            return Err(BacnetError::NetworkLayerDestination);
        }
        let _ = hop_count;
    }
    if control & NPDU_SOURCE_SPECIFIER != 0 {
        if npdu.len() < pos + 3 {
            return Err(BacnetError::InvalidFrame("truncated NPDU source".into()));
        }
        let slen = npdu[pos + 2] as usize;
        pos += 3;
        if npdu.len() < pos + slen {
            return Err(BacnetError::InvalidFrame("truncated NPDU source".into()));
        }
        pos += slen;
    }
    if pos > npdu.len() {
        return Err(BacnetError::InvalidFrame("truncated NPDU".into()));
    }
    Ok((control, &npdu[pos..]))
}

/// Parses a complete BVLC frame into a typed message.
pub fn parse_message(frame: &[u8]) -> BacnetResult<BacnetMessage> {
    let bvlc = parse_bvlc(frame)?;
    parse_apdu(bvlc.apdu)
}

/// Parses an APDU into a typed message.
pub fn parse_apdu(apdu: &[u8]) -> BacnetResult<BacnetMessage> {
    if apdu.len() > MAX_APDU_LENGTH {
        return Err(BacnetError::ApduTooLarge {
            len: apdu.len(),
            max: MAX_APDU_LENGTH,
        });
    }
    let Some(&header) = apdu.first() else {
        return Err(BacnetError::InvalidFrame("empty APDU".into()));
    };
    match header & 0xF0 {
        PDU_UNCONFIRMED_REQUEST => parse_unconfirmed(apdu),
        PDU_CONFIRMED_REQUEST => parse_confirmed(apdu),
        PDU_COMPLEX_ACK => parse_complex_ack(apdu),
        PDU_SIMPLE_ACK => {
            if apdu.len() < 3 {
                return Err(BacnetError::InvalidFrame("truncated SimpleACK".into()));
            }
            Ok(BacnetMessage::SimpleAck {
                invoke_id: apdu[1],
                service: apdu[2],
            })
        }
        PDU_ERROR => parse_error_pdu(apdu),
        PDU_REJECT => {
            if apdu.len() < 3 {
                return Err(BacnetError::InvalidFrame("truncated Reject".into()));
            }
            Ok(BacnetMessage::Reject {
                invoke_id: apdu[1],
                reason: apdu[2],
            })
        }
        PDU_ABORT => {
            if apdu.len() < 3 {
                return Err(BacnetError::InvalidFrame("truncated Abort".into()));
            }
            Ok(BacnetMessage::Abort {
                invoke_id: apdu[1],
                reason: apdu[2],
            })
        }
        other => Err(BacnetError::UnsupportedPdu(other)),
    }
}

fn parse_unconfirmed(apdu: &[u8]) -> BacnetResult<BacnetMessage> {
    if apdu.len() < 2 {
        return Err(BacnetError::InvalidFrame(
            "truncated Unconfirmed-Request".into(),
        ));
    }
    match apdu[1] {
        SERVICE_I_AM => parse_i_am(apdu),
        SERVICE_WHO_IS => parse_who_is(apdu),
        service => Err(BacnetError::UnsupportedService(service)),
    }
}

fn parse_who_is(apdu: &[u8]) -> BacnetResult<BacnetMessage> {
    let body = &apdu[2..];
    if body.is_empty() {
        return Ok(BacnetMessage::WhoIs {
            low: 0,
            high: MAX_OBJECT_INSTANCE,
        });
    }
    if body.len() != 6 {
        return Err(BacnetError::InvalidFrame("invalid Who-Is body".into()));
    }
    let low = decode_unsigned_24(&body[0..3]);
    let high = decode_unsigned_24(&body[3..6]);
    if low > high || high > MAX_OBJECT_INSTANCE {
        return Err(BacnetError::InvalidFrame("invalid Who-Is range".into()));
    }
    Ok(BacnetMessage::WhoIs { low, high })
}

fn parse_i_am(apdu: &[u8]) -> BacnetResult<BacnetMessage> {
    let mut pos = 2;
    let (tag, len, offset) = read_application_tag(apdu, pos)?;
    if tag != 12 || len != 4 {
        return Err(BacnetError::InvalidFrame(
            "I-Am must start with an object identifier".into(),
        ));
    }
    pos = offset + len;
    let device = ObjectIdentifier::decode(&apdu[offset..end_of(apdu, offset, len)?])?;
    if device.object_type != ObjectType::Device {
        return Err(BacnetError::InvalidFrame(
            "I-Am object is not a device".into(),
        ));
    }
    let max_apdu = decode_application_unsigned(apdu, &mut pos)?;
    let segmentation = decode_application_numeric(apdu, &mut pos)?;
    let vendor_id = decode_application_unsigned(apdu, &mut pos)?;
    if pos != apdu.len() {
        return Err(BacnetError::InvalidFrame("trailing I-Am bytes".into()));
    }
    Ok(BacnetMessage::IAm(IAm {
        device,
        max_apdu: u16::try_from(max_apdu)
            .map_err(|_| BacnetError::InvalidFrame("I-Am max APDU overflow".into()))?,
        segmentation: u8::try_from(segmentation)
            .map_err(|_| BacnetError::InvalidFrame("I-Am segmentation overflow".into()))?,
        vendor_id: u16::try_from(vendor_id)
            .map_err(|_| BacnetError::InvalidFrame("I-Am vendor id overflow".into()))?,
    }))
}

fn parse_confirmed(apdu: &[u8]) -> BacnetResult<BacnetMessage> {
    if apdu.len() < 3 {
        return Err(BacnetError::InvalidFrame(
            "truncated Confirmed-Request".into(),
        ));
    }
    // Segmented confirmed requests are not supported by the read bridge.
    if apdu[0] & 0x08 != 0 {
        return Err(BacnetError::InvalidFrame(
            "segmented BACnet requests are not supported".into(),
        ));
    }
    let service = apdu[2];
    match service {
        SERVICE_READ_PROPERTY => Ok(BacnetMessage::ReadProperty(decode_read_property_apdu(
            apdu,
        )?)),
        service => Err(BacnetError::UnsupportedService(service)),
    }
}

/// Decodes a Confirmed-Request ReadProperty APDU.
pub fn decode_read_property_apdu(apdu: &[u8]) -> BacnetResult<ReadPropertyRequest> {
    if apdu.len() < 3 || apdu[0] & 0xF0 != PDU_CONFIRMED_REQUEST {
        return Err(BacnetError::InvalidFrame("not a Confirmed-Request".into()));
    }
    if apdu[2] != SERVICE_READ_PROPERTY {
        return Err(BacnetError::UnsupportedService(apdu[2]));
    }
    let invoke_id = apdu[1];
    let (tag, len, offset) = read_context_tag(apdu, 3)?;
    if tag != 0 || len != 4 {
        return Err(BacnetError::InvalidFrame(
            "ReadProperty must start with object identifier tag 0".into(),
        ));
    }
    let object = ObjectIdentifier::decode(&apdu[offset..offset + 4])?;
    let mut pos = offset + len;
    let (tag, len, offset) = read_context_tag(apdu, pos)?;
    if tag != 1 || len == 0 || len > 4 {
        return Err(BacnetError::InvalidFrame(
            "ReadProperty property identifier must be context tag 1".into(),
        ));
    }
    pos = offset + len;
    let property = PropertyId(decode_unsigned_be(&apdu[offset..pos]) as u32);
    if pos != apdu.len() {
        return Err(BacnetError::InvalidFrame(
            "trailing ReadProperty bytes".into(),
        ));
    }
    Ok(ReadPropertyRequest {
        invoke_id,
        object,
        property,
    })
}

fn parse_complex_ack(apdu: &[u8]) -> BacnetResult<BacnetMessage> {
    if apdu.len() < 3 {
        return Err(BacnetError::InvalidFrame("truncated ComplexACK".into()));
    }
    let invoke_id = apdu[1];
    let service = apdu[2];
    if service != SERVICE_READ_PROPERTY {
        return Err(BacnetError::UnsupportedService(service));
    }
    let mut pos = 3;
    if apdu.get(pos).copied() != Some(0x3E) {
        return Err(BacnetError::InvalidFrame(
            "ReadProperty-ACK missing opening tag 3".into(),
        ));
    }
    pos += 1;
    let (value, next) = decode_application_value(apdu, pos)?;
    pos = next;
    if apdu.get(pos).copied() != Some(0x3F) {
        return Err(BacnetError::InvalidFrame(
            "ReadProperty-ACK missing closing tag 3".into(),
        ));
    }
    pos += 1;
    if pos != apdu.len() {
        return Err(BacnetError::InvalidFrame(
            "trailing ReadProperty-ACK bytes".into(),
        ));
    }
    Ok(BacnetMessage::ReadPropertyAck { invoke_id, value })
}

fn parse_error_pdu(apdu: &[u8]) -> BacnetResult<BacnetMessage> {
    if apdu.len() < 5 {
        return Err(BacnetError::InvalidFrame("truncated Error PDU".into()));
    }
    let invoke_id = apdu[1];
    let service = apdu[2];
    let (error_class, next) = decode_application_value(apdu, 3)?;
    let (error_code, next) = decode_application_value(apdu, next)?;
    if next != apdu.len() {
        return Err(BacnetError::InvalidFrame("trailing Error PDU bytes".into()));
    }
    let class = match error_class {
        BacnetValue::Enumerated(value) => value,
        BacnetValue::Unsigned(value) => value as u32,
        _ => {
            return Err(BacnetError::InvalidFrame(
                "Error PDU class is not enumerated".into(),
            ))
        }
    };
    let code = match error_code {
        BacnetValue::Enumerated(value) => value,
        BacnetValue::Unsigned(value) => value as u32,
        _ => {
            return Err(BacnetError::InvalidFrame(
                "Error PDU code is not enumerated".into(),
            ))
        }
    };
    Ok(BacnetMessage::Error {
        invoke_id,
        service,
        error_class: class,
        error_code: code,
    })
}

/// Decodes one application-tagged value. Returns the value and the next offset.
pub fn decode_application_value(data: &[u8], pos: usize) -> BacnetResult<(BacnetValue, usize)> {
    let header = *data
        .get(pos)
        .ok_or_else(|| BacnetError::InvalidFrame("missing application tag".into()))?;
    if header & 0x08 != 0 {
        return Err(BacnetError::InvalidFrame(
            "expected application tag, found context tag".into(),
        ));
    }
    // Boolean is the one application tag whose LVT field is the value.
    if header >> 4 == 1 {
        return match header & 0x07 {
            0 => Ok((BacnetValue::Boolean(false), pos + 1)),
            1 => Ok((BacnetValue::Boolean(true), pos + 1)),
            _ => Err(BacnetError::InvalidFrame(
                "boolean tag must carry one bit".into(),
            )),
        };
    }
    let (tag, len, offset) = read_application_tag(data, pos)?;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| BacnetError::InvalidFrame("application value overflow".into()))?;
    if end > data.len() {
        return Err(BacnetError::InvalidFrame(
            "truncated application value".into(),
        ));
    }
    let body = &data[offset..end];
    let value = match tag {
        0 => {
            if len != 0 {
                return Err(BacnetError::InvalidFrame("null tag has a length".into()));
            }
            BacnetValue::Null
        }
        2 => {
            if body.is_empty() || body.len() > 8 {
                return Err(BacnetError::InvalidFrame(
                    "unsigned value must be 1..=8 bytes".into(),
                ));
            }
            BacnetValue::Unsigned(decode_unsigned_be(body))
        }
        3 => {
            if body.is_empty() || body.len() > 8 {
                return Err(BacnetError::InvalidFrame(
                    "signed value must be 1..=8 bytes".into(),
                ));
            }
            let mut raw: u64 = 0;
            for byte in body {
                raw = (raw << 8) | u64::from(*byte);
            }
            let shift = 64 - 8 * body.len();
            BacnetValue::Signed(((raw << shift) as i64) >> shift)
        }
        4 => {
            if len != 4 {
                return Err(BacnetError::InvalidFrame("real must be four bytes".into()));
            }
            BacnetValue::Real(f32::from_bits(u32::from_be_bytes([
                body[0], body[1], body[2], body[3],
            ])))
        }
        5 => {
            if len != 8 {
                return Err(BacnetError::InvalidFrame(
                    "double must be eight bytes".into(),
                ));
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(body);
            BacnetValue::Double(f64::from_bits(u64::from_be_bytes(bytes)))
        }
        9 => {
            if body.is_empty() || body.len() > 4 {
                return Err(BacnetError::InvalidFrame(
                    "enumerated value must be 1..=4 bytes".into(),
                ));
            }
            let raw = decode_unsigned_be(body);
            BacnetValue::Enumerated(raw as u32)
        }
        12 => {
            if len != 4 {
                return Err(BacnetError::InvalidFrame(
                    "object identifier must be four bytes".into(),
                ));
            }
            // Object identifiers are only consumed by structural messages.
            return Err(BacnetError::UnsupportedValueType(tag));
        }
        other => return Err(BacnetError::UnsupportedValueType(other)),
    };
    Ok((value, end))
}

fn decode_application_unsigned(data: &[u8], pos: &mut usize) -> BacnetResult<u64> {
    let (value, next) = decode_application_value(data, *pos)?;
    match value {
        BacnetValue::Unsigned(raw) => {
            *pos = next;
            Ok(raw)
        }
        _ => Err(BacnetError::InvalidFrame(
            "expected application-tagged unsigned value".into(),
        )),
    }
}

fn decode_application_numeric(data: &[u8], pos: &mut usize) -> BacnetResult<u32> {
    let (value, next) = decode_application_value(data, *pos)?;
    match value {
        BacnetValue::Enumerated(raw) => {
            *pos = next;
            Ok(raw)
        }
        BacnetValue::Unsigned(raw) => {
            *pos = next;
            Ok(raw as u32)
        }
        _ => Err(BacnetError::InvalidFrame(
            "expected application-tagged enumerated value".into(),
        )),
    }
}

/// Reads an application tag header, returning `(tag, length, body_offset)`.
fn read_application_tag(data: &[u8], pos: usize) -> BacnetResult<(u8, usize, usize)> {
    let header = *data
        .get(pos)
        .ok_or_else(|| BacnetError::InvalidFrame("missing application tag".into()))?;
    if header & 0x08 != 0 {
        return Err(BacnetError::InvalidFrame(
            "expected application tag, found context tag".into(),
        ));
    }
    let tag = header >> 4;
    read_tag_length(data, pos, header & 0x07).map(|(len, offset)| (tag, len, offset))
}

/// Reads a context tag header, returning `(tag, length, body_offset)`.
fn read_context_tag(data: &[u8], pos: usize) -> BacnetResult<(u8, usize, usize)> {
    let header = *data
        .get(pos)
        .ok_or_else(|| BacnetError::InvalidFrame("missing context tag".into()))?;
    if header & 0x08 == 0 {
        return Err(BacnetError::InvalidFrame(
            "expected context tag, found application tag".into(),
        ));
    }
    let tag = header >> 4;
    read_tag_length(data, pos, header & 0x07).map(|(len, offset)| (tag, len, offset))
}

fn read_tag_length(data: &[u8], pos: usize, lvt: u8) -> BacnetResult<(usize, usize)> {
    match lvt {
        0..=4 => Ok((usize::from(lvt), pos + 1)),
        5 => {
            // Extended length: 1, 3, or 5 bytes (254/255 markers).
            let first = *data
                .get(pos + 1)
                .ok_or_else(|| BacnetError::InvalidFrame("truncated extended tag length".into()))?;
            match first {
                0..=253 => Ok((usize::from(first), pos + 2)),
                254 => {
                    if data.len() < pos + 4 {
                        return Err(BacnetError::InvalidFrame(
                            "truncated extended tag length".into(),
                        ));
                    }
                    Ok((
                        u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize,
                        pos + 4,
                    ))
                }
                255 => Err(BacnetError::InvalidFrame(
                    "tag lengths above 65535 are not supported".into(),
                )),
            }
        }
        _ => Err(BacnetError::InvalidFrame(
            "opening/closing tag where a value was expected".into(),
        )),
    }
}

fn end_of(data: &[u8], offset: usize, len: usize) -> BacnetResult<usize> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| BacnetError::InvalidFrame("value offset overflow".into()))?;
    if end > data.len() {
        return Err(BacnetError::InvalidFrame("truncated value".into()));
    }
    Ok(end)
}

fn decode_unsigned_24(bytes: &[u8]) -> u32 {
    (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2])
}

fn decode_unsigned_be(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHO_IS_GLOBAL: &[u8] = &[
        0x81, 0x0B, 0x00, 0x08, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08,
    ];

    fn analog_input(instance: u32) -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::AnalogInput, instance).unwrap()
    }

    #[test]
    fn recorded_who_is_decodes_and_round_trips() {
        let message = parse_message(WHO_IS_GLOBAL).unwrap();
        assert_eq!(
            message,
            BacnetMessage::WhoIs {
                low: 0,
                high: MAX_OBJECT_INSTANCE
            }
        );
        assert_eq!(encode_who_is(), WHO_IS_GLOBAL);
    }

    #[test]
    fn i_am_round_trips() {
        let i_am = IAm::new(1001, 480, 0, 0x0021);
        let frame = encode_i_am(&i_am).unwrap();
        assert!(frame.len() <= MAX_BVLC_LENGTH);
        assert_eq!(parse_message(&frame).unwrap(), BacnetMessage::IAm(i_am));
    }

    #[test]
    fn read_property_request_round_trips() {
        let frame = encode_read_property(7, analog_input(3), PropertyId::PRESENT_VALUE).unwrap();
        let message = parse_message(&frame).unwrap();
        assert_eq!(
            message,
            BacnetMessage::ReadProperty(ReadPropertyRequest {
                invoke_id: 7,
                object: analog_input(3),
                property: PropertyId::PRESENT_VALUE,
            })
        );
        // Recorded APDU bytes: Confirmed-Request, invoke 7, RP, obj id, prop 85.
        assert_eq!(
            &frame[6..],
            &[0x00, 0x07, 0x0C, 0x0C, 0x00, 0x00, 0x00, 0x03, 0x19, 0x55]
        );
    }

    #[test]
    fn analog_ack_round_trips_to_fixed_point() {
        let frame = encode_read_property_ack(9, &BacnetValue::Real(21.5));
        let message = parse_message(&frame).unwrap();
        let BacnetMessage::ReadPropertyAck { invoke_id, value } = message else {
            panic!("unexpected message: {message:?}");
        };
        assert_eq!(invoke_id, 9);
        assert_eq!(value, BacnetValue::Real(21.5));
        assert_eq!(
            value.to_fixed_point(tirbase_types::UNIT_DEG_C, -1),
            Some(FixedPointValue::new(215, -1, tirbase_types::UNIT_DEG_C))
        );
    }

    #[test]
    fn binary_ack_decodes_enumerated_and_boolean() {
        for (value, expected) in [
            (BacnetValue::Enumerated(1), true),
            (BacnetValue::Enumerated(0), false),
            (BacnetValue::Boolean(true), true),
        ] {
            let frame = encode_read_property_ack(1, &value);
            let BacnetMessage::ReadPropertyAck { value, .. } = parse_message(&frame).unwrap()
            else {
                panic!("expected ack");
            };
            assert_eq!(value.as_bool(), Some(expected));
        }
    }

    #[test]
    fn error_and_reject_pdus_are_typed() {
        let error = encode_error_pdu(4, SERVICE_READ_PROPERTY, 2, 32);
        assert_eq!(
            parse_message(&error).unwrap(),
            BacnetMessage::Error {
                invoke_id: 4,
                service: SERVICE_READ_PROPERTY,
                error_class: 2,
                error_code: 32,
            }
        );
        let reject = encode_reject(5, 9);
        assert_eq!(
            parse_message(&reject).unwrap(),
            BacnetMessage::Reject {
                invoke_id: 5,
                reason: 9
            }
        );
    }

    #[test]
    fn write_encoding_is_rejected_with_a_typed_error() {
        let error = encode_write_property(
            1,
            analog_input(0),
            PropertyId::PRESENT_VALUE,
            &BacnetValue::Real(1.0),
        )
        .unwrap_err();
        assert!(matches!(error, BacnetError::WriteRejected { .. }));
        assert!(error.to_string().contains("read-only MVP"));
    }

    #[test]
    fn oversized_frames_are_rejected() {
        let oversized = vec![0x81; MAX_BVLC_LENGTH + 1];
        assert!(matches!(
            parse_bvlc(&oversized),
            Err(BacnetError::ApduTooLarge { .. })
        ));
        let long_apdu = vec![0u8; MAX_APDU_LENGTH + 1];
        assert!(matches!(
            parse_apdu(&long_apdu),
            Err(BacnetError::ApduTooLarge { .. })
        ));
    }

    #[test]
    fn malformed_frames_are_errors_not_panics() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x81],
            &[0x81, 0x0A, 0x00],
            &[0x82, 0x0A, 0x00, 0x04, 0x01, 0x00],
            &[0x81, 0x0A, 0x00, 0x04, 0x01, 0x00],
            &[0x81, 0x0A, 0xFF, 0xFF, 0x01, 0x00],
            &[0x81, 0x0B, 0x00, 0x06, 0x01, 0x80],
            &[0x81, 0x0B, 0x00, 0x07, 0x01, 0x00, 0x10],
            &[0x81, 0x0B, 0x00, 0x08, 0x01, 0x00, 0x10, 0x00],
        ];
        for case in cases {
            let _ = parse_message(case);
        }
    }

    /// Deterministic property test: every application value survives an
    /// encode/decode round trip, and arbitrary parser input never panics.
    #[test]
    fn application_values_round_trip_and_parser_is_total() {
        let values = [
            BacnetValue::Null,
            BacnetValue::Boolean(false),
            BacnetValue::Boolean(true),
            BacnetValue::Unsigned(0),
            BacnetValue::Unsigned(255),
            BacnetValue::Unsigned(u64::MAX),
            BacnetValue::Signed(-1),
            BacnetValue::Signed(0),
            BacnetValue::Signed(i64::MIN),
            BacnetValue::Signed(i64::MAX),
            BacnetValue::Enumerated(0),
            BacnetValue::Enumerated(u32::MAX),
            BacnetValue::Real(21.5),
            BacnetValue::Real(-0.0),
            BacnetValue::Double(1.0e-9),
        ];
        for value in values {
            let encoded = encode_application_value(&value);
            let (decoded, next) = decode_application_value(&encoded, 0).unwrap();
            assert_eq!(next, encoded.len(), "{value:?}");
            assert_eq!(decoded, value, "{value:?}");
        }

        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..2_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state as usize) % 64;
            let mut bytes = Vec::with_capacity(len);
            let mut cursor = state;
            for _ in 0..len {
                cursor = cursor
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                bytes.push((cursor >> 33) as u8);
            }
            let _ = parse_message(&bytes);
        }
    }

    #[test]
    fn segmented_requests_and_routed_npdus_are_rejected() {
        // Confirmed-Request with the segmented bit set.
        let mut frame =
            encode_read_property(1, analog_input(0), PropertyId::PRESENT_VALUE).unwrap();
        frame[6] |= 0x08;
        assert!(matches!(
            parse_message(&frame),
            Err(BacnetError::InvalidFrame(_))
        ));

        // Destination specifier with a non-global DNET.
        let apdu = [0x10, 0x08];
        let npdu = [0x01, 0x20, 0x00, 0x05, 0x00, 0xFF];
        let routed = encode_bvlc(BVLC_ORIGINAL_UNICAST, &npdu, &apdu);
        assert!(matches!(
            parse_message(&routed),
            Err(BacnetError::NetworkLayerDestination)
        ));
    }

    #[test]
    fn instance_and_object_type_bounds() {
        assert!(ObjectIdentifier::new(ObjectType::AnalogInput, MAX_OBJECT_INSTANCE).is_ok());
        assert!(matches!(
            ObjectIdentifier::new(ObjectType::AnalogInput, MAX_OBJECT_INSTANCE + 1),
            Err(BacnetError::InvalidObjectInstance(_))
        ));
        assert!(matches!(
            ObjectType::from_code(42),
            Err(BacnetError::UnsupportedObjectType(42))
        ));
        let id = ObjectIdentifier::new(ObjectType::BinaryValue, 7).unwrap();
        assert_eq!(ObjectIdentifier::decode(&id.encode()).unwrap(), id);

        assert!(matches!(
            encode_who_is_range(10, 5),
            Err(BacnetError::InvalidFrame(_))
        ));
        assert!(matches!(
            encode_who_is_range_unicast(0, MAX_OBJECT_INSTANCE + 1),
            Err(BacnetError::InvalidFrame(_))
        ));
        let ranged = encode_who_is_range_unicast(100, 200).unwrap();
        assert_eq!(
            parse_message(&ranged).unwrap(),
            BacnetMessage::WhoIs {
                low: 100,
                high: 200
            }
        );
    }
}
