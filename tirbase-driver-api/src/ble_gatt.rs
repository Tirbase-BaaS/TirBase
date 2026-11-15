// SPDX-License-Identifier: Apache-2.0

//! BLE advertisement and GATT payload parsing for the CC-06 probe (Apache-2.0).
//!
//! The module is pure: it parses raw advertising data and standard
//! temperature/humidity GATT values without I/O, async, or a clock. The
//! guard-owned probe supplies the bytes and classifies transport failures.
//!
//! The default profile is the Bluetooth SIG Environmental Sensing service
//! (`0x181A`) with the Temperature (`0x2A6E`, sint16, 0.01 °C) and Humidity
//! (`0x2A6F`, uint16, 0.01 %RH) characteristics. Callers may substitute any
//! service/characteristic UUIDs through [`BleGattUuidMap`]; the payload encoding
//! stays the SIG one.

use std::fmt;

use tirbase_types::{FixedPointValue, UNIT_DEG_C, UNIT_PERCENT};

/// Environmental Sensing service (16-bit SIG UUID `0x181A`).
pub const ENVIRONMENTAL_SENSING_SERVICE: BleUuid = BleUuid::from_u16(0x181A);
/// Temperature characteristic (16-bit SIG UUID `0x2A6E`).
pub const TEMPERATURE_CHARACTERISTIC: BleUuid = BleUuid::from_u16(0x2A6E);
/// Humidity characteristic (16-bit SIG UUID `0x2A6F`).
pub const HUMIDITY_CHARACTERISTIC: BleUuid = BleUuid::from_u16(0x2A6F);

/// Maximum advertising payload accepted from a peripheral.
pub const MAX_ADVERTISEMENT_BYTES: usize = 512;
/// Maximum service UUIDs retained from one advertisement.
pub const MAX_ADVERTISEMENT_SERVICES: usize = 16;
/// Maximum local-name length retained from one advertisement.
pub const MAX_LOCAL_NAME_BYTES: usize = 64;
/// Fixed-point exponent of the SIG temperature/humidity values.
pub const CLIMATE_EXPONENT: i8 = -2;
/// Absolute zero in hundredths of a degree Celsius.
pub const ABSOLUTE_ZERO_CENTI_CELSIUS: i16 = -27_315;
/// 100 % relative humidity in hundredths of a percent.
pub const MAX_HUMIDITY_CENTI_PERCENT: u16 = 10_000;

/// A 128-bit BLE UUID in canonical (big-endian) byte order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BleUuid([u8; 16]);

impl BleUuid {
    /// Builds a UUID from a 16-bit SIG alias (`0000xxxx-0000-1000-8000-00805f9b34fb`).
    pub const fn from_u16(short: u16) -> Self {
        let bytes = short.to_be_bytes();
        Self([
            0x00, 0x00, bytes[0], bytes[1], 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f,
            0x9b, 0x34, 0xfb,
        ])
    }

    /// Builds a UUID from its 16 canonical bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parses a canonical UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) or a
    /// 4-digit 16-bit alias.
    pub fn parse(input: &str) -> Result<Self, BleGattError> {
        let input = input.trim();
        if input.len() == 4 && !input.contains('-') {
            let short = u16::from_str_radix(input, 16)
                .map_err(|_| BleGattError::InvalidUuid(input.to_string()))?;
            return Ok(Self::from_u16(short));
        }

        let mut hex = String::with_capacity(32);
        for (index, ch) in input.chars().enumerate() {
            if matches!(index, 8 | 13 | 18 | 23) {
                if ch != '-' {
                    return Err(BleGattError::InvalidUuid(input.to_string()));
                }
                continue;
            }
            if !ch.is_ascii_hexdigit() {
                return Err(BleGattError::InvalidUuid(input.to_string()));
            }
            hex.push(ch);
        }
        if hex.len() != 32 {
            return Err(BleGattError::InvalidUuid(input.to_string()));
        }
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                .map_err(|_| BleGattError::InvalidUuid(input.to_string()))?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for BleUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
            b[14], b[15]
        )
    }
}

impl fmt::Debug for BleUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Parsed advertising data relevant to a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleAdvertisement {
    service_uuids: Vec<BleUuid>,
    local_name: Option<String>,
}

impl BleAdvertisement {
    /// Builds an advertisement from already-decoded fields (used by a radio
    /// adapter that receives structured properties instead of raw AD bytes).
    pub fn new(
        service_uuids: impl IntoIterator<Item = BleUuid>,
        local_name: Option<String>,
    ) -> Result<Self, BleGattError> {
        let mut services = Vec::new();
        for uuid in service_uuids {
            if !services.contains(&uuid) {
                services.push(uuid);
            }
        }
        if services.len() > MAX_ADVERTISEMENT_SERVICES {
            return Err(BleGattError::TooManyServiceUuids {
                max: MAX_ADVERTISEMENT_SERVICES,
            });
        }
        if let Some(name) = &local_name {
            if name.len() > MAX_LOCAL_NAME_BYTES {
                return Err(BleGattError::InvalidName);
            }
        }
        Ok(Self {
            service_uuids: services,
            local_name,
        })
    }

    /// Service UUIDs in advertisement order.
    pub fn service_uuids(&self) -> &[BleUuid] {
        &self.service_uuids
    }

    /// Advertised local name, when present.
    pub fn local_name(&self) -> Option<&str> {
        self.local_name.as_deref()
    }

    /// Whether the advertisement carries `uuid`.
    pub fn has_service(&self, uuid: BleUuid) -> bool {
        self.service_uuids.contains(&uuid)
    }
}

/// Parses BLE advertising data (length/type/value structures).
///
/// Malformed lengths, truncated records, invalid UUID list lengths, and
/// non-UTF-8 names are rejected. Unknown AD types are ignored. A zero length
/// terminates the structure, as the BLE specification requires.
pub fn parse_advertisement(bytes: &[u8]) -> Result<BleAdvertisement, BleGattError> {
    if bytes.len() > MAX_ADVERTISEMENT_BYTES {
        return Err(BleGattError::AdvertisementTooLarge {
            len: bytes.len(),
            max: MAX_ADVERTISEMENT_BYTES,
        });
    }

    let mut services = Vec::new();
    let mut local_name = None;
    let mut offset = 0;
    while offset < bytes.len() {
        let length = usize::from(bytes[offset]);
        offset += 1;
        if length == 0 {
            break;
        }
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(BleGattError::TruncatedAdvertisement { offset: offset - 1 })?;
        let ad_type = bytes[offset];
        let data = &bytes[offset + 1..end];
        offset = end;

        match ad_type {
            0x02 | 0x03 => {
                if data.len() % 2 != 0 {
                    return Err(BleGattError::MalformedUuidList { ad_type });
                }
                for pair in data.chunks_exact(2) {
                    push_service(
                        &mut services,
                        BleUuid::from_u16(u16::from_le_bytes([pair[0], pair[1]])),
                    )?;
                }
            }
            0x06 | 0x07 => {
                if data.len() % 16 != 0 {
                    return Err(BleGattError::MalformedUuidList { ad_type });
                }
                for chunk in data.chunks_exact(16) {
                    let mut canonical = [0u8; 16];
                    // Advertising UUIDs are little-endian on air.
                    for (index, byte) in chunk.iter().rev().enumerate() {
                        canonical[index] = *byte;
                    }
                    push_service(&mut services, BleUuid::from_bytes(canonical))?;
                }
            }
            0x08 | 0x09 => {
                if data.len() > MAX_LOCAL_NAME_BYTES {
                    return Err(BleGattError::InvalidName);
                }
                let name = std::str::from_utf8(data).map_err(|_| BleGattError::InvalidName)?;
                local_name = Some(name.to_string());
            }
            _ => {}
        }
    }

    BleAdvertisement::new(services, local_name)
}

fn push_service(services: &mut Vec<BleUuid>, uuid: BleUuid) -> Result<(), BleGattError> {
    if services.contains(&uuid) {
        return Ok(());
    }
    if services.len() >= MAX_ADVERTISEMENT_SERVICES {
        return Err(BleGattError::TooManyServiceUuids {
            max: MAX_ADVERTISEMENT_SERVICES,
        });
    }
    services.push(uuid);
    Ok(())
}

/// Configurable service/characteristic UUID map for the climate profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleGattUuidMap {
    service: BleUuid,
    temperature: BleUuid,
    humidity: BleUuid,
}

impl BleGattUuidMap {
    /// Validates a custom UUID map.
    pub fn new(
        service: BleUuid,
        temperature: BleUuid,
        humidity: BleUuid,
    ) -> Result<Self, BleGattError> {
        if temperature == humidity {
            return Err(BleGattError::InvalidUuidMap(
                "temperature and humidity characteristics must differ",
            ));
        }
        if service == temperature || service == humidity {
            return Err(BleGattError::InvalidUuidMap(
                "service UUID must differ from its characteristics",
            ));
        }
        Ok(Self {
            service,
            temperature,
            humidity,
        })
    }

    /// The Bluetooth SIG Environmental Sensing profile.
    pub const fn standard() -> Self {
        Self {
            service: ENVIRONMENTAL_SENSING_SERVICE,
            temperature: TEMPERATURE_CHARACTERISTIC,
            humidity: HUMIDITY_CHARACTERISTIC,
        }
    }

    pub const fn service(&self) -> BleUuid {
        self.service
    }

    pub const fn temperature(&self) -> BleUuid {
        self.temperature
    }

    pub const fn humidity(&self) -> BleUuid {
        self.humidity
    }
}

impl Default for BleGattUuidMap {
    fn default() -> Self {
        Self::standard()
    }
}

/// Decoded temperature/humidity pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleClimateReading {
    pub temperature: FixedPointValue,
    pub humidity: FixedPointValue,
}

/// Decodes a SIG Temperature characteristic value.
///
/// The value is a 2-byte little-endian signed integer in 0.01 °C. Values below
/// absolute zero are rejected rather than reported as measurements.
pub fn decode_gatt_temperature(bytes: &[u8]) -> Result<FixedPointValue, BleGattError> {
    let raw = read_i16("temperature", bytes)?;
    if raw < ABSOLUTE_ZERO_CENTI_CELSIUS {
        return Err(BleGattError::ValueOutOfRange {
            field: "temperature",
        });
    }
    Ok(FixedPointValue::new(
        i64::from(raw),
        CLIMATE_EXPONENT,
        UNIT_DEG_C,
    ))
}

/// Decodes a SIG Humidity characteristic value.
///
/// The value is a 2-byte little-endian unsigned integer in 0.01 %RH. Values
/// above 100 % are rejected.
pub fn decode_gatt_humidity(bytes: &[u8]) -> Result<FixedPointValue, BleGattError> {
    let raw = read_u16("humidity", bytes)?;
    if raw > MAX_HUMIDITY_CENTI_PERCENT {
        return Err(BleGattError::ValueOutOfRange { field: "humidity" });
    }
    Ok(FixedPointValue::new(
        i64::from(raw),
        CLIMATE_EXPONENT,
        UNIT_PERCENT,
    ))
}

/// Decodes both characteristics of the climate profile.
pub fn decode_climate(
    temperature_bytes: &[u8],
    humidity_bytes: &[u8],
) -> Result<BleClimateReading, BleGattError> {
    Ok(BleClimateReading {
        temperature: decode_gatt_temperature(temperature_bytes)?,
        humidity: decode_gatt_humidity(humidity_bytes)?,
    })
}

/// Encodes a temperature in hundredths of a degree Celsius.
pub fn encode_temperature_centi_celsius(centi_celsius: i16) -> [u8; 2] {
    centi_celsius.to_le_bytes()
}

/// Encodes a humidity in hundredths of a percent.
pub fn encode_humidity_centi_percent(centi_percent: u16) -> [u8; 2] {
    centi_percent.to_le_bytes()
}

fn read_i16(field: &'static str, bytes: &[u8]) -> Result<i16, BleGattError> {
    let pair: [u8; 2] = bytes.try_into().map_err(|_| BleGattError::PayloadLength {
        field,
        len: bytes.len(),
    })?;
    Ok(i16::from_le_bytes(pair))
}

fn read_u16(field: &'static str, bytes: &[u8]) -> Result<u16, BleGattError> {
    let pair: [u8; 2] = bytes.try_into().map_err(|_| BleGattError::PayloadLength {
        field,
        len: bytes.len(),
    })?;
    Ok(u16::from_le_bytes(pair))
}

/// Advertisement or GATT payload error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleGattError {
    AdvertisementTooLarge { len: usize, max: usize },
    TruncatedAdvertisement { offset: usize },
    MalformedUuidList { ad_type: u8 },
    InvalidUuid(String),
    InvalidName,
    TooManyServiceUuids { max: usize },
    InvalidUuidMap(&'static str),
    PayloadLength { field: &'static str, len: usize },
    ValueOutOfRange { field: &'static str },
}

impl fmt::Display for BleGattError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdvertisementTooLarge { len, max } => {
                write!(f, "advertisement is {len} bytes (max {max})")
            }
            Self::TruncatedAdvertisement { offset } => {
                write!(f, "truncated advertisement record at offset {offset}")
            }
            Self::MalformedUuidList { ad_type } => {
                write!(f, "malformed UUID list in AD type 0x{ad_type:02x}")
            }
            Self::InvalidUuid(value) => write!(f, "invalid UUID '{value}'"),
            Self::InvalidName => write!(f, "invalid or oversized local name"),
            Self::TooManyServiceUuids { max } => {
                write!(f, "advertisement carries more than {max} service UUIDs")
            }
            Self::InvalidUuidMap(reason) => write!(f, "invalid UUID map: {reason}"),
            Self::PayloadLength { field, len } => {
                write!(f, "{field} payload is {len} bytes; expected 2")
            }
            Self::ValueOutOfRange { field } => {
                write!(f, "{field} value is outside the physical range")
            }
        }
    }
}

impl std::error::Error for BleGattError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn ad(records: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for record in records {
            out.push(record.len() as u8);
            out.extend_from_slice(record);
        }
        out
    }

    #[test]
    fn uuid_round_trips_short_and_canonical_forms() {
        assert_eq!(
            BleUuid::from_u16(0x181A).to_string(),
            "0000181a-0000-1000-8000-00805f9b34fb"
        );
        assert_eq!(
            BleUuid::parse("0000181A-0000-1000-8000-00805F9B34FB").unwrap(),
            ENVIRONMENTAL_SENSING_SERVICE
        );
        assert_eq!(
            BleUuid::parse("181a").unwrap(),
            ENVIRONMENTAL_SENSING_SERVICE
        );
        assert!(BleUuid::parse("181").is_err());
        assert!(BleUuid::parse("zzzz").is_err());
    }

    #[test]
    fn advertisement_extracts_services_and_name() {
        let bytes = ad(&[
            &[0x01, 0x06],
            &[0x03, 0x1A, 0x18],
            &[0x09, b'T', b'H', b' '],
        ]);
        let parsed = parse_advertisement(&bytes).unwrap();
        assert_eq!(parsed.service_uuids(), &[ENVIRONMENTAL_SENSING_SERVICE]);
        assert_eq!(parsed.local_name(), Some("TH "));
        assert!(parsed.has_service(ENVIRONMENTAL_SENSING_SERVICE));
    }

    #[test]
    fn advertisement_decodes_a_128_bit_service_in_canonical_order() {
        let uuid = BleUuid::parse("12345678-1234-5678-9abc-def012345678").unwrap();
        let mut record = vec![0x07];
        record.extend(uuid.as_bytes().iter().rev());
        let parsed = parse_advertisement(&ad(&[&record])).unwrap();
        assert_eq!(parsed.service_uuids(), &[uuid]);
    }

    #[test]
    fn malformed_advertisements_are_rejected() {
        assert!(matches!(
            parse_advertisement(&[0x05, 0x09, b'a']),
            Err(BleGattError::TruncatedAdvertisement { .. })
        ));
        assert!(matches!(
            parse_advertisement(&[0x02, 0x03, 0x1A]),
            Err(BleGattError::MalformedUuidList { .. })
        ));
        assert!(matches!(
            parse_advertisement(&[0x02, 0x09, 0xFF, 0xFE]),
            Err(BleGattError::InvalidName)
        ));
        let oversized = vec![0u8; MAX_ADVERTISEMENT_BYTES + 1];
        assert!(matches!(
            parse_advertisement(&oversized),
            Err(BleGattError::AdvertisementTooLarge { .. })
        ));
    }

    #[test]
    fn uuid_map_rejects_collisions_and_accepts_custom_uuids() {
        let temp = BleUuid::parse("0000aaaa-0000-1000-8000-00805f9b34fb").unwrap();
        let humidity = BleUuid::parse("0000bbbb-0000-1000-8000-00805f9b34fb").unwrap();
        let map = BleGattUuidMap::new(ENVIRONMENTAL_SENSING_SERVICE, temp, humidity).unwrap();
        assert_eq!(map.temperature(), temp);
        assert!(matches!(
            BleGattUuidMap::new(ENVIRONMENTAL_SENSING_SERVICE, temp, temp),
            Err(BleGattError::InvalidUuidMap(_))
        ));
        assert!(matches!(
            BleGattUuidMap::new(temp, temp, humidity),
            Err(BleGattError::InvalidUuidMap(_))
        ));
    }

    #[test]
    fn temperature_is_fixed_point_centi_celsius() {
        assert_eq!(
            decode_gatt_temperature(&encode_temperature_centi_celsius(2_150)).unwrap(),
            FixedPointValue::new(2_150, -2, UNIT_DEG_C)
        );
        assert_eq!(
            decode_gatt_temperature(&encode_temperature_centi_celsius(-1_050)).unwrap(),
            FixedPointValue::new(-1_050, -2, UNIT_DEG_C)
        );
    }

    #[test]
    fn humidity_is_fixed_point_centi_percent() {
        assert_eq!(
            decode_gatt_humidity(&encode_humidity_centi_percent(4_500)).unwrap(),
            FixedPointValue::new(4_500, -2, UNIT_PERCENT)
        );
    }

    #[test]
    fn malformed_gatt_payloads_are_rejected() {
        assert!(matches!(
            decode_gatt_temperature(&[0x01]),
            Err(BleGattError::PayloadLength { .. })
        ));
        assert!(matches!(
            decode_gatt_temperature(&[0x01, 0x02, 0x03]),
            Err(BleGattError::PayloadLength { .. })
        ));
        assert!(matches!(
            decode_gatt_humidity(&[]),
            Err(BleGattError::PayloadLength { .. })
        ));
    }

    #[test]
    fn physically_impossible_values_are_rejected() {
        assert!(matches!(
            decode_gatt_temperature(&encode_temperature_centi_celsius(-30_000)),
            Err(BleGattError::ValueOutOfRange {
                field: "temperature"
            })
        ));
        assert!(matches!(
            decode_gatt_humidity(&encode_humidity_centi_percent(10_001)),
            Err(BleGattError::ValueOutOfRange { field: "humidity" })
        ));
    }

    #[test]
    fn climate_pair_decodes_both_fields() {
        let reading = decode_climate(
            &encode_temperature_centi_celsius(2_150),
            &encode_humidity_centi_percent(4_500),
        )
        .unwrap();
        assert_eq!(reading.temperature.mantissa, 2_150);
        assert_eq!(reading.humidity.mantissa, 4_500);
    }
}
