//! Modbus register-map format and parser (CLAIM-34.8, PV-10.4/10.7).
//!
//! Format (TOML/line-oriented docs) per parameter:
//! - `register` (u16 address, 0-based in file; callers may interpret 4xxxx notation in docs)
//! - `function` (FC: 3|4|6|16)
//! - `kind` (`holding`|`input`|`coil`/register semantic)
//! - `data_type` (`u16`|`i16`|`u32`|`i32`|`bool`)
//! - `scale_mantissa` (i64), `scale_exponent` (i8)
//! - `offset_mantissa` (i64), `offset_exponent` (i8)
//! - `word_order` (`big_endian`|`little_endian`|`mid_big`|`mid_little`)
//! - `unit_id` (u16), `writable` (bool), `name` (string)

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterWordOrder {
    BigEndian,
    LittleEndian,
    MidBigEndian,
    MidLittleEndian,
}

impl RegisterWordOrder {
    pub fn parse(s: &str) -> Result<Self, RegisterMapError> {
        match s
            .trim()
            .to_ascii_lowercase()
            .replace(['-', ' '], "_")
            .as_str()
        {
            "big_endian" | "be" => Ok(Self::BigEndian),
            "little_endian" | "le" => Ok(Self::LittleEndian),
            "mid_big_endian" | "mid_big" | "big_endian_word_swap" => Ok(Self::MidBigEndian),
            "mid_little_endian" | "mid_little" | "little_endian_word_swap" => {
                Ok(Self::MidLittleEndian)
            }
            other => Err(RegisterMapError::InvalidField {
                field: "word_order".into(),
                message: format!("unsupported word order '{other}'"),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterDef {
    pub name: String,
    pub register: u16,
    pub function: u8,
    pub data_type: String,
    pub scale_mantissa: i64,
    pub scale_exponent: i8,
    pub offset_mantissa: i64,
    pub offset_exponent: i8,
    pub word_order: RegisterWordOrder,
    pub unit_id: u16,
    pub writable: bool,
    pub quantity: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModbusRegisterMap {
    pub device_class: String,
    pub registers: Vec<RegisterDef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterMapError {
    InvalidField { field: String, message: String },
    MissingField(String),
    Parse(String),
}

impl fmt::Display for RegisterMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterMapError::InvalidField { field, message } => {
                write!(f, "register map field '{field}': {message}")
            }
            RegisterMapError::MissingField(field) => {
                write!(f, "register map missing field '{field}'")
            }
            RegisterMapError::Parse(m) => write!(f, "register map parse error: {m}"),
        }
    }
}

impl std::error::Error for RegisterMapError {}

fn parse_kv(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line == "[[register]]" || line.starts_with('[') {
        return None;
    }
    let (k, v) = line.split_once('=')?;
    let v = v.trim().trim_matches('"').trim_matches('\'');
    Some((k.trim().to_string(), v.to_string()))
}

fn parse_bool(v: &str) -> Result<bool, RegisterMapError> {
    match v.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(RegisterMapError::InvalidField {
            field: "writable".into(),
            message: format!("invalid boolean '{v}'"),
        }),
    }
}

impl ModbusRegisterMap {
    /// Parse a simple TOML-like register map document. This is intentionally small
    /// and deterministic (no external TOML dependency in drivers crate) and accepts
    /// the documented register-map subset.
    pub fn parse(input: &str) -> Result<Self, RegisterMapError> {
        let mut map = ModbusRegisterMap::default();
        let mut current: Option<RegisterDef> = None;
        let mut in_register = false;
        for (lineno, raw) in input.lines().enumerate() {
            let line = raw.trim();
            if line == "[[register]]" {
                if let Some(def) = current.take() {
                    validate_def(&def)?;
                    map.registers.push(def);
                }
                in_register = true;
                current = Some(RegisterDef {
                    name: String::new(),
                    register: 0,
                    function: 3,
                    data_type: "i16".into(),
                    scale_mantissa: 1,
                    scale_exponent: 0,
                    offset_mantissa: 0,
                    offset_exponent: 0,
                    word_order: RegisterWordOrder::BigEndian,
                    unit_id: 0,
                    writable: false,
                    quantity: 1,
                });
                continue;
            }
            if let Some((k, v)) = parse_kv(line) {
                if !in_register && k == "device_class" {
                    map.device_class = v;
                    continue;
                }
                let def = current.as_mut().ok_or_else(|| {
                    RegisterMapError::Parse(format!(
                        "line {}: key outside [[register]]",
                        lineno + 1
                    ))
                })?;
                match k.as_str() {
                    "name" => def.name = v,
                    "register" | "address" => {
                        def.register = v.parse().map_err(|_| RegisterMapError::InvalidField {
                            field: "register".into(),
                            message: format!("invalid u16 '{v}'"),
                        })?;
                    }
                    "function" | "fc" => {
                        let fc: u8 = v.parse().map_err(|_| RegisterMapError::InvalidField {
                            field: "function".into(),
                            message: format!("invalid function code '{v}'"),
                        })?;
                        if !matches!(fc, 3 | 4 | 6 | 16) {
                            return Err(RegisterMapError::InvalidField {
                                field: "function".into(),
                                message: format!("unsupported FC {fc}; expected 3,4,6,16"),
                            });
                        }
                        def.function = fc;
                    }
                    "data_type" | "type" => def.data_type = v,
                    "scale_mantissa" | "scale" => {
                        def.scale_mantissa =
                            v.parse().map_err(|_| RegisterMapError::InvalidField {
                                field: "scale_mantissa".into(),
                                message: format!("invalid i64 '{v}'"),
                            })?;
                    }
                    "scale_exponent" => {
                        def.scale_exponent =
                            v.parse().map_err(|_| RegisterMapError::InvalidField {
                                field: "scale_exponent".into(),
                                message: format!("invalid i8 '{v}'"),
                            })?;
                    }
                    "offset_mantissa" | "offset" => {
                        def.offset_mantissa =
                            v.parse().map_err(|_| RegisterMapError::InvalidField {
                                field: "offset_mantissa".into(),
                                message: format!("invalid i64 '{v}'"),
                            })?;
                    }
                    "offset_exponent" => {
                        def.offset_exponent =
                            v.parse().map_err(|_| RegisterMapError::InvalidField {
                                field: "offset_exponent".into(),
                                message: format!("invalid i8 '{v}'"),
                            })?;
                    }
                    "word_order" => def.word_order = RegisterWordOrder::parse(&v)?,
                    "unit_id" => {
                        def.unit_id = v.parse().map_err(|_| RegisterMapError::InvalidField {
                            field: "unit_id".into(),
                            message: format!("invalid u16 '{v}'"),
                        })?;
                    }
                    "writable" => def.writable = parse_bool(&v)?,
                    "quantity" | "count" => {
                        def.quantity = v.parse().map_err(|_| RegisterMapError::InvalidField {
                            field: "quantity".into(),
                            message: format!("invalid u16 '{v}'"),
                        })?;
                    }
                    _ => {}
                }
            }
        }
        if let Some(def) = current.take() {
            validate_def(&def)?;
            map.registers.push(def);
        }
        if map.registers.is_empty() {
            return Err(RegisterMapError::MissingField("register".into()));
        }
        Ok(map)
    }
}

fn validate_def(def: &RegisterDef) -> Result<(), RegisterMapError> {
    if def.name.trim().is_empty() {
        return Err(RegisterMapError::MissingField("name".into()));
    }
    if !matches!(def.function, 3 | 4 | 6 | 16) {
        return Err(RegisterMapError::InvalidField {
            field: "function".into(),
            message: format!("unsupported FC {}", def.function),
        });
    }
    if def.quantity == 0 {
        return Err(RegisterMapError::InvalidField {
            field: "quantity".into(),
            message: "quantity must be >= 1".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_register_map() {
        let doc = r#"
device_class = "cold_room_modbus"

[[register]]
name = "temperature_c"
register = 0
function = 4
data_type = "i16"
scale_mantissa = 1
scale_exponent = -1
offset_mantissa = 0
offset_exponent = 0
word_order = "big_endian"
unit_id = 1
writable = false
quantity = 1
"#;
        let m = ModbusRegisterMap::parse(doc).unwrap();
        assert_eq!(m.device_class, "cold_room_modbus");
        assert_eq!(m.registers.len(), 1);
        assert_eq!(m.registers[0].name, "temperature_c");
        assert_eq!(m.registers[0].function, 4);
    }

    #[test]
    fn rejects_bad_function_code() {
        let doc = r#"
[[register]]
name = "x"
register = 1
function = 99
"#;
        let err = ModbusRegisterMap::parse(doc).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("function"), "{msg}");
    }
}
