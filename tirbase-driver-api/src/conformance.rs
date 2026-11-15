// SPDX-License-Identifier: Apache-2.0

//! Vendor conformance harness for pure device drivers.
//!
//! The harness exercises a [`DriverTrait`] implementation against the rules the
//! TirBase runtime relies on, without touching any device or network:
//!
//! 1. **Encode/decode round-trip** — golden request/response frames produce the
//!    documented [`FixedPointValue`].
//! 2. **Bounded time** — every operation completes within
//!    [`DRIVER_OPERATION_TIMEOUT`] against the caller-supplied monotonic clock.
//! 3. **Typed errors** — unknown parameters and malformed frames return
//!    [`DriverError`] variants instead of panicking.
//! 4. **Scaling** — register-map scale/offset conversion round-trips and matches
//!    the documented formula.
//! 5. **Word order** — 32-bit values transmit in the declared word order and
//!    decode back to the original raw value.
//! 6. **No I/O** — driver sources do not reference networking, filesystem, or
//!    process APIs (lexical guard; the guard process owns all device I/O).
//!
//! A passing report is necessary evidence that a driver is safe to embed in the
//! out-of-process driver boundary. It is not a substitute for the runtime's own
//! deadline enforcement or the guard's sandbox.

use crate::driver_trait::{
    run_with_timeout, ActuationPermitRef, DriverError, DriverTrait, DRIVER_OPERATION_TIMEOUT,
};
use crate::register_map::{ModbusRegisterMap, RegisterDef, RegisterWordOrder};
use tirbase_types::FixedPointValue;

/// Parameter name used to prove that unknown parameters are rejected.
pub const UNKNOWN_PARAMETER: &str = "__tirbase_conformance_unknown_parameter__";

/// One golden scenario for the codec conformance suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecCase {
    /// Human-readable case name (used in report entries).
    pub name: String,
    /// Parameter to read; must be a parameter the driver advertises.
    pub parameter: String,
    /// A well-formed read response frame for `parameter`.
    pub read_response: Vec<u8>,
    /// Expected value decoded from `read_response`.
    pub expected_read: FixedPointValue,
    /// A well-formed read-back frame for the actuation path.
    pub read_back_frame: Vec<u8>,
    /// Expected value decoded from `read_back_frame`.
    pub expected_read_back: FixedPointValue,
    /// Actuation permit to encode.
    pub actuation: ActuationPermitRef,
    /// Expected actuation frame, when the wire format is fixed by the driver.
    pub expected_actuation: Option<Vec<u8>>,
    /// A well-formed health-check response frame.
    pub health_response: Vec<u8>,
    /// Whether `health_response` must report a healthy device.
    pub expected_healthy: bool,
}

/// Outcome of one conformance check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable check identifier, e.g. `round_trip:temperature_c`.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable evidence or failure reason.
    pub detail: String,
}

impl Check {
    /// Records a passing check.
    pub fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: true,
            detail: detail.into(),
        }
    }

    /// Records a failing check.
    pub fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: false,
            detail: detail.into(),
        }
    }
}

/// Collection of conformance checks produced by the harness.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConformanceReport {
    /// Every check executed, in execution order.
    pub checks: Vec<Check>,
}

impl ConformanceReport {
    /// Creates an empty report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a check.
    pub fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    /// Appends every check from `other`.
    pub fn merge(&mut self, other: ConformanceReport) {
        self.checks.extend(other.checks);
    }

    /// True when at least one check ran and all of them passed.
    pub fn passed(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.passed)
    }

    /// Failing checks only.
    pub fn failures(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    /// Panics with a structured list of failures.
    ///
    /// Intended for vendor integration tests:
    /// `harness.run(...).assert_ok();`
    pub fn assert_ok(&self) {
        if self.passed() {
            return;
        }
        let mut message = String::from("driver conformance failed:");
        if self.checks.is_empty() {
            message.push_str("\n  (no checks were executed)");
        }
        for failure in self.failures() {
            message.push_str(&format!("\n  FAIL {}: {}", failure.name, failure.detail));
        }
        panic!("{message}");
    }
}

/// Runs the codec, scaling, word-order, and no-I/O checks as one report.
///
/// `clock` is a caller-supplied monotonic millisecond clock; the harness never
/// reads a clock itself (drivers must not depend on `tirbase-core`).
pub fn run_conformance<D: DriverTrait>(
    driver: &D,
    cases: &[CodecCase],
    map: &ModbusRegisterMap,
    sources: &[SourceFile<'_>],
    clock: &dyn Fn() -> u64,
) -> ConformanceReport {
    let harness = ConformanceHarness::new(clock);
    let mut report = harness.check_codec(driver, cases);
    report.merge(harness.check_bounded_time(driver, cases));
    report.merge(check_register_scaling(map));
    report.merge(check_word_order());
    report.merge(check_no_io(sources));
    report
}

/// Conformance harness bound to one monotonic clock.
pub struct ConformanceHarness<'a> {
    clock: &'a dyn Fn() -> u64,
}

impl<'a> ConformanceHarness<'a> {
    /// Creates a harness that measures elapsed time with `clock` (milliseconds).
    pub fn new(clock: &'a dyn Fn() -> u64) -> Self {
        Self { clock }
    }

    /// Runs encode/decode round-trip, health, and typed-error checks.
    pub fn check_codec<D: DriverTrait>(
        &self,
        driver: &D,
        cases: &[CodecCase],
    ) -> ConformanceReport {
        let mut report = ConformanceReport::new();
        if cases.is_empty() {
            report.push(Check::fail(
                "round_trip",
                "the conformance suite must contain at least one codec case",
            ));
            return report;
        }

        for case in cases {
            let encoded = run_with_timeout("encode_read", self.clock, || {
                driver.encode_read(&case.parameter)
            });
            let encoded = match encoded {
                Ok(frame) => frame,
                Err(e) => {
                    report.push(Check::fail(
                        format!("round_trip:{}", case.name),
                        format!("encode_read({}) failed: {e}", case.parameter),
                    ));
                    continue;
                }
            };

            let decoded = run_with_timeout("decode_read_response", self.clock, || {
                driver.decode_read_response(&case.read_response)
            });
            let read_back = run_with_timeout("decode_read_back", self.clock, || {
                driver.decode_read_back(&case.read_back_frame)
            });
            let actuation = run_with_timeout("encode_actuation", self.clock, || {
                driver.encode_actuation(&case.actuation)
            });
            let health_encoded = run_with_timeout("encode_health_check", self.clock, || {
                driver.encode_health_check()
            });
            let health_decoded = run_with_timeout("decode_health_response", self.clock, || {
                driver.decode_health_response(&case.health_response)
            });

            let mut problems: Vec<String> = Vec::new();
            match decoded {
                Ok(value) if value == case.expected_read => {}
                Ok(value) => problems.push(format!(
                    "decode_read_response returned {value:?}, expected {:?}",
                    case.expected_read
                )),
                Err(e) => problems.push(format!("decode_read_response failed: {e}")),
            }
            match read_back {
                Ok(value) if value == case.expected_read_back => {}
                Ok(value) => problems.push(format!(
                    "decode_read_back returned {value:?}, expected {:?}",
                    case.expected_read_back
                )),
                Err(e) => problems.push(format!("decode_read_back failed: {e}")),
            }
            match actuation {
                Ok(frame) => {
                    if let Some(expected) = &case.expected_actuation {
                        if &frame != expected {
                            problems.push(format!(
                                "encode_actuation returned {frame:02x?}, expected {expected:02x?}"
                            ));
                        }
                    }
                }
                Err(e) => problems.push(format!("encode_actuation failed: {e}")),
            }
            if let Err(e) = health_encoded {
                problems.push(format!("encode_health_check failed: {e}"));
            }
            match health_decoded {
                Ok(health) if health.healthy == case.expected_healthy => {}
                Ok(health) => problems.push(format!(
                    "decode_health_response reported healthy={}, expected {}",
                    health.healthy, case.expected_healthy
                )),
                Err(e) => problems.push(format!("decode_health_response failed: {e}")),
            }

            report.push(if problems.is_empty() {
                Check::pass(
                    format!("round_trip:{}", case.name),
                    format!(
                        "{} encoded as {} byte(s); golden response and read-back decoded",
                        case.parameter,
                        encoded.len()
                    ),
                )
            } else {
                Check::fail(format!("round_trip:{}", case.name), problems.join("; "))
            });
        }

        report.merge(self.check_typed_errors(driver));
        report
    }

    /// Proves that unknown parameters and malformed frames produce typed errors.
    pub fn check_typed_errors<D: DriverTrait>(&self, driver: &D) -> ConformanceReport {
        let mut report = ConformanceReport::new();

        let unknown = run_with_timeout("encode_read", self.clock, || {
            driver.encode_read(UNKNOWN_PARAMETER)
        });
        report.push(match unknown {
            Err(DriverError::UnsupportedParam(param)) if param == UNKNOWN_PARAMETER => Check::pass(
                "typed_error:unsupported_param",
                "unknown parameter rejected with DriverError::UnsupportedParam",
            ),
            Err(e) => Check::fail(
                "typed_error:unsupported_param",
                format!("expected UnsupportedParam for an unknown parameter, got {e:?}"),
            ),
            Ok(_) => Check::fail(
                "typed_error:unsupported_param",
                "unknown parameter was accepted",
            ),
        });

        let bad_read = driver.decode_read_response(&[]);
        report.push(match bad_read {
            Err(DriverError::InvalidFrame(_)) => Check::pass(
                "typed_error:invalid_read_frame",
                "empty read frame rejected with DriverError::InvalidFrame",
            ),
            Err(e) => Check::fail(
                "typed_error:invalid_read_frame",
                format!("expected InvalidFrame for an empty frame, got {e:?}"),
            ),
            Ok(_) => Check::fail(
                "typed_error:invalid_read_frame",
                "empty read frame was accepted",
            ),
        });

        let bad_read_back = driver.decode_read_back(&[]);
        report.push(match bad_read_back {
            Err(DriverError::InvalidFrame(_)) => Check::pass(
                "typed_error:invalid_read_back_frame",
                "empty read-back frame rejected with DriverError::InvalidFrame",
            ),
            Err(e) => Check::fail(
                "typed_error:invalid_read_back_frame",
                format!("expected InvalidFrame for an empty frame, got {e:?}"),
            ),
            Ok(_) => Check::fail(
                "typed_error:invalid_read_back_frame",
                "empty read-back frame was accepted",
            ),
        });

        // Health decoding must return a typed result rather than panicking.
        let health = driver.decode_health_response(&[]);
        report.push(match health {
            Ok(h) => Check::pass(
                "typed_error:health_result",
                format!("empty health frame handled: healthy={}", h.healthy),
            ),
            Err(DriverError::Timeout(_))
            | Err(DriverError::InvalidFrame(_))
            | Err(DriverError::UnsupportedParam(_))
            | Err(DriverError::Codec(_))
            | Err(DriverError::Capability(_))
            | Err(DriverError::Exception { .. }) => Check::pass(
                "typed_error:health_result",
                "empty health frame produced a typed DriverError",
            ),
        });

        report
    }

    /// Confirms that each advertised read path completes inside the deadline.
    pub fn check_bounded_time<D: DriverTrait>(
        &self,
        driver: &D,
        cases: &[CodecCase],
    ) -> ConformanceReport {
        let mut report = ConformanceReport::new();
        let limit_ms = DRIVER_OPERATION_TIMEOUT.as_millis() as u64;
        if cases.is_empty() {
            report.push(Check::fail(
                "bounded_time",
                "no codec cases supplied to the bounded-time check",
            ));
            return report;
        }
        for case in cases {
            let start = (self.clock)();
            let result = driver.encode_read(&case.parameter);
            let elapsed = (self.clock)().saturating_sub(start);
            let within = elapsed <= limit_ms && !matches!(result, Err(DriverError::Timeout(_)));
            report.push(if within {
                Check::pass(
                    format!("bounded_time:{}", case.name),
                    format!("encode_read completed in {elapsed} ms (limit {limit_ms} ms)"),
                )
            } else {
                Check::fail(
                    format!("bounded_time:{}", case.name),
                    format!("encode_read took {elapsed} ms or timed out (limit {limit_ms} ms)"),
                )
            });
        }
        report
    }
}

/// One driver source file supplied to the no-I/O guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceFile<'a> {
    /// Path shown in failures.
    pub path: &'a str,
    /// Full file contents.
    pub contents: &'a str,
}

/// Tokens that indicate a driver is reaching for device or process I/O.
///
/// Drivers are codecs: the guard process owns sockets, serial ports, files, and
/// child processes. A vendor driver must not reference these APIs.
pub const FORBIDDEN_IO_TOKENS: &[&str] = &[
    "std::fs",
    "std::net",
    "std::process",
    "std::os::",
    "std::io",
    "std::thread::spawn",
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "UnixStream",
    "UnixListener",
    "File::open",
    "File::create",
    "OpenOptions",
    "rusqlite",
    "reqwest",
    "nix::",
    "libc::",
];

/// Lexically checks that driver sources contain no I/O APIs.
///
/// Comment lines and trailing `//` comments are ignored so that documentation
/// may explain the rule without tripping it. This is a source-level guard: it
/// catches imports and calls, not dynamically constructed API names.
pub fn check_no_io(sources: &[SourceFile<'_>]) -> ConformanceReport {
    let mut report = ConformanceReport::new();
    if sources.is_empty() {
        report.push(Check::fail(
            "no_io",
            "no driver sources supplied; refusing to pass vacuously",
        ));
        return report;
    }

    let mut violations: Vec<String> = Vec::new();
    for source in sources {
        for (index, raw_line) in source.contents.lines().enumerate() {
            let code = strip_comment(raw_line);
            let code = code.trim();
            if code.is_empty() {
                continue;
            }
            for token in FORBIDDEN_IO_TOKENS {
                if code.contains(token) {
                    violations.push(format!(
                        "{}:{} references `{}`",
                        source.path,
                        index + 1,
                        token
                    ));
                }
            }
        }
    }

    report.push(if violations.is_empty() {
        Check::pass(
            "no_io",
            format!(
                "{} source file(s) contain no fs/net/process APIs",
                sources.len()
            ),
        )
    } else {
        Check::fail("no_io", violations.join("; "))
    });
    report
}

fn strip_comment(line: &str) -> &str {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('*') {
        return "";
    }
    match line.find("//") {
        Some(index) => &line[..index],
        None => line,
    }
}

/// Verifies register-map scaling round-trips and matches the documented formula.
///
/// For each register: `raw -> words -> raw` must be identity, and
/// `decode_to_scaled_i64(words)` must equal
/// `raw * scale_mantissa + offset_mantissa * 10^(offset_exponent - scale_exponent)`
/// (the common `10^scale_exponent` factor is the fixed-point exponent).
pub fn check_register_scaling(map: &ModbusRegisterMap) -> ConformanceReport {
    let mut report = ConformanceReport::new();
    if map.registers.is_empty() {
        report.push(Check::fail("scaling", "register map declares no registers"));
        return report;
    }
    for def in &map.registers {
        report.push(check_register_scaling_one(def));
    }
    report
}

fn check_register_scaling_one(def: &RegisterDef) -> Check {
    let name = format!("scaling:{}", def.name);
    if def.scale_mantissa == 0 {
        return Check::fail(name, "scale_mantissa must not be 0");
    }
    let offset_factor = match pow10(def.offset_exponent.saturating_sub(def.scale_exponent)) {
        Some(v) => v,
        None => return Check::fail(name, "offset exponent is out of range"),
    };

    for raw in sample_raw_values(def) {
        let words = match def.encode_raw_i128(raw) {
            Ok(words) => words,
            Err(e) => return Check::fail(name, format!("encode_raw_i128({raw}) failed: {e}")),
        };
        let decoded_raw = match def.decode_raw_i128(&words) {
            Ok(value) => value,
            Err(e) => return Check::fail(name, format!("decode_raw_i128 failed: {e}")),
        };
        if decoded_raw != raw {
            return Check::fail(
                name,
                format!("raw round-trip {raw} -> {words:?} -> {decoded_raw}"),
            );
        }

        let scaled = match def.decode_to_scaled_i64(&words) {
            Ok(value) => value,
            Err(e) => return Check::fail(name, format!("decode_to_scaled_i64 failed: {e}")),
        };
        let expected =
            raw * def.scale_mantissa as i128 + def.offset_mantissa as i128 * offset_factor;
        if i128::from(scaled) != expected {
            return Check::fail(
                name,
                format!("scaled value {scaled} != expected {expected} for raw {raw}"),
            );
        }

        let reencoded = match def.encode_scaled_i64(scaled) {
            Ok(words) => words,
            Err(e) => return Check::fail(name, format!("encode_scaled_i64({scaled}) failed: {e}")),
        };
        match def.decode_to_scaled_i64(&reencoded) {
            Ok(again) if again == scaled => {}
            Ok(again) => {
                return Check::fail(
                    name,
                    format!("scaled round-trip {scaled} -> {reencoded:?} -> {again}"),
                )
            }
            Err(e) => {
                return Check::fail(name, format!("scaled round-trip decode failed: {e}"));
            }
        }
    }

    Check::pass(
        name,
        format!(
            "{} sample(s) round-tripped ({} registers/value)",
            sample_raw_values(def).len(),
            def.registers_per_value().unwrap_or(0)
        ),
    )
}

fn sample_raw_values(def: &RegisterDef) -> Vec<i128> {
    match def.data_type_normalized().as_str() {
        "bool" => vec![0, 1],
        "u16" | "uint16" => vec![0, 1, 100, 65535],
        "u32" | "uint32" => vec![0, 1, 100, 65535],
        "i16" | "int16" => vec![0, 1, -1, 100, -100],
        "i32" | "int32" => vec![0, 1, -1, 100, -100],
        // f32 values are truncated to i128 by the decoder; round-tripping
        // fractional samples is not meaningful, so probe integral values only.
        "f32" | "float32" => vec![0, 1, -1],
        _ => vec![0],
    }
}

fn pow10(exp: i8) -> Option<i128> {
    if exp < 0 {
        return Some(1);
    }
    let mut value: i128 = 1;
    for _ in 0..exp.min(38) {
        value = value.checked_mul(10)?;
    }
    Some(value)
}

/// Verifies 32-bit word-order handling with golden wire words.
///
/// Wire order for `raw = 0x1122_3344`:
/// `big_endian -> [0x1122, 0x3344]`, `little_endian -> [0x3344, 0x1122]`,
/// `mid_big -> [0x3344, 0x1122]`, `mid_little -> [0x1122, 0x3344]`.
pub fn check_word_order() -> ConformanceReport {
    let mut report = ConformanceReport::new();
    let cases = [
        (
            RegisterWordOrder::BigEndian,
            [0x1122u16, 0x3344u16],
            "big_endian",
        ),
        (
            RegisterWordOrder::LittleEndian,
            [0x3344, 0x1122],
            "little_endian",
        ),
        (RegisterWordOrder::MidBigEndian, [0x3344, 0x1122], "mid_big"),
        (
            RegisterWordOrder::MidLittleEndian,
            [0x1122, 0x3344],
            "mid_little",
        ),
    ];

    for (order, expected_words, label) in cases {
        let mut def = register_def("word_order", "u32");
        def.word_order = order;
        let name = format!("word_order:{label}");
        let raw: i128 = 0x1122_3344;
        match def.encode_raw_i128(raw) {
            Ok(words) if words == expected_words => match def.decode_raw_i128(&words) {
                Ok(decoded) if decoded == raw => report.push(Check::pass(
                    name,
                    format!("{words:04x?} encode/decode round-trip"),
                )),
                Ok(decoded) => report.push(Check::fail(
                    name,
                    format!("decoded {decoded:#x} instead of {raw:#x}"),
                )),
                Err(e) => report.push(Check::fail(name, format!("decode failed: {e}"))),
            },
            Ok(words) => report.push(Check::fail(
                name,
                format!("encoded {words:04x?}, expected {expected_words:04x?}"),
            )),
            Err(e) => report.push(Check::fail(name, format!("encode failed: {e}"))),
        }
    }
    report
}

fn register_def(name: &str, data_type: &str) -> RegisterDef {
    RegisterDef {
        name: name.into(),
        register: 0,
        function: 4,
        data_type: data_type.into(),
        scale_mantissa: 1,
        scale_exponent: 0,
        offset_mantissa: 0,
        offset_exponent: 0,
        word_order: RegisterWordOrder::BigEndian,
        unit_id: 0,
        writable: false,
        quantity: 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver_trait::{
        DeviceModel, DriverHealth, DriverResult, Frame, ParameterDescriptor,
    };
    use tirbase_types::{TargetId, UNIT_DEG_C};

    fn fp(mantissa: i64, exponent: i8) -> FixedPointValue {
        FixedPointValue::new(mantissa, exponent, UNIT_DEG_C)
    }

    struct TextDriver;

    impl DriverTrait for TextDriver {
        fn capability_discovery(&self) -> DriverResult<DeviceModel> {
            DeviceModel::try_new(
                "text".into(),
                vec![ParameterDescriptor {
                    name: "temperature_c".into(),
                    unit_id: UNIT_DEG_C,
                    unit_label: "degC".into(),
                    range: [fp(-400, -1), fp(100, -1)],
                    writable: false,
                }],
            )
            .map_err(|e| DriverError::Capability(e.to_string()))
        }

        fn encode_read(&self, param: &str) -> DriverResult<Frame> {
            if param != "temperature_c" {
                return Err(DriverError::UnsupportedParam(param.into()));
            }
            Ok(b"RD 0\n".to_vec())
        }

        fn decode_read_response(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
            let text =
                std::str::from_utf8(frame).map_err(|e| DriverError::InvalidFrame(e.to_string()))?;
            let value = text
                .strip_prefix("VAL ")
                .ok_or_else(|| DriverError::InvalidFrame("missing VAL prefix".into()))?
                .trim()
                .parse::<i64>()
                .map_err(|e| DriverError::InvalidFrame(e.to_string()))?;
            Ok(fp(value, -1))
        }

        fn encode_actuation(&self, permit: &ActuationPermitRef) -> DriverResult<Frame> {
            Ok(format!("WR {}", permit.value.mantissa).into_bytes())
        }

        fn decode_read_back(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
            let text =
                std::str::from_utf8(frame).map_err(|e| DriverError::InvalidFrame(e.to_string()))?;
            let value = text
                .strip_prefix("RB ")
                .ok_or_else(|| DriverError::InvalidFrame("missing RB prefix".into()))?
                .trim()
                .parse::<i64>()
                .map_err(|e| DriverError::InvalidFrame(e.to_string()))?;
            Ok(fp(value, -1))
        }

        fn encode_health_check(&self) -> DriverResult<Frame> {
            Ok(b"PING\n".to_vec())
        }

        fn decode_health_response(&self, frame: &[u8]) -> DriverResult<DriverHealth> {
            Ok(DriverHealth {
                healthy: frame == b"PONG\n",
                detail: String::from_utf8_lossy(frame).into_owned(),
            })
        }
    }

    fn case() -> CodecCase {
        CodecCase {
            name: "temperature".into(),
            parameter: "temperature_c".into(),
            read_response: b"VAL 250\n".to_vec(),
            expected_read: fp(250, -1),
            read_back_frame: b"RB 250\n".to_vec(),
            expected_read_back: fp(250, -1),
            actuation: ActuationPermitRef {
                target_id: TargetId::new("t1"),
                param: "temperature_c".into(),
                value: fp(250, -1),
                entry_id: [1u8; 16],
            },
            expected_actuation: Some(b"WR 250".to_vec()),
            health_response: b"PONG\n".to_vec(),
            expected_healthy: true,
        }
    }

    #[test]
    fn passing_driver_conforms() {
        let report = run_conformance(
            &TextDriver,
            &[case()],
            &ModbusRegisterMap::parse(
                "device_class = \"x\"\n[[register]]\nname = \"temperature_c\"\nregister = 0\nfunction = 4\ndata_type = \"i16\"\nscale_mantissa = 1\nscale_exponent = -1\nquantity = 1\n",
            )
            .unwrap(),
            &[SourceFile {
                path: "src/lib.rs",
                contents: "pub fn encode() -> u8 { 1 }\n",
            }],
            &|| 0,
        );
        assert!(report.passed(), "failures: {:?}", report.failures());
    }

    #[test]
    fn wrong_golden_frame_is_reported() {
        let mut bad = case();
        bad.expected_read = fp(251, -1);
        let report = ConformanceHarness::new(&|| 0).check_codec(&TextDriver, &[bad]);
        assert!(!report.passed());
        assert!(
            report
                .failures()
                .iter()
                .any(|check| check.name == "round_trip:temperature"),
            "{:?}",
            report.failures()
        );
    }

    #[test]
    fn empty_suite_and_no_sources_fail_vacuously() {
        let harness = ConformanceHarness::new(&|| 0);
        assert!(!harness.check_codec(&TextDriver, &[]).passed());
        assert!(!harness.check_bounded_time(&TextDriver, &[]).passed());
        assert!(!check_no_io(&[]).passed());
    }

    #[test]
    fn io_token_in_source_is_reported() {
        let report = check_no_io(&[SourceFile {
            path: "src/lib.rs",
            contents: "use std::net::TcpStream;\n",
        }]);
        assert!(!report.passed());
    }

    #[test]
    fn commented_io_token_is_ignored() {
        let report = check_no_io(&[SourceFile {
            path: "src/lib.rs",
            contents: "// drivers never use std::net\npub fn f() {}\n",
        }]);
        assert!(report.passed());
    }

    #[test]
    fn word_order_has_golden_permutations() {
        assert!(check_word_order().passed());
    }
}
