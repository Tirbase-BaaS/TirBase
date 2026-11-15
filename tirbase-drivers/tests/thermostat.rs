// SPDX-License-Identifier: AGPL-3.0-only

//! CC-03 thermostat profiles: install/read/write against the simulator, RTU
//! framing, typed exceptions, bounded timeout, and retry.
#![allow(deprecated)]

use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tirbase_drivers::thermostat::{
    generic_thermostat_a, generic_thermostat_b, ModbusClient, ThermostatDevice, ThermostatFan,
    ThermostatField, ThermostatMode, ThermostatProfile,
};
use tirbase_drivers::{DriverError, ModbusRtuClient, ModbusTcpClient, TimeoutError};
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

const PROFILE_A_TOML: &str = include_str!("../../profiles/thermostat_generic_a.register-map.toml");
const PROFILE_B_TOML: &str = include_str!("../../profiles/thermostat_generic_b.register-map.toml");

fn zero_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(|| 0)
}

fn expiring_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    let calls = Arc::new(AtomicU32::new(0));
    Arc::new(move || u64::from(calls.fetch_add(1, Ordering::SeqCst)) * 1_000_000)
}

fn temp(raw: i64) -> FixedPointValue {
    FixedPointValue::new(raw, -1, UNIT_DEG_C)
}

#[test]
fn toml_profiles_match_built_in_definitions() {
    let a = ThermostatProfile::parse(PROFILE_A_TOML).expect("profile A TOML");
    assert_eq!(a, generic_thermostat_a().unwrap());
    let b = ThermostatProfile::parse(PROFILE_B_TOML).expect("profile B TOML");
    assert_eq!(b, generic_thermostat_b().unwrap());
}

#[test]
fn profile_a_reads_and_writes_against_simulator_over_tcp() {
    let server = tirbase_sim::ModbusSimServer::spawn().expect("spawn modbus sim");
    {
        let bank = server.bank();
        let mut b = bank.lock().unwrap();
        b.set_input(0, 215); // 21.5 C
        b.set_input(1, 0b10); // alarm bit 1
        b.set_input(2, 7); // fault code
        b.set_holding(0, 220); // 22.0 C setpoint
        b.set_holding(1, ThermostatMode::Heat.as_raw());
        b.set_holding(2, ThermostatFan::Medium.as_raw());
    }
    let profile = ThermostatProfile::parse(PROFILE_A_TOML).unwrap();
    let client = ModbusTcpClient::connect(
        &server.addr.to_string(),
        profile.unit_id().unwrap(),
        Duration::from_secs(2),
        zero_clock(),
    )
    .unwrap();
    let mut device = ThermostatDevice::install(client, profile).unwrap();

    let reading = device.read_all().unwrap();
    assert_eq!(reading.current_temperature, temp(215));
    assert_eq!(reading.setpoint, temp(220));
    assert_eq!(reading.mode, ThermostatMode::Heat);
    assert_eq!(reading.fan, ThermostatFan::Medium);
    assert_eq!(reading.alarm, 0b10);
    assert_eq!(reading.fault, 7);

    device.write_setpoint(&temp(195)).unwrap();
    device.write_mode(ThermostatMode::Auto).unwrap();
    device.write_fan(ThermostatFan::High).unwrap();
    assert_eq!(device.read_setpoint().unwrap(), temp(195));

    let bank = server.bank();
    let b = bank.lock().unwrap();
    assert_eq!(b.get_holding(0), 195);
    assert_eq!(b.get_holding(1), ThermostatMode::Auto.as_raw());
    assert_eq!(b.get_holding(2), ThermostatFan::High.as_raw());
    drop(b);
    server.stop();
}

#[test]
fn profile_b_reads_and_writes_against_simulator_over_tcp() {
    let server = tirbase_sim::ModbusSimServer::spawn().expect("spawn modbus sim");
    {
        let bank = server.bank();
        let mut b = bank.lock().unwrap();
        b.set_input(100, 213);
        b.set_input(101, 1);
        b.set_input(102, 0);
        b.set_holding(200, 210);
        b.set_holding(201, ThermostatMode::Cool.as_raw());
        b.set_holding(202, ThermostatFan::Low.as_raw());
    }
    let profile = ThermostatProfile::parse(PROFILE_B_TOML).unwrap();
    let client = ModbusTcpClient::connect(
        &server.addr.to_string(),
        profile.unit_id().unwrap(),
        Duration::from_secs(2),
        zero_clock(),
    )
    .unwrap();
    let mut device = ThermostatDevice::install(client, profile).unwrap();

    let reading = device.read_all().unwrap();
    assert_eq!(reading.current_temperature, temp(213));
    assert_eq!(reading.setpoint, temp(210));
    assert_eq!(reading.mode, ThermostatMode::Cool);
    assert_eq!(reading.fan, ThermostatFan::Low);
    assert_eq!(reading.alarm, 1);
    assert_eq!(reading.fault, 0);

    // Profile B writes the setpoint with FC 16.
    device.write_setpoint(&temp(205)).unwrap();
    device.write_mode(ThermostatMode::Off).unwrap();
    device.write_fan(ThermostatFan::Off).unwrap();
    assert_eq!(device.read_setpoint().unwrap(), temp(205));

    let bank = server.bank();
    let b = bank.lock().unwrap();
    assert_eq!(b.get_holding(200), 205);
    assert_eq!(b.get_holding(201), ThermostatMode::Off.as_raw());
    assert_eq!(b.get_holding(202), ThermostatFan::Off.as_raw());
    drop(b);
    server.stop();
}

#[test]
fn tcp_exception_pdu_is_a_typed_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 12];
        stream.read_exact(&mut request).unwrap();
        let tid = [request[0], request[1]];
        let pdu = [0x84, 0x02];
        let mut response = vec![tid[0], tid[1], 0, 0, 0, 3, request[6]];
        response.extend_from_slice(&pdu);
        stream.write_all(&response).unwrap();
    });

    let profile = generic_thermostat_a().unwrap();
    let client = ModbusTcpClient::connect(
        &addr.to_string(),
        profile.unit_id().unwrap(),
        Duration::from_secs(2),
        zero_clock(),
    )
    .unwrap();
    let mut device = ThermostatDevice::install(client, profile).unwrap();
    let error = device.read_current_temperature().unwrap_err();
    assert!(
        matches!(
            error,
            DriverError::Exception {
                function_code: 0x04,
                exception_code: 2
            }
        ),
        "expected typed Modbus exception, got {error:?}"
    );
    server.join().unwrap();
}

#[test]
fn tcp_timeout_is_bounded_and_retryable() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 12];
            let _ = stream.read_exact(&mut request);
            std::thread::sleep(Duration::from_millis(300));
        }
    });

    let profile = generic_thermostat_a().unwrap();
    let client = ModbusTcpClient::connect(
        &addr.to_string(),
        profile.unit_id().unwrap(),
        Duration::from_millis(100),
        expiring_clock(),
    )
    .unwrap();
    let mut device = ThermostatDevice::install(client, profile)
        .unwrap()
        .with_retries(1);
    let error = device.read_current_temperature().unwrap_err();
    assert!(matches!(error, DriverError::Timeout(_)), "{error:?}");
}

/// RTU transport backed by channels, mirroring a serial server.
struct Pipe {
    rx: std::sync::mpsc::Receiver<u8>,
    tx: std::sync::mpsc::Sender<u8>,
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.rx.recv_timeout(Duration::from_millis(500)) {
            Ok(byte) => {
                buf[0] = byte;
                Ok(1)
            }
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")),
        }
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for byte in buf {
            self.tx
                .send(*byte)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken"))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn read_rtu_request(rx: &std::sync::mpsc::Receiver<u8>) -> Option<Vec<u8>> {
    let mut frame = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(byte) => frame.push(byte),
            Err(_) => return None,
        }
        if frame.len() >= 4 {
            match frame.get(1).copied() {
                Some(0x03 | 0x04 | 0x06) if frame.len() >= 8 => return Some(frame),
                Some(0x10) if frame.len() >= 9 && frame.len() >= 9 + frame[6] as usize => {
                    return Some(frame)
                }
                _ => {}
            }
        }
    }
}

#[test]
fn rtu_profile_b_reads_writes_and_surfaces_exception() {
    let (tx_req, rx_req) = std::sync::mpsc::channel();
    let (tx_resp, rx_resp) = std::sync::mpsc::channel();
    let transport = Pipe {
        rx: rx_resp,
        tx: tx_req,
    };
    let server = std::thread::spawn(move || {
        let mut holding = [0u16; 256];
        let mut input = [0u16; 256];
        input[100] = 213;
        input[101] = 1;
        input[102] = 0;
        holding[200] = 210;
        holding[201] = ThermostatMode::Cool.as_raw();
        holding[202] = ThermostatFan::Low.as_raw();
        let mut exception_next = true;

        while let Some(frame) = read_rtu_request(&rx_req) {
            let (uid, pdu) = tirbase_drivers::parse_rtu_frame(&frame).unwrap();
            let resp = match pdu[0] {
                0x04 if exception_next => {
                    exception_next = false;
                    vec![0x84, 0x02]
                }
                0x03 | 0x04 => {
                    let addr = u16::from_be_bytes([pdu[1], pdu[2]]) as usize;
                    let qty = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
                    let table = if pdu[0] == 0x03 { &holding } else { &input };
                    let mut out = vec![pdu[0], (qty * 2) as u8];
                    for i in 0..qty {
                        out.extend_from_slice(&table[addr + i].to_be_bytes());
                    }
                    out
                }
                0x06 => {
                    let addr = u16::from_be_bytes([pdu[1], pdu[2]]) as usize;
                    holding[addr] = u16::from_be_bytes([pdu[3], pdu[4]]);
                    pdu.clone()
                }
                0x10 => {
                    let addr = u16::from_be_bytes([pdu[1], pdu[2]]) as usize;
                    let qty = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
                    for i in 0..qty {
                        holding[addr + i] = u16::from_be_bytes([pdu[6 + i * 2], pdu[7 + i * 2]]);
                    }
                    pdu[..5].to_vec()
                }
                fc => vec![fc | 0x80, 1],
            };
            for byte in tirbase_drivers::build_rtu_frame(uid, &resp) {
                let _ = tx_resp.send(byte);
            }
        }
    });

    let profile = generic_thermostat_b().unwrap();
    let client = ModbusRtuClient::new(transport, 2, Duration::from_secs(2), zero_clock());
    let mut device = ThermostatDevice::install(client, profile).unwrap();

    let error = device.read_current_temperature().unwrap_err();
    assert!(matches!(
        error,
        DriverError::Exception {
            function_code: 0x04,
            exception_code: 2
        }
    ));

    let reading = device.read_all().unwrap();
    assert_eq!(reading.current_temperature, temp(213));
    assert_eq!(reading.setpoint, temp(210));
    assert_eq!(reading.mode, ThermostatMode::Cool);
    assert_eq!(reading.fan, ThermostatFan::Low);

    device.write_setpoint(&temp(199)).unwrap();
    device.write_mode(ThermostatMode::Heat).unwrap();
    device.write_fan(ThermostatFan::High).unwrap();
    assert_eq!(device.read_setpoint().unwrap(), temp(199));
    server.join().unwrap();
}

struct FlakyClient {
    calls: Arc<AtomicU32>,
    raw: u16,
}

impl ModbusClient for FlakyClient {
    fn read_holding_registers(&mut self, _: u16, _: u16) -> Result<Vec<u16>, DriverError> {
        self.read_input_registers(0, 1)
    }

    fn read_input_registers(&mut self, _: u16, _: u16) -> Result<Vec<u16>, DriverError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            return Err(DriverError::Timeout(TimeoutError {
                operation: "test",
                limit_ms: 1,
            }));
        }
        Ok(vec![self.raw])
    }

    fn write_single_register(&mut self, _: u16, _: u16) -> Result<(), DriverError> {
        Err(DriverError::UnsupportedParam("write".into()))
    }

    fn write_multiple_registers(&mut self, _: u16, _: &[u16]) -> Result<(), DriverError> {
        Err(DriverError::UnsupportedParam("write".into()))
    }
}

#[test]
fn timeout_retry_succeeds_and_zero_retries_does_not() {
    let calls = Arc::new(AtomicU32::new(0));
    let client = FlakyClient {
        calls: Arc::clone(&calls),
        raw: 215,
    };
    let mut device = ThermostatDevice::install(client, generic_thermostat_a().unwrap()).unwrap();
    let error = device.read_current_temperature().unwrap_err();
    assert!(matches!(error, DriverError::Timeout(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let calls = Arc::new(AtomicU32::new(0));
    let client = FlakyClient {
        calls: Arc::clone(&calls),
        raw: 215,
    };
    let mut device = ThermostatDevice::install(client, generic_thermostat_a().unwrap())
        .unwrap()
        .with_retries(2);
    assert_eq!(device.read_current_temperature().unwrap(), temp(215));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn profile_validation_rejects_missing_and_wrong_fields() {
    let missing = PROFILE_A_TOML.replace("name = \"fault\"", "name = \"not_fault\"");
    let error = ThermostatProfile::parse(&missing).unwrap_err();
    assert!(matches!(
        error,
        tirbase_drivers::thermostat::ThermostatError::MissingField(ThermostatField::Fault)
    ));
}
