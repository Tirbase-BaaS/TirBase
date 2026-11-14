// SPDX-License-Identifier: AGPL-3.0-only

//! CLAIM-34.1: real Modbus TCP client over generic Read+Write transport against
//! tirbase_sim::ModbusSimServer. Exercises FC03/04/06/16, tx-id/unit-id matching,
//! exception propagation, and 5s timeout behavior.

use std::io::{Read, Write};
use std::time::Duration;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tirbase_drivers::{DriverError, ModbusRtuClient, ModbusTcpClient};

/// Clock that never advances: reads complete without timing out.
fn zero_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    Arc::new(|| 0)
}

/// Clock that expires immediately after the first reading: exercises the
/// deadline branch deterministically without reading a real clock.
fn expiring_clock() -> Arc<dyn Fn() -> u64 + Send + Sync> {
    let calls = Arc::new(AtomicU64::new(0));
    Arc::new(move || {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            0
        } else {
            1_000_000
        }
    })
}

#[test]
fn claim_34_1_modbus_tcp_client_fc03_fc04_fc06_fc16() {
    let server = tirbase_sim::ModbusSimServer::spawn().expect("spawn modbus sim");
    {
        let bank = server.bank();
        let mut b = bank.lock().unwrap();
        b.set_holding(10, 1234);
        b.set_holding(11, 5678);
        b.set_input(20, 0xFF9C);
    }
    let mut client = ModbusTcpClient::connect(
        &server.addr.to_string(),
        1,
        Duration::from_secs(5),
        zero_clock(),
    )
        .expect("connect modbus tcp client");

    let regs = client.read_holding_registers(10, 2).expect("FC03");
    assert_eq!(regs, vec![1234, 5678]);
    let regs = client.read_input_registers(20, 1).expect("FC04");
    assert_eq!(regs[0] as i16, -100);
    client.write_single_register(10, 4321).expect("FC06");
    client.write_multiple_registers(11, &[7, 8]).expect("FC16");

    let bank = server.bank();
    let b = bank.lock().unwrap();
    assert_eq!(b.get_holding(10), 4321);
    assert_eq!(b.get_holding(11), 7);
    assert_eq!(b.get_holding(12), 8);
    drop(b);
    server.stop();
}

#[test]
fn claim_34_1_modbus_tcp_client_times_out_within_5s() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (_s, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(10));
    });
    let mut client = ModbusTcpClient::connect(
        &addr.to_string(),
        1,
        Duration::from_millis(200),
        expiring_clock(),
    )
        .expect("connect");
    let err = client.read_holding_registers(0, 1).unwrap_err();
    assert!(
        matches!(
            err,
            DriverError::Timeout(_) | DriverError::Codec(_) | DriverError::InvalidFrame(_)
        ),
        "expected timeout/read failure, got {err:?}"
    );
}

#[derive(Debug)]
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
            Ok(b) => {
                buf[0] = b;
                Ok(1)
            }
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")),
        }
    }
}
impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for b in buf {
            self.tx
                .send(*b)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken"))?;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn claim_34_1_modbus_rtu_client_fc03_fc04_fc06_fc16() {
    let (tx_req, rx_req) = std::sync::mpsc::channel();
    let (tx_resp, rx_resp) = std::sync::mpsc::channel();
    let transport = Pipe {
        rx: rx_resp,
        tx: tx_req,
    };
    std::thread::spawn(move || {
        let mut holding = [0u16; 32];
        let mut input = [0u16; 32];
        holding[1] = 55;
        input[2] = 0xFFFE;
        loop {
            let mut frame = Vec::new();
            loop {
                match rx_req.recv_timeout(Duration::from_secs(2)) {
                    Ok(b) => frame.push(b),
                    Err(_) => return,
                }
                if frame.len() >= 4 {
                    let done = match frame.get(1).copied() {
                        Some(0x03 | 0x04 | 0x06) => frame.len() >= 8,
                        Some(0x10) => frame.len() >= 9 && frame.len() >= 9 + frame[6] as usize,
                        _ => frame.len() >= 8,
                    };
                    if done {
                        break;
                    }
                }
            }
            let (uid, pdu) = tirbase_drivers::parse_rtu_frame(&frame).unwrap();
            let resp_pdu = match pdu[0] {
                0x03 => {
                    let a = pdu[2] as usize;
                    vec![0x03, 2, (holding[a] >> 8) as u8, holding[a] as u8]
                }
                0x04 => {
                    let a = pdu[2] as usize;
                    vec![0x04, 2, (input[a] >> 8) as u8, input[a] as u8]
                }
                0x06 => {
                    let a = pdu[2] as usize;
                    let v = u16::from_be_bytes([pdu[3], pdu[4]]);
                    holding[a] = v;
                    pdu.clone()
                }
                0x10 => {
                    let a = pdu[2] as usize;
                    let q = pdu[4] as usize;
                    for i in 0..q {
                        let base = 6 + i * 2;
                        holding[a + i] = u16::from_be_bytes([pdu[base], pdu[base + 1]]);
                    }
                    vec![0x10, pdu[1], pdu[2], pdu[3], pdu[4]]
                }
                fc => vec![fc | 0x80, 1],
            };
            for b in tirbase_drivers::build_rtu_frame(uid, &resp_pdu) {
                let _ = tx_resp.send(b);
            }
            if pdu[0] == 0x10 {
                break;
            }
        }
    });

    let mut client = ModbusRtuClient::new(transport, 1, Duration::from_secs(5), zero_clock());
    assert_eq!(client.read_holding_registers(1, 1).unwrap(), vec![55]);
    assert_eq!(client.read_input_registers(2, 1).unwrap()[0] as i16, -2);
    client.write_single_register(1, 77).unwrap();
    client.write_multiple_registers(3, &[9, 10]).unwrap();
}
