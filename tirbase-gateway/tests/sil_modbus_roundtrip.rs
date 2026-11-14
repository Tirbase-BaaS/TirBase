// SPDX-License-Identifier: AGPL-3.0-only

//! Software-in-the-loop Modbus rig (CLAIM-52.2 support).
//!
//! The physical HIL tests in `hil_modbus_roundtrip.rs` need a real RS-485 bus
//! and device. This test runs the **same production client** (`ModbusTcpClient`
//! from `tirbase-drivers`) against an in-process Modbus TCP slave, so FC
//! 03/04/06/16 framing, decoding and exception handling are executed on every
//! CI run instead of only on lab hardware.
//!
//! It is explicitly *not* a substitute for the hardware claim: it proves the
//! protocol path, not the electrical/bus behaviour.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tirbase_drivers::modbus::ModbusTcpClient;

const REGISTERS: usize = 16;

struct Slave {
    registers: Arc<Mutex<[u16; REGISTERS]>>,
    stop: Arc<AtomicBool>,
    addr: std::net::SocketAddr,
}

impl Slave {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind slave");
        let addr = listener.local_addr().expect("slave addr");
        let registers = Arc::new(Mutex::new([0u16; REGISTERS]));
        let stop = Arc::new(AtomicBool::new(false));
        let regs = registers.clone();
        let stop_thread = stop.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_thread.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = stream {
                    let _ = serve(stream, &regs);
                }
            }
        });
        Slave {
            registers,
            stop,
            addr,
        }
    }
}

impl Drop for Slave {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn serve(mut stream: TcpStream, registers: &Arc<Mutex<[u16; REGISTERS]>>) -> std::io::Result<()> {
    loop {
        let mut header = [0u8; 7];
        if stream.read_exact(&mut header).is_err() {
            return Ok(());
        }
        let tid = u16::from_be_bytes([header[0], header[1]]);
        let unit = header[6];
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let mut pdu = vec![0u8; len.saturating_sub(1)];
        stream.read_exact(&mut pdu)?;

        let fc = pdu[0];
        let mut regs = registers.lock().unwrap();
        let response: Vec<u8> = match fc {
            0x03 | 0x04 => {
                let address = u16::from_be_bytes([pdu[1], pdu[2]]) as usize;
                let quantity = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
                if address + quantity > REGISTERS {
                    vec![fc | 0x80, 0x02]
                } else {
                    let mut out = vec![fc, (quantity * 2) as u8];
                    for value in &regs[address..address + quantity] {
                        out.extend_from_slice(&value.to_be_bytes());
                    }
                    out
                }
            }
            0x06 => {
                let address = u16::from_be_bytes([pdu[1], pdu[2]]) as usize;
                let value = u16::from_be_bytes([pdu[3], pdu[4]]);
                if address >= REGISTERS {
                    vec![fc | 0x80, 0x02]
                } else {
                    regs[address] = value;
                    pdu.clone()
                }
            }
            0x10 => {
                let address = u16::from_be_bytes([pdu[1], pdu[2]]) as usize;
                let quantity = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
                if address + quantity > REGISTERS {
                    vec![fc | 0x80, 0x02]
                } else {
                    for (offset, chunk) in pdu[6..].chunks_exact(2).take(quantity).enumerate() {
                        regs[address + offset] = u16::from_be_bytes([chunk[0], chunk[1]]);
                    }
                    vec![0x10, pdu[1], pdu[2], pdu[3], pdu[4]]
                }
            }
            _ => vec![fc | 0x80, 0x01],
        };

        let mut out = Vec::with_capacity(7 + response.len());
        out.extend_from_slice(&tid.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&((response.len() + 1) as u16).to_be_bytes());
        out.push(unit);
        out.extend_from_slice(&response);
        stream.write_all(&out)?;
        stream.flush()?;
    }
}

fn client(slave: &Slave) -> ModbusTcpClient<TcpStream> {
    let stream = TcpStream::connect(slave.addr).expect("connect slave");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    ModbusTcpClient::new(
        stream,
        1,
        Duration::from_secs(2),
        Arc::new(|| 0u64),
    )
}

#[test]
fn sil_modbus_fc03_fc04_fc06_fc16_round_trips() {
    let slave = Slave::start();
    let mut client = client(&slave);

    client.write_single_register(5, 1234).expect("FC06 write");
    assert_eq!(
        client.read_holding_registers(5, 1).expect("FC03 read"),
        vec![1234]
    );

    client
        .write_multiple_registers(7, &[11, 22, 33])
        .expect("FC16 write");
    assert_eq!(
        client.read_holding_registers(7, 3).expect("FC03 read back"),
        vec![11, 22, 33]
    );
    assert_eq!(
        client.read_input_registers(7, 3).expect("FC04 read"),
        vec![11, 22, 33]
    );

 // The slave really holds the values (not just an echo).
    assert_eq!(slave.registers.lock().unwrap()[5], 1234);
    assert_eq!(&slave.registers.lock().unwrap()[7..10], &[11, 22, 33]);
}

#[test]
fn sil_modbus_out_of_range_read_returns_exception() {
    let slave = Slave::start();
    let mut client = client(&slave);
    let error = client
        .read_holding_registers(15, 4)
        .expect_err("out-of-range read must surface the Modbus exception");
    let text = format!("{error:?}");
    assert!(
        text.to_lowercase().contains("exception") || text.contains("2"),
        "expected a Modbus exception error, got {text}"
    );
}
