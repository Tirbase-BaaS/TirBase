// SPDX-License-Identifier: AGPL-3.0-only

//! Minimal Modbus TCP server for integration tests and conformance (CLAIM-34.1, PV-10.7).
//! Supports FC 03, 04, 06, 16 against an in-memory register bank.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Default)]
pub struct RegisterBank {
    pub holding: BTreeMap<u16, u16>,
    pub input: BTreeMap<u16, u16>,
}

impl RegisterBank {
    pub fn get_holding(&self, addr: u16) -> u16 {
        *self.holding.get(&addr).unwrap_or(&0)
    }
    pub fn get_input(&self, addr: u16) -> u16 {
        *self.input.get(&addr).unwrap_or(&0)
    }
    pub fn set_holding(&mut self, addr: u16, value: u16) {
        self.holding.insert(addr, value);
    }
    pub fn set_input(&mut self, addr: u16, value: u16) {
        self.input.insert(addr, value);
    }
}

#[derive(Clone)]
pub struct ModbusServerHandle {
    pub addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    bank: Arc<Mutex<RegisterBank>>,
}

impl ModbusServerHandle {
    pub fn bank(&self) -> Arc<Mutex<RegisterBank>> {
        Arc::clone(&self.bank)
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

pub struct ModbusSimServer;

impl ModbusSimServer {
 /// Bind on an ephemeral port and spawn a background accept loop.
    pub fn spawn() -> std::io::Result<ModbusServerHandle> {
        Self::spawn_with_bank(RegisterBank::default())
    }

    pub fn spawn_with_bank(bank: RegisterBank) -> std::io::Result<ModbusServerHandle> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let bank = Arc::new(Mutex::new(bank));
        let stop_t = Arc::clone(&stop);
        let bank_t = Arc::clone(&bank);
        thread::spawn(move || {
            while !stop_t.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let b = Arc::clone(&bank_t);
                        let s = Arc::clone(&stop_t);
                        thread::spawn(move || {
                            let _ = handle_conn(stream, b, s);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(ModbusServerHandle { addr, stop, bank })
    }
}

fn read_exact_or_eof(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) => return Ok(false),
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn handle_conn(
    mut stream: TcpStream,
    bank: Arc<Mutex<RegisterBank>>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    stream.set_write_timeout(Some(Duration::from_millis(200)))?;
    while !stop.load(Ordering::SeqCst) {
        let mut mbap = [0u8; 7];
        match read_exact_or_eof(&mut stream, &mut mbap) {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(e) => return Err(e),
        }
        let len = u16::from_be_bytes([mbap[4], mbap[5]]) as usize;
        if !(2..=260).contains(&len) {
            return Ok(());
        }
        let mut rest = vec![0u8; len.saturating_sub(1)];
        if !read_exact_or_eof(&mut stream, &mut rest)? {
            return Ok(());
        }
        let mut pdu = Vec::with_capacity(1 + rest.len());
        pdu.push(mbap[6]); // not used; real PDU follows in rest? MBAP: uid is byte 6, PDU starts byte 7.
 // We read 7 bytes total into mbap: [tid0 tid1 pid0 pid1 len0 len1 uid]
        pdu.clear();
        pdu.extend_from_slice(&rest); // rest contains full PDU starting at FC
        let resp_pdu = process_pdu(&pdu, &bank);
        let resp_len = (1 + resp_pdu.len()) as u16;
        let mut out = Vec::with_capacity(7 + resp_pdu.len());
        out.extend_from_slice(&mbap[0..2]); // tid
        out.extend_from_slice(&[0, 0]); // pid
        out.extend_from_slice(&resp_len.to_be_bytes());
        out.push(mbap[6]); // uid
        out.extend_from_slice(&resp_pdu);
        let _ = stream.write_all(&out);
    }
    Ok(())
}

fn exception(fc: u8, code: u8) -> Vec<u8> {
    vec![fc | 0x80, code]
}

fn process_pdu(pdu: &[u8], bank: &Arc<Mutex<RegisterBank>>) -> Vec<u8> {
    if pdu.is_empty() {
        return exception(0, 1);
    }
    let fc = pdu[0];
    match fc {
        0x03 => {
            if pdu.len() < 5 {
                return exception(fc, 3);
            }
            let addr = u16::from_be_bytes([pdu[1], pdu[2]]);
            let qty = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
            if qty == 0 || qty > 125 {
                return exception(fc, 3);
            }
            let b = bank.lock().unwrap();
            let mut out = vec![0x03, (qty * 2) as u8];
            for i in 0..qty {
                out.extend_from_slice(&b.get_holding(addr.wrapping_add(i as u16)).to_be_bytes());
            }
            out
        }
        0x04 => {
            if pdu.len() < 5 {
                return exception(fc, 3);
            }
            let addr = u16::from_be_bytes([pdu[1], pdu[2]]);
            let qty = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
            if qty == 0 || qty > 125 {
                return exception(fc, 3);
            }
            let b = bank.lock().unwrap();
            let mut out = vec![0x04, (qty * 2) as u8];
            for i in 0..qty {
                out.extend_from_slice(&b.get_input(addr.wrapping_add(i as u16)).to_be_bytes());
            }
            out
        }
        0x06 => {
            if pdu.len() < 5 {
                return exception(fc, 3);
            }
            let addr = u16::from_be_bytes([pdu[1], pdu[2]]);
            let val = u16::from_be_bytes([pdu[3], pdu[4]]);
            bank.lock().unwrap().set_holding(addr, val);
            pdu[0..5].to_vec()
        }
        0x10 => {
            if pdu.len() < 6 {
                return exception(fc, 3);
            }
            let addr = u16::from_be_bytes([pdu[1], pdu[2]]);
            let qty = u16::from_be_bytes([pdu[3], pdu[4]]);
            let byte_count = pdu[5] as usize;
            if byte_count != qty as usize * 2 || pdu.len() < 6 + byte_count {
                return exception(fc, 3);
            }
            let mut b = bank.lock().unwrap();
            for i in 0..qty as usize {
                let v = u16::from_be_bytes([pdu[6 + i * 2], pdu[7 + i * 2]]);
                b.set_holding(addr.wrapping_add(i as u16), v);
            }
            vec![0x10, pdu[1], pdu[2], pdu[3], pdu[4]]
        }
        _ => exception(fc, 1),
    }
}

impl Drop for ModbusServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}
