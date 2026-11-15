// SPDX-License-Identifier: AGPL-3.0-only

//! Modbus TCP/RTU clients (CLAIM-34.1, PV-10.7).
//!
//! The pure frame codec — FC 03/04/06/16 request builders, response decoders,
//! MBAP/RTU framing, and CRC-16 — lives in the Apache-2.0
//! `tirbase_driver_api::modbus_codec` crate and is re-exported here. This module
//! owns the transport clients; the guard/transport owns the actual device I/O.
//!
//! ## TCP framing (MBAP)
//! `transaction_id(u16) | protocol_id(u16=0) | length(u16) | unit_id(u8) | PDU`
//!
//! ## RTU framing
//! `unit_id(u8) | PDU | crc16(u16 LE)` — CRC over `unit_id + PDU`.

use std::sync::Arc;

use tirbase_driver_api::driver_trait::{DriverError, DriverResult, TimeoutError};

// The pure frame codec (FC 03/04/06/16, MBAP/RTU parsing, CRC-16) lives in the
// Apache-2.0 `tirbase-driver-api` crate. Re-exported here for compatibility.
pub use tirbase_driver_api::modbus_codec::*;

/// Caller-supplied monotonic millisecond clock (PV-3.12): drivers never read a
/// clock, because they may not depend on `tirbase-core`'s `TimeSource`.
pub type MonotonicMillisFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Real Modbus TCP client over any `Read + Write` transport (CLAIM-34.1).
/// All I/O uses explicit timeouts; frame building/decoding delegates to the
/// pure codec helpers above.
pub struct ModbusTcpClient<T: std::io::Read + std::io::Write> {
    transport: T,
    pub unit_id: u8,
    next_transaction: u16,
    io_timeout: std::time::Duration,
    clock: MonotonicMillisFn,
}

impl<T: std::io::Read + std::io::Write> ModbusTcpClient<T> {
    pub fn new(
        transport: T,
        unit_id: u8,
        io_timeout: std::time::Duration,
        clock: MonotonicMillisFn,
    ) -> Self {
        Self {
            transport,
            unit_id,
            next_transaction: 1,
            io_timeout,
            clock,
        }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    fn alloc_tid(&mut self) -> u16 {
        let t = self.next_transaction;
        self.next_transaction = self.next_transaction.wrapping_add(1).max(1);
        t
    }

    fn request(&mut self, pdu: &[u8]) -> DriverResult<ModbusTcpAdu> {
        let _span = tracing::info_span!(
            "adapter.modbus.request",
            audit = true,
            adapter = "modbus",
            transport = "tcp",
            unit_id = self.unit_id,
            pdu_len = pdu.len()
        )
        .entered();
        let tid = self.alloc_tid();
        let len = (1 + pdu.len()) as u16;
        let mut out = Vec::with_capacity(7 + pdu.len());
        out.extend_from_slice(&tid.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&len.to_be_bytes());
        out.push(self.unit_id);
        out.extend_from_slice(pdu);
        self.transport
            .write_all(&out)
            .and_then(|_| self.transport.flush())
            .map_err(|e| DriverError::Codec(format!("modbus write: {e}")))?;
        let adu = read_tcp_adu_with_timeout(&mut self.transport, self.io_timeout, &*self.clock)?;
        if adu.transaction_id != tid {
            return Err(DriverError::InvalidFrame(format!(
                "transaction id mismatch: expected {tid}, got {}",
                adu.transaction_id
            )));
        }
        if adu.unit_id != self.unit_id {
            return Err(DriverError::InvalidFrame(format!(
                "unit id mismatch: expected {}, got {}",
                self.unit_id, adu.unit_id
            )));
        }
        Ok(adu)
    }

    pub fn read_holding_registers(
        &mut self,
        address: u16,
        quantity: u16,
    ) -> DriverResult<Vec<u16>> {
        let pdu = [
            0x03,
            (address >> 8) as u8,
            address as u8,
            (quantity >> 8) as u8,
            quantity as u8,
        ];
        let adu = self.request(&pdu)?;
        decode_read_registers_response(&adu.pdu, 0x03)
    }

    pub fn read_input_registers(&mut self, address: u16, quantity: u16) -> DriverResult<Vec<u16>> {
        let pdu = [
            0x04,
            (address >> 8) as u8,
            address as u8,
            (quantity >> 8) as u8,
            quantity as u8,
        ];
        let adu = self.request(&pdu)?;
        decode_read_registers_response(&adu.pdu, 0x04)
    }

    pub fn write_single_register(&mut self, address: u16, value: u16) -> DriverResult<()> {
        let pdu = [
            0x06,
            (address >> 8) as u8,
            address as u8,
            (value >> 8) as u8,
            value as u8,
        ];
        let adu = self.request(&pdu)?;
        decode_write_single_response(&adu.pdu, address, value)
    }

    pub fn write_multiple_registers(&mut self, address: u16, values: &[u16]) -> DriverResult<()> {
        let quantity = values.len() as u16;
        let mut pdu = vec![
            0x10,
            (address >> 8) as u8,
            address as u8,
            (quantity >> 8) as u8,
            quantity as u8,
            (values.len() * 2) as u8,
        ];
        for v in values {
            pdu.extend_from_slice(&v.to_be_bytes());
        }
        let adu = self.request(&pdu)?;
        decode_write_multiple_response(&adu.pdu, address, quantity)
    }
}

/// Reads until `buf` is full, enforcing `timeout` against the caller-supplied
/// monotonic clock. Drivers must not depend on `tirbase-core` (layer
/// isolation, CLAIM-1.3), so the process-wide `TimeSource` is injected instead
/// of being read here (PV-3.12).
fn read_exact_timeout<R: std::io::Read>(
    r: &mut R,
    buf: &mut [u8],
    timeout: std::time::Duration,
    clock: &dyn Fn() -> u64,
) -> DriverResult<()> {
    let start = clock();
    let timeout_millis = timeout.as_millis() as u64;
    let mut off = 0;
    while off < buf.len() {
        if clock().saturating_sub(start) > timeout_millis {
            return Err(DriverError::Timeout(TimeoutError {
                operation: "modbus_read",
                limit_ms: timeout.as_millis() as u64,
            }));
        }
        match r.read(&mut buf[off..]) {
            Ok(0) => return Err(DriverError::InvalidFrame("unexpected EOF".into())),
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if clock().saturating_sub(start) > timeout_millis {
                    return Err(DriverError::Timeout(TimeoutError {
                        operation: "modbus_read",
                        limit_ms: timeout_millis,
                    }));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => return Err(DriverError::Codec(format!("modbus read: {e}"))),
        }
    }
    Ok(())
}

pub fn read_tcp_adu_with_timeout<R: std::io::Read>(
    r: &mut R,
    timeout: std::time::Duration,
    clock: &dyn Fn() -> u64,
) -> DriverResult<ModbusTcpAdu> {
    let mut mbap = [0u8; 7];
    read_exact_timeout(r, &mut mbap, timeout, clock)?;
    let len = u16::from_be_bytes([mbap[4], mbap[5]]) as usize;
    if !(2..=260).contains(&len) {
        return Err(DriverError::InvalidFrame(format!(
            "invalid MBAP length {len}"
        )));
    }
    let mut rest = vec![0u8; len - 1];
    read_exact_timeout(r, &mut rest, timeout, clock)?;
    let mut frame = mbap.to_vec();
    frame.extend_from_slice(&rest);
    parse_tcp_adu(&frame)
}

impl ModbusTcpClient<std::net::TcpStream> {
    pub fn connect(
        addr: &str,
        unit_id: u8,
        timeout: std::time::Duration,
        clock: MonotonicMillisFn,
    ) -> DriverResult<Self> {
        let addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| DriverError::Codec(format!("addr: {e}")))?;
        let stream = std::net::TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| DriverError::Codec(format!("connect: {e}")))?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();
        Ok(Self::new(stream, unit_id, timeout, clock))
    }
}

#[cfg(unix)]
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModbusRtuSerialConfig {
    pub baud_rate: u32,
    pub data_bits: u8,
    pub parity: ModbusRtuParity,
    pub stop_bits: u8,
    pub read_timeout_ms: u32,
}

#[cfg(unix)]
impl Default for ModbusRtuSerialConfig {
    fn default() -> Self {
        Self {
            baud_rate: 9600,
            data_bits: 8,
            parity: ModbusRtuParity::None,
            stop_bits: 1,
            read_timeout_ms: 1000,
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModbusRtuParity {
    #[default]
    None,
    Even,
    Odd,
}

/// Open and configure a Modbus RTU serial device (CLAIM-34.8, PV-10.4/PV-10.7).
///
/// Returns an owned file descriptor configured for raw 8N1/E/O RTU framing as
/// specified by `config`. The guard takes ownership of the resulting fd and may
/// pass it to an isolated driver child via `SCM_RIGHTS`.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn open_modbus_rtu(
    path: &std::path::Path,
    config: ModbusRtuSerialConfig,
) -> std::io::Result<std::os::unix::io::OwnedFd> {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    use nix::sys::termios::{
        self, BaudRate, ControlFlags, InputFlags, LocalFlags, OutputFlags, SetArg,
    };
    use std::os::unix::io::{AsFd, FromRawFd, OwnedFd};

    let fd = open(
        path,
        OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    // SAFETY: `nix::fcntl::open` returns a freshly opened fd on success.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut tio = termios::tcgetattr(owned.as_fd()).map_err(std::io::Error::from)?;
    termios::cfmakeraw(&mut tio);
    let baud = match config.baud_rate {
        1200 => BaudRate::B1200,
        2400 => BaudRate::B2400,
        4800 => BaudRate::B4800,
        9600 => BaudRate::B9600,
        19200 => BaudRate::B19200,
        38400 => BaudRate::B38400,
        57600 => BaudRate::B57600,
        115200 => BaudRate::B115200,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported Modbus RTU baud rate {}", config.baud_rate),
            ))
        }
    };
    termios::cfsetispeed(&mut tio, baud).map_err(std::io::Error::from)?;
    termios::cfsetospeed(&mut tio, baud).map_err(std::io::Error::from)?;

    tio.control_flags.remove(ControlFlags::CSIZE);
    tio.control_flags.insert(match config.data_bits {
        7 => ControlFlags::CS7,
        8 => ControlFlags::CS8,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported data bits {}", config.data_bits),
            ))
        }
    });
    match config.stop_bits {
        1 => tio.control_flags.remove(ControlFlags::CSTOPB),
        2 => tio.control_flags.insert(ControlFlags::CSTOPB),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported stop bits {}", config.stop_bits),
            ))
        }
    }
    match config.parity {
        ModbusRtuParity::None => {
            tio.control_flags.remove(ControlFlags::PARENB);
            tio.control_flags.remove(ControlFlags::PARODD);
        }
        ModbusRtuParity::Even => {
            tio.control_flags.insert(ControlFlags::PARENB);
            tio.control_flags.remove(ControlFlags::PARODD);
        }
        ModbusRtuParity::Odd => {
            tio.control_flags.insert(ControlFlags::PARENB);
            tio.control_flags.insert(ControlFlags::PARODD);
        }
    }
    tio.control_flags
        .insert(ControlFlags::CLOCAL | ControlFlags::CREAD);
    tio.input_flags.remove(
        InputFlags::IXON
            | InputFlags::IXOFF
            | InputFlags::IXANY
            | InputFlags::IGNPAR
            | InputFlags::PARMRK
            | InputFlags::INPCK,
    );
    tio.output_flags.remove(OutputFlags::OPOST);
    tio.local_flags.remove(
        LocalFlags::ECHO
            | LocalFlags::ECHONL
            | LocalFlags::ICANON
            | LocalFlags::ISIG
            | LocalFlags::IEXTEN,
    );
    // VMIN=0, VTIME in deciseconds for bounded reads.
    tio.control_chars[termios::SpecialCharacterIndices::VMIN as usize] = 0;
    tio.control_chars[termios::SpecialCharacterIndices::VTIME as usize] =
        ((config.read_timeout_ms / 100).clamp(1, 255)) as u8;
    termios::tcsetattr(owned.as_fd(), SetArg::TCSANOW, &tio).map_err(std::io::Error::from)?;
    termios::tcflush(owned.as_fd(), termios::FlushArg::TCIOFLUSH).map_err(std::io::Error::from)?;
    Ok(owned)
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModbusRtuParity {
    #[default]
    None,
    Even,
    Odd,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ModbusRtuSerialConfig {
    pub baud_rate: u32,
    pub data_bits: u8,
    pub parity: ModbusRtuParity,
    pub stop_bits: u8,
    pub read_timeout_ms: u32,
}

#[cfg(not(unix))]
pub fn open_modbus_rtu(
    _path: &std::path::Path,
    _config: ModbusRtuSerialConfig,
) -> std::io::Result<std::io::Stdin> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Modbus RTU serial open requires a Unix platform",
    ))
}

/// Real Modbus RTU client over a serial-like `Read + Write` transport.
pub struct ModbusRtuClient<T: std::io::Read + std::io::Write> {
    transport: T,
    pub unit_id: u8,
    io_timeout: std::time::Duration,
    clock: MonotonicMillisFn,
}

impl<T: std::io::Read + std::io::Write> ModbusRtuClient<T> {
    pub fn new(
        transport: T,
        unit_id: u8,
        io_timeout: std::time::Duration,
        clock: MonotonicMillisFn,
    ) -> Self {
        Self {
            transport,
            unit_id,
            io_timeout,
            clock,
        }
    }

    fn request(&mut self, pdu: &[u8], expected_fc: u8) -> DriverResult<Vec<u8>> {
        let _span = tracing::info_span!(
            "adapter.modbus.request",
            audit = true,
            adapter = "modbus",
            transport = "rtu",
            unit_id = self.unit_id,
            function_code = expected_fc
        )
        .entered();
        let frame = build_rtu_frame(self.unit_id, pdu);
        self.transport
            .write_all(&frame)
            .and_then(|_| self.transport.flush())
            .map_err(|e| DriverError::Codec(format!("rtu write: {e}")))?;
        let buf = self.read_response(expected_fc)?;
        let (uid, resp_pdu) = parse_rtu_frame(&buf)?;
        if uid != self.unit_id {
            return Err(DriverError::InvalidFrame(format!(
                "rtu unit id mismatch: {uid}"
            )));
        }
        if let Some((fc, ex)) = parse_exception(&resp_pdu) {
            return Err(DriverError::Exception {
                function_code: fc,
                exception_code: ex,
            });
        }
        if resp_pdu.first().copied() != Some(expected_fc) {
            return Err(DriverError::InvalidFrame(format!(
                "expected FC 0x{expected_fc:02x}, got 0x{:02x}",
                resp_pdu.first().copied().unwrap_or(0)
            )));
        }
        Ok(resp_pdu)
    }

    /// Reads an RTU response whose length depends on the function code and, for
    /// reads, the returned byte count. Exception frames are three bytes shorter
    /// than the success frame, so a fixed-length read would miss them.
    fn read_response(&mut self, expected_fc: u8) -> DriverResult<Vec<u8>> {
        let mut header = [0u8; 2];
        read_exact_timeout(
            &mut self.transport,
            &mut header,
            self.io_timeout,
            &*self.clock,
        )?;
        let mut frame = header.to_vec();
        if header[1] & 0x80 != 0 {
            // exception code + CRC
            let mut tail = [0u8; 3];
            read_exact_timeout(
                &mut self.transport,
                &mut tail,
                self.io_timeout,
                &*self.clock,
            )?;
            frame.extend_from_slice(&tail);
            return Ok(frame);
        }
        let tail_len = match expected_fc {
            0x03 | 0x04 => {
                let mut count = [0u8; 1];
                read_exact_timeout(
                    &mut self.transport,
                    &mut count,
                    self.io_timeout,
                    &*self.clock,
                )?;
                let byte_count = count[0] as usize;
                if byte_count == 0 || !byte_count.is_multiple_of(2) || byte_count > 250 {
                    return Err(DriverError::InvalidFrame(format!(
                        "invalid RTU byte count {byte_count}"
                    )));
                }
                frame.push(count[0]);
                byte_count + 2
            }
            0x06 | 0x10 => 6,
            other => {
                return Err(DriverError::InvalidFrame(format!(
                    "unsupported RTU response FC 0x{other:02x}"
                )))
            }
        };
        let mut tail = vec![0u8; tail_len];
        read_exact_timeout(
            &mut self.transport,
            &mut tail,
            self.io_timeout,
            &*self.clock,
        )?;
        frame.extend_from_slice(&tail);
        Ok(frame)
    }

    pub fn read_holding_registers(
        &mut self,
        address: u16,
        quantity: u16,
    ) -> DriverResult<Vec<u16>> {
        let pdu = [
            0x03,
            (address >> 8) as u8,
            address as u8,
            (quantity >> 8) as u8,
            quantity as u8,
        ];
        let resp_pdu = self.request(&pdu, 0x03)?;
        decode_read_registers_response(&resp_pdu, 0x03)
    }

    pub fn read_input_registers(&mut self, address: u16, quantity: u16) -> DriverResult<Vec<u16>> {
        let pdu = [
            0x04,
            (address >> 8) as u8,
            address as u8,
            (quantity >> 8) as u8,
            quantity as u8,
        ];
        let resp_pdu = self.request(&pdu, 0x04)?;
        decode_read_registers_response(&resp_pdu, 0x04)
    }

    pub fn write_single_register(&mut self, address: u16, value: u16) -> DriverResult<()> {
        let pdu = [
            0x06,
            (address >> 8) as u8,
            address as u8,
            (value >> 8) as u8,
            value as u8,
        ];
        let resp_pdu = self.request(&pdu, 0x06)?;
        decode_write_single_response(&resp_pdu, address, value)
    }

    pub fn write_multiple_registers(&mut self, address: u16, values: &[u16]) -> DriverResult<()> {
        let quantity = values.len() as u16;
        let mut pdu = vec![
            0x10,
            (address >> 8) as u8,
            address as u8,
            (quantity >> 8) as u8,
            quantity as u8,
            (values.len() * 2) as u8,
        ];
        for v in values {
            pdu.extend_from_slice(&v.to_be_bytes());
        }
        let resp_pdu = self.request(&pdu, 0x10)?;
        decode_write_multiple_response(&resp_pdu, address, quantity)
    }
}
