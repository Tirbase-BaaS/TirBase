//! `DeviceTransport` — parent/guard-owned connection to the physical device
//! (CLAIM-34.8, PV-10.4, PV-10.7, S35).
//!
//! Narrow `unsafe` is confined to Unix fd ownership boundaries (OwnedFd/raw fd).
#![allow(unsafe_code)]

use std::io;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

/// Parent-owned physical device transport.
#[derive(Debug)]
pub enum DeviceTransport {
    /// Modbus TCP client socket owned by the guard/parent.
    ModbusTcp(TcpStream),
    /// Modbus RTU / serial device fd owned by the guard/parent.
    #[cfg(unix)]
    ModbusRtu(OwnedFd),
    /// Generic pre-opened device fd owned by the guard/parent.
    #[cfg(unix)]
    Raw(OwnedFd),
}

impl DeviceTransport {
    pub fn connect_modbus_tcp(
        addr: &str,
        connect_timeout: Duration,
        io_timeout: Option<Duration>,
    ) -> io::Result<Self> {
        let addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid socket addr: {e}"),
            )
        })?;
        let stream = TcpStream::connect_timeout(&addr, connect_timeout)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(io_timeout)?;
        stream.set_write_timeout(io_timeout)?;
        Ok(DeviceTransport::ModbusTcp(stream))
    }

    /// Open/configure a Modbus RTU serial device. Real termios configuration is
    /// performed by the platform opener (typically `tirbase-drivers`); the guard
    /// takes ownership of the resulting fd.
    #[cfg(unix)]
    pub fn open_modbus_rtu_with<F>(opener: F) -> io::Result<Self>
    where
        F: FnOnce() -> io::Result<OwnedFd>,
    {
        Ok(DeviceTransport::ModbusRtu(opener()?))
    }

    #[cfg(unix)]
    pub fn from_modbus_rtu_fd(fd: OwnedFd) -> Self {
        DeviceTransport::ModbusRtu(fd)
    }

    #[cfg(unix)]
    pub fn from_raw_fd(fd: OwnedFd) -> Self {
        DeviceTransport::Raw(fd)
    }

    /// Legacy unsafe-shaped API retained for compatibility; callers should prefer
    /// `from_modbus_rtu_fd(OwnedFd)`.
    ///
    /// # Safety
    /// `fd` must be a valid, open file descriptor not owned elsewhere.
    #[cfg(unix)]
    pub unsafe fn from_raw_modbus_rtu(fd: RawFd) -> Self {
        DeviceTransport::ModbusRtu(OwnedFd::from_raw_fd(fd))
    }

    /// Real Modbus RTU serial open/config via platform opener (CLAIM-34.8).
    /// Production callers pass `tirbase_drivers::open_modbus_rtu` with a
    /// `ModbusRtuSerialConfig` (termios-configured fd); the guard owns the fd.
    #[cfg(unix)]
    pub fn open_modbus_rtu(
        path: &Path,
        baud_rate: u32,
        data_bits: u8,
        parity: tirbase_drivers::ModbusRtuParity,
        stop_bits: u8,
        read_timeout_ms: u32,
    ) -> io::Result<Self> {
        let cfg = tirbase_drivers::ModbusRtuSerialConfig {
            baud_rate,
            data_bits,
            parity,
            stop_bits,
            read_timeout_ms,
        };
        Self::open_modbus_rtu_with(|| tirbase_drivers::open_modbus_rtu(path, cfg))
    }

    /// Placeholder path-based RTU open for non-Unix or when no platform opener is
    /// supplied. Production callers must use `open_modbus_rtu_with` / `open_modbus_rtu`.
    pub fn modbus_rtu_path_unavailable(_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "real Modbus RTU open requires a Unix platform opener (open_modbus_rtu_with)",
        ))
    }

    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> RawFd {
        match self {
            DeviceTransport::ModbusTcp(s) => s.as_raw_fd(),
            DeviceTransport::ModbusRtu(fd) | DeviceTransport::Raw(fd) => fd.as_raw_fd(),
        }
    }

    #[cfg(unix)]
    pub fn try_clone_fd(&self) -> io::Result<OwnedFd> {
        match self {
            DeviceTransport::ModbusTcp(s) => s.try_clone().map(OwnedFd::from),
            DeviceTransport::ModbusRtu(fd) | DeviceTransport::Raw(fd) => fd.try_clone(),
        }
    }
}

/// Guard-side wiring: hold `DeviceTransport` and pass its fd to the driver child.
#[derive(Debug)]
pub struct GuardDeviceTransport {
    pub transport: DeviceTransport,
}

impl GuardDeviceTransport {
    pub fn new(transport: DeviceTransport) -> Self {
        Self { transport }
    }

    /// Pass the device fd to the child using the provided SCM_RIGHTS sender.
    ///
    /// `send_fd(socket_fd, device_fd)` must transfer `device_fd` via SCM_RIGHTS on
    /// `socket_fd`. Wiring mutation check (34.8): omitting SCM_RIGHTS passing must
    /// fail tests.
    #[cfg(unix)]
    pub fn pass_device_fd_with<F>(&self, socket_fd: RawFd, send_fd: F) -> io::Result<()>
    where
        F: FnOnce(RawFd, RawFd) -> io::Result<()>,
    {
        let dup = self.transport.try_clone_fd()?;
        let device_fd = dup.into_raw_fd();
        let res = send_fd(socket_fd, device_fd);
        if res.is_err() {
            // Reclaim the dup on sender failure; sender owns on success.
            // SAFETY: `device_fd` came from `into_raw_fd()` above and sender did not take it.
            drop(unsafe { OwnedFd::from_raw_fd(device_fd) });
        }
        res
    }

    #[cfg(unix)]
    /// Convenience: pass fd using a sender with a typed error.
    pub fn pass_device_fd_result<E, F>(&self, socket_fd: RawFd, send_fd: F) -> Result<(), E>
    where
        F: FnOnce(RawFd, RawFd) -> Result<(), E>,
        E: From<io::Error> + std::fmt::Display,
    {
        self.pass_device_fd_with(socket_fd, |sock, dev| {
            send_fd(sock, dev).map_err(|e| io::Error::other(e.to_string()))
        })
        .map_err(E::from)
    }

    #[cfg(not(unix))]
    pub fn pass_device_fd_with<F>(&self, _socket_fd: i32, _send_fd: F) -> io::Result<()>
    where
        F: FnOnce(i32, i32) -> io::Result<()>,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SCM_RIGHTS unavailable",
        ))
    }
}
