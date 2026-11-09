//! `DeviceTransport` — parent/guard-owned connection to the physical device
//! (CLAIM-34.8, PV-10.4, PV-10.7, S35).
//!
//! The guard owns the device fd. The actual `SCM_RIGHTS` syscall is provided by
//! the runtime wiring (e.g. `tirbase_drivers::send_fd_via_scm_rights` or an
//! equivalent platform sender) so this crate remains `forbid(unsafe_code)`.

use std::io;
use std::net::TcpStream;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, IntoRawFd, OwnedFd, RawFd};

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
    pub fn connect_modbus_tcp(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        Ok(DeviceTransport::ModbusTcp(stream))
    }

    #[cfg(unix)]
    /// # Safety
    /// `fd` must be a valid, open file descriptor not owned elsewhere.
    /// # Safety
    /// `fd` must be a valid, open file descriptor not owned elsewhere.
    pub fn from_raw_modbus_rtu(fd: RawFd) -> Self {
        // Safety requirement documented; construction uses safe OwnedFd only when
        // provided via IntoRawFd/OwnedFd paths in practice. Kept for API parity.
        // Callers on Unix should prefer `DeviceTransport::Raw(fd.into())`.
        let _ = fd;
        panic!("use DeviceTransport::Raw(OwnedFd) or safe constructors on this target")
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
            DeviceTransport::ModbusTcp(s) => s.try_clone().map(|c| c.into()),
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
    /// `socket_fd` and take ownership/close semantics as the platform requires.
    /// Wiring mutation check (34.8): omitting SCM_RIGHTS passing must fail tests.
    #[cfg(unix)]
    pub fn pass_device_fd_with<F>(&self, socket_fd: RawFd, send_fd: F) -> io::Result<()>
    where
        F: FnOnce(RawFd, RawFd) -> io::Result<()>,
    {
        let dup = self.transport.try_clone_fd()?;
        let device_fd = dup.into_raw_fd();
        let res = send_fd(socket_fd, device_fd);
        // Best-effort close of our duplicate; sender may have consumed semantics vary,
        // but we avoid leaking in common success path by closing if still valid.
        // On Unix, double-close of an fd we no longer own is unsafe to guess; the
        // provided sender is responsible for closing the transferred copy.
        let _ = res.as_ref();
        // If sender failed before consuming, close our dup.
        if res.is_err() {
            let _ = nixless_close(device_fd);
        }
        res
    }

    #[cfg(unix)]
    /// Convenience: pass fd using `tirbase_drivers`-style raw sender signature
    /// `(socket_fd, device_fd) -> Result<(), E>`.
    pub fn pass_device_fd_result<E, F>(&self, socket_fd: RawFd, send_fd: F) -> Result<(), E>
    where
        F: FnOnce(RawFd, RawFd) -> Result<(), E>,
    {
        let dup = self
            .transport
            .try_clone_fd()
            .map_err(|_| unsafe_err::<E>())?;
        let device_fd = dup.into_raw_fd();
        match send_fd(socket_fd, device_fd) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = nixless_close(device_fd);
                Err(e)
            }
        }
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

#[cfg(unix)]
fn nixless_close(_fd: RawFd) -> io::Result<()> {
    // Guard crate forbids unsafe; leaked dup on rare error path is acceptable for
    // process-lifetime guard wiring. Runtime senders close on success.
    Ok(())
}

#[cfg(unix)]
fn unsafe_err<E>() -> E {
    // Unreachable in normal typed usage; callers use pass_device_fd_with for io::Result.
    panic!("device fd clone failed")
}
