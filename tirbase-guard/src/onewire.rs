// SPDX-License-Identifier: AGPL-3.0-only

//! Guard-owned 1-Wire transport for the DS18B20 driver (CC-02, CLAIM-34.x).
//!
//! [`W1SysfsBus`] reads Linux `w1_slave` files through a non-blocking fd with a
//! caller-supplied monotonic millisecond clock and a deadline enforced by
//! `poll(2)`. There is no unbounded blocking read: every wait is bounded by
//! [`W1SysfsBus::timeout`], and oversized files are rejected.
//!
//! [`GuardOneWireSensor`] wires the transport into
//! [`tirbase_drivers::onewire::Ds18b20Sensor`] so the guard can read a
//! temperature and observe health/fault state.
#![allow(unsafe_code)]

use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tirbase_drivers::modbus::MonotonicMillisFn;
use tirbase_drivers::onewire::{
    parse_w1_slave, Ds18b20Bus, Ds18b20Fault, Ds18b20Health, Ds18b20Resolution, Ds18b20RomId,
    Ds18b20Sensor, OneWireError, W1SlaveReading, CMD_CONVERT_T, CMD_READ_SCRATCHPAD,
    SCRATCHPAD_LEN,
};
use tirbase_types::FixedPointValue;

/// Maximum bytes accepted from one `w1_slave` read (the real file is ~80 bytes).
pub const MAX_W1_SLAVE_BYTES: usize = 4_096;

/// Linux `w1_therm` sysfs transport with bounded reads.
pub struct W1SysfsBus {
    slave_path: PathBuf,
    timeout: Duration,
    clock: MonotonicMillisFn,
    last_command: Option<u8>,
}

impl std::fmt::Debug for W1SysfsBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("W1SysfsBus")
            .field("slave_path", &self.slave_path)
            .field("timeout", &self.timeout)
            .field("last_command", &self.last_command)
            .finish_non_exhaustive()
    }
}

impl W1SysfsBus {
    /// Opens `<device_dir>/w1_slave` (for example
    /// `/sys/bus/w1/devices/28-000006b4a69b`).
    pub fn new(
        device_dir: impl AsRef<Path>,
        timeout: Duration,
        clock: MonotonicMillisFn,
    ) -> Result<Self, OneWireError> {
        let slave_path = device_dir.as_ref().join("w1_slave");
        Self::from_slave_path(slave_path, timeout, clock)
    }

    /// Uses an explicit `w1_slave` path (tests, bind mounts, non-sysfs trees).
    pub fn from_slave_path(
        slave_path: impl Into<PathBuf>,
        timeout: Duration,
        clock: MonotonicMillisFn,
    ) -> Result<Self, OneWireError> {
        let slave_path = slave_path.into();
        if !slave_path.exists() {
            return Err(OneWireError::Disconnected);
        }
        Ok(Self {
            slave_path,
            timeout,
            clock,
            last_command: None,
        })
    }

    /// Path of the underlying `w1_slave` file.
    pub fn slave_path(&self) -> &Path {
        &self.slave_path
    }

    /// Configured bound for a single read.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Reads and parses the current `w1_slave` document.
    pub fn read_slave(&mut self) -> Result<W1SlaveReading, OneWireError> {
        let bytes = read_bounded(
            &self.slave_path,
            self.timeout,
            self.clock.as_ref(),
            MAX_W1_SLAVE_BYTES,
        )?;
        let document = String::from_utf8(bytes)
            .map_err(|error| OneWireError::Protocol(format!("non-UTF-8 w1_slave: {error}")))?;
        parse_w1_slave(&document)
            .map_err(|error| OneWireError::Protocol(format!("w1_slave parse: {error}")))
    }
}

impl Ds18b20Bus for W1SysfsBus {
    fn reset_presence(&mut self) -> Result<bool, OneWireError> {
        // The kernel driver owns reset/presence; a missing device node is the
        // sysfs equivalent of a missing presence pulse.
        match self.slave_path.try_exists() {
            Ok(present) => Ok(present),
            Err(error) => Err(OneWireError::Io(error.to_string())),
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), OneWireError> {
        // w1_therm performs the conversion as part of the w1_slave read, so
        // write only validates the transaction the sensor asked for.
        match bytes.last().copied() {
            Some(CMD_CONVERT_T) | Some(CMD_READ_SCRATCHPAD) => {
                self.last_command = bytes.last().copied();
                Ok(())
            }
            Some(command) => Err(OneWireError::Protocol(format!(
                "unsupported 1-Wire command 0x{command:02x} for w1_therm"
            ))),
            None => Err(OneWireError::Protocol("empty 1-Wire frame".into())),
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, OneWireError> {
        if self.last_command != Some(CMD_READ_SCRATCHPAD) {
            return Err(OneWireError::Protocol(
                "w1_slave read without a Read Scratchpad command".into(),
            ));
        }
        let mut scratchpad = self.read_slave()?.scratchpad;
        scratchpad.truncate(len.min(SCRATCHPAD_LEN));
        Ok(scratchpad)
    }

    fn wait_conversion(&mut self, _resolution: Ds18b20Resolution) -> Result<(), OneWireError> {
        // w1_therm blocks for the conversion inside read(2), which is itself
        // bounded by read_bounded's poll deadline.
        Ok(())
    }
}

/// Guard-facing DS18B20 sensor: transport plus health/fault state.
#[derive(Debug)]
pub struct GuardOneWireSensor {
    sensor: Ds18b20Sensor<W1SysfsBus>,
}

impl GuardOneWireSensor {
    /// Opens a sysfs DS18B20 device directory.
    pub fn open(
        device_dir: impl AsRef<Path>,
        timeout: Duration,
        clock: MonotonicMillisFn,
        rom: Option<Ds18b20RomId>,
        resolution: Ds18b20Resolution,
    ) -> Result<Self, OneWireError> {
        let bus = W1SysfsBus::new(device_dir, timeout, clock)?;
        Ok(Self {
            sensor: Ds18b20Sensor::new(bus, rom, resolution),
        })
    }

    /// Uses an explicit `w1_slave` path.
    pub fn open_slave(
        slave_path: impl Into<PathBuf>,
        timeout: Duration,
        clock: MonotonicMillisFn,
        rom: Option<Ds18b20RomId>,
        resolution: Ds18b20Resolution,
    ) -> Result<Self, OneWireError> {
        let bus = W1SysfsBus::from_slave_path(slave_path, timeout, clock)?;
        Ok(Self {
            sensor: Ds18b20Sensor::new(bus, rom, resolution),
        })
    }

    /// Reads the current temperature.
    pub fn read_temperature(&mut self) -> Result<FixedPointValue, Ds18b20Fault> {
        self.sensor.read_temperature()
    }

    /// Current health/fault snapshot.
    pub fn health(&self) -> Ds18b20Health {
        self.sensor.health()
    }

    /// Last fault, if any.
    pub fn fault_state(&self) -> Option<Ds18b20Fault> {
        self.sensor.fault_state()
    }

    /// True when the last read succeeded.
    pub fn is_healthy(&self) -> bool {
        self.sensor.is_healthy()
    }

    /// Underlying sensor (transport access, counters).
    pub fn sensor(&self) -> &Ds18b20Sensor<W1SysfsBus> {
        &self.sensor
    }

    /// Mutable underlying sensor.
    pub fn sensor_mut(&mut self) -> &mut Ds18b20Sensor<W1SysfsBus> {
        &mut self.sensor
    }
}

/// Reads a file through a non-blocking fd, bounded by `poll(2)` and `timeout`.
fn read_bounded(
    path: &Path,
    timeout: Duration,
    clock: &dyn Fn() -> u64,
    max_bytes: usize,
) -> Result<Vec<u8>, OneWireError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                OneWireError::Disconnected
            } else {
                OneWireError::Io(error.to_string())
            }
        })?;
    let fd = file.as_raw_fd();
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let start = clock();
    let mut output = Vec::new();
    let mut buffer = [0u8; 512];

    loop {
        let elapsed = clock().saturating_sub(start).min(i64::MAX as u64) as i32;
        let remaining = timeout_ms.saturating_sub(elapsed);
        if remaining == 0 && elapsed > 0 {
            return Err(OneWireError::Timeout {
                operation: "w1_slave_read",
            });
        }
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll_fd points to one initialized pollfd for the duration.
        let ready = unsafe { libc::poll(&mut poll_fd, 1, remaining) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(OneWireError::Io(error.to_string()));
        }
        if ready == 0 {
            // Some platforms do not report POLLHUP on a drained FIFO. If data
            // was already read, a non-blocking read distinguishes EOF from a
            // still-open writer.
            if !output.is_empty() {
                // SAFETY: buffer is valid for writes and fd is open.
                let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
                if count == 0 {
                    break;
                }
                if count > 0 {
                    output.extend_from_slice(&buffer[..count as usize]);
                    continue;
                }
            }
            return Err(OneWireError::Timeout {
                operation: "w1_slave_read",
            });
        }
        if poll_fd.revents & libc::POLLIN == 0 {
            if poll_fd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                break;
            }
            continue;
        }
        // SAFETY: buffer is valid for writes of buffer.len() and fd is open.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => continue,
                _ => return Err(OneWireError::Io(error.to_string())),
            }
        }
        if count == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..count as usize]);
        if output.len() > max_bytes {
            return Err(OneWireError::Protocol(format!(
                "w1_slave exceeded {max_bytes} bytes"
            )));
        }
    }
    Ok(output)
}
