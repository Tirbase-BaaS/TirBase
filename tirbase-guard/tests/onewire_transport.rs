// SPDX-License-Identifier: AGPL-3.0-only

//! CC-02 guard tests: bounded `w1_slave` transport and health/fault state.
#![cfg(unix)]

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tirbase_drivers::modbus::MonotonicMillisFn;
use tirbase_drivers::onewire::{
    Ds18b20Bus, Ds18b20Fault, Ds18b20Resolution, OneWireError, CMD_READ_SCRATCHPAD, CMD_SKIP_ROM,
};
use tirbase_guard::onewire::{GuardOneWireSensor, W1SysfsBus, MAX_W1_SLAVE_BYTES};
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

const RECORDED: &str = "72 01 4b 46 7f ff 0e 10 57 : crc=57 YES\n\
                        72 01 4b 46 7f ff 0e 10 57 t=23125\n";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "tirbase-onewire-{tag}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn clock() -> MonotonicMillisFn {
    Arc::new(|| 0)
}

fn recorded_temp() -> FixedPointValue {
    FixedPointValue::new(231_250, -4, UNIT_DEG_C)
}

#[test]
fn sysfs_read_cycle_exposes_health() {
    let dir = TempDir::new("sysfs");
    fs::write(dir.path().join("w1_slave"), RECORDED).unwrap();

    let mut sensor = GuardOneWireSensor::open(
        dir.path(),
        Duration::from_millis(250),
        clock(),
        None,
        Ds18b20Resolution::Bits12,
    )
    .unwrap();

    assert_eq!(sensor.read_temperature().unwrap(), recorded_temp());
    let health = sensor.health();
    assert!(health.is_healthy());
    assert!(health.present);
    assert_eq!(health.successful_reads, 1);
    assert_eq!(health.last_temperature, Some(recorded_temp()));
    assert_eq!(sensor.fault_state(), None);

    // The kernel path needs no conversion wait for a direct scratchpad read.
    assert_eq!(
        sensor.sensor().bus().slave_path(),
        dir.path().join("w1_slave")
    );
}

#[test]
fn bad_crc_in_sysfs_frame_is_a_fault() {
    let dir = TempDir::new("bad-crc");
    fs::write(
        dir.path().join("w1_slave"),
        RECORDED.replace("72 01", "73 01"),
    )
    .unwrap();

    let mut sensor = GuardOneWireSensor::open(
        dir.path(),
        Duration::from_millis(250),
        clock(),
        None,
        Ds18b20Resolution::Bits12,
    )
    .unwrap();

    assert!(matches!(
        sensor.read_temperature(),
        Err(Ds18b20Fault::BadCrc { .. })
    ));
    assert!(sensor.health().present, "a CRC reply proves presence");
    assert!(!sensor.is_healthy());
}

#[test]
fn removed_device_is_reported_disconnected() {
    let dir = TempDir::new("unplug");
    fs::write(dir.path().join("w1_slave"), RECORDED).unwrap();
    let mut sensor = GuardOneWireSensor::open(
        dir.path(),
        Duration::from_millis(250),
        clock(),
        None,
        Ds18b20Resolution::Bits12,
    )
    .unwrap();
    sensor.read_temperature().unwrap();

    fs::remove_file(dir.path().join("w1_slave")).unwrap();
    assert_eq!(sensor.read_temperature(), Err(Ds18b20Fault::Disconnected));
    assert!(!sensor.health().present);
    assert_eq!(sensor.health().successful_reads, 1);
}

#[test]
fn missing_device_dir_is_rejected() {
    let dir = TempDir::new("missing");
    let error = W1SysfsBus::new(
        dir.path().join("28-not-there"),
        Duration::from_millis(50),
        clock(),
    )
    .unwrap_err();
    assert!(matches!(error, OneWireError::Disconnected));
}

#[test]
fn fifo_read_times_out_instead_of_blocking_forever() {
    let dir = TempDir::new("fifo");
    let fifo = dir.path().join("w1_slave");
    let c_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_path is a valid NUL-terminated path in a writable temp dir.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

    let mut bus = W1SysfsBus::from_slave_path(&fifo, Duration::from_millis(100), clock()).unwrap();
    assert!(bus.reset_presence().unwrap());
    bus.write(&[CMD_SKIP_ROM, CMD_READ_SCRATCHPAD]).unwrap();

    let error = bus.read_bytes(9).unwrap_err();
    assert!(matches!(error, OneWireError::Timeout { .. }), "{error:?}");
}

#[test]
fn oversized_w1_slave_is_rejected() {
    let dir = TempDir::new("oversized");
    fs::write(
        dir.path().join("w1_slave"),
        vec![b'x'; MAX_W1_SLAVE_BYTES + 1],
    )
    .unwrap();
    let mut bus = W1SysfsBus::new(dir.path(), Duration::from_millis(250), clock()).unwrap();
    assert!(matches!(
        bus.read_slave(),
        Err(OneWireError::Protocol(message)) if message.contains("exceeded")
    ));
}

#[test]
fn fifo_with_writer_is_read_normally() {
    let dir = TempDir::new("fifo-writer");
    let fifo = dir.path().join("w1_slave");
    let c_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_path is a valid NUL-terminated path in a writable temp dir.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

    let writer_path = fifo.clone();
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        eprintln!("writer opening");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(writer_path)
            .unwrap();
        eprintln!("writer opened");
        file.write_all(RECORDED.as_bytes()).unwrap();
        eprintln!("writer wrote");
    });

    let mut sensor = GuardOneWireSensor::open_slave(
        &fifo,
        Duration::from_millis(500),
        clock(),
        None,
        Ds18b20Resolution::Bits12,
    )
    .unwrap();
    assert_eq!(sensor.read_temperature().unwrap(), recorded_temp());
    writer.join().unwrap();
}
