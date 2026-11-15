// SPDX-License-Identifier: AGPL-3.0-only

//! CC-02 DS18B20 driver tests: full read cycle, recorded frames, and faults.

#[allow(deprecated)]
use tirbase_drivers::driver_trait::DriverTrait;
use tirbase_drivers::onewire::{
    crc8, parse_scratchpad, parse_w1_slave, Ds18b20Bus, Ds18b20Codec, Ds18b20Fault,
    Ds18b20Resolution, Ds18b20RomId, Ds18b20Sensor, OneWireError, CMD_CONVERT_T, CMD_MATCH_ROM,
    CMD_READ_SCRATCHPAD, CMD_SKIP_ROM, SCRATCHPAD_LEN,
};
use tirbase_sim::SimOneWireBus;
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

/// Recorded from a Linux `w1_therm` device (23.125 °C, 12-bit).
const RECORDED_W1_SLAVE: &str = include_str!("data/ds18b20_w1_slave.txt");

fn temp(raw: i64) -> FixedPointValue {
    FixedPointValue::new(raw * 625, -4, UNIT_DEG_C)
}

fn sensor(bus: SimOneWireBus) -> Ds18b20Sensor<SimOneWireBus> {
    Ds18b20Sensor::new(bus, None, Ds18b20Resolution::Bits12)
}

#[test]
fn full_convert_and_read_cycle_against_simulator() {
    let bus = SimOneWireBus::new(0x0191, Ds18b20Resolution::Bits12);
    let mut sensor = sensor(bus);

    let reading = sensor.convert_and_read().expect("full read cycle");
    assert_eq!(reading, temp(0x0191));
    assert_eq!(reading, FixedPointValue::new(250_625, -4, UNIT_DEG_C));

    let health = sensor.health();
    assert!(health.is_healthy());
    assert_eq!(health.successful_reads, 1);
    assert_eq!(health.consecutive_failures, 0);
    assert_eq!(health.last_temperature, Some(reading));
    assert_eq!(health.last_fault, None);

    assert_eq!(
        sensor.bus().writes(),
        &[
            vec![CMD_SKIP_ROM, CMD_CONVERT_T],
            vec![CMD_SKIP_ROM, CMD_READ_SCRATCHPAD],
        ]
    );
    assert_eq!(sensor.bus().conversion_waits_ms(), &[750]);
    assert_eq!(sensor.bus().virtual_time_ms(), 750);
}

#[test]
fn recorded_w1_slave_frame_decodes_and_replays() {
    let parsed = parse_w1_slave(RECORDED_W1_SLAVE).expect("recorded document");
    assert!(parsed.crc_ok);
    assert_eq!(parsed.temperature_millidegrees, Some(23_125));

    let pad = parse_scratchpad(&parsed.scratchpad).expect("recorded scratchpad");
    assert_eq!(pad.temperature().expect("temperature"), temp(0x0172));

    let mut sensor = sensor(SimOneWireBus::from_w1_slave(RECORDED_W1_SLAVE).unwrap());
    assert_eq!(sensor.read_temperature().unwrap(), temp(0x0172));
}

#[test]
fn bad_crc_is_rejected_without_panic() {
    let mut bus = SimOneWireBus::new(0x0191, Ds18b20Resolution::Bits12);
    bus.set_bad_crc();
    let mut sensor = sensor(bus);

    let fault = sensor.read_temperature().expect_err("bad CRC must fail");
    match fault {
        Ds18b20Fault::BadCrc { computed, received } => {
            assert_ne!(computed, received);
        }
        other => panic!("expected BadCrc, got {other:?}"),
    }
    assert_eq!(sensor.health().consecutive_failures, 1);
    assert_eq!(sensor.health().successful_reads, 0);
    assert!(sensor.health().present, "a CRC reply proves presence");
    assert!(!sensor.is_healthy());

    // Recovery clears the recorded fault.
    let bus = sensor.bus_mut();
    bus.set_bad_crc();
    assert_eq!(sensor.read_temperature().unwrap(), temp(0x0191));
    assert_eq!(sensor.health().last_fault, None);
    assert_eq!(sensor.health().consecutive_failures, 0);
}

#[test]
fn short_scratchpad_is_reported_with_length() {
    let mut bus = SimOneWireBus::new(0x0191, Ds18b20Resolution::Bits12);
    bus.set_short_read(Some(4));
    let mut sensor = sensor(bus);

    assert_eq!(
        sensor.read_temperature(),
        Err(Ds18b20Fault::ShortScratchpad { len: 4 })
    );
}

#[test]
fn disconnected_probe_is_reported() {
    let mut bus = SimOneWireBus::new(0x0191, Ds18b20Resolution::Bits12);
    bus.set_present(false);
    let mut sensor = sensor(bus);

    assert_eq!(sensor.read_temperature(), Err(Ds18b20Fault::Disconnected));
    assert!(!sensor.health().present);
    assert!(!sensor.is_healthy());
}

#[test]
fn impossible_temperature_and_power_on_value_are_faults() {
    let mut bus = SimOneWireBus::new(0x0191, Ds18b20Resolution::Bits12);
    bus.set_temperature_raw(3000); // 187.5 °C
    let mut sensor = sensor(bus);
    assert_eq!(
        sensor.read_temperature(),
        Err(Ds18b20Fault::ImpossibleTemperature { raw: 3000 })
    );

    sensor.bus_mut().set_temperature_raw(0x0550);
    assert_eq!(sensor.read_temperature(), Err(Ds18b20Fault::PowerOnReset));
}

#[test]
fn bus_contention_and_transport_timeout_are_reported() {
    let mut bus = SimOneWireBus::new(0x0191, Ds18b20Resolution::Bits12);
    bus.set_contention(true);
    let mut sensor = sensor(bus);
    assert_eq!(sensor.read_temperature(), Err(Ds18b20Fault::BusContention));

    sensor.bus_mut().set_contention(false);
    sensor.bus_mut().set_timeout(true);
    assert_eq!(
        sensor.read_temperature(),
        Err(Ds18b20Fault::Timeout {
            operation: "reset_presence"
        })
    );
}

#[test]
fn conversion_timing_tracks_resolution() {
    for (resolution, expected_ms) in [
        (Ds18b20Resolution::Bits9, 94),
        (Ds18b20Resolution::Bits10, 188),
        (Ds18b20Resolution::Bits11, 375),
        (Ds18b20Resolution::Bits12, 750),
    ] {
        let cfg = resolution.config_bits() | 0x1F;
        let raw = 0x0191i16
            & match resolution {
                Ds18b20Resolution::Bits9 => 0xFFF8u16 as i16,
                Ds18b20Resolution::Bits10 => 0xFFFCu16 as i16,
                Ds18b20Resolution::Bits11 => 0xFFFEu16 as i16,
                Ds18b20Resolution::Bits12 => -1,
            };
        let mut bus = SimOneWireBus::new(raw, resolution);
        bus.set_conversion_required(true);
        let mut sensor = Ds18b20Sensor::new(bus, None, resolution);
        sensor.convert_and_read().unwrap();
        assert_eq!(sensor.bus().conversion_waits_ms(), &[expected_ms]);
        assert_eq!(sensor.bus().virtual_time_ms(), expected_ms);
        // Config byte matches the requested resolution too.
        assert_eq!(sensor.bus().scratchpad()[4], cfg);
    }
}

#[test]
fn reading_before_conversion_completes_is_rejected() {
    let mut bus = SimOneWireBus::new(0x0191, Ds18b20Resolution::Bits12);
    bus.set_conversion_required(true);
    Ds18b20Bus::write(&mut bus, &[CMD_SKIP_ROM, CMD_CONVERT_T]).unwrap();
    Ds18b20Bus::write(&mut bus, &[CMD_SKIP_ROM, CMD_READ_SCRATCHPAD]).unwrap();
    assert_eq!(
        Ds18b20Bus::read_bytes(&mut bus, SCRATCHPAD_LEN),
        Err(OneWireError::ConversionIncomplete)
    );
}

#[test]
fn match_rom_addressing_uses_the_recorded_id() {
    let rom = Ds18b20RomId::from_sysfs_name("28-000006b4a69b").unwrap();
    let bus = SimOneWireBus::new(0x0191, Ds18b20Resolution::Bits12);
    let mut sensor = Ds18b20Sensor::new(bus, Some(rom), Ds18b20Resolution::Bits12);

    sensor.read_temperature().unwrap();
    let expected = {
        let mut frame = vec![CMD_MATCH_ROM];
        frame.extend_from_slice(&rom.bytes());
        frame.push(CMD_READ_SCRATCHPAD);
        frame
    };
    assert_eq!(sensor.bus().writes(), &[expected]);
}

#[test]
fn codec_reports_health_and_rejects_actuation() {
    let codec = Ds18b20Codec::new(Ds18b20Resolution::Bits12);
    let model = codec.capability_discovery().unwrap();
    assert_eq!(model.device_class, "ds18b20");
    assert_eq!(model.parameters[0].name, "temperature_c");
    assert!(!model.parameters[0].writable);
    assert_eq!(model.parameters[0].range, [temp(-880), temp(2000)]);

    let mut frame = [0x72, 0x01, 0x4b, 0x46, 0x7f, 0xff, 0x0e, 0x10, 0x57];
    assert!(codec.decode_health_response(&frame).unwrap().healthy);
    frame[8] = crc8(&frame[..8]).wrapping_add(1);
    let health = codec.decode_health_response(&frame).unwrap();
    assert!(!health.healthy);
    assert!(health.detail.contains("CRC"));
}
