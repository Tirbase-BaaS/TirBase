// SPDX-License-Identifier: AGPL-3.0-only

//! ST-02: protocol ingest, point mapping, health, stale detection and read-only
//! guarantees.

use tirbase_venue::{EffectiveWindow, Gate, TopologyVersion, Venue, Zone};
use tirbase_venue_gateway::{
    BackoffPolicy, ConnectionSupervisor, DecodedPoint, GatewayError, HealthEvent, PointAddress,
    PointId, PointMapping, PointTarget, PointValue, Protocol, SafetyClass, VenueGateway,
};

fn parsed<T>(value: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().expect("fixture identifier")
}

fn topology() -> TopologyVersion {
    let venue = Venue {
        id: parsed("venue-1"),
        name: "Grand Hall".to_string(),
    };
    TopologyVersion::new(
        parsed("topology-1"),
        venue.clone(),
        EffectiveWindow::new(0, None).unwrap(),
        vec![Zone {
            id: parsed("zone-north"),
            venue_id: venue.id.clone(),
            name: "North stand".to_string(),
        }],
        vec![Gate {
            id: parsed("gate-n1"),
            zone_id: parsed("zone-north"),
            name: "North 1".to_string(),
        }],
        vec![],
        vec![],
    )
    .unwrap()
}

fn gateway() -> VenueGateway {
    VenueGateway::new(topology(), 60_000_000).expect("gateway")
}

fn north() -> tirbase_venue::ZoneId {
    parsed("zone-north")
}

fn mapping(point_id: &str, address: PointAddress, target: PointTarget) -> PointMapping {
    PointMapping::new(parsed(point_id), address, target)
}

fn mqtt_address(topic: &str) -> PointAddress {
    PointAddress::Mqtt {
        topic: topic.to_string(),
    }
}

#[test]
fn mappings_group_points_by_venue_target() {
    let mut gateway = gateway();
    let gate_id: tirbase_venue::GateId = parsed("gate-n1");
    let equipment_id: tirbase_venue_gateway::EquipmentId = parsed("ahu-1");

    gateway
        .register(mapping(
            "p-gate",
            mqtt_address("venue/gate/n1"),
            PointTarget::Gate {
                gate_id: gate_id.clone(),
            },
        ))
        .unwrap();
    gateway
        .register(mapping(
            "p-occ",
            PointAddress::Modbus {
                unit_id: 1,
                function: 4,
                register: 100,
            },
            PointTarget::Occupancy { zone_id: north() },
        ))
        .unwrap();
    gateway
        .register(
            mapping(
                "p-env",
                mqtt_address("venue/env/temp"),
                PointTarget::Environment { zone_id: north() },
            )
            .with_unit("degC"),
        )
        .unwrap();
    gateway
        .register(mapping(
            "p-equip",
            PointAddress::Knx {
                group_address: 0x0005,
            },
            PointTarget::Equipment {
                equipment_id: equipment_id.clone(),
                zone_id: north(),
            },
        ))
        .unwrap();

    let snapshot = gateway.snapshot();
    assert_eq!(
        snapshot.gates.get(&gate_id),
        Some(&vec![parsed::<PointId>("p-gate")])
    );
    assert_eq!(
        snapshot.occupancy.get(&north()),
        Some(&vec![parsed::<PointId>("p-occ")])
    );
    assert_eq!(
        snapshot.environment.get(&north()),
        Some(&vec![parsed::<PointId>("p-env")])
    );
    assert_eq!(
        snapshot.equipment.get(&equipment_id),
        Some(&vec![parsed::<PointId>("p-equip")])
    );
}

#[test]
fn mapping_rejects_unknown_targets_and_write_addresses() {
    let mut gateway = gateway();

    let unknown_zone = gateway
        .register(mapping(
            "p-occ",
            mqtt_address("occ"),
            PointTarget::Occupancy {
                zone_id: parsed("zone-missing"),
            },
        ))
        .expect_err("unknown zone");
    assert!(matches!(unknown_zone, GatewayError::UnknownZone(_)));

    let unknown_gate = gateway
        .register(mapping(
            "p-gate",
            mqtt_address("gate"),
            PointTarget::Gate {
                gate_id: parsed("gate-missing"),
            },
        ))
        .expect_err("unknown gate");
    assert!(matches!(unknown_gate, GatewayError::UnknownGate(_)));

    let write_register = gateway
        .register(mapping(
            "p-write",
            PointAddress::Modbus {
                unit_id: 1,
                function: 0x06,
                register: 10,
            },
            PointTarget::Occupancy { zone_id: north() },
        ))
        .expect_err("write register mapping");
    assert!(matches!(write_register, GatewayError::WritePathRejected(_)));

    gateway
        .register(mapping(
            "p-ok",
            mqtt_address("occ"),
            PointTarget::Occupancy { zone_id: north() },
        ))
        .unwrap();
    let duplicate = gateway
        .register(mapping(
            "p-duplicate",
            mqtt_address("occ"),
            PointTarget::Environment { zone_id: north() },
        ))
        .expect_err("duplicate address");
    assert!(matches!(duplicate, GatewayError::DuplicateAddress(_)));
}

#[test]
fn stale_point_raises_one_health_event_until_refreshed() {
    let mut gateway = gateway();
    let point_id: PointId = parsed("p-occ");
    gateway
        .register(mapping(
            "p-occ",
            mqtt_address("venue/zone/north/occupancy"),
            PointTarget::Occupancy { zone_id: north() },
        ))
        .unwrap();
    let decoded = DecodedPoint::new(
        mqtt_address("venue/zone/north/occupancy"),
        PointValue::Count(120),
    );

    gateway.ingest(decoded.clone(), 0).unwrap();
    assert_eq!(gateway.occupancy_total(&north()), 120);
    assert!(gateway.tick(60_000_000).is_empty());
    assert_eq!(gateway.occupancy_total(&north()), 120);

    let events = gateway.tick(60_000_001);
    assert_eq!(events.len(), 1);
    match &events[0].event {
        HealthEvent::PointStale {
            point_id: stale,
            last_seen_utc_us,
            stale_after_us,
        } => {
            assert_eq!(stale, &point_id);
            assert_eq!(*last_seen_utc_us, 0);
            assert_eq!(*stale_after_us, 60_000_000);
        }
        other => panic!("expected PointStale, got {other:?}"),
    }
    assert!(gateway.is_stale(&point_id));
    assert_eq!(gateway.occupancy_total(&north()), 0);
    // The event is edge-triggered, not repeated every tick.
    assert!(gateway.tick(70_000_000).is_empty());

    let update = gateway.ingest(decoded, 70_000_000).unwrap();
    assert!(update.recovered);
    assert!(!gateway.is_stale(&point_id));
    assert_eq!(gateway.occupancy_total(&north()), 120);
    assert!(matches!(
        gateway.health_events().last().map(|record| &record.event),
        Some(HealthEvent::PointRecovered { .. })
    ));
}

#[test]
fn reconnect_is_bounded_and_recovers() {
    let policy = BackoffPolicy::new(1_000, 4_000, 2).unwrap();
    let mut supervisor = ConnectionSupervisor::new(Protocol::Bacnet, policy);

    assert_eq!(
        supervisor.disconnected(0),
        HealthEvent::ReconnectScheduled {
            protocol: Protocol::Bacnet,
            attempt: 1,
            retry_at_utc_us: 1_000,
        }
    );
    assert!(supervisor.retry_due(1_000));
    supervisor.start_retry();
    assert!(!supervisor.retry_due(1_000));

    assert_eq!(
        supervisor.disconnected(1_000),
        HealthEvent::ReconnectScheduled {
            protocol: Protocol::Bacnet,
            attempt: 2,
            retry_at_utc_us: 3_000,
        }
    );
    assert_eq!(
        supervisor.disconnected(3_000),
        HealthEvent::ReconnectExhausted {
            protocol: Protocol::Bacnet,
            attempts: 2,
        }
    );
    assert!(supervisor.is_exhausted());

    let mut gateway = gateway();
    assert!(gateway.mark_failed(Protocol::Mqtt, 0).is_some());
    assert!(gateway.mark_connected(Protocol::Mqtt, 5).is_some());
    assert!(gateway
        .supervisor(Protocol::Mqtt)
        .map(|supervisor| supervisor.is_connected())
        .unwrap_or(false));
}

#[test]
fn safety_points_are_read_only_and_auditable() {
    let mut gateway = gateway();
    gateway
        .register(
            mapping(
                "p-fire",
                mqtt_address("venue/fire/door"),
                PointTarget::Equipment {
                    equipment_id: parsed("fire-door-1"),
                    zone_id: north(),
                },
            )
            .life_safety(),
        )
        .unwrap();
    gateway
        .register(mapping(
            "p-occ",
            mqtt_address("venue/occ"),
            PointTarget::Occupancy { zone_id: north() },
        ))
        .unwrap();

    let safety = gateway.life_safety_points();
    assert_eq!(safety.len(), 1);
    assert_eq!(safety[0].point_id.as_str(), "p-fire");
    assert_eq!(safety[0].safety, SafetyClass::LifeSafety);

    // Readings flow one way only: ingest returns a value snapshot and there is
    // no command/actuation method on the gateway.
    let update = gateway
        .ingest(
            DecodedPoint::new(mqtt_address("venue/fire/door"), PointValue::Boolean(false)),
            10,
        )
        .unwrap();
    assert_eq!(update.value, PointValue::Boolean(false));
    assert!(matches!(
        gateway.ingest(
            DecodedPoint::new(mqtt_address("venue/unknown"), PointValue::Boolean(true)),
            11,
        ),
        Err(GatewayError::UnknownPointAddress(_))
    ));
}

// ---------------------------------------------------------------------------
// BACnet/IP
// ---------------------------------------------------------------------------

#[cfg(feature = "bacnet")]
#[test]
fn bacnet_recorded_read_ack_maps_to_environment() {
    use tirbase_driver_api::{ObjectIdentifier, ObjectType};
    use tirbase_venue_gateway::protocol::bacnet::{
        decode_read_property_ack, read_property_request,
    };
    use tirbase_venue_gateway::sim::BacnetSim;

    let object = ObjectIdentifier::new(ObjectType::AnalogInput, 3).unwrap();
    let recorded: &[u8] = &[
        0x81, 0x0A, 0x00, 0x0C, 0x01, 0x00, 0x30, 0x01, 0x0C, 0x3E, 0x44, 0x41, 0xAC, 0x00, 0x00,
        0x3F,
    ];
    assert_eq!(
        BacnetSim::read_property_ack(object, tirbase_driver_api::BacnetValue::Real(21.5)),
        recorded
    );
    let decoded = decode_read_property_ack(object, recorded).unwrap();
    assert_eq!(
        decoded.address,
        PointAddress::Bacnet {
            object_type: 0,
            instance: 3,
            property: 85,
        }
    );
    assert_eq!(decoded.value, PointValue::number(215, -1));

    // The poll request is a read, and a write encoder is unavailable through
    // the gateway entirely.
    let request = read_property_request(object, 1).unwrap();
    assert_eq!(request[6], 0x00, "Confirmed-Request PDU");
    assert_eq!(request[8], 0x0C, "ReadProperty service");

    let mut gateway = gateway();
    gateway
        .register(mapping(
            "p-temp",
            decoded.address.clone(),
            PointTarget::Environment { zone_id: north() },
        ))
        .unwrap();
    gateway.ingest(decoded, 1_000).unwrap();
    assert_eq!(
        gateway.point_value(&parsed::<PointId>("p-temp")),
        Some(&PointValue::number(215, -1))
    );
}

#[cfg(feature = "bacnet")]
#[test]
fn bacnet_write_service_is_rejected() {
    use tirbase_driver_api::{encode_write_property, BacnetValue, ObjectIdentifier, ObjectType};

    let object = ObjectIdentifier::new(ObjectType::AnalogValue, 1).unwrap();
    let error = encode_write_property(
        1,
        object,
        tirbase_driver_api::PropertyId::PRESENT_VALUE,
        &BacnetValue::Real(1.0),
    )
    .expect_err("BACnet write encoding is rejected");
    assert!(error.to_string().contains("read-only"));
}

// ---------------------------------------------------------------------------
// Modbus TCP/RTU
// ---------------------------------------------------------------------------

#[cfg(feature = "modbus")]
#[test]
fn modbus_recorded_tcp_and_rtu_responses_decode() {
    use tirbase_venue_gateway::protocol::modbus::{
        decode_rtu_read_response, decode_tcp_read_response,
    };
    use tirbase_venue_gateway::sim::ModbusSim;

    let tcp: &[u8] = &[
        0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x2A,
    ];
    let readings = decode_tcp_read_response(1, 100, tcp).unwrap();
    assert_eq!(readings.len(), 1);
    assert_eq!(
        readings[0].address,
        PointAddress::Modbus {
            unit_id: 1,
            function: 3,
            register: 100,
        }
    );
    assert_eq!(readings[0].value, PointValue::number(42, 0));

    let rtu = ModbusSim::rtu_read_response(1, &[42, 7]);
    let rtu_readings = decode_rtu_read_response(1, 100, &rtu).unwrap();
    assert_eq!(rtu_readings.len(), 2);
    assert_eq!(rtu_readings[1].value, PointValue::number(7, 0));

    let mismatch = decode_tcp_read_response(2, 100, tcp).unwrap_err();
    assert!(matches!(
        mismatch,
        tirbase_venue_gateway::ProtocolError::UnitMismatch { .. }
    ));
}

#[cfg(feature = "modbus")]
#[test]
fn modbus_write_response_is_rejected() {
    use tirbase_venue_gateway::protocol::modbus::decode_tcp_read_response;
    use tirbase_venue_gateway::ProtocolError;

    // FC06 Write-Single-Register response: unit 1, register 100, value 42.
    let write_response: &[u8] = &[
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x64, 0x00, 0x2A,
    ];
    let error = decode_tcp_read_response(1, 100, write_response).unwrap_err();
    assert!(matches!(error, ProtocolError::WritePathRejected(_)));
}

// ---------------------------------------------------------------------------
// KNX/IP
// ---------------------------------------------------------------------------

#[cfg(feature = "knx")]
#[test]
fn knx_recorded_group_values_decode() {
    use tirbase_venue_gateway::protocol::knx::decode_group_value_indication;
    use tirbase_venue_gateway::sim::{KnxSim, KnxSimValue};

    let recorded_bool: &[u8] = &[
        0x06, 0x10, 0x04, 0x20, 0x00, 0x15, 0x04, 0x01, 0x00, 0x00, 0x29, 0x00, 0xBC, 0xE0, 0x00,
        0x01, 0x00, 0x01, 0x01, 0x00, 0x81,
    ];
    assert_eq!(
        KnxSim::group_value_indication(0x0001, KnxSimValue::Bool(true)),
        recorded_bool
    );
    let decoded = decode_group_value_indication(recorded_bool).unwrap();
    assert_eq!(decoded.address, PointAddress::Knx { group_address: 1 });
    assert_eq!(decoded.value, PointValue::Boolean(true));

    let dpt9 = KnxSim::group_value_indication(0x0002, KnxSimValue::Dpt9Centi(2150));
    let decoded = decode_group_value_indication(&dpt9).unwrap();
    assert_eq!(decoded.address, PointAddress::Knx { group_address: 2 });
    assert_eq!(decoded.value, PointValue::number(2150, -2));
}

#[cfg(feature = "knx")]
#[test]
fn knx_bus_write_request_is_rejected() {
    use tirbase_venue_gateway::protocol::knx::decode_group_value_indication;
    use tirbase_venue_gateway::sim::{KnxSim, KnxSimValue};
    use tirbase_venue_gateway::ProtocolError;

    let mut frame = KnxSim::group_value_indication(0x0001, KnxSimValue::Bool(true));
    frame[10] = 0x11; // cEMI L_Data.req
    let error = decode_group_value_indication(&frame).unwrap_err();
    assert!(matches!(error, ProtocolError::WritePathRejected(_)));
}

// ---------------------------------------------------------------------------
// MQTT
// ---------------------------------------------------------------------------

#[cfg(feature = "mqtt")]
#[test]
fn mqtt_recorded_publish_decodes_and_updates_occupancy() {
    use tirbase_venue_gateway::protocol::mqtt::decode_publish;
    use tirbase_venue_gateway::sim::MqttSim;

    let recorded: &[u8] = &[0x30, 0x07, 0x00, 0x03, b'a', b'/', b'b', b'4', b'2'];
    assert_eq!(MqttSim::publish("a/b", b"42"), recorded);
    let decoded = decode_publish(recorded).unwrap();
    assert_eq!(
        decoded.address,
        PointAddress::Mqtt {
            topic: "a/b".to_string()
        }
    );
    assert_eq!(decoded.value, PointValue::number(42, 0));

    let mut gateway = gateway();
    gateway
        .register(mapping(
            "p-occ",
            decoded.address.clone(),
            PointTarget::Occupancy { zone_id: north() },
        ))
        .unwrap();
    gateway.ingest(decoded, 500).unwrap();
    assert_eq!(gateway.occupancy_total(&north()), 42);

    let bad = decode_publish(&[0x00]).unwrap_err();
    assert!(matches!(
        bad,
        tirbase_venue_gateway::ProtocolError::Codec(_)
    ));
}

// ---------------------------------------------------------------------------
// All protocols in one venue model
// ---------------------------------------------------------------------------

#[cfg(all(
    feature = "bacnet",
    feature = "modbus",
    feature = "knx",
    feature = "mqtt"
))]
#[test]
fn points_from_all_four_protocols_appear_in_the_venue_model() {
    use tirbase_driver_api::{BacnetValue, ObjectIdentifier, ObjectType};
    use tirbase_venue_gateway::protocol::{
        bacnet::decode_read_property_ack, knx::decode_group_value_indication,
        modbus::decode_tcp_read_response, mqtt::decode_publish,
    };
    use tirbase_venue_gateway::sim::{BacnetSim, KnxSim, KnxSimValue, ModbusSim, MqttSim};

    let mut gateway = gateway();

    // BACnet environment sensor.
    let object = ObjectIdentifier::new(ObjectType::AnalogInput, 3).unwrap();
    let bacnet = decode_read_property_ack(
        object,
        &BacnetSim::read_property_ack(object, BacnetValue::Real(19.5)),
    )
    .unwrap();
    gateway
        .register(mapping(
            "p-bacnet-temp",
            bacnet.address.clone(),
            PointTarget::Environment { zone_id: north() },
        ))
        .unwrap();
    gateway.ingest(bacnet, 1_000).unwrap();

    // Modbus occupancy counter.
    let modbus =
        decode_tcp_read_response(1, 200, &ModbusSim::tcp_read_response(1, &[321])).unwrap();
    gateway
        .register(mapping(
            "p-modbus-occ",
            modbus[0].address.clone(),
            PointTarget::Occupancy { zone_id: north() },
        ))
        .unwrap();
    gateway.ingest(modbus[0].clone(), 1_000).unwrap();

    // KNX gate contact.
    let knx = decode_group_value_indication(&KnxSim::group_value_indication(
        0x0102,
        KnxSimValue::Bool(true),
    ))
    .unwrap();
    gateway
        .register(mapping(
            "p-knx-gate",
            knx.address.clone(),
            PointTarget::Gate {
                gate_id: parsed("gate-n1"),
            },
        ))
        .unwrap();
    gateway.ingest(knx, 1_000).unwrap();

    // MQTT equipment status.
    let mqtt = decode_publish(&MqttSim::publish("venue/equipment/ahu-1", b"true")).unwrap();
    gateway
        .register(mapping(
            "p-mqtt-equipment",
            mqtt.address.clone(),
            PointTarget::Equipment {
                equipment_id: parsed("ahu-1"),
                zone_id: north(),
            },
        ))
        .unwrap();
    gateway.ingest(mqtt, 1_000).unwrap();

    let snapshot = gateway.snapshot();
    assert_eq!(snapshot.environment.get(&north()).map(Vec::len), Some(1));
    assert_eq!(snapshot.occupancy.get(&north()).map(Vec::len), Some(1));
    assert_eq!(snapshot.gates.values().map(Vec::len).sum::<usize>(), 1);
    assert_eq!(snapshot.equipment.values().map(Vec::len).sum::<usize>(), 1);
    assert_eq!(gateway.occupancy_total(&north()), 321);

    assert_eq!(
        gateway.point_value(&parsed::<PointId>("p-bacnet-temp")),
        Some(&PointValue::number(195, -1))
    );
    assert_eq!(
        gateway.point_value(&parsed::<PointId>("p-knx-gate")),
        Some(&PointValue::Boolean(true))
    );
    assert_eq!(
        gateway.point_value(&parsed::<PointId>("p-mqtt-equipment")),
        Some(&PointValue::Boolean(true))
    );

    // All points stale together, all raise exactly one event each.
    let stale = gateway.tick(60_001_001);
    assert_eq!(stale.len(), 4);
    assert!(stale
        .iter()
        .all(|record| matches!(record.event, HealthEvent::PointStale { .. })));
}
