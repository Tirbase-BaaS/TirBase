//! TirBase device driver framework (CLAIM-33.x, PV-10, PV-4.21, INV-6).
//!
//! Provides the pure codec [`DriverTrait`], [`DeviceModel`], actuation frame
//! helpers, and out-of-process driver isolation/lifecycle primitives.
//!
//! # Layering (CLAIM-33.1, CLAIM-33.8, PV-10.3)
//! `tirbase-drivers` depends **only** on `tirbase-types`. It must not import
//! `tirbase-guard` or `tirbase-core`. CI enforces this via manifest/layering
//! checks.
//!
//! <!-- STATE-INVENTORY: RECONSTRUCTIBLE driver runtime -->

#![deny(unsafe_code)]
// Warn on dead private code across this crate. `pub` items are naturally exempt
// (the Rust dead_code lint does not fire on reachable public items).
#![warn(dead_code)]

pub mod cold_room_sim;
pub mod driver_trait;
pub mod isolation;
pub mod lifecycle;
pub mod modbus;
pub mod mqtt;
pub mod register_map;

pub use cold_room_sim::{ColdRoomSimDriver, FirstOrderThermalModel};
pub use driver_trait::{
    run_with_timeout, ActuationPermitRef, DeviceModel, DriverError, DriverHealth, DriverResult,
    DriverTrait, EmptyDeviceModelError, Frame, ParameterDescriptor, TimeoutError,
    DRIVER_OPERATION_TIMEOUT,
};
pub use isolation::{
    apply_child_sandbox, create_driver_socketpair, recv_fd_via_scm_rights,
    scm_rights_device_fd_plan, send_fd_via_scm_rights, verify_peercred, DriverSocketPair,
    DriverSpawnPlan, IsolationError, KernelIsolationCaps, DEGRADED_ISOLATION_OPT_IN_FLAG,
    DRIVER_SOCKET_FD_ARG,
};
pub use lifecycle::{
    apply_restart_decision, DriverCrashSupervisor, DriverLifecycle, DriverRestartDecision,
    LifecycleConfigError, DRIVER_RESTART_INITIAL, DRIVER_RESTART_MAX, DRIVER_RESTART_MAX_RETRIES,
};
pub use modbus::{
    build_rtu_frame, crc16_rtu, decode_read_registers_response, decode_write_multiple_response,
    decode_write_single_response, open_modbus_rtu, parse_exception, parse_rtu_frame, parse_tcp_adu,
    read_tcp_adu_with_timeout, FunctionCode, ModbusRtuClient, ModbusRtuParity,
    ModbusRtuSerialConfig, ModbusTcpAdu, ModbusTcpClient, ModbusTcpCodec, WireMode,
};

pub use mqtt::{
    client_config_with_roots, connect_tls_only, install_crypto_provider, parse_mqtts_uri,
    MqttBridgeCodec, MqttConnectConfig, MqttError, MqttQoS, MqttSecurityError, MqttTlsClient,
    TlsTcpStream, TlsValidatedEndpoint,
};

pub use register_map::{ModbusRegisterMap, RegisterDef, RegisterMapError, RegisterWordOrder};
pub use tirbase_types;

#[cfg(test)]
mod tests {
    use super::*;
    use tirbase_types::{FixedPointValue, TargetId, UNIT_DEG_C};

    fn fp(m: i64) -> FixedPointValue {
        FixedPointValue::new(m, 0, UNIT_DEG_C)
    }

    struct DummyDriver;
    impl DriverTrait for DummyDriver {
        fn capability_discovery(&self) -> DriverResult<DeviceModel> {
            DeviceModel::try_new(
                "cold_room".into(),
                vec![ParameterDescriptor {
                    name: "setpoint_c".into(),
                    unit_id: UNIT_DEG_C,
                    unit_label: "degC".into(),
                    range: [fp(-40), fp(10)],
                    writable: true,
                }],
            )
            .map_err(|e| DriverError::Capability(e.to_string()))
        }
        fn encode_read(&self, param: &str) -> DriverResult<Frame> {
            if param != "setpoint_c" {
                return Err(DriverError::UnsupportedParam(param.into()));
            }
            Ok(b"READ:setpoint_c".to_vec())
        }
        fn decode_read_response(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
            if frame != b"RESP:setpoint_c" {
                return Err(DriverError::InvalidFrame("unexpected".into()));
            }
            Ok(fp(4))
        }
        fn encode_actuation(&self, permit: &ActuationPermitRef) -> DriverResult<Frame> {
            // [CLAIM-33.4] codec-only encoding from permit view; no I/O.
            Ok(format!(
                "ACT:{}:{}:{}",
                permit.target_id.as_str(),
                permit.param,
                permit.value.mantissa
            )
            .into_bytes())
        }
        fn decode_read_back(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
            // [CLAIM-33.4] codec-only decode of read-back frame.
            let s =
                std::str::from_utf8(frame).map_err(|e| DriverError::InvalidFrame(e.to_string()))?;
            let v = s
                .rsplit(':')
                .next()
                .ok_or_else(|| DriverError::InvalidFrame("empty".into()))?;
            let mantissa = v
                .parse::<i64>()
                .map_err(|e| DriverError::InvalidFrame(e.to_string()))?;
            Ok(fp(mantissa))
        }
        fn encode_health_check(&self) -> DriverResult<Frame> {
            Ok(b"HEALTH?".to_vec())
        }
        fn decode_health_response(&self, frame: &[u8]) -> DriverResult<DriverHealth> {
            Ok(DriverHealth {
                healthy: frame == b"HEALTH:OK",
                detail: String::from_utf8_lossy(frame).into_owned(),
            })
        }
    }

    // [CLAIM-33.2, CLAIM-33.4] DriverTrait encode/decode codec surface.
    #[test]
    fn driver_trait_codec_roundtrip() {
        let d = DummyDriver;
        let model = d.capability_discovery().expect("capability");
        assert_eq!(model.device_class, "cold_room");
        assert_eq!(model.parameters.len(), 1);

        let read = d.encode_read("setpoint_c").unwrap();
        let v = d.decode_read_response(b"RESP:setpoint_c").unwrap();
        assert_eq!(read, b"READ:setpoint_c");
        assert_eq!(v, fp(4));

        let permit = ActuationPermitRef {
            target_id: TargetId::new("cold-room-1"),
            param: "setpoint_c".into(),
            value: fp(3),
            entry_id: [9u8; 16],
        };
        let frame = d.encode_actuation(&permit).unwrap();
        assert!(std::str::from_utf8(&frame).unwrap().contains("ACT:"));
        let rb = d.decode_read_back(b"RB:3").unwrap();
        assert_eq!(rb, fp(3));

        let h = d.decode_health_response(&d.encode_health_check().unwrap());
        assert!(h.is_ok());
    }

    // [CLAIM-33.2] each operation returns within 5,000 ms or TimeoutError.
    #[test]
    fn driver_timeout_error_is_typed() {
        let e = run_with_timeout("slow_op", || {
            std::thread::sleep(std::time::Duration::from_millis(5_050));
            Ok::<_, DriverError>(())
        })
        .unwrap_err();
        match e {
            DriverError::Timeout(te) => {
                assert_eq!(te.operation, "slow_op");
                assert_eq!(te.limit_ms, 5_000);
            }
            other => panic!("expected TimeoutError, got {other:?}"),
        }
    }

    #[test]
    fn run_with_timeout_passes_fast_ops() {
        let v = run_with_timeout("fast", || Ok::<_, DriverError>(7_u8)).unwrap();
        assert_eq!(v, 7);
    }

    // [CLAIM-33.3] DeviceModel has runtime UnitId tags, FixedPointValue ranges,
    // writability flags, and rejects empty models.
    #[test]
    fn device_model_requires_at_least_one_parameter() {
        let err = DeviceModel::try_new("empty".into(), vec![]).unwrap_err();
        assert!(err.to_string().contains("at least one parameter"));
    }

    #[test]
    fn device_model_preserves_unit_range_writability() {
        let m = DeviceModel::try_new(
            "x".into(),
            vec![ParameterDescriptor {
                name: "p".into(),
                unit_id: UNIT_DEG_C,
                unit_label: "degC".into(),
                range: [fp(-1), fp(1)],
                writable: false,
            }],
        )
        .unwrap();
        assert_eq!(m.parameters[0].unit_id, UNIT_DEG_C);
        assert_eq!(m.parameters[0].range[0], fp(-1));
        assert!(!m.parameters[0].writable);
    }
}
