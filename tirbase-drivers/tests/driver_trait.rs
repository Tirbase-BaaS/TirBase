//! CLAIM-33.2/33.3/33.4 (PV-10.1, PV-10.2, PV-4.21, INV-6): DriverTrait codec,
//! DeviceModel validation, and ActuationPermitRef encode/decode integration.

use tirbase_drivers::{
    ActuationPermitRef, DeviceModel, DriverError, DriverHealth, DriverResult, DriverTrait, Frame,
    ParameterDescriptor, DRIVER_OPERATION_TIMEOUT,
};
use tirbase_types::{FixedPointValue, TargetId, UNIT_DEG_C};

fn fp(m: i64) -> FixedPointValue {
    FixedPointValue::new(m, 0, UNIT_DEG_C)
}

struct CodecOnlyDriver;
impl DriverTrait for CodecOnlyDriver {
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
        Ok(format!("R:{param}").into_bytes())
    }
    fn decode_read_response(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        let s = std::str::from_utf8(frame).map_err(|e| DriverError::InvalidFrame(e.to_string()))?;
        let v = s
            .strip_prefix("V:")
            .ok_or_else(|| DriverError::InvalidFrame("missing V:".into()))?;
        Ok(fp(v
            .parse()
            .map_err(|e| DriverError::InvalidFrame(format!("{e}")))?))
    }
    fn encode_actuation(&self, permit: &ActuationPermitRef) -> DriverResult<Frame> {
        Ok(format!(
            "A:{}:{}:{}",
            permit.target_id.as_str(),
            permit.param,
            permit.value.mantissa
        )
        .into_bytes())
    }
    fn decode_read_back(&self, frame: &[u8]) -> DriverResult<FixedPointValue> {
        let s = std::str::from_utf8(frame).map_err(|e| DriverError::InvalidFrame(e.to_string()))?;
        let v = s
            .strip_prefix("RB:")
            .ok_or_else(|| DriverError::InvalidFrame("missing RB:".into()))?;
        Ok(fp(v
            .parse()
            .map_err(|e| DriverError::InvalidFrame(format!("{e}")))?))
    }
    fn encode_health_check(&self) -> DriverResult<Frame> {
        Ok(b"H?".to_vec())
    }
    fn decode_health_response(&self, frame: &[u8]) -> DriverResult<DriverHealth> {
        Ok(DriverHealth {
            healthy: frame == b"OK",
            detail: String::from_utf8_lossy(frame).into_owned(),
        })
    }
}

#[test]
fn driver_trait_all_operations_are_codec_only() {
    let d = CodecOnlyDriver;
    let model = d.capability_discovery().unwrap();
    assert_eq!(model.parameters[0].unit_id, UNIT_DEG_C);
    assert_eq!(model.parameters[0].range, [fp(-40), fp(10)]);
    assert!(model.parameters[0].writable);

    assert_eq!(d.encode_read("setpoint_c").unwrap(), b"R:setpoint_c");
    assert_eq!(d.decode_read_response(b"V:5").unwrap(), fp(5));

    let permit = ActuationPermitRef {
        target_id: TargetId::new("t1"),
        param: "setpoint_c".into(),
        value: fp(4),
        entry_id: [1u8; 16],
    };
    let act = d.encode_actuation(&permit).unwrap();
    assert!(String::from_utf8(act).unwrap().starts_with("A:"));
    assert_eq!(d.decode_read_back(b"RB:4").unwrap(), fp(4));

    let h = d.decode_health_response(b"OK").unwrap();
    assert!(h.healthy);
    assert_eq!(d.encode_health_check().unwrap(), b"H?");
    assert_eq!(DRIVER_OPERATION_TIMEOUT.as_millis(), 5_000);
}

#[test]
fn device_model_rejects_empty_parameters() {
    let err = DeviceModel::try_new("x".into(), vec![]).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("zero") || msg.contains("at least one parameter"));
}

// Wiring mutation check (33.3): accepting empty DeviceModel must fail this test.
#[test]
fn empty_device_model_is_never_accepted() {
    assert!(DeviceModel::try_new("m".into(), vec![]).is_err());
    let bad = DeviceModel {
        device_class: "m".into(),
        parameters: vec![],
    };
    assert!(bad.validate().is_err());
}

#[test]
fn timeout_error_is_typed() {
    let err = tirbase_drivers::run_with_timeout("op", || {
        std::thread::sleep(std::time::Duration::from_millis(5_010));
        Ok::<_, DriverError>(())
    })
    .unwrap_err();
    match err {
        DriverError::Timeout(t) => {
            assert_eq!(t.operation, "op");
            assert_eq!(t.limit_ms, 5_000);
            assert!(t.to_string().contains("5000"));
        }
        other => panic!("expected timeout, got {other:?}"),
    }
}
