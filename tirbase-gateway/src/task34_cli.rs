//! Task 34 production CLI/runtime paths (CLAIM-34.1/2/3/5).
//!
//! These subcommands are exercised by gateway binary integration tests spawning
//! `CARGO_BIN_EXE_tirbase-gateway`. They use real driver clients/models and the
//! real profile install path.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tirbase_drivers::cold_room_sim::ColdRoomSimDriver;
use tirbase_drivers::driver_trait::DriverTrait;
use tirbase_drivers::modbus::ModbusTcpClient;
use tirbase_drivers::mqtt::{client_config_with_roots, install_crypto_provider, MqttTlsClient};
use tirbase_drivers::register_map::ModbusRegisterMap;
use tirbase_guard::envelope::install_profile;
use tirbase_guard::trust_root::{AuthorizedRoleSigner, RolePolicy, TrustRootRecord};
use tirbase_types::CommandRole;

use crate::profiles::load_profile_from_path;

#[derive(Debug, Deserialize)]
struct PaFixture {
    did: String,
    public_key_hex: String,
}

fn load_trust_root(path: &PathBuf) -> Result<TrustRootRecord> {
    let body = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let fx: PaFixture = serde_json::from_str(&body).context("parse PA fixture json")?;
    let pk = hex::decode(fx.public_key_hex.trim()).context("decode PA public key hex")?;
    let mut roles = std::collections::BTreeMap::new();
    roles.insert(
        CommandRole::PolicyAuthority,
        RolePolicy::new(
            1,
            vec![AuthorizedRoleSigner {
                did: fx.did,
                public_key: pk,
            }],
        ),
    );
    Ok(TrustRootRecord {
        version: 1,
        root_ca_public_keys: vec![vec![1; 32]],
        threshold_k: 1,
        role_thresholds: roles,
        device_class_floors: std::collections::BTreeMap::new(),
        expiry_est: i64::MAX,
        revoked_root_ca_keys: Vec::new(),
        signatures: Vec::new(),
    })
}

pub fn run_profile_install(profile_path: &PathBuf, trust_root_path: &PathBuf) -> Result<()> {
    let profile = load_profile_from_path(profile_path).map_err(|e| anyhow::anyhow!(e))?;
    let trust = load_trust_root(trust_root_path)?;
    let model = crate::profiles::cold_room_device_model();
    install_profile(&profile, &model, &trust)
        .map_err(|e| anyhow::anyhow!("profile install rejected: {e:?}"))?;
    println!("PROFILE_INSTALLED:device_class={}", profile.device_class);
    println!(
        "PROFILE_ID={}",
        profile
            .profile_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    Ok(())
}

pub fn run_modbus_smoke(addr: &str, op: &str, register: u16, values: &[u16]) -> Result<()> {
    let mut client = ModbusTcpClient::connect(addr, 1, Duration::from_secs(5))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    match op {
        "read-holding" => {
            let qty = values.first().copied().unwrap_or(1);
            let regs = client
                .read_holding_registers(register, qty)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("MODBUS_OK:op=read-holding regs={:?}", regs);
        }
        "read-input" => {
            let qty = values.first().copied().unwrap_or(1);
            let regs = client
                .read_input_registers(register, qty)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("MODBUS_OK:op=read-input regs={:?}", regs);
        }
        "write-single" => {
            let v = *values.first().context("write-single needs value")?;
            client
                .write_single_register(register, v)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("MODBUS_OK:op=write-single register={register} value={v}");
        }
        "write-multiple" => {
            if values.is_empty() {
                bail!("write-multiple needs values");
            }
            client
                .write_multiple_registers(register, values)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("MODBUS_OK:op=write-multiple register={register} values={values:?}");
        }
        _ => bail!("unsupported modbus op: {op}"),
    }
    Ok(())
}

pub fn run_mqtt_smoke(
    uri: &str,
    ca_cert_pem_path: &PathBuf,
    topic: &str,
    payload: &str,
) -> Result<()> {
    install_crypto_provider();
    let pem = std::fs::read(ca_cert_pem_path)?;
    let mut reader = std::io::BufReader::new(pem.as_slice());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse CA cert PEM")?;
    let cfg = client_config_with_roots(certs, false).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut client =
        MqttTlsClient::connect_mqtts(uri, "tirbase-gateway-task34", cfg, Duration::from_secs(5))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    client
        .publish_qos0(topic, payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pid = client
        .publish_qos1(topic, payload.as_bytes(), Duration::from_secs(5))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("MQTT_OK:qos0=1 qos1_pid={pid}");
    Ok(())
}

pub fn run_cold_room_step(seed: u64, steps: usize) -> Result<()> {
    let mut driver = ColdRoomSimDriver::new(seed, "cold_room#1");

    // Exercise the canonical DriverTrait codec, not just the model internals:
    // capability discovery, the health-check codec and a read request/response.
    let model = driver
        .capability_discovery()
        .map_err(|e| anyhow::anyhow!("driver capability discovery: {e}"))?;
    let _read_request = driver
        .encode_read("temperature_c")
        .map_err(|e| anyhow::anyhow!("driver encode_read: {e}"))?;
    let health = driver
        .decode_health_response(b"HEALTH:OK")
        .map_err(|e| anyhow::anyhow!("driver decode_health_response: {e}"))?;

    let mut last = 0i64;
    for _ in 0..steps {
        last = driver.model.step();
    }
    println!(
        "COLD_ROOM_OK:seed={seed} steps={steps} temp_mdeg_c={last} compressor_on={} device_class={} params={} health={}",
        driver.model.compressor_on,
        model.device_class,
        model.parameters.len(),
        health.healthy
    );
    Ok(())
}

/// Parse and validate a Modbus register map document (CLAIM-33.x / task 34).
///
/// Exposes the real `tirbase_drivers::register_map` parser from the gateway
/// binary so operators can validate a map before deploying it.
pub fn run_register_map_check(path: &PathBuf) -> Result<()> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read register map {}", path.display()))?;
    let map = ModbusRegisterMap::parse(&body)
        .map_err(|e| anyhow::anyhow!("register map rejected: {e}"))?;
    println!(
        "REGISTER_MAP_OK:device_class={} registers={}",
        map.device_class,
        map.registers.len()
    );
    for reg in &map.registers {
        let width = reg
            .registers_per_value()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        println!(
            "REGISTER:{} name={} function={} type={} width={} writable={}",
            reg.register,
            reg.name,
            reg.function,
            reg.data_type_normalized(),
            width,
            reg.writable
        );
    }
    Ok(())
}


/// Report 7-day rolling average and projected durable write bytes/day at the
/// Linux block layer (PV-15.4, CLAIM-44.6).
pub fn run_flash_wear_estimate(data_path: &PathBuf, budget_bytes_per_day: u64) -> Result<()> {
    let est = crate::flash_budget::estimate_for_data_path(data_path.as_path(), budget_bytes_per_day);
    println!(
        "FLASH_WEAR_ESTIMATE:block_device={} supported={} budget_bytes_per_day={} today_bytes={} projected_bytes_per_day={} rolling_7d_avg_bytes_per_day={} throttling_active={} group_commit_window_ms={} high_critical_bypass={}",
        est.block_device.as_deref().unwrap_or("none"),
        est.block_layer_supported,
        est.budget_bytes_per_day,
        est.today_bytes,
        est.projected_bytes_per_day,
        est.rolling_7d_avg_bytes_per_day,
        est.throttling_active,
        est.group_commit_window_ms,
        est.high_critical_bypass
    );
    println!("{}", serde_json::to_string_pretty(&est).context("serialize flash-wear estimate")?);
    Ok(())
}
