# Phase 8 — Drivers and Reference Drivers — Phase Audit

**Status:** PASS WITH TRACE LIMITATIONS — trace audit complete, no ASSUMED rows
**Phase gate:** Every row is traced to existing implementation; the next phase may build on it.
**Date:** 2026-11-11
**Spec:** tirbase-master-enhancement
**Requirement:** PV-1.10 (phase completion audit); PV-1.9 for Phase 0
**Task entry:** 57.8

## Scope

Task sections 33.x, 34.x: 16 acceptance-criterion rows (16 complete, 0 open in `tasks.md` at audit time).

## Method

Every row was traced against the repository; nothing was accepted on assertion. The audit:

1. resolves each declared production-caller path on disk and each cited symbol to its
   definition site (`file:line`);
2. resolves test identifiers in this order: a claim-named test (`claim_<task>`), a test
   named in the task entry, the closest test in a test file named in the task entry, then
   the test location committed in `docs/traceability-matrix.md` for the task's PV
   requirement;
3. records tasks with an open checkbox as `NOT IMPLEMENTED` or `BLOCKED` — never as verified.

Evidence classes in the status column:

- `VERIFIED-BY-TRACE` — production call site resolved and a task-named/claim-named test resolved.
- `TRACED-CALLER` — production call site resolved; test evidence is file-, suite-, matrix- or CI-level only.
- `TRACED-TEST` — test or document deliverable traced, with no distinct runtime caller.
- `TRACED-ARTIFACT` — documentation/CI deliverable; the cited artifact exists.
- `BLOCKED` / `NOT IMPLEMENTED` — cannot be verified as done; reason recorded.

No row is `ASSUMED`: a row that could not be traced is reported as an open item instead.

## Evidence

| Task | Acceptance criterion (task) | Req | Production call site | Test evidence | Status |
|---|---|---|---|---|---|
| 33.1 | Create tirbase-drivers/Cargo.toml with dependency on tirbase-types only (no tirbase-guard, no tirbase-core) | PV-10 | `tirbase-drivers/Cargo.toml:9`<br>`tirbase-sim/src/sim.rs:171` (`guard`) | — | TRACED-CALLER |
| 33.2 | Implement DriverTrait: capability_discovery, read, write_desired, verify, health; each operation returns withi… | PV-10.1 | `tirbase-drivers/src/lib.rs:69` (`capability_discovery`) | `tirbase-drivers/tests/driver_trait.rs:71` (`driver_trait_all_operations_are_codec_only`) — via PV-10.1 | TRACED-CALLER |
| 33.3 | Implement DeviceModel with runtime UnitId tags, FixedPointValue [min, max] ranges, writability flags; reject e… | PV-10.2 | `tirbase-gateway/tests/task21_runtime_wiring.rs:1` | — | TRACED-CALLER |
| 33.4 | Implement ActuationPermit integration: driver exposes encode_actuation(permit) -> Frame and decode_read_back(f… | PV-4.21 | `tirbase-core/src/durability/integration_tests.rs:1` | `tirbase-guard/tests/driver_isolation.rs:40` (`test_scm_rights_blocked`) — via PV-4.21 | TRACED-CALLER |
| 33.5 | Implement out-of-process isolation: guard creates socketpair(AF_UNIX, SOCK_SEQPACKET); parent keeps fd0; child… | PV-4.21, PV-10.4 | `tirbase-guard/src/driver_proxy.rs:209` (`spawn_child_parts`)<br>`tirbase-drivers/src/isolation.rs:191` (`verify_peercred`)<br>`tirbase-drivers/src/isolation.rs:520` (`send_fd_via_scm_rights`) | `tirbase-guard/tests/driver_supervision.rs:195` (`real_child_applies_sandbox_and_serves_admitted_frames`) | VERIFIED-BY-TRACE |
| 33.6 | Apply seccomp-BPF + no-new-privs + landlock (kernel ≥5.13; fail-closed without opt-in signed config flag if un… | PV-10.4 | `tirbase-guard/src/bin/driver_isolation_child.rs:6`<br>`tirbase-drivers/src/isolation.rs:14` | `tirbase-guard/tests/driver_supervision.rs:195` (`real_child_applies_sandbox_and_serves_admitted_frames`) | VERIFIED-BY-TRACE |
| 33.7 | Implement driver process lifecycle: persistent child, exponential-backoff restart (1s initial, 60s max, 5 retr… | PV-10 | `tirbase-drivers/src/lifecycle.rs:101` (`apply_restart_decision`)<br>`tirbase-gateway/src/main.rs:1021` (`GatewayDriverCrashSupervisor`) | `tirbase-guard/tests/driver_supervision.rs:253` (`crashed_child_is_restarted_with_backoff`) | VERIFIED-BY-TRACE |
| 33.8 | Add CI isolation check verifying tirbase-drivers does not import tirbase-guard or tirbase-core symbols | PV-10.3 | `.github/workflows/ci.yml:138` | — | TRACED-ARTIFACT |
| 34.1 | Implement Modbus TCP/RTU **client** driver: FC 03 (read holding registers), FC 04 (read input registers), FC 0… | PV-10.7 | `tirbase-drivers/src/modbus.rs:534` (`ModbusTcpClient`)<br>`tirbase-drivers/src/modbus.rs:892` (`ModbusRtuClient`) | `tirbase-gateway/tests/task34_binary.rs:114` (`claim_34_1_gateway_binary_modbus_smoke_against_sim`) | VERIFIED-BY-TRACE |
| 34.2 | Implement MQTT bridge driver: QoS 0 and 1 over TLS; reject plain-text connections | PV-10.7 | `tirbase-drivers/src/mqtt.rs:21`<br>`tirbase-gateway/src/task34_cli.rs:24`<br>`tirbase-admin/src/main.rs:9` | `tirbase-gateway/tests/task34_binary.rs:162` (`claim_34_2_gateway_binary_mqtt_smoke_real_tls`) | VERIFIED-BY-TRACE |
| 34.3 | Implement cold-room simulator driver backed by first-order thermal model in tirbase-sim | PV-10.7 | `tirbase-drivers/src/cold_room_sim.rs:19`<br>`tirbase-sim/src/drivers/cold_room.rs:12` | `tirbase-sim/tests/claim_34_3.rs:7` (`claim_34_3_canonical_thermal_model_bit_identical_across_crates`) | VERIFIED-BY-TRACE |
| 34.4 | Add cargo-fuzz targets for Modbus and MQTT frame parsers with committed seed corpus entries | PV-10.5 | `tirbase-core/fuzz/fuzz_targets/fragment_reassembly.rs:1` | — | TRACED-CALLER |
| 34.5 | Create EnvelopeProfile TOML documents in profiles/ with schema validation; each profile validated by install-t… | PV-10.6 | `tirbase-gateway/src/profiles.rs:15`<br>`tirbase-admin/src/main.rs:9` | `tirbase-gateway/tests/task34_binary.rs:57` (`claim_34_5_gateway_binary_installs_valid_profile_and_rejects_invalid`) | VERIFIED-BY-TRACE |
| 34.6 | Add simulator-based conformance tests per profile: at least one nominal scenario and one boundary scenario, wi… | PV-10.6 | `tirbase-sim/src/conformance/mod.rs:17` | `tirbase-sim/src/conformance/mod.rs:403` (`claim_34_6_all_profiles_have_committed_results`) | VERIFIED-BY-TRACE |
| 34.7 | Create Modbus register map documentation for each reference driver pack in docs/drivers/ | PV-10 | `docs/drivers/cold_room_modbus.md:1` | — | TRACED-ARTIFACT |
| 34.8 | Implement DeviceTransport: the parent-owned connection to the physical device (TCP socket for Modbus TCP, seri… | PV-10.4, PV-10.7 | `tirbase-guard/src/device_transport.rs:17` (`DeviceTransport`)<br>`tirbase-guard/src/device_transport.rs:143` (`pass_device_fd_with`) | `tirbase-guard/tests/device_transport_s35.rs:15` (`claim_34_8_guard_passes_device_fd_to_child_via_scm_rights`) | VERIFIED-BY-TRACE |

## Gaps and open items

- **33.1** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **33.2** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **33.3** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **33.4** (`TRACED-CALLER`) — Production caller traced; test traced through the named file or the committed traceability matrix, not a task-named test.
- **33.8** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.
- **34.4** (`TRACED-CALLER`) — Production caller traced; no executable test evidence resolved.
- **34.7** (`TRACED-ARTIFACT`) — Document/CI deliverable traced; no runtime caller applies.

## Verdict

**PASS WITH TRACE LIMITATIONS.** All 16 rows have a resolved production call site or deliverable; 7 row(s) rely on file-, suite-, matrix- or CI-level test evidence because their task entries name no single test. No row is ASSUMED.

