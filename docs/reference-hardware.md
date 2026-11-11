# Reference Hardware Profile (PV-15.1, CLAIM-44.1)

> **Status:** Reference profile defined for baseline/performance and assurance validation. All numerical resource/performance budgets apply to profile **(a)** unless explicitly stated otherwise.

**Release reviewed against:** `<fill at release>`  
**Last reviewed (UTC):** `<YYYY-MM-DD>`

## Profiles

### (a) Baseline gateway (aarch64/armv7 performance baseline)

- **Board:** Raspberry Pi 4 Model B, **1 GB RAM**
- **Architectures:** aarch64 (64-bit userspace/kernel where used) and armv7 (32-bit baseline) cross-build targets
- **Storage:** microSD / reference boot media used for flash-wear and persistence measurements (record exact model/capacity in `docs/perf-baseline.md` per run)
- **OS:** Debian 11+ compatible userspace (per packaging targets); record kernel/version in baseline runs
- **Purpose:** canonical platform for "measure-first" benchmarks and default numerical budgets (set at **120% of measured baseline**)
- **Budget scope:** CPU latency, throughput, RSS/binary-size (when measured), and flash-write budgets apply to this profile unless noted

### (b) Level 2 assurance gateway (TPM2 add-on)

- **Base:** second gateway unit equivalent to profile (a) hardware class
- **Security add-on:** **TPM 2.0** module/add-on (discrete or firmware TPM as validated per deployment; record exact part/interface in test evidence)
- **Purpose:** Level 2 assurance testing per RD-2 and RD-7 (hardware-backed key/counter/attestation paths, wear-leveling/endurance validation where applicable)
- **Notes:** Level 2 claims are evidence-gated; stub/backed implementations must be reported with their actual assurance level

### (c) Power-cut / power-fault test rig

- **Device:** **smart PDU** (remotely switchable, scriptable power cycling)
- **Purpose:** controlled power-cut, brownout/restart, and durability/reconciliation tests (PV-9.x / failure-injection procedures)
- **Requirements:** ability to cut/restore power on schedule, log event times, and correlate with gateway boot/recovery logs

### (d) Field-bus I/O and actuation simulation

- **Adapter:** **USB RS-485 adapter** (record chipset/driver details per lab setup)
- **Endpoint:** **Modbus device or simulation host** on a real RS-485 bus (physical device preferred; hardware simulator acceptable when it exercises the real bus/electrical path)
- **Purpose:** driver integration, register-map validation, timing/timeout/fault behavior, and end-to-end guarded actuation tests

## Measurement and evidence requirements

- Every baseline run recorded in `docs/perf-baseline.md` MUST state: profile ID, exact hardware revision, storage media, OS/kernel, Rust/toolchain versions, build flags/features, ambient/thermal notes if relevant, and date.
- Numerical budgets are set **after** measure-first runs at **120% of baseline** (20% headroom) unless a requirement specifies otherwise.
- CI/automated gates that cannot run on physical RPi hardware must document the execution environment and treat hardware baselines as the authoritative budget source once captured.

## Lab inventory checklist (per release/lab campaign)

| Item | Required for | Present | Identifier/notes |
|---|---|---:|---|
| RPi 4B 1 GB (profile a) | Baseline perf/RSS/flash budgets | ☐ |  |
| Second gateway + TPM2 (profile b) | Level 2 assurance (RD-2, RD-7) | ☐ |  |
| Smart PDU (profile c) | Power-cut / durability tests | ☐ |  |
| USB RS-485 adapter + Modbus device/sim host (profile d) | Driver/field-bus validation | ☐ |  |

---
*Reference hardware definition for PV-15.1/CLAIM-44.1. Budgets derived per PV-15.2 measure-first process.*
