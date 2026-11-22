# Insurance evidence — controls

Each control names its requirement, how it is verified and where the evidence
lives. `SR-xx` links to `safety/safety-requirements.md`.

| Control | Requirement | Verification | Evidence |
|---|---|---|---|
| Fail-secure gate state and restart to a defined state | SR-01 | HIL campaign and commissioning drill | `docs/evidence/hil/st12-venue-gate-safety/` |
| Offline decision from a signed policy | SR-02, SR-10 | Offline drill with the network removed | Commissioning checklist |
| Revocation enforced offline | SR-03 | Revoked test credential refused with the vendor unreachable | Connector tests; commissioning |
| Replay suppression | SR-04 | Same scan presented twice; one admit | Connector tests; commissioning replay |
| Capacity refusal | SR-05 | Load test to the envelope; refusal visible | Commissioning load test |
| Lockdown authorisation and audit | SR-06 | Unauthorised and authorised commands; drill | ST-08 evidence; drill record |
| Mechanical egress independent of software | SR-07 | Physical inspection and release test | Commissioning inspection |
| No life-safety control | SR-08 | Life-safety point and alarm refusal; no fire family | ST-15 tests; `EXCLUSIONS.md` |
| Clock-jump immunity | SR-09 | Time change during a decision | HIL clock case |
| Metadata-only CCTV with enforced retention | SR-11 | Retention deadline and access audit | ST-13 tests; customer DPIA |
| Credential data minimisation | SR-12 | Feed schema review; pseudonymous references | Privacy register |
| PA template, zone, priority and audit | SR-13 | Test announcement and replay | ST-15 PA tests |
| Supported firmware and spares | SR-14 | Asset register, firmware baseline, spares count | `hardware/` |
| Accredited people | SR-15 | Badge and commissioning sign-off | `integrator/` |
| Mapping validation and tenancy | SR-16 | Conflict and unmapped-id tests | Commissioning check |
| Monitoring, on-call and incident command | SR-17 | Rota, thresholds, drill | `managed-ops/` |
| Credential and network hardening | SR-18 | Unique rotated credentials, segmentation, admin audit | `insurance/auditability.md` |

## Control gaps to disclose

- No independent safety review yet (`review/safety-review-record.md` unsigned).
- No counsel review of the authority and insurance templates yet.
- No live-season loss data; incident history is pilot-only.
- Site-specific capacity and timing figures are verified only at commissioning.

Disclose these gaps to the underwriter rather than presenting the controls as
independently assured.
