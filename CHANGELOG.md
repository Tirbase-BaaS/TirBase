# Changelog

All notable public API changes to this project are recorded in this file.
Every public API addition, removal, or modification is recorded as a distinct
entry before the corresponding release tag (CLAIM-49.4, PV-17.4).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0).

## [Unreleased]

### Added
- **Gateway admin OpenAPI 3.1 definition** (`docs/api/gateway-admin-openapi.yaml`) covering guard/gateway admin native API endpoints (CLAIM-49.1).
- **TypeScript gateway admin SDK** generated from the OpenAPI definition (`sdk/typescript/`, `scripts/generate-gateway-sdk.mjs`); manual edits to generated sources are rejected by CI (CLAIM-49.1, CLAIM-49.2).
- **CI WASM/public API diff gate** comparing the `tirbase-core` public surface against `tirbase-core/wasm-public-api.txt` to detect unintended surface additions (CLAIM-49.3, `scripts/check-wasm-public-api.sh`).
- **mdBook documentation site** (`docs/book.toml`, `docs/src/`) covering architecture overview, threat model, operator guide, deployment hardening, per-vertical pages, and indexed API/config/procedure references (CLAIM-50.1).
- **README Status regeneration from `CLAIMS.md`** via CI (`scripts/generate-readme-status.py`, CLAIM-50.2).
- **Vertical demo packs** (CLAIM-48.1–48.6): `energy-edge` (S1,S2), `water-pumping` (S1,S3, Modbus simulator/register map), `logistics-node` (S10,S12 CRDT BaaS), `buildings-bms` (S1,S2, BACnet simulator placeholder), `remote-ops-mesh` (S12 partition+rejoin), and `defense-logistics` (S3, M-of-N movement orders simulation), each with `profiles/` where applicable, `scenarios/`, `sim/config.toml`, `run.sh`, and `docs/` including non-goals.

### Changed
- None.

### Removed
- None.

### Fixed
- None.

### Security
- Demo pack documentation explicitly states non-goals and out-of-scope protections per vertical (PV-16.2).
