# Changelog

All notable public API changes to this project are recorded in this file.
Every public API addition, removal, or modification is recorded as a distinct
entry before the corresponding release tag (CLAIM-49.4, PV-17.4).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0).

## [Unreleased]

### Added
- **Claim evidence gates (F-02):** `CLAIMS.md` now records a `Production Caller` column and a closed status vocabulary (`Proven`, `Implemented and wired (unproven)`, `Implemented but not wired`, `Planned`). `scripts/check-claims-schema.py` fails CI when a caller path is not reachable from a crate root; `scripts/check-docs-claims.sh` turns the documentation claims (threat model, invariant catalogue, security-event catalogue, unit registry, freshness policy) into executable section checks; `docs/security-critical-callers.toml` plus `scripts/reverse-proof.py` provide remove-the-caller negative proofs (CLAIM-14.2, CLAIM-20.1, CLAIM-G1.9, CLAIM-G1.11) and run nightly in `.github/workflows/reverse-proof.yml`. Release summary: `docs/releases/v0.1.0.md`.
- **Mesh command ingress (CLAIM-35.7):** `GossipMessage::InboundCommand` plus `CoreHandle::publish_mesh_command` / `subscribe_mesh_commands`, and the production receiver `command_ingress/mesh.rs::run_mesh_command_receiver`, started from `main.rs` when `mesh_command_ingress = true` and a signed profile is installed. Mesh-delivered commands run the same Stage 0–19 guard pipeline with `IngressSource::Mesh`; delivery never bypasses admission. Covered by `inbound_mesh_command_is_delivered_to_subscriber` and `mesh_command_receiver_runs_every_command_through_admission`.

### Added (previous)
- **Cross-build parity proof (Property 1):** `scripts/cross-build-parity.sh`, parity-probe feature/export (`tirbase-core/src/parity_probe.rs`, `core_cross_build_parity_hash`), and CI `test` job step `Cross-build parity (native vs real WASM state hash, Property 1)` proving byte-identical deterministic state hashes for native vs real WASM over an identical canonical sequence including signed Migration Deltas and list/RGA writes.
- **Real-mesh proofs:** concurrent list insertion preservation over real Swarm-backed mesh (`api::real_mesh_tests::two_devices_concurrent_list_insertions_preserved_over_real_mesh`), and CI-proven coverage cited for M-of-N revocation accumulation/threshold (CLAIM-G1.11, Property 7), saturate renewal/termination, contamination/ICO/sidecar, and live quorum/durability paths.
- **Property 20 sequence coverage:** `tests::properties::prop_20_sequence_covers_renewal_and_termination_events` (activation, renewal, M-of-N termination, expiry).
- **API parity extension:** `tests::api_parity::sdk_typescript_admin_constants_match_gateway_openapi` asserting `sdk/typescript` `ADMIN_PATHS`/`OPERATION_IDS` match `docs/api/gateway-admin-openapi.yaml` (parity-probe export exempted as test-only).
- **Gateway admin OpenAPI 3.1 definition** (`docs/api/gateway-admin-openapi.yaml`) covering guard/gateway admin native API endpoints (CLAIM-49.1).
- **TypeScript gateway admin SDK** generated from the OpenAPI definition (`sdk/typescript/`, `scripts/generate-gateway-sdk.mjs`); manual edits to generated sources are rejected by CI (CLAIM-49.1, CLAIM-49.2).
- **CI WASM/public API diff gate** comparing the `tirbase-core` public surface against `tirbase-core/wasm-public-api.txt` to detect unintended surface additions (CLAIM-49.3, `scripts/check-wasm-public-api.sh`).
- **mdBook documentation site** (`docs/book.toml`, `docs/src/`) covering architecture overview, threat model, operator guide, deployment hardening, per-vertical pages, and indexed API/config/procedure references (CLAIM-50.1).
- **README Status regeneration from `CLAIMS.md`** via CI (`scripts/generate-readme-status.py`, CLAIM-50.2).
- **Vertical demo packs** (CLAIM-48.1–48.6): `energy-edge` (S1,S2), `water-pumping` (S1,S3, Modbus simulator/register map), `logistics-node` (S10,S12 CRDT BaaS), `buildings-bms` (S1,S2, BACnet simulator placeholder), `remote-ops-mesh` (S12 partition+rejoin), and `defense-logistics` (S3, M-of-N movement orders simulation), each with `profiles/` where applicable, `scenarios/`, `sim/config.toml`, `run.sh`, and `docs/` including non-goals.
- **Closeout audit:** `docs/audits/e2e-wiring-ws8-closeout.md` (workstream → production caller → test → CI job → residual risk).

### Changed
- `CLAIMS.md` table schema is now five columns (claim, text, status, production caller, test/gate); the old `Implemented` and `Wired` statuses were replaced, and the CLI/threat-model/traceability documents were reconciled with the registry. The generated README status now lists any claim that is implemented but not wired as explicitly not done.
- Reconciled `README.md`, `CLAIMS.md` (CLAIM-G1.11 plus CLAIM-59.1–59.7 for cross-build parity, schema determinism, DRR/compaction/queue, real-mesh transport wiring, contamination/Side-Car replay, LWW/RGA merge, and the TypeScript SDK surface), `docs/traceability-matrix.md` (rows added for Req 1.4/Property 1, Property 7/Req 9.1 and 9.3, Property 15/Req 17.1 and 20.5, DRR/compaction/queue, CCE/Side-Car, and mesh transport), and `tirbase-core/tests/README.md` (stale WASM compile-error note replaced; Cross-Device Mesh Sync moved from PARTIAL to VERIFIED) to match CI-proven status; residual hardware/environment/scale blockers (real BLE radio, cross-host RF, and the full 100,000-delta queue run) are explicit and evidence-backed.

### Removed
- None.

### Fixed
- **CRDT array/list convergence:** `CrdtEngine` now stores JSON arrays as real Automerge lists (RGA-capable) and projects list values as JSON arrays on read/merge/projection, fixing a defect exposed by real-mesh concurrent list insertion proof.

### Security
- Demo pack documentation explicitly states non-goals and out-of-scope protections per vertical (PV-16.2).
