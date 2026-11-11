# Public API Reference

This page indexes the public API surfaces and their authoritative sources.

## Workspace crates

| Crate | Public API manifest | Notes |
|---|---|---|
| `tirbase-types` | `tirbase-types/public-api.txt` | Shared types/newtypes, units, `FixedPointValue`, roles |
| `tirbase-core` | `tirbase-core/public-api.txt`, `tirbase-core/wasm-public-api.txt` | CRDT, identity/auth, store, transport, migration traits/APIs |
| `tirbase-guard` | `tirbase-guard/public-api.txt` | Command guard, envelope/policy, effects/replay/time/permit APIs |
| `tirbase-drivers` | `tirbase-drivers/public-api.txt` | Driver trait and device/driver interfaces |
| `tirbase-sim` | `tirbase-sim/public-api.txt` | Simulator, models, scenarios, runner, invariant APIs |
| `tirbase-demo` | `tirbase-demo/public-api.txt` | Demo pack format helpers/constants |

Binary crates (`tirbase-gateway`, `tirbase-admin`) expose operational CLIs and
network/admin interfaces rather than library public API manifests.

## Gateway admin HTTP/socket API

- Machine-readable definition (OpenAPI 3.1): [`docs/api/gateway-admin-openapi.yaml`](../../api/gateway-admin-openapi.yaml)
- Generated TypeScript SDK: `sdk/typescript/` (generated from the OpenAPI spec; manual edits rejected by CI)

## WASM surface

- `tirbase-core` WASM/public API baseline: `tirbase-core/wasm-public-api.txt`
- CI diffs the public/WASM surface against this baseline to detect unintended additions (CLAIM-49.3).

For detailed type signatures, consult the per-crate `public-api.txt` manifests and
generated Rust/SDK docs.
