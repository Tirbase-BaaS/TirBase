# @tirbase/sdk

TypeScript SDK wrapping the WASM-compiled `tirbase-core` — offline-first, local-first BaaS with P2P mesh sync.

## Installation

```bash
npm install @tirbase/sdk
```

`@tirbase/sdk` is the Apache-2.0 TypeScript wrapper. It depends on
`@tirbase/core-wasm`, which is the AGPL-3.0-only `tirbase-core` compiled to
WASM. The two are separate packages so the wrapper can stay permissive while the
runtime stays copyleft.

## Building the WASM Artefact

The `tirbase-sdk/wasm/` directory is the source of the separately published
`@tirbase/core-wasm` package. It is a generated build artefact. Before using the
SDK (or running integration tests against the real WASM module), build it from
the workspace root:

```bash
wasm-pack build \
  --target web \
  --out-dir ../tirbase-sdk/wasm \
  tirbase-core \
  --no-default-features --features wasm
```

Or via the npm script from the `tirbase-sdk/` directory:

```bash
npm run build:wasm
```

**Prerequisites:**
- Rust stable toolchain with the `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/) 0.15.0 or newer

## Usage

```typescript
import { TirBase } from '@tirbase/sdk';

const db = await TirBase.init({
  storagePath: './local.db',
});

// Write
const result = await db.write({
  table: 'reports',
  key: 'report-42',
  data: { title: 'Situation Report', body: '...' },
});
// result.durabilityTier: 'UNCOMMITTED' | 'TIER1' | 'TIER2'

// Read
const report = await db.read({ table: 'reports', key: 'report-42' });

// Query
const reports = await db.query({ table: 'reports', filter: { status: 'open' } });

// Trust level (synchronous)
const level = db.trustLevel; // 'VERIFIED' | 'UNVERIFIED' | 'REVOKED'

// Mesh status (synchronous)
const mesh = db.meshStatus; // { status: 'connected' | 'connecting' | 'disconnected', peerCount: number }
```

## Events

```typescript
db.on('unverified-warning', (w) => console.warn('Device unverified since', w.unverifiedSince));
db.on('trust-level-changed', (e) => console.log('Trust changed:', e.previousLevel, '→', e.newLevel));
db.on('incident-created', (ico) => showContaminationBanner(ico));
db.on('incident-updated', (ico) => updateContaminationBanner(ico));
db.on('incident-closed', (ico) => dismissContaminationBanner(ico.id));
db.on('durability-tier-changed', (e) => console.log('Durability:', e.newTier));
```

## Manager Operations

```typescript
await db.initiateRevocation({
  targetDid: 'did:key:...',
  managerToken: myToken, // root-CA-signed, unexpired, `RevocationManager` role
  nowSecs: Math.floor(Date.now() / 1000),
});
// Req 9.1–9.4 accumulation state + Req 9.5 last-known device status:
// { signaturesCollected, signaturesRequired, status,
//   lastKnownTrustLevel, lastRevocationDeltaReceivedAt }
const status = await db.revocationStatus({ targetDid: 'did:key:...' });
await db.verifyData({ contaminationRootDeltaId: '...', managerToken: myToken });
await db.adminClose({ incidentId: '...', managerToken: myToken });
await db.activateSaturateMode({ biscuitTokenHex: myTokenHex });
// Heartbeat renewal extends the 60-minute lease by 60 minutes (Req 13.4):
await db.renewSaturateMode({ biscuitTokenHex: myTokenHex });
// M-of-N termination (Req 13.6): this device signs `terminationMessageHex`
// automatically; pass the co-signatures collected from the other Managers.
await db.terminateSaturateMode({
  terminationMessageHex: '7361747572617465',
  coManagerSignatures: [{ did: 'did:key:z6Mk...', signatureHex: '...' }],
});
```

## Running Tests

```bash
npm test
```

`pretest` builds both WASM targets: the browser bundle in `wasm/` and a
`--target nodejs` artefact in `wasm-test/` that Jest loads directly. The
manager-operation suites (`tirbase-manager-ops.wasm.test.ts`,
`saturate-issuance.gateway.test.ts`) therefore execute the real core — no
`MockWasmCore` on the asserted path. `saturate-issuance.gateway.test.ts` also
boots the real `tirbase-gateway` binary, mints a DISASTER_ALERT token over the
admin socket and activates Saturate_Mode in a real WASM device, so it requires
a built gateway (`cargo build -p tirbase-gateway --bin tirbase-gateway`, or
`TIRBASE_GATEWAY_BIN`). Only the delegation/plumbing specs in `tirbase.test.ts`
use the mock.
