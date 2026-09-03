# @tirbase/sdk

TypeScript SDK wrapping the WASM-compiled `tirbase-core` — offline-first, local-first BaaS with P2P mesh sync.

## Installation

```bash
npm install @tirbase/sdk
```

## Building the WASM Artefact

The `tirbase-sdk/wasm/` directory is **not committed** — it is a generated build artefact. Before using the SDK (or running integration tests against the real WASM module), build it from the workspace root:

```bash
wasm-pack build tirbase-core \
  --no-default-features --features wasm \
  --target web \
  --out-dir ../tirbase-sdk/wasm
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
await db.initiateRevocation({ targetDid: 'did:key:...', managerToken: myToken });
const status = await db.revocationStatus({ targetDid: 'did:key:...' });
await db.verifyData({ contaminationRootDeltaId: '...', managerToken: myToken });
await db.adminClose({ incidentId: '...', managerToken: myToken });
await db.activateSaturateMode({ biscuitTokenHex: myTokenHex });
```

## Running Tests

```bash
npm test
```

Tests use a `MockWasmCore` and do not require the WASM artefact to be built.
