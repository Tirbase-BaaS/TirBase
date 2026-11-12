# `@tirbase/gateway-admin-sdk`

Generated TypeScript client for the TirBase gateway admin surface
(`docs/api/gateway-admin-openapi.yaml`, CLAIM-49.1/49.2). `src/client.ts`,
`src/index.ts` and `src/types.ts` are generated — change the OpenAPI document
and run `node scripts/generate-gateway-sdk.mjs` instead of editing them.

The client is transport-agnostic: it needs a `fetch`-shaped function and
returns a typed `AdminResult<T>` (`ok`, `status`, `data` or `error`) for every
path in `ADMIN_PATHS`.

## Node: mutual TLS

The remote admin listener is mTLS-only, so a client certificate is mandatory.
Node has no browser-style certificate store, so import the transport helper
from the `./mtls` subpath (kept separate so a browser bundle never pulls in
`node:https`):

```ts
import fs from 'node:fs';
import { GatewayAdminClient } from '@tirbase/gateway-admin-sdk';
import { createMtlsFetch } from '@tirbase/gateway-admin-sdk/mtls';

const client = new GatewayAdminClient({
  baseUrl: 'https://gateway.internal:9443',
  token: biscuitTokenHex, // Authorization: Bearer <hex>
  fetchImpl: createMtlsFetch({
    cert: fs.readFileSync('client.pem'),
    key: fs.readFileSync('client.key'),
    ca: fs.readFileSync('ca.pem'),
  }),
});
```

`createMtlsFetch` verifies the server against `ca` by default
(`rejectUnauthorized: true`) and sends an explicit `Content-Length`, which the
gateway's remote admin reader requires.

## Browser

Browsers choose client certificates from the OS/browser store during the TLS
handshake and do not expose them to JavaScript. Use the global `fetch` and let
the handshake select the certificate; `fetchInit` carries any extra request
fields:

```ts
new GatewayAdminClient({
  baseUrl: 'https://gateway.internal:9443',
  token: biscuitTokenHex,
  fetchInit: { credentials: 'include' }, // when the cert is session-selected
});
```

Mutual TLS must be provisioned out of band (certificate imported into the
browser profile or pushed by device management); the SDK cannot attach a
certificate programmatically.

## undici

`fetchInit` is merged into every request but cannot override the method,
headers or body the client owns, so an undici dispatcher bound to a TLS agent
can be supplied directly:

```ts
import { Agent } from 'undici';

new GatewayAdminClient({
  baseUrl: 'https://gateway.internal:9443',
  token: biscuitTokenHex,
  fetchInit: { dispatcher: new Agent({ connect: { cert, key, ca } }) },
});
```

## DISASTER_ALERT tokens

Saturate-mode activation needs a token carrying `caveat("disaster-alert")`.
`mint` issues it; the caveat is restricted to the core allowlist, and an
unknown value is rejected with `400 MINT_CAVEAT_REJECTED`:

```ts
const { data } = await client.mint({
  did: gatewayDid,
  role: 'PolicyAuthority',
  ttl_secs: 3600,
  caveat: 'disaster-alert',
});
// data.token_hex is the credential `activateSaturateMode` expects
```
