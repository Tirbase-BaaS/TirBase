# TirBase Operator Console

Apache-2.0 web console shell for cold-chain, POS and venue operations. It talks
to the gateway **only** through the generated OpenAPI client
(`@tirbase/gateway-admin-sdk`), which is also Apache-2.0. No AGPL gateway or
core source is imported or bundled; `npm run check:licence` enforces this
boundary in CI.

## Run

```bash
# from the repository root, once
npm --prefix sdk/typescript ci
npm --prefix sdk/typescript run build

npm --prefix console ci
npm --prefix console run dev
```

Open `http://127.0.0.1:4173`. Enter the gateway base URL (empty when the console
is served from the same origin), the tenant and a scoped Bearer token.

Remote admin is mTLS-only. Browsers cannot attach an arbitrary client
certificate to `fetch`, so deploy the console behind a reverse proxy on the
gateway origin (or use the browser/OS certificate store). For development,
`TIRBASE_CONSOLE_PROXY=https://127.0.0.1:8443` and
`TIRBASE_CONSOLE_PROXY_INSECURE=1` enable the Vite `/admin` proxy.

## Checks

```bash
npm run typecheck
npm run build
npm run check:licence
npm run test:e2e
```

Playwright boots the Vite server and intercepts `/admin/**` with an in-memory
gateway. Every request is checked against the OpenAPI `ADMIN_PATHS`; the suite
covers keyboard-only operation, contrast, labels, localization, time zones,
tenant switching, empty/error states and one journey per vertical.

## Structure

- `packages/design-system/` — shared Apache-2.0 primitives and WCAG-AA tokens.
- `src/api.ts` — the only data adapter; imports the generated SDK.
- `src/i18n.ts` — English/Spanish dictionaries and translation hook.
- `src/screens/` — cold-chain, POS, venue and settings screens.
- `e2e/` — Playwright shell and journey tests.
