#!/usr/bin/env bash
# Ensures the TypeScript gateway admin SDK is generated from the OpenAPI definition
# and rejects manual changes (CLAIM-49.2, PV-17.1).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

node scripts/generate-gateway-sdk.mjs

# If generation produced any diff, the committed SDK was edited manually or is stale.
if ! git diff --quiet -- sdk/typescript/src sdk/typescript/generation-manifest.json sdk/typescript/openapi.yaml; then
  echo "ERROR: sdk/typescript generated files differ from docs/api/gateway-admin-openapi.yaml output."
  echo "Manual SDK changes are rejected. Regenerate with: node scripts/generate-gateway-sdk.mjs"
  git --no-pager diff -- sdk/typescript/src sdk/typescript/generation-manifest.json sdk/typescript/openapi.yaml || true
  exit 1
fi

echo "OK: TypeScript gateway admin SDK matches OpenAPI-generated output."
