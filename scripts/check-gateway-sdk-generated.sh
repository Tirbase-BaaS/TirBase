#!/usr/bin/env bash
# Ensures the TypeScript and Python gateway admin SDKs are generated from the
# OpenAPI definition and rejects manual changes (CLAIM-49.2, PV-17.1).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

node scripts/generate-gateway-sdk.mjs

# If generation produced any diff, the committed SDK was edited manually or is stale.
if ! git diff --quiet -- sdk/typescript/src sdk/typescript/generation-manifest.json sdk/typescript/openapi.yaml sdk/python; then
  echo "ERROR: generated SDK files differ from docs/api/gateway-admin-openapi.yaml output."
  echo "Manual SDK changes are rejected. Regenerate with: node scripts/generate-gateway-sdk.mjs"
  git --no-pager diff -- sdk/typescript/src sdk/typescript/generation-manifest.json sdk/typescript/openapi.yaml sdk/python || true
  exit 1
fi

echo "OK: TypeScript and Python gateway admin SDKs match OpenAPI-generated output."
