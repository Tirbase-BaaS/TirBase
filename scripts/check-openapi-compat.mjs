#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only

// F-08: rejects breaking OpenAPI changes unless info.version is bumped.
//
// The lock records the canonical API surface (paths + methods + operationIds)
// and the spec version. A difference is breaking when the version is
// unchanged. Run with --update after an intentional version bump to refresh
// the lock; CI runs the default check mode and fails on a stale lock.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const specPath = path.join(root, 'docs', 'api', 'gateway-admin-openapi.yaml');
const lockPath = path.join(root, 'docs', 'api', 'openapi-compat.lock.json');

function surface(yaml) {
  const paths = {};
  let currentPath = null;
  let currentMethod = null;
  for (const line of yaml.split('\n')) {
    const p = /^ {2}(\/admin\/[A-Za-z0-9_\-/{}]+):\s*$/.exec(line);
    if (p) {
      currentPath = p[1];
      paths[currentPath] ??= {};
      currentMethod = null;
      continue;
    }
    const m = /^ {4}(get|post|patch|delete|put):\s*$/.exec(line);
    if (m && currentPath) {
      currentMethod = m[1];
      continue;
    }
    const id = /^ {6}operationId:\s*([A-Za-z0-9_]+)/.exec(line);
    if (id && currentPath && currentMethod) {
      paths[currentPath][currentMethod] = id[1];
    }
  }
  return paths;
}

const spec = fs.readFileSync(specPath, 'utf8');
const version = /^ {2}version:\s*"([^"]+)"/m.exec(spec)?.[1] ?? 'unknown';
const paths = surface(spec);
const canonical = JSON.stringify({ paths }, Object.keys(paths).sort());
const hash = crypto.createHash('sha256').update(canonical).digest('hex');

const update = process.argv.includes('--update');
const previous = fs.existsSync(lockPath)
  ? JSON.parse(fs.readFileSync(lockPath, 'utf8'))
  : null;

if (!previous) {
  if (!update) {
    console.error(`ERROR: ${path.relative(root, lockPath)} is missing; run with --update.`);
    process.exit(1);
  }
} else if (previous.hash !== hash) {
  if (previous.version === version) {
    const previousPaths = previous.paths ?? {};
    const removed = [];
    for (const [p, methods] of Object.entries(previousPaths)) {
      for (const [method, operationId] of Object.entries(methods)) {
        if (paths[p]?.[method] !== operationId) removed.push(`${method.toUpperCase()} ${p}`);
      }
    }
    console.error('ERROR: breaking OpenAPI change without a version bump.');
    console.error(`  info.version is still ${version}; changed/removed operations:`);
    for (const entry of removed) console.error(`    - ${entry}`);
    console.error('Bump info.version and run: node scripts/check-openapi-compat.mjs --update');
    process.exit(1);
  }
  if (!update) {
    console.error(
      `ERROR: OpenAPI surface differs from the committed lock (${previous.version} -> ${version}).`,
    );
    console.error('Run: node scripts/check-openapi-compat.mjs --update');
    process.exit(1);
  }
} else {
  console.log(`OK: OpenAPI ${version} matches the compatibility lock.`);
  process.exit(0);
}

if (!update) {
  console.log(`OK: OpenAPI ${version} versioned change; lock refresh required.`);
  process.exit(0);
}

fs.writeFileSync(
  lockPath,
  JSON.stringify({ version, algorithm: 'sha256', hash, paths }, null, 2) + '\n',
);
console.log(`updated ${path.relative(root, lockPath)} for OpenAPI ${version}`);
