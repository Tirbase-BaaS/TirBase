#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Normalises the Node-target `wasm-pack build --target nodejs` output used by
// the real-WASM SDK tests (`tirbase-sdk/wasm-test/`). The Node build is a test
// artefact only: it is gitignored and never published. It exists because the
// browser-target glue is an ES module, while Jest runs the TypeScript SDK in a
// CommonJS environment — the Node target lets the tests execute the *real*
// compiled core in-process, with the SDK's production bridge on the asserted
// path.

import { readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(here, '..', 'wasm-test');

const packagePath = join(wasmDir, 'package.json');
const pkg = JSON.parse(await readFile(packagePath, 'utf8'));

pkg.name = '@tirbase/core-wasm-test';
pkg.version = '0.1.0';
pkg.license = 'AGPL-3.0-only';
pkg.description = 'TirBase core WASM (Node target, test artefact only)';
pkg.private = true;
delete pkg.type;
pkg.files = ['tirbase_core_bg.wasm', 'tirbase_core.js'];

await writeFile(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);
await writeFile(join(wasmDir, '.gitignore'), '*\n');

// Stale per-device glue copies from a previous build must not survive: each is
// a snapshot of the old `#[wasm_bindgen]` signature.
for (const entry of await readdir(wasmDir)) {
  if (entry.startsWith('device_') && entry.endsWith('.js')) {
    await rm(join(wasmDir, entry));
  }
}

// The Node target still emits wasm-bindgen snippets as ES modules. Node 24's
// `require(esm)` accepts them, but Jest's CommonJS runtime does not, so rewrite
// each snippet to the equivalent CommonJS shape. The snippet body is unchanged.
async function normaliseSnippets(dir) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      await normaliseSnippets(full);
      continue;
    }
    if (!entry.name.endsWith('.js')) continue;
    const source = await readFile(full, 'utf8');
    const names = [];
    let body = source.replace(
      /export\s+(async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(/g,
      (_match, asyncKw, name) => {
        names.push(name);
        return `${asyncKw ?? ''}function ${name}(`;
      },
    );
    if (names.length === 0) continue;
    body += `\nmodule.exports = { ${names.join(', ')} };\n`;
    await writeFile(full, body);
  }
}

await normaliseSnippets(join(wasmDir, 'snippets'));
