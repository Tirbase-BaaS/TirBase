#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// wasm-pack generates wasm/package.json from the Cargo package name and
// license. The published package is intentionally scoped and AGPL-licensed,
// so restore the stable package identity after every build.

import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const wasmDir = join(here, '..', 'wasm');
const packagePath = join(wasmDir, 'package.json');
const gitignorePath = join(wasmDir, '.gitignore');

const pkg = JSON.parse(await readFile(packagePath, 'utf8'));

pkg.name = '@tirbase/core-wasm';
pkg.version = '0.1.0';
pkg.license = 'AGPL-3.0-only';
pkg.description = 'TirBase core compiled to WASM (AGPL-3.0-only)';

const requiredFiles = [
  'tirbase_core_bg.wasm',
  'tirbase_core.js',
  'tirbase_core.d.ts',
  'tirbase_core_bg.wasm.d.ts',
];
pkg.files = [...new Set([...(pkg.files ?? []), ...requiredFiles])];

await writeFile(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);

// wasm-pack writes a blanket "*" ignore file. Keep the tracked manifest
// visible to git while still ignoring the generated glue and binary.
await writeFile(gitignorePath, '*\n!.gitignore\n!package.json\n');
