#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

// F-09 licence boundary: the operator console may import the Apache-2.0
// generated SDK and its own workspace packages, never the AGPL gateway/core.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repo = path.resolve(root, '..');
const sourceDirs = [
  path.join(root, 'src'),
  path.join(root, 'packages'),
  path.join(root, 'venue-command-center'),
];
const allowedBare = new Set([
  'react',
  'react-dom',
  'react-dom/client',
  'react/jsx-runtime',
  '@tirbase/console-design-system',
  '@tirbase/gateway-admin-sdk',
  '@tirbase/console-design-system/styles.css',
  '@playwright/test',
]);

function walk(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, files);
    else if (/\.(ts|tsx|js|jsx|css)$/.test(entry.name)) files.push(full);
  }
  return files;
}

const violations = [];
for (const dir of sourceDirs) {
  for (const file of walk(dir)) {
    const relative = path.relative(root, file);
    const text = fs.readFileSync(file, 'utf8');
    if (!text.includes('SPDX-License-Identifier: Apache-2.0')) {
      violations.push(`${relative}: missing Apache-2.0 SPDX header`);
    }
    if (/SPDX-License-Identifier:\s*AGPL/i.test(text)) {
      violations.push(`${relative}: AGPL SPDX header`);
    }
    // The POS domain crate is AGPL-3.0-only; the Apache-2.0 console model must
    // stay independent of it, so even a textual reference is a violation.
    if (/tirbase-(gateway|core|guard|admin|pos)(\/|[\s'"`])/i.test(text)) {
      violations.push(`${relative}: references AGPL gateway/core/pos code`);
    }
    for (const match of text.matchAll(/(?:from\s+|import\s*\()['"]([^'"]+)['"]/g)) {
      const specifier = match[1];
      if (specifier.startsWith('.')) {
        const target = path.resolve(path.dirname(file), specifier);
        if (path.relative(root, target).startsWith('..')) {
          violations.push(`${relative}: import escapes the console (${specifier})`);
        }
      } else if (
        !specifier.startsWith('node:') &&
        !allowedBare.has(specifier) &&
        !specifier.endsWith('.css')
      ) {
        violations.push(`${relative}: disallowed dependency ${specifier}`);
      }
    }
  }
}

// The generated SDK itself must live in the Apache-2.0 SDK package, not in a
// gateway crate.
const sdk = path.join(repo, 'sdk', 'typescript', 'package.json');
if (!fs.existsSync(sdk)) violations.push('missing Apache-2.0 generated SDK');

const dist = path.join(root, 'dist', 'assets');
if (fs.existsSync(dist)) {
  for (const file of fs.readdirSync(dist).filter((name) => name.endsWith('.js'))) {
    const text = fs.readFileSync(path.join(dist, file), 'utf8');
    if (
      text.includes('AGPL-3.0') ||
      text.includes('tirbase-gateway') ||
      text.includes('tirbase-pos')
    ) {
      violations.push(`dist/${file}: bundled AGPL marker`);
    }
  }
}

if (violations.length) {
  console.error('Console licence boundary check failed:');
  for (const violation of violations) console.error(`  - ${violation}`);
  process.exit(1);
}
console.log('OK: console sources and bundle contain only Apache-2.0 code.');
