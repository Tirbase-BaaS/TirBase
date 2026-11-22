// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../..');

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4191',
    trace: 'retain-on-failure',
    viewport: { width: 1440, height: 1000 },
  },
  webServer: [
    {
      command:
        'cargo run --quiet -p tirbase-venue-command-center --bin venue-command-center -- --port 4190',
      cwd: repoRoot,
      url: 'http://127.0.0.1:4190/api/health',
      reuseExistingServer: false,
      timeout: 300_000,
    },
    {
      command: 'python3 -m http.server 4191 --bind 127.0.0.1',
      cwd: here,
      url: 'http://127.0.0.1:4191/index.html',
      reuseExistingServer: false,
      timeout: 30_000,
    },
  ],
});
