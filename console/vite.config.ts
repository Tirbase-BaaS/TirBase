// SPDX-License-Identifier: Apache-2.0
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Resolve directly to the generated Apache-2.0 SDK source; never to the
// gateway workspace.
const sdkEntry = fileURLToPath(new URL('../sdk/typescript/src/index.ts', import.meta.url));

// The console is deployed behind the same origin as the gateway admin
// listener (reverse proxy or Vite proxy in development), so it never needs
// CORS. `/admin` is proxied to the local TLS listener only when both proxy
// variables are provided; tests intercept HTTP instead.
const target = process.env.TIRBASE_CONSOLE_PROXY;

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@tirbase/gateway-admin-sdk': sdkEntry } },
  server: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
    proxy: target
      ? {
          '/admin': {
            target,
            changeOrigin: false,
            secure: process.env.TIRBASE_CONSOLE_PROXY_INSECURE !== '1',
          },
        }
      : undefined,
  },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true },
  build: { sourcemap: false },
});
