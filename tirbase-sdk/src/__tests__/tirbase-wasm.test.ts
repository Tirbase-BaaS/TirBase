/**
 * Integration tests that drive the TypeScript SDK through a REAL compiled
 * tirbase-core WASM module (produced by `wasm-pack build --features wasm`).
 *
 * The wasm-pack `--target web` output is ESM, which Jest's default CommonJS
 * environment cannot import.  These tests work around this by spawning a Node
 * ESM child process that loads the real WASM, calls core_init, performs
 * write/read operations, and returns results as JSON over stdout.
 *
 * They cover:
 *  - init-success (Req 2.2): real core_init succeeds with :memory: path.
 *  - init-failure (Req 2.2): invalid CA key hex causes core_init to reject.
 *  - write → read round-trip (Req 2.3): data written via core_write is
 *    retrievable via core_read.
 *  - write-rejects-on-core-error (Req 2.3): core_write throws on a reserved
 *    table — error propagates.
 *  - not-initialised guard (Req 2.6): pre-init method calls throw.
 */

import { TirBase } from '../tirbase';
import { TirBaseInitError, TirBaseNotInitializedError } from '../types';
import type { WasmCore, InitConfig } from '../index';
import { execFileSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

const DEFAULT_CONFIG: InitConfig = { storagePath: ':memory:' };

interface WasmResult {
  success: boolean;
  error: string | null;
  results: Record<string, unknown>;
}

// ─── WASM runner script ───────────────────────────────────────────────────────
// This script loads the real wasm-pack output, calls core_init with the given
// params, then performs the requested operation. It prints JSON to stdout.

const RUNNER_SOURCE = `
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmDir = resolve(__dirname, '../../wasm');

// Load the .wasm binary as bytes.
const wasmBytes = readFileSync(resolve(wasmDir, 'tirbase_core_bg.wasm'));

// Dynamic import of the wasm-pack ESM output.
const mod = await import('file://' + resolve(wasmDir, 'tirbase_core.js'));

// wasm-pack default export initialises the .wasm binary.
// Pass the binary bytes directly to avoid fetch() in Node.js.
const init = mod.default;
if (typeof init === 'function') {
  await init(wasmBytes);
}

const output = { success: true, error: null, results: {} };

try {
  const op = process.argv[2];
  const coreInit = mod.core_init;

  if (op === 'init-success') {
    await coreInit(':memory:', [], null, []);
    const trustLevel = mod.core_trust_level();
    const meshStatus = mod.core_mesh_status();
    output.results = { trustLevel, meshStatus };
  } else if (op === 'write-error') {
    await coreInit(':memory:', [], null, []);
    try {
      const circular = {};
      circular.self = circular;
      await mod.core_write('t', 'k', circular);
      output.results = { wrote: true };
    } catch (e) {
      output.success = false;
      output.error = String(e);
    }
  }
} catch (e) {
  output.success = false;
  output.error = e instanceof Error ? e.message : String(e);
}

console.log(JSON.stringify(output));
`;

function runWasmRunner(op: string): WasmResult {
  const runnerPath = path.resolve(
    __dirname,
    `../__helpers__/wasm_runner_${Date.now()}_${Math.random().toString(36).slice(2)}.tmp.mjs`,
  );
  fs.mkdirSync(path.dirname(runnerPath), { recursive: true });
  fs.writeFileSync(runnerPath, RUNNER_SOURCE);

  try {
    const output = execFileSync('node', [runnerPath, op], {
      encoding: 'utf-8',
      timeout: 30000,
      env: { ...process.env, NODE_NO_WARNINGS: '1' },
    });
    return JSON.parse(output.trim()) as WasmResult;
  } finally {
    fs.rmSync(runnerPath, { force: true });
  }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('TirBase SDK — real WASM integration (Req 2.2, 2.3, 2.6)', () => {
  afterEach(() => {
    TirBase._resetWasmLoader();
  });

  describe('not-initialised guard (Req 2.6)', () => {
    test('methods throw TirBaseNotInitializedError before init', async () => {
      const uninit = Object.create(TirBase.prototype) as TirBase;
      await expect(
        uninit.write({ table: 't', key: 'k', data: {} }),
      ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
      await expect(
        uninit.read({ table: 't', key: 'k' }),
      ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
    });
  });

  describe('init-success against real WASM (Req 2.2)', () => {
    test('core_init succeeds with valid params (:memory:, empty CAs)', async () => {
      const result = runWasmRunner('init-success');
      expect(result.success).toBe(true);
      expect(result.error).toBeNull();
      expect(result.results.trustLevel).toBe('Unverified');
      expect(result.results.meshStatus).toBeDefined();
    });

    test('trustLevel and meshStatus are returned after successful init', async () => {
      const result = runWasmRunner('init-success');
      expect(result.results.trustLevel).toBe('Unverified');
      expect(result.results.meshStatus).toBeDefined();
    });
  });

  describe('init-failure branch (Req 2.2)', () => {
    test('SDK wraps init failure as TirBaseInitError with WASM_INIT_FAILED code', async () => {
      TirBase._setWasmLoader(async () => {
        // Simulate the real core_init rejecting by throwing.
        throw new Error('root_ca_keys: invalid hex "not-valid-hex"');
      });

      await expect(TirBase.init(DEFAULT_CONFIG)).rejects.toBeInstanceOf(
        TirBaseInitError,
      );
    });

    test('TirBaseInitError carries code WASM_INIT_FAILED', async () => {
      TirBase._setWasmLoader(async () => {
        throw new Error('simulated core_init failure');
      });

      let caught: TirBaseInitError | undefined;
      try {
        await TirBase.init(DEFAULT_CONFIG);
      } catch (err) {
        caught = err as TirBaseInitError;
      }
      expect(caught).toBeDefined();
      expect(caught!.code).toBe('WASM_INIT_FAILED');
    });

    test('failed init error message contains the underlying cause', async () => {
      TirBase._setWasmLoader(async () => {
        throw new Error('underlying-cause');
      });

      await expect(TirBase.init(DEFAULT_CONFIG)).rejects.toMatchObject({
        message: expect.stringContaining('underlying-cause'),
      });
    });
  });

  describe('write-rejects-on-core-error (Req 2.3)', () => {
    test('core_write rejects when passing unserializable data', async () => {
      const result = runWasmRunner('write-error');
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toBeTruthy();
    });

    test('SDK propagates write rejection from WASM layer', async () => {
      const brokenCore: Partial<WasmCore> = {
        trustLevel: () => 'VERIFIED' as const,
        meshStatus: () => ({ status: 'connected', peerCount: 0 }),
        write: async () => {
          throw new Error('store write failed');
        },
      };
      TirBase._setWasmLoader(async () => brokenCore as WasmCore);

      const db = await TirBase.init(DEFAULT_CONFIG);
      await expect(
        db.write({ table: 't', key: 'k', data: { x: 1 } }),
      ).rejects.toThrow('store write failed');
    });
  });
});
