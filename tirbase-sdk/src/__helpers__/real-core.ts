// SPDX-License-Identifier: Apache-2.0

/**
 * Harness for the real-WASM SDK tests.
 *
 * The tests execute the compiled `tirbase-core` WASM module in-process. The
 * artefact is the Node-target build produced by `npm run build:wasm:test`
 * (same crate, same `wasm` feature set, same `#[wasm_bindgen]` exports as the
 * browser build — only the module format differs so Jest's CommonJS runtime
 * can load it).
 *
 * Nothing here is a test double: every call goes through the SDK's production
 * initialisation (`initialiseCore` → real `core_init`), the production bridge,
 * `TirBase`, and the module's real exports. Only the CommonJS module resolution
 * differs from the browser loader's dynamic ESM import.
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import { createRequire } from 'module';
import * as path from 'path';

import { TirBase } from '../tirbase';
import type { DeploymentConfig, InitConfig } from '../types';
import { initialiseCore } from '../wasm-bridge';

const nodeRequire = createRequire(__filename);

/** Directory containing the Node-target WASM build. */
export const WASM_TEST_DIR = path.resolve(__dirname, '../../wasm-test');

/** Repository root (for `cargo run`). */
const REPO_ROOT = path.resolve(__dirname, '../../..');

/** Cryptographic fixtures produced by the Rust example. */
export interface WasmFixtures {
  rootCaSeedHex: string;
  rootCaPublicHex: string;
  managerDid: string;
  managerTokenHex: string;
  foreignTokenHex: string;
  disasterAlertTokenHex: string;
  terminationMessage: string;
  terminationMessageHex: string;
  coManagers: Array<{ did: string; signatureHex: string }>;
}

let cachedFixtures: WasmFixtures | null = null;

/**
 * Generate (once per Jest process) the token/signature fixtures with the
 * production `tirbase-core` helpers. The WASM module verifies them; the
 * fixtures are inputs to the asserted path, never a bypass of it.
 */
export function fixtures(): WasmFixtures {
  if (cachedFixtures !== null) return cachedFixtures;
  const stdout = execFileSync(
    'cargo',
    [
      'run',
      '-q',
      '-p',
      'tirbase-core',
      '--features',
      'test-hooks',
      '--example',
      'wasm_e2e_fixtures',
    ],
    {
      cwd: REPO_ROOT,
      encoding: 'utf-8',
      timeout: 600_000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  cachedFixtures = JSON.parse(stdout.trim()) as WasmFixtures;
  return cachedFixtures;
}

function assertWasmTestBuildExists(): void {
  const wasm = path.join(WASM_TEST_DIR, 'tirbase_core_bg.wasm');
  if (!fs.existsSync(wasm)) {
    throw new Error(
      `Real-WASM test artefact missing at ${wasm}. ` +
        'Run `npm run build:wasm:test` (or `npm test`, whose pretest does).',
    );
  }
}

/**
 * Path to a distinct copy of the wasm-pack Node glue.
 *
 * Each copy is a separate CommonJS module and therefore a separate WASM
 * instance with its own thread-local `CORE` slot — i.e. a second real device.
 */
export function modulePathForDevice(device: string): string {
  assertWasmTestBuildExists();
  const base = path.join(WASM_TEST_DIR, 'tirbase_core.js');
  if (device === 'default') return base;
  const copy = path.join(WASM_TEST_DIR, `device_${device}.js`);
  if (!fs.existsSync(copy)) {
    fs.copyFileSync(base, copy);
  }
  return copy;
}

/** Build the `InitConfig` for one real device. */
export function deviceConfig(
  deploymentConfig: DeploymentConfig,
  storagePath = ':memory:',
): InitConfig {
  return { storagePath, deploymentConfig };
}

/**
 * Open a real-WASM `TirBase` instance.
 *
 * The Node-target glue is CommonJS, so it is loaded with `require` and handed
 * to the production `initialiseCore` function (the same `core_init` call and
 * config mapping `loadWasmCore` performs). Everything after that — the bridge,
 * `TirBase`, every export — is the production code path; only the module
 * resolution differs from the browser ESM loader.
 */
export async function openDevice(
  config: InitConfig,
  device = 'default',
): Promise<TirBase> {
  const mod = nodeRequire(modulePathForDevice(device)) as Record<
    string,
    unknown
  >;
  const core = await initialiseCore(mod, config);
  TirBase._setWasmLoader(async () => core);
  return TirBase.init(config);
}

/**
 * Deliver every outbound frame from `sender` to each receiver, awaiting the
 * full inbound pipeline (merge + projection + side-effect events) on each.
 */
export async function broadcast(
  sender: TirBase,
  receivers: TirBase[],
): Promise<number> {
  const frames = sender.drainOutboundMessages();
  for (const frame of frames) {
    for (const receiver of receivers) {
      await receiver.receivePeerMessage(frame);
    }
  }
  return frames.length;
}
