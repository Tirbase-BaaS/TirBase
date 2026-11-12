// SPDX-License-Identifier: Apache-2.0

/**
 * Cross-component e2e: the real gateway binary mints a DISASTER_ALERT caveat
 * token through the production `POST /admin/mint` path, and a real WASM device
 * activates Saturate_Mode with it.
 *
 * Everything on the asserted path is production code:
 *
 * 1. `tirbase-gateway` (real binary) is booted with the mTLS remote admin
 *    listener and the Unix admin socket, trusting the root CA the WASM device
 *    also trusts (`TIRBASE_E2E_ROOT_CA_SEED_HEX` → `mint` seed).
 * 2. The token is minted over the kernel-authenticated local admin socket,
 *    exactly as an operator would (`{cmd:"mint", payload:{…, caveat:
 *    "disaster-alert"}}`).
 * 3. The device is a real `wasm-pack --target nodejs` build of `tirbase-core`
 *    opened through the production SDK init, and activation runs the real
 *    `SaturateModeStateMachine` in that core.
 *
 * Requires a built gateway binary (`cargo build -p tirbase-gateway --bin
 * tirbase-gateway`, or `TIRBASE_GATEWAY_BIN`).
 */

import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

import { TirBase } from '../tirbase';
import { deviceConfig, fixtures, openDevice, type WasmFixtures } from '../__helpers__/real-core';

jest.setTimeout(240_000);

const REPO_ROOT = path.resolve(__dirname, '../../..');
const GATEWAY_BIN =
  process.env.TIRBASE_GATEWAY_BIN ??
  path.join(REPO_ROOT, 'target', 'debug', 'tirbase-gateway');

interface GatewaySetup {
  configPath: string;
  socketPath: string;
  remoteAddr: string;
  caCertPath: string;
  clientCertPath: string;
  clientKeyPath: string;
  targetId: string;
  rootCaPublicHex: string;
}

function waitFor(
  predicate: () => boolean,
  timeoutMs: number,
  description: string,
): Promise<void> {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const poll = () => {
      if (predicate()) {
        resolve();
        return;
      }
      if (Date.now() - started > timeoutMs) {
        reject(new Error(`timed out waiting for ${description}`));
        return;
      }
      setTimeout(poll, 100);
    };
    poll();
  });
}

/** One JSON line request/response on the kernel-authenticated admin socket. */
function adminCommand(
  socketPath: string,
  command: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ path: socketPath });
    let body = '';
    socket.on('connect', () => socket.write(`${JSON.stringify(command)}\n`));
    socket.on('data', (chunk) => {
      body += String(chunk);
    });
    socket.on('end', () => {
      try {
        resolve(JSON.parse(body.trim().split('\n')[0]!) as Record<string, unknown>);
      } catch (error) {
        reject(new Error(`admin response was not JSON: ${body}`));
      }
    });
    socket.on('error', reject);
  });
}

describe('gateway-issued DISASTER_ALERT token activates Saturate_Mode on a real WASM device', () => {
  let F: WasmFixtures;
  let tmpDir: string;
  let setup: GatewaySetup;
  let server: ChildProcess | undefined;
  let device: TirBase | undefined;
  const serverLogs: string[] = [];

  beforeAll(async () => {
    F = fixtures();

    expect(fs.existsSync(GATEWAY_BIN)).toBe(true);

    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tirbase-saturate-e2e-'));
    const stdout = execFileSync(
      'cargo',
      [
        'run',
        '-q',
        '-p',
        'tirbase-gateway',
        '--example',
        'admin_e2e_setup',
        '--',
        tmpDir,
      ],
      {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 600_000,
        maxBuffer: 16 * 1024 * 1024,
        env: { ...process.env, TIRBASE_E2E_ROOT_CA_SEED_HEX: F.rootCaSeedHex },
      },
    );
    const lines = stdout.trim().split('\n');
    setup = JSON.parse(lines[lines.length - 1]!) as GatewaySetup;

    server = spawn(GATEWAY_BIN, [setup.configPath], {
      env: { ...process.env, RUST_LOG: 'info' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    server.stdout?.on('data', (chunk) => serverLogs.push(String(chunk)));
    server.stderr?.on('data', (chunk) => serverLogs.push(String(chunk)));
    server.on('exit', (code) => {
      serverLogs.push(`gateway exited with ${code}`);
    });

    await waitFor(
      () =>
        fs.existsSync(setup.socketPath) &&
        serverLogs.some((line) => line.includes('tirbase-gateway started')),
      40_000,
      'the gateway to boot',
    );

    // The device trusts its own root CA; the gateway must be minting with the
    // same one, otherwise the token minted below could never verify.
    expect(setup.rootCaPublicHex).toBe(F.rootCaPublicHex);

    device = await openDevice(
      deviceConfig({
        rootCaPublicKeys: [F.rootCaPublicHex],
        revocationM: 2,
        revocationN: 3,
      }),
      'saturate-issuance',
    );
    await device.presentToken(F.managerTokenHex);
  });

  afterAll(() => {
    server?.kill('SIGKILL');
    if (tmpDir !== undefined) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('the gateway mints a disaster-alert token the WASM core activates with', async () => {
    // A PolicyAuthority token without the caveat is valid but may not activate.
    const plain = await adminCommand(setup.socketPath, {
      cmd: 'mint',
      payload: {
        did: 'did:key:z6MkGatewayIssuedOperator',
        role: 'PolicyAuthority',
        ttl_secs: 3600,
      },
    });
    expect(plain.status).toBe(200);
    expect(plain.caveat).toBeUndefined();
    await expect(
      device!.activateSaturateMode({ biscuitTokenHex: String(plain.token_hex) }),
    ).rejects.toThrow(/caveat|verification failed|Authorisation/i);

    // The issued credential: same endpoint, caveat attached.
    const minted = await adminCommand(setup.socketPath, {
      cmd: 'mint',
      payload: {
        did: 'did:key:z6MkGatewayIssuedOperator',
        role: 'PolicyAuthority',
        ttl_secs: 3600,
        caveat: 'disaster-alert',
      },
    });
    expect(minted.status).toBe(200);
    expect(minted.caveat).toBe('disaster-alert');
    const token = String(minted.token_hex);
    expect(token).toMatch(/^[0-9a-f]+$/);

    // Not activated yet: heartbeat renewal only succeeds inside an active
    // Saturate_Mode lease.
    await expect(
      device!.renewSaturateMode({ biscuitTokenHex: token }),
    ).rejects.toThrow(/not in SATURATE mode/i);

    await expect(
      device!.activateSaturateMode({ biscuitTokenHex: token }),
    ).resolves.toBeUndefined();

    // Renewal succeeding is the observable proof that activation reached the
    // real `SaturateModeStateMachine` rather than being accepted and dropped.
    await expect(
      device!.renewSaturateMode({ biscuitTokenHex: token }),
    ).resolves.toBeUndefined();
  });
});
