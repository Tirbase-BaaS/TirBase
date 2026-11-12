// SPDX-License-Identifier: Apache-2.0

/**
 * End-to-end test for the generated gateway-admin TypeScript SDK.
 *
 * A real `tirbase-gateway` binary is booted with the remote (mTLS) admin
 * listener enabled and driven exclusively through `GatewayAdminClient`. The
 * fixture — PKI, trust root, gateway config and a PolicyAuthority-signed
 * command — is produced by `tirbase-gateway/examples/admin_e2e_setup.rs`
 * using the production guard/identity code.
 *
 * Every path in `ADMIN_PATHS` and every `OPERATION_IDS` entry is exercised and
 * asserted to a *typed* result: a success payload, or a typed JSON error with
 * a numeric status (never `501`, never a silent skip).
 *
 * Requires:
 *   TIRBASE_GATEWAY_BIN   path to a built `tirbase-gateway` binary
 *   (fallback: <repo>/target/debug/tirbase-gateway)
 */

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test, { after, before } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  ADMIN_PATHS,
  GatewayAdminClient,
  OPERATION_IDS,
} from '../dist/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '../../..');
const GATEWAY_BIN =
  process.env.TIRBASE_GATEWAY_BIN ??
  path.join(REPO_ROOT, 'target', 'debug', 'tirbase-gateway');

/** operationId → generated client method, for coverage accounting. */
const OP_TO_METHOD = {
  chainRecovery: 'chainRecovery',
  challengeNonce: 'challenge',
  clearUnknown: 'unknownClear',
  enrollDevice: 'enroll',
  epochBump: 'epochBump',
  exitLockdown: 'lockdownExit',
  getMode: 'mode',
  issuerStatus: 'status',
  leasePreempt: 'leasePreempt',
  listEvents: 'events',
  mintToken: 'mint',
  pushPolicy: 'policy',
  quarantineReplay: 'quarantineReplay',
  restoreDevice: 'restore',
  rolloutStatus: 'rolloutStatus',
  rotateKey: 'rotate',
  sequenceReset: 'sequenceReset',
  simulateCommand: 'simulate',
  timeReset: 'timeReset',
};

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/** HTTPS fetch limited to what `GatewayAdminClient` uses. */
function mtlsFetch({ cert, key, ca }) {
  return (url, init = {}) =>
    new Promise((resolve, reject) => {
      const target = new URL(url);
      const headers = { ...init.headers };
      // The remote admin surface is a deliberately small HTTP/1.1 reader that
      // honours Content-Length and rejects chunked bodies, so send an explicit
      // length instead of letting Node chunk the request.
      if (init.body !== undefined) {
        headers['content-length'] = String(Buffer.byteLength(init.body));
      }
      const request = https.request(
        {
          hostname: target.hostname,
          port: target.port,
          path: `${target.pathname}${target.search}`,
          method: init.method ?? 'GET',
          headers,
          cert,
          key,
          ca,
          // The test CA signs the server certificate for 127.0.0.1; the
          // trusted CA is supplied above, so the handshake is genuinely
          // verified (no rejectUnauthorized:false).
          rejectUnauthorized: true,
        },
        (response) => {
          let body = '';
          response.on('data', (chunk) => {
            body += chunk;
          });
          response.on('end', () => {
            resolve({
              ok: response.statusCode >= 200 && response.statusCode < 300,
              status: response.statusCode,
              json: async () => JSON.parse(body),
            });
          });
        },
      );
      request.on('error', reject);
      if (init.body !== undefined) request.write(init.body);
      request.end();
    });
}

/** Mint a Biscuit token through the real local admin socket. */
function mintOverUnixSocket(socketPath, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ path: socketPath });
    let body = '';
    socket.on('connect', () => {
      socket.write(`${JSON.stringify(payload)}\n`);
    });
    socket.on('data', (chunk) => {
      body += chunk;
    });
    socket.on('end', () => {
      try {
        resolve(JSON.parse(body.trim()));
      } catch (error) {
        reject(new Error(`admin socket returned non-JSON: ${body} (${error})`));
      }
    });
    socket.on('error', reject);
    socket.setTimeout(15_000, () => reject(new Error('admin socket timeout')));
  });
}

function waitFor(condition, timeoutMs, describe) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const poll = () => {
      if (condition()) return resolve();
      if (Date.now() > deadline) {
        reject(new Error(`timed out waiting for ${describe}`));
        return;
      }
      setTimeout(poll, 50);
    };
    poll();
  });
}

let tmpDir;
let setup;
let server;
let serverLogs = [];
let client;
let token;

function expectTypedSuccess(result, label) {
  assert.equal(result.ok, true, `${label} must succeed: ${JSON.stringify(result)}`);
  assert.equal(result.status, 200, `${label} HTTP status`);
  assert.ok(result.data && typeof result.data === 'object', `${label} payload`);
  assert.equal(result.data.status, 200, `${label} typed status`);
  return result.data;
}

function expectTypedDenial(result, label) {
  assert.equal(result.ok, false, `${label} must be denied/accepted-typed, got ${JSON.stringify(result)}`);
  assert.notEqual(result.status, 200, `${label} must not silently succeed`);
  assert.notEqual(result.status, 501, `${label} must not be unimplemented`);
  assert.ok(result.error && typeof result.error === 'object', `${label} typed error body`);
  assert.equal(typeof result.error.status, 'number', `${label} error carries status`);
  assert.ok(
    typeof result.error.code === 'string' || typeof result.error.error === 'string',
    `${label} error carries code/error: ${JSON.stringify(result.error)}`,
  );
  return result.error;
}

before(async () => {
  assert.ok(
    fs.existsSync(GATEWAY_BIN),
    `gateway binary not found at ${GATEWAY_BIN}; build it or set TIRBASE_GATEWAY_BIN`,
  );

  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tirbase-gw-sdk-'));
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
    { cwd: REPO_ROOT, encoding: 'utf8', timeout: 600_000, maxBuffer: 16 * 1024 * 1024 },
  );
  const lines = stdout.trim().split('\n');
  setup = JSON.parse(lines[lines.length - 1]);

  server = spawn(GATEWAY_BIN, [setup.configPath], {
    env: { ...process.env, RUST_LOG: 'info' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (chunk) => serverLogs.push(String(chunk)));
  server.stderr.on('data', (chunk) => serverLogs.push(String(chunk)));
  server.on('exit', (code) => {
    serverLogs.push(`gateway exited with ${code}`);
  });

  await waitFor(
    () =>
      fs.existsSync(setup.socketPath) &&
      serverLogs.some((line) => line.includes('tirbase-gateway started')),
    40_000,
    `gateway boot (logs: ${serverLogs.join('').slice(-2000)})`,
  );

  const minted = await mintOverUnixSocket(setup.socketPath, {
    cmd: 'mint',
    payload: { did: 'did:key:sdk-e2e-auditor', role: 'Auditor', ttl_secs: 3600 },
  });
  assert.equal(minted.status, 200, `auditor token mint: ${JSON.stringify(minted)}`);
  token = minted.token_hex;

  client = new GatewayAdminClient({
    baseUrl: `https://${setup.remoteAddr}`,
    token,
    fetchImpl: mtlsFetch({
      cert: fs.readFileSync(setup.clientCertPath),
      key: fs.readFileSync(setup.clientKeyPath),
      ca: fs.readFileSync(setup.caCertPath),
    }),
  });
});

after(() => {
  if (server && server.exitCode === null) server.kill('SIGKILL');
  if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('the generated surface covers every documented path and operation', () => {
  assert.equal(ADMIN_PATHS.length, 19);
  assert.equal(OPERATION_IDS.length, 19);
  for (const operationId of OPERATION_IDS) {
    const method = OP_TO_METHOD[operationId];
    assert.ok(method, `operation ${operationId} has no client method mapping`);
    assert.equal(
      typeof client[method],
      'function',
      `generated client is missing ${method} for ${operationId}`,
    );
  }
});

test('remote admin requires a client certificate', async () => {
  const anonymous = new GatewayAdminClient({
    baseUrl: `https://${setup.remoteAddr}`,
    token,
    fetchImpl: mtlsFetch({ ca: fs.readFileSync(setup.caCertPath) }),
  });
  await assert.rejects(
    () => anonymous.mode(),
    /certificate|handshake|socket|alert/i,
  );
});

test('mode / events / rollout-status are typed successes', async () => {
  const mode = expectTypedSuccess(await client.mode(), 'getMode');
  assert.equal(mode.mode, 'Normal');
  assert.equal(mode.allows_commands, true);

  const events = expectTypedSuccess(
    await client.events(),
    'listEvents',
  );
  assert.ok(Array.isArray(events.events), 'events payload is an array');
  assert.equal(events.view_window_days, 7);

  const rollout = expectTypedSuccess(
    await client.rolloutStatus(),
    'rolloutStatus',
  );
  assert.equal(rollout.profile_installed, true);
  assert.equal(rollout.self_update, 'BLOCKED_PENDING_RFC_TUF');
});

test('mint returns a real scoped token and enforces the TTL ceiling', async () => {
  const minted = expectTypedSuccess(
    await client.mint({ did: 'did:key:sdk-e2e-issuer', role: 'CommandIssuer', ttl_secs: 3600 }),
    'mintToken',
  );
  assert.match(minted.token_hex, /^[0-9a-f]+$/);

  const tooLong = await client.mint({
    did: 'did:key:sdk-e2e-issuer',
    role: 'CommandIssuer',
    ttl_secs: 86_401,
  });
  const error = expectTypedDenial(tooLong, 'mintToken(ttl>86400)');
  assert.equal(error.status, 409);
  assert.equal(error.code, 'MINT_TTL_EXCEEDED');
});

test('challenge and simulate run the real pipelines', async () => {
  const issued = expectTypedSuccess(
    await client.challenge({ target_id: setup.targetId, param: 'setpoint_c' }),
    'challengeNonce',
  );
  assert.equal(issued.outcome, 'challenge_issued');
  assert.match(issued.nonce_hex, /^[0-9a-f]{64}$/);

  const simulated = expectTypedSuccess(
    await client.simulate(setup.simulateBody),
    'simulateCommand',
  );
  assert.equal(simulated.simulated, true);
});

test('rotate replaces the device identity', async () => {
  const rotated = expectTypedSuccess(await client.rotate(), 'rotateKey');
  assert.equal(rotated.outcome, 'key_rotated');
  assert.match(rotated.new_did, /^did:key:z/);
});

test('issuer status returns the guard-status shape', async () => {
  const status = expectTypedSuccess(
    await client.status('did:key:sdk-e2e-issuer'),
    'issuerStatus',
  );
  assert.equal(status.self_query, false);
  assert.ok(Array.isArray(status.anti_replay));
  assert.ok(status.rate_limit && typeof status.rate_limit === 'object');
});

test('every signature-bearing operation reaches its auth gate with a typed answer', async () => {
  // These operations require role-signed operations (PolicyAuthority /
  // RevocationManager / M-of-N TimeAnchor). Re-implementing the guard's
  // canonical signing encoding in JavaScript would be a second implementation
  // of a security-critical format, so the SDK test asserts the *typed* answer
  // the real endpoint gives an unsigned request: it must reach the auth gate
  // (never 404/501/silent skip). The signed success paths are covered by
  // `tirbase-gateway/tests/admin_endpoints_binary.rs` against the same binary.
  const denials = {
    enrollDevice: await client.enroll({}),
    pushPolicy: await client.policy({}),
    exitLockdown: await client.lockdownExit({}),
    chainRecovery: await client.chainRecovery({}),
    sequenceReset: await client.sequenceReset({}),
    leasePreempt: await client.leasePreempt({}),
    quarantineReplay: await client.quarantineReplay({}),
    timeReset: await client.timeReset({}),
    clearUnknown: await client.unknownClear({}),
    restoreDevice: await client.restore({}),
    epochBump: await client.epochBump({}),
  };
  for (const [label, result] of Object.entries(denials)) {
    const error = expectTypedDenial(result, label);
    assert.ok(
      [400, 403, 409, 503].includes(error.status),
      `${label} typed status ${error.status}: ${JSON.stringify(error)}`,
    );
  }
});
