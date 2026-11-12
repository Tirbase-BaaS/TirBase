// SPDX-License-Identifier: Apache-2.0

/**
 * Unit tests for the generated client's transport options.
 *
 * `fetchInit` exists so callers can supply transport-level request fields the
 * generated client does not model — `credentials` for a browser-managed client
 * certificate, or an undici `dispatcher` bound to a TLS agent. The client must
 * merge them into every request without letting them override the method,
 * headers or serialised body it owns.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { GatewayAdminClient } from '../dist/index.js';

function recordingFetch() {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      status: 200,
      json: async () => ({ status: 200, ok: true }),
    };
  };
  return { calls, fetchImpl };
}

test('fetchInit is merged into every request', async () => {
  const { calls, fetchImpl } = recordingFetch();
  const dispatcher = { kind: 'undici-agent' };
  const client = new GatewayAdminClient({
    baseUrl: 'https://gateway.example:9443/',
    token: 'deadbeef',
    fetchImpl,
    fetchInit: { credentials: 'include', dispatcher },
  });

  await client.mode();
  await client.mint({ did: 'did:key:x', role: 'Auditor', ttl_secs: 3600 });

  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(call.init.credentials, 'include');
    assert.equal(call.init.dispatcher, dispatcher);
  }
  assert.equal(calls[0].url, 'https://gateway.example:9443/admin/mode');
  assert.equal(calls[1].url, 'https://gateway.example:9443/admin/mint');
  assert.equal(calls[1].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    did: 'did:key:x',
    role: 'Auditor',
    ttl_secs: 3600,
  });
});

test('transport fields cannot override the request the client owns', async () => {
  const { calls, fetchImpl } = recordingFetch();
  const client = new GatewayAdminClient({
    baseUrl: 'https://gateway.example:9443',
    token: 'deadbeef',
    fetchImpl,
    fetchInit: { method: 'DELETE', headers: { authorization: 'Bearer nope' } },
  });

  await client.mode();

  assert.equal(calls[0].init.method, 'GET');
  assert.equal(calls[0].init.headers.authorization, 'Bearer deadbeef');
});
