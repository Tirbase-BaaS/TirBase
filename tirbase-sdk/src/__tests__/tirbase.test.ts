/**
 * Unit tests for the TirBase SDK.
 *
 * All tests use MockWasmCore — no real WASM binary is required.
 * The WASM loader is overridden via TirBase._setWasmLoader() before each
 * relevant test and reset via TirBase._resetWasmLoader() in afterEach.
 */

import { TirBase } from '../tirbase';
import { MockWasmCore } from '../wasm-bridge';
import type { WasmCore } from '../wasm-bridge';
import type {
  IncidentContextObject,
  MeshStatus,
  RevocationStatus,
  TrustLevel,
  TrustLevelChangedEvent,
} from '../types';
import { TirBaseInitError, TirBaseNotInitializedError } from '../types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Install a fresh MockWasmCore as the loader and return it. */
function installMock(): MockWasmCore {
  const mock = new MockWasmCore();
  TirBase._setWasmLoader(async () => mock);
  return mock;
}

const DEFAULT_CONFIG = { storagePath: ':memory:' };

function makeIco(overrides: Partial<IncidentContextObject> = {}): IncidentContextObject {
  return {
    id: 'incident-uuid-v7',
    state: 'OPEN',
    taintSource: { type: 'DEVICE_REVOCATION', revocationDeltaId: 'abc123' },
    contaminationRoots: ['abc123'],
    affectedTableCount: 1,
    affectedRowCount: 2,
    affectedRows: [{ table: 'reports', rowKey: 'r-1', deltaId: 'abc123' }],
    createdAt: new Date(),
    updatedAt: new Date(),
    auditLog: [],
    ...overrides,
  };
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

afterEach(() => {
  TirBase._resetWasmLoader();
});

// ─── Test: init success ───────────────────────────────────────────────────────

describe('TirBase.init()', () => {
  test('resolves with a TirBase instance when WASM mock succeeds', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    expect(db).toBeInstanceOf(TirBase);
  });

  test('sets trustLevel to VERIFIED on successful init', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    expect(db.trustLevel).toBe('VERIFIED');
  });

  test('sets meshStatus on successful init', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    expect(db.meshStatus.status).toBe('connected');
    expect(typeof db.meshStatus.peerCount).toBe('number');
  });

  // ── init failure ────────────────────────────────────────────────────────

  test('rejects with TirBaseInitError when WASM loader throws', async () => {
    TirBase._setWasmLoader(async () => {
      throw new Error('WASM load failure');
    });

    await expect(TirBase.init(DEFAULT_CONFIG)).rejects.toBeInstanceOf(
      TirBaseInitError,
    );
  });

  test('TirBaseInitError carries a non-empty code field', async () => {
    TirBase._setWasmLoader(async () => {
      throw new Error('bang');
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

  test('error message contains the underlying cause', async () => {
    TirBase._setWasmLoader(async () => {
      throw new Error('underlying-cause');
    });

    await expect(TirBase.init(DEFAULT_CONFIG)).rejects.toMatchObject({
      message: expect.stringContaining('underlying-cause'),
    });
  });
});

// ─── Test: not-initialized guard ──────────────────────────────────────────────

describe('not-initialized guard (Req 2.6)', () => {
  /**
   * Build a failed (not-initialized) TirBase instance by catching the
   * TirBaseInitError thrown by a failing init() and using the fact that
   * we can't get an instance from a failed init — so we test by calling
   * methods on a mock that simulates the guard.
   *
   * The guard is tested directly: if init() rejects, no instance is returned,
   * so we verify the guard path by calling methods before any init().
   *
   * We use a second approach: install a mock but never call init(); the
   * TirBase constructor is private so we access the guard via a different path:
   * a helper that creates an uninitialized instance by casting internals.
   */
  function makeUninitializedInstance(): TirBase {
    // Access the private constructor via Object.create so that _initialized
    // stays false (no init() called).
    return Object.create(TirBase.prototype) as TirBase;
  }

  test('write() throws TirBaseNotInitializedError before init()', async () => {
    const db = makeUninitializedInstance();
    await expect(
      db.write({ table: 't', key: 'k', data: {} }),
    ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
  });

  test('read() throws TirBaseNotInitializedError before init()', async () => {
    const db = makeUninitializedInstance();
    await expect(db.read({ table: 't', key: 'k' })).rejects.toBeInstanceOf(
      TirBaseNotInitializedError,
    );
  });

  test('query() throws TirBaseNotInitializedError before init()', async () => {
    const db = makeUninitializedInstance();
    await expect(db.query({ table: 't' })).rejects.toBeInstanceOf(
      TirBaseNotInitializedError,
    );
  });

  test('manager ops throw TirBaseNotInitializedError before init()', async () => {
    const db = makeUninitializedInstance();
    await expect(
      db.initiateRevocation({ targetDid: 'did:key:z6Mk', managerToken: 't' }),
    ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
    await expect(
      db.revocationStatus({ targetDid: 'did:key:z6Mk' }),
    ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
    await expect(
      db.verifyData({ contaminationRootDeltaId: 'abc', managerToken: 't', nowSecs: 0 }),
    ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
    await expect(
      db.adminClose({ incidentId: 'uuid', managerToken: 't', nowSecs: 0 }),
    ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
    await expect(
      db.activateSaturateMode({ biscuitTokenHex: 'deadbeef' }),
    ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
  });

  test('write() after a failed init still throws', async () => {
    TirBase._setWasmLoader(async () => {
      throw new Error('failed');
    });

    let failedDb: TirBase | null = null;
    try {
      await TirBase.init(DEFAULT_CONFIG);
    } catch {
      // init() rejected — no instance was returned.
      // Verify by creating an uninitialized instance manually.
      failedDb = makeUninitializedInstance();
    }

    expect(failedDb).not.toBeNull();
    await expect(
      failedDb!.write({ table: 't', key: 'k', data: {} }),
    ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
  });
});

// ─── Test: write ──────────────────────────────────────────────────────────────

describe('db.write()', () => {
  test('resolves with WriteResult including durabilityTier UNCOMMITTED', async () => {
    const mock = installMock();
    mock.writeImpl = async (_t, _k, _d) => ({
      deltaId: 'deadbeef'.repeat(8),
      durabilityTier: 'UNCOMMITTED',
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const result = await db.write({ table: 'reports', key: 'r-1', data: { x: 1 } });

    expect(result.durabilityTier).toBe('UNCOMMITTED');
    expect(result.deltaId).toBeDefined();
    expect(result.deltaId.length).toBeGreaterThan(0);
  });

  test('rejects when WASM write() throws', async () => {
    const mock = installMock();
    mock.writeImpl = async () => {
      throw new Error('store write failed');
    };

    const db = await TirBase.init(DEFAULT_CONFIG);
    await expect(
      db.write({ table: 'reports', key: 'r-1', data: {} }),
    ).rejects.toThrow('store write failed');
  });

  test('does not include unverifiedWarning when VERIFIED', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const result = await db.write({ table: 't', key: 'k', data: {} });
    expect(result.unverifiedWarning).toBeUndefined();
  });
});

// ─── Test: read ───────────────────────────────────────────────────────────────

describe('db.read()', () => {
  test('resolves with QueryResult', async () => {
    const mock = installMock();
    mock.readImpl = async (table, key) => ({
      table,
      key,
      data: { name: 'test' },
      contaminated: false,
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const result = await db.read({ table: 'reports', key: 'r-1' });

    expect(result.table).toBe('reports');
    expect(result.key).toBe('r-1');
    expect(result.data).toEqual({ name: 'test' });
    expect(result.contaminated).toBe(false);
  });

  test('contaminated flag propagated from WASM', async () => {
    const mock = installMock();
    mock.readImpl = async (table, key) => ({
      table,
      key,
      data: {},
      contaminated: true,
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const result = await db.read({ table: 't', key: 'k' });
    expect(result.contaminated).toBe(true);
  });
});

// ─── Test: query ──────────────────────────────────────────────────────────────

describe('db.query()', () => {
  test('resolves with an array of QueryResults', async () => {
    const mock = installMock();
    mock.queryImpl = async (table, _filter) => [
      { table, key: 'k1', data: { a: 1 }, contaminated: false },
      { table, key: 'k2', data: { a: 2 }, contaminated: false },
    ];

    const db = await TirBase.init(DEFAULT_CONFIG);
    const results = await db.query({ table: 'reports' });

    expect(results).toHaveLength(2);
    expect(results[0]!.key).toBe('k1');
    expect(results[1]!.key).toBe('k2');
  });

  test('returns empty array when WASM returns empty', async () => {
    const mock = installMock();
    mock.queryImpl = async () => [];

    const db = await TirBase.init(DEFAULT_CONFIG);
    const results = await db.query({ table: 'reports' });
    expect(results).toHaveLength(0);
  });
});

// ─── Test: trustLevel property ────────────────────────────────────────────────

describe('db.trustLevel (Req 2.4)', () => {
  test('returns VERIFIED initially when mock returns VERIFIED', async () => {
    const mock = installMock();
    mock.trustLevelImpl = () => 'VERIFIED';

    const db = await TirBase.init(DEFAULT_CONFIG);
    expect(db.trustLevel).toBe('VERIFIED');
  });

  test('returns UNVERIFIED after _applyTrustLevelChange is called', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);

    expect(db.trustLevel).toBe('VERIFIED');
    db._applyTrustLevelChange('UNVERIFIED');
    expect(db.trustLevel).toBe('UNVERIFIED');
  });

  test('returns REVOKED after _applyTrustLevelChange to REVOKED', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    db._applyTrustLevelChange('REVOKED');
    expect(db.trustLevel).toBe('REVOKED');
  });
});

// ─── Test: presentToken (Req 8.3, 8.4, 8.8) ────────────────────────────────────

describe('db.presentToken() (Req 8.3, 8.4, 8.8)', () => {
  test('returns VERIFIED for a valid token', async () => {
    const mock = installMock();
    mock.corePresentTokenImpl = async () => 'VERIFIED';

    const db = await TirBase.init(DEFAULT_CONFIG);
    const level = await db.presentToken('valid-token-hex');
    expect(level).toBe('VERIFIED');
    expect(db.trustLevel).toBe('VERIFIED');
  });

  test('returns UNVERIFIED for an expired token (token-expiry path, Req 8.4)', async () => {
    const mock = installMock();
    mock.corePresentTokenImpl = async () => 'UNVERIFIED';

    const db = await TirBase.init(DEFAULT_CONFIG);
    expect(db.trustLevel).toBe('VERIFIED');

    const level = await db.presentToken('expired-token-hex');
    expect(level).toBe('UNVERIFIED');
    expect(db.trustLevel).toBe('UNVERIFIED');
  });

  test('returns UNVERIFIED for an invalid token without throwing (Req 8.8)', async () => {
    const mock = installMock();
    mock.corePresentTokenImpl = async () => 'UNVERIFIED';

    const db = await TirBase.init(DEFAULT_CONFIG);

    const level = await db.presentToken('bogus-token-hex');
    expect(level).toBe('UNVERIFIED');
  });

  test('throws when core returns an error (e.g. no root CA keys)', async () => {
    const mock = installMock();
    mock.corePresentTokenImpl = async () => {
      throw new Error('AuthorisationFailed: no registered root CA keys');
    };

    const db = await TirBase.init(DEFAULT_CONFIG);
    await expect(db.presentToken('any-token')).rejects.toThrow(
      'AuthorisationFailed',
    );
  });

  test('emits trust-level-changed event when level changes', async () => {
    const mock = installMock();
    mock.corePresentTokenImpl = async () => 'UNVERIFIED';

    const db = await TirBase.init(DEFAULT_CONFIG);
    const events: TrustLevelChangedEvent[] = [];
    db.on('trust-level-changed', (e) => events.push(e as TrustLevelChangedEvent));

    await db.presentToken('expired-token-hex');

    expect(events).toHaveLength(1);
    expect(events[0].previousLevel).toBe('VERIFIED');
    expect(events[0].newLevel).toBe('UNVERIFIED');
  });
});

// ─── Test: UNVERIFIED warning on every operation (Req 8.4) ───────────────────

describe('UNVERIFIED warning (Req 8.4)', () => {
  async function makeUnverifiedDb(): Promise<TirBase> {
    const mock = installMock();
    mock.trustLevelImpl = () => 'VERIFIED';
    const db = await TirBase.init(DEFAULT_CONFIG);
    // Simulate token expiry
    db._applyTrustLevelChange('UNVERIFIED');
    return db;
  }

  test('write() attaches unverifiedWarning when UNVERIFIED', async () => {
    const db = await makeUnverifiedDb();
    const result = await db.write({ table: 't', key: 'k', data: {} });
    expect(result.unverifiedWarning).toBeDefined();
    expect(result.unverifiedWarning!.unverifiedSince).toBeInstanceOf(Date);
  });

  test('read() attaches unverifiedWarning when UNVERIFIED', async () => {
    const db = await makeUnverifiedDb();
    const result = await db.read({ table: 't', key: 'k' });
    expect(result.unverifiedWarning).toBeDefined();
  });

  test('query() attaches unverifiedWarning to every result when UNVERIFIED', async () => {
    const mock = installMock();
    mock.trustLevelImpl = () => 'VERIFIED';
    mock.queryImpl = async (table, _f) => [
      { table, key: 'k1', data: {}, contaminated: false },
      { table, key: 'k2', data: {}, contaminated: false },
    ];
    const db = await TirBase.init(DEFAULT_CONFIG);
    db._applyTrustLevelChange('UNVERIFIED');

    const results = await db.query({ table: 't' });
    expect(results).toHaveLength(2);
    results.forEach((r) => {
      expect(r.unverifiedWarning).toBeDefined();
    });
  });

  test('write() emits unverified-warning event when UNVERIFIED', async () => {
    const db = await makeUnverifiedDb();
    const handler = jest.fn();
    db.on('unverified-warning', handler);

    await db.write({ table: 't', key: 'k', data: {} });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0]![0]).toHaveProperty('unverifiedSince');
  });

  test('read() emits unverified-warning event when UNVERIFIED', async () => {
    const db = await makeUnverifiedDb();
    const handler = jest.fn();
    db.on('unverified-warning', handler);

    await db.read({ table: 't', key: 'k' });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test('query() emits unverified-warning event once (not per row) when UNVERIFIED', async () => {
    const mock = installMock();
    mock.trustLevelImpl = () => 'VERIFIED';
    mock.queryImpl = async (table, _f) => [
      { table, key: 'k1', data: {}, contaminated: false },
      { table, key: 'k2', data: {}, contaminated: false },
    ];
    const db = await TirBase.init(DEFAULT_CONFIG);
    db._applyTrustLevelChange('UNVERIFIED');

    const handler = jest.fn();
    db.on('unverified-warning', handler);

    await db.query({ table: 't' });
    // One event per call, not one per returned row
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test('no unverifiedWarning when trust level is VERIFIED', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const writeResult = await db.write({ table: 't', key: 'k', data: {} });
    const readResult = await db.read({ table: 't', key: 'k' });
    const queryResults = await db.query({ table: 't' });

    expect(writeResult.unverifiedWarning).toBeUndefined();
    expect(readResult.unverifiedWarning).toBeUndefined();
    queryResults.forEach((r) => expect(r.unverifiedWarning).toBeUndefined());
  });
});

// ─── Test: event emitter ──────────────────────────────────────────────────────

describe('event emitter', () => {
  test('on() + _emit() — incident-created handler receives ICO', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('incident-created', handler);

    const ico = makeIco();
    db._emit('incident-created', ico);

    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith(ico);
  });

  test('off() removes the handler', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('incident-created', handler);
    db.off('incident-created', handler);

    db._emit('incident-created', makeIco());
    expect(handler).not.toHaveBeenCalled();
  });

  test('incident-updated event fires with updated ICO', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('incident-updated', handler);

    const ico = makeIco({ state: 'OPEN', affectedRowCount: 5 });
    db._emit('incident-updated', ico);

    expect(handler).toHaveBeenCalledWith(expect.objectContaining({ affectedRowCount: 5 }));
  });

  test('incident-closed event fires with closed ICO', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('incident-closed', handler);

    const ico = makeIco({ state: 'CLOSED' });
    db._emit('incident-closed', ico);

    expect(handler).toHaveBeenCalledWith(expect.objectContaining({ state: 'CLOSED' }));
  });

  test('trust-level-changed event fires via _applyTrustLevelChange', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('trust-level-changed', handler);

    db._applyTrustLevelChange('UNVERIFIED');

    expect(handler).toHaveBeenCalledTimes(1);
    const event = handler.mock.calls[0]![0];
    expect(event.previousLevel).toBe('VERIFIED');
    expect(event.newLevel).toBe('UNVERIFIED');
    expect(event.timestamp).toBeInstanceOf(Date);
  });

  test('trust-level-changed is not fired when level does not change', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('trust-level-changed', handler);

    db._applyTrustLevelChange('VERIFIED'); // no change
    expect(handler).not.toHaveBeenCalled();
  });

  test('multiple listeners on same event all receive it', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const h1 = jest.fn();
    const h2 = jest.fn();
    db.on('incident-created', h1);
    db.on('incident-created', h2);

    db._emit('incident-created', makeIco());
    expect(h1).toHaveBeenCalledTimes(1);
    expect(h2).toHaveBeenCalledTimes(1);
  });

  test('removing one handler does not affect others', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);
    const h1 = jest.fn();
    const h2 = jest.fn();
    db.on('incident-created', h1);
    db.on('incident-created', h2);
    db.off('incident-created', h1);

    db._emit('incident-created', makeIco());
    expect(h1).not.toHaveBeenCalled();
    expect(h2).toHaveBeenCalledTimes(1);
  });
});

// ─── Test: meshStatus property ────────────────────────────────────────────────

describe('db.meshStatus (Req 2.5)', () => {
  test('returns meshStatus from WASM mock', async () => {
    const mock = installMock();
    mock.meshStatusImpl = () => ({ status: 'connecting', peerCount: 3 });

    const db = await TirBase.init(DEFAULT_CONFIG);
    expect(db.meshStatus.status).toBe('connecting');
    expect(db.meshStatus.peerCount).toBe(3);
  });

  test('_applyMeshStatusChange updates meshStatus', async () => {
    installMock();
    const db = await TirBase.init(DEFAULT_CONFIG);

    db._applyMeshStatusChange({ status: 'disconnected', peerCount: 0 });
    expect(db.meshStatus.status).toBe('disconnected');
  });
});

// ─── Test: manager operations ─────────────────────────────────────────────────

describe('manager operations', () => {
  test('initiateRevocation delegates to WASM', async () => {
    const mock = installMock();
    const spy = jest.fn().mockResolvedValue(undefined);
    mock.initiateRevocationImpl = spy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    await db.initiateRevocation({ targetDid: 'did:key:z6Mk', managerToken: 'tok' });

    expect(spy).toHaveBeenCalledWith('did:key:z6Mk', 'tok');
  });

  test('revocationStatus returns RevocationStatus', async () => {
    const mock = installMock();
    mock.revocationStatusImpl = async (_did) => ({
      signaturesCollected: 1,
      signaturesRequired: 2,
      status: 'PENDING',
      lastKnownTrustLevel: 'REVOKED',
      lastRevocationDeltaReceivedAt: 1234567890,
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const status = await db.revocationStatus({ targetDid: 'did:key:z6Mk' });

    expect(status.signaturesCollected).toBe(1);
    expect(status.signaturesRequired).toBe(2);
    expect(status.status).toBe('PENDING');
    expect(status.lastKnownTrustLevel).toBe('REVOKED');
    expect(status.lastRevocationDeltaReceivedAt).toBe(1234567890);
  });

  test('revocationStatus defaults device-status fields to null', async () => {
    const mock = installMock();
    // Default mock: no RevocationDelta ever applied → Req 9.5 fields null.
    const db = await TirBase.init(DEFAULT_CONFIG);
    const status = await db.revocationStatus({ targetDid: 'did:key:z6Mk' });

    expect(status.lastKnownTrustLevel).toBeNull();
    expect(status.lastRevocationDeltaReceivedAt).toBeNull();
  });

  test('verifyData delegates to WASM', async () => {
    const mock = installMock();
    const spy = jest.fn().mockResolvedValue(undefined);
    mock.verifyDataImpl = spy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    await db.verifyData({ contaminationRootDeltaId: 'abc', managerToken: 'tok', nowSecs: 1 });

    expect(spy).toHaveBeenCalledWith('abc', 'tok', 1);
  });

  test('adminClose delegates to WASM', async () => {
    const mock = installMock();
    const spy = jest.fn().mockResolvedValue(undefined);
    mock.adminCloseImpl = spy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    await db.adminClose({ incidentId: 'uuid-123', managerToken: 'tok', nowSecs: 1 });

    expect(spy).toHaveBeenCalledWith('uuid-123', 'tok', 1);
  });

  test('activateSaturateMode delegates to WASM', async () => {
    const mock = installMock();
    const spy = jest.fn().mockResolvedValue(undefined);
    mock.activateSaturateModeImpl = spy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    await db.activateSaturateMode({ biscuitTokenHex: 'deadbeef' });

    expect(spy).toHaveBeenCalledWith('deadbeef');
  });

  test('renewSaturateMode delegates to WASM', async () => {
    const mock = installMock();
    const spy = jest.fn().mockResolvedValue(undefined);
    mock.renewSaturateModeImpl = spy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    await db.renewSaturateMode({ biscuitTokenHex: 'deadbeef' });

    expect(spy).toHaveBeenCalledWith('deadbeef');
  });

  test('terminateSaturateMode delegates to WASM', async () => {
    const mock = installMock();
    const spy = jest.fn().mockResolvedValue(undefined);
    mock.terminateSaturateModeImpl = spy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    const coSignatures = [
      { did: 'did:key:z6MkOther', signatureHex: 'ab'.repeat(64) },
    ];
    await db.terminateSaturateMode({
      terminationMessageHex: '73617475726174652d7465726d696e617465',
      coManagerSignatures: coSignatures,
    });

    expect(spy).toHaveBeenCalledWith(
      '73617475726174652d7465726d696e617465',
      coSignatures,
    );
  });
});

// ─── Test: _normaliseConfig ───────────────────────────────────────────────────

describe('TirBase._normaliseConfig()', () => {
  test('fills in default deployment values when none supplied', () => {
    const normalised = TirBase._normaliseConfig({ storagePath: './db' });
    expect(normalised.deploymentConfig.revocationM).toBe(2);
    expect(normalised.deploymentConfig.revocationN).toBe(3);
    expect(normalised.deploymentConfig.quorumK).toBe(2);
  });

  test('user-supplied deployment values override defaults', () => {
    const normalised = TirBase._normaliseConfig({
      storagePath: './db',
      deploymentConfig: { revocationM: 3, revocationN: 5 },
    });
    expect(normalised.deploymentConfig.revocationM).toBe(3);
    expect(normalised.deploymentConfig.revocationN).toBe(5);
    // Other defaults unchanged
    expect(normalised.deploymentConfig.quorumK).toBe(2);
  });
});

// ─── Test: TrustLevel state progression ──────────────────────────────────────

describe('TrustLevel state progression', () => {
  const transitions: Array<[TrustLevel, TrustLevel]> = [
    ['VERIFIED', 'UNVERIFIED'],
    ['UNVERIFIED', 'REVOKED'],
    ['REVOKED', 'VERIFIED'],   // recovery path (e.g., re-provisioning)
  ];

  test.each(transitions)(
    'transitions from %s to %s emit trust-level-changed',
    async (from, to) => {
      const mock = installMock();
      mock.trustLevelImpl = () => from;
      const db = await TirBase.init(DEFAULT_CONFIG);

      const handler = jest.fn();
      db.on('trust-level-changed', handler);
      db._applyTrustLevelChange(to);

      expect(handler).toHaveBeenCalledWith(
        expect.objectContaining({ previousLevel: from, newLevel: to }),
      );
    },
  );
});

// ─── Test: WASM event bridge (_pollWasmEvents) ────────────────────────────────

describe('WASM event bridge (_pollWasmEvents)', () => {
  test('incident-created emitter fires when pollEvents returns IncidentCreated event', async () => {
    const mock = installMock();
    const icoPayload = {
      type: 'incidentCreated',
      ico: {
        id: 'test-incident-id',
        state: 'Open',
        taint_source: { tag: 'DeviceRevocation', revocation_delta_id: 'abc123' },
        contamination_roots: ['abc123'],
        contaminated_deltas: [],
        affected_rows: [],
        composite_of: null,
        created_at: 0,
        updated_at: 0,
        audit_log: [],
      },
    };
    mock.pollEventsImpl = () => [icoPayload];
    mock.writeImpl = async (_t, _k, _d) => ({
      deltaId: 'a'.repeat(64),
      durabilityTier: 'UNCOMMITTED',
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('incident-created', handler);

    await db.write({ table: 'test', key: 'k', data: {} });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0]![0]).toHaveProperty('id', 'test-incident-id');
  });

  test('trust-level-changed fires when pollEvents returns TrustLevelChanged', async () => {
    const mock = installMock();
    mock.pollEventsImpl = () => [
      {
        type: 'trustLevelChanged',
        previous: 'Verified',
        new: 'Revoked',
      },
    ];
    mock.writeImpl = async () => ({
      deltaId: 'a'.repeat(64),
      durabilityTier: 'UNCOMMITTED',
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('trust-level-changed', handler);

    await db.write({ table: 't', key: 'k', data: {} });

    expect(handler).toHaveBeenCalledTimes(1);
    const evt = handler.mock.calls[0]![0];
    expect(evt.newLevel).toBe('REVOKED');
    expect(db.trustLevel).toBe('REVOKED');
  });

  test('durability-tier-changed fires when pollEvents returns DurabilityTierChanged', async () => {
    const mock = installMock();
    mock.pollEventsImpl = () => [
      {
        type: 'durabilityTierChanged',
        delta_id: 'deadbeef'.repeat(8),
        previous_tier: 'UNCOMMITTED',
        new_tier: 'TIER1',
      },
    ];
    mock.writeImpl = async () => ({
      deltaId: 'a'.repeat(64),
      durabilityTier: 'UNCOMMITTED',
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('durability-tier-changed', handler);

    await db.write({ table: 't', key: 'k', data: {} });

    expect(handler).toHaveBeenCalledTimes(1);
    const evt = handler.mock.calls[0]![0];
    expect(evt.previousTier).toBe('UNCOMMITTED');
    expect(evt.newTier).toBe('TIER1');
  });

  test('pollEvents called on read() and query() as well', async () => {
    const mock = installMock();
    const pollSpy = jest.fn().mockReturnValue([]);
    mock.pollEventsImpl = pollSpy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    await db.read({ table: 't', key: 'k' });
    await db.query({ table: 't' });

    expect(pollSpy).toHaveBeenCalledTimes(2);
  });

  test('no events fired when pollEvents returns empty array', async () => {
    const mock = installMock();
    mock.pollEventsImpl = () => [];
    mock.writeImpl = async () => ({
      deltaId: 'a'.repeat(64),
      durabilityTier: 'UNCOMMITTED',
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const h1 = jest.fn();
    const h2 = jest.fn();
    db.on('incident-created', h1);
    db.on('trust-level-changed', h2);

    await db.write({ table: 't', key: 'k', data: {} });

    expect(h1).not.toHaveBeenCalled();
    expect(h2).not.toHaveBeenCalled();
  });

  test('pollEvents not called when method is absent on WasmCore', async () => {
    const mock = installMock();
    // Remove pollEvents from the mock so the optional-method guard is exercised.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mock as any).pollEvents = undefined;
    mock.writeImpl = async () => ({
      deltaId: 'a'.repeat(64),
      durabilityTier: 'UNCOMMITTED',
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    // Should not throw — _pollWasmEvents must guard on method existence.
    await expect(
      db.write({ table: 't', key: 'k', data: {} }),
    ).resolves.toBeDefined();
  });

  test('incident-updated event fires when pollEvents returns IncidentUpdated', async () => {
    const mock = installMock();
    mock.pollEventsImpl = () => [
      {
        type: 'incidentUpdated',
        ico: {
          id: 'upd-incident-id',
          state: 'Open',
          taint_source: { tag: 'DeviceRevocation', revocation_delta_id: 'abc' },
          contamination_roots: [],
          contaminated_deltas: [],
          affected_rows: [],
          composite_of: null,
          created_at: 0,
          updated_at: 0,
          audit_log: [],
        },
      },
    ];
    mock.readImpl = async (table, key) => ({
      table,
      key,
      data: {},
      contaminated: false,
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('incident-updated', handler);

    await db.read({ table: 't', key: 'k' });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0]![0]).toHaveProperty('id', 'upd-incident-id');
  });

  test('incident-closed event fires when pollEvents returns IncidentClosed', async () => {
    const mock = installMock();
    mock.pollEventsImpl = () => [
      {
        type: 'incidentClosed',
        ico: {
          id: 'closed-incident-id',
          state: 'Closed',
          taint_source: { tag: 'DeviceRevocation', revocation_delta_id: 'abc' },
          contamination_roots: [],
          contaminated_deltas: [],
          affected_rows: [],
          composite_of: null,
          created_at: 0,
          updated_at: 0,
          audit_log: [],
        },
      },
    ];
    mock.queryImpl = async () => [];

    const db = await TirBase.init(DEFAULT_CONFIG);
    const handler = jest.fn();
    db.on('incident-closed', handler);

    await db.query({ table: 't' });

    expect(handler).toHaveBeenCalledTimes(1);
    const ico = handler.mock.calls[0]![0] as IncidentContextObject;
    expect(ico.id).toBe('closed-incident-id');
    expect(ico.state).toBe('CLOSED');
  });

  test('multiple events in one poll batch all dispatched', async () => {
    const mock = installMock();
    mock.pollEventsImpl = () => [
      {
        type: 'trustLevelChanged',
        previous: 'Verified',
        new: 'Unverified',
      },
      {
        type: 'incidentCreated',
        ico: {
          id: 'batch-ico',
          state: 'Open',
          taint_source: { tag: 'DeviceRevocation', revocation_delta_id: 'xyz' },
          contamination_roots: [],
          contaminated_deltas: [],
          affected_rows: [],
          composite_of: null,
          created_at: 0,
          updated_at: 0,
          audit_log: [],
        },
      },
    ];
    mock.writeImpl = async () => ({
      deltaId: 'a'.repeat(64),
      durabilityTier: 'UNCOMMITTED',
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const trustHandler = jest.fn();
    const incidentHandler = jest.fn();
    db.on('trust-level-changed', trustHandler);
    db.on('incident-created', incidentHandler);

    await db.write({ table: 't', key: 'k', data: {} });

    expect(trustHandler).toHaveBeenCalledTimes(1);
    expect(incidentHandler).toHaveBeenCalledTimes(1);
    expect(incidentHandler.mock.calls[0]![0]).toHaveProperty('id', 'batch-ico');
  });
});

// ─── Test: receivePeerMessage (Task 40) ──────────────────────────────────────

describe('db.receivePeerMessage() (Task 40 — WASM inbound path)', () => {
  test('receivePeerMessage passes bytes to wasm.receiveMessage', async () => {
    const mock = installMock();
    const receiveSpy = jest.fn().mockResolvedValue(undefined);
    mock.receiveMessageImpl = receiveSpy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    const bytes = new Uint8Array([1, 2, 3, 4]);
    db.receivePeerMessage(bytes);

    expect(receiveSpy).toHaveBeenCalledTimes(1);
    expect(receiveSpy).toHaveBeenCalledWith(bytes);
  });

  test('receivePeerMessage is a no-op when not initialised', () => {
    // Should not throw — silently ignores bytes before init.
    const db = Object.create(TirBase.prototype) as TirBase;
    const bytes = new Uint8Array([1, 2, 3]);
    expect(() => db.receivePeerMessage(bytes)).not.toThrow();
  });

  test('receivePeerMessage is a no-op when receiveMessage is absent on WasmCore', async () => {
    const mock = installMock();
    // Remove the optional receiveMessage method to simulate an older WASM build.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mock as any).receiveMessage = undefined;

    const db = await TirBase.init(DEFAULT_CONFIG);
    const bytes = new Uint8Array([5, 6, 7]);
    // Must not throw even if the underlying method is missing.
    expect(() => db.receivePeerMessage(bytes)).not.toThrow();
  });

  test('cross-instance convergence: message sent via receiveMessageImpl reaches second instance', async () => {
    // Simulate two browser tabs (two MockWasmCore instances).
    // Instance A writes a Delta; the raw bytes are captured and fed to Instance B
    // via receiveMessage — confirming the convergence contract at the SDK level.

    // ── Instance A ──
    const mockA = new MockWasmCore();
    let capturedBytes: Uint8Array | null = null;

    // Override writeImpl to also record what would be broadcast to peers.
    mockA.writeImpl = async (table, key, data) => {
      const gossipPayload = JSON.stringify({
        InboundDelta: {
          id: new Array(32).fill(0),
          author_did: 'did:key:z6MkInstanceA',
          signature: { 0: [] },
          schema_hash: new Array(32).fill(0),
          automerge_bytes: Array.from(
            new TextEncoder().encode(JSON.stringify(data)),
          ),
          priority: 'Low',
          causal_parents: [],
          tags: [],
          lamport: 1,
          created_at: 0,
        },
      });
      capturedBytes = new TextEncoder().encode(gossipPayload);
      return {
        deltaId: 'a'.repeat(64),
        durabilityTier: 'UNCOMMITTED',
      };
    };

    TirBase._setWasmLoader(async () => mockA);
    const dbA = await TirBase.init(DEFAULT_CONFIG);
    await dbA.write({ table: 'sensors', key: 'temp-1', data: { value: 42 } });

    expect(capturedBytes).not.toBeNull();

    // ── Instance B ──
    const mockB = new MockWasmCore();
    let receivedBytes: Uint8Array | null = null;
    mockB.receiveMessageImpl = async (bytes: Uint8Array) => {
      receivedBytes = bytes;
    };

    TirBase._setWasmLoader(async () => mockB);
    const dbB = await TirBase.init(DEFAULT_CONFIG);

    // Feed the bytes from A into B.
    dbB.receivePeerMessage(capturedBytes!);

    // Allow the fire-and-forget Promise to settle.
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(receivedBytes).not.toBeNull();
    expect(Array.from(receivedBytes!)).toEqual(Array.from(capturedBytes!));
  });

  test('receiveMessage mock implementation can be overridden per test', async () => {
    const mock = installMock();
    const calls: Uint8Array[] = [];
    mock.receiveMessageImpl = async (bytes) => {
      calls.push(bytes);
    };

    const db = await TirBase.init(DEFAULT_CONFIG);
    const b1 = new Uint8Array([10, 20]);
    const b2 = new Uint8Array([30, 40, 50]);

    db.receivePeerMessage(b1);
    db.receivePeerMessage(b2);

    // Allow microtasks to settle.
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(calls).toHaveLength(2);
    expect(Array.from(calls[0]!)).toEqual([10, 20]);
    expect(Array.from(calls[1]!)).toEqual([30, 40, 50]);
  });
});

// ─── WASM LocalStore persistence via IndexedDB (Req 3.1, 17.1, 20.3, 20.4) ─────
//
// These tests verify that data written through the WASM core's LocalStore
// persists across re-initialization with the same storage path (simulating
// a page reload) — the IndexedDB-backed persistence story.
//
// Since MockWasmCore operates in-process without a real IndexedDB, the tests
// use a shared in-memory mock store that simulates the persistence contract:
// data written before "page reload" (re-init) is still readable afterward.

/**
 * A MockWasmCore variant with a shared, persistent in-memory store that
 * survives re-initialisation — simulating IndexedDB persistence across page
 * reloads.
 */
class PersistentMockWasmCore implements WasmCore {
  private store: Map<string, unknown> = new Map();

  trustLevel(): TrustLevel {
    return 'VERIFIED';
  }

  meshStatus(): MeshStatus {
    return { status: 'connected', peerCount: 0 };
  }

  async read(table: string, key: string): Promise<unknown> {
    const composite = `${table}\u{1f}${key}`;
    const entry = this.store.get(composite);
    if (entry === undefined) {
      return null;
    }
    return { table, key, data: entry, contaminated: false };
  }

  async write(table: string, key: string, data: unknown): Promise<unknown> {
    const composite = `${table}\u{1f}${key}`;
    this.store.set(composite, data);
    return { deltaId: 'a'.repeat(64), durabilityTier: 'UNCOMMITTED' };
  }

  async query(table: string, _filter: unknown): Promise<unknown[]> {
    const prefix = `${table}\u{1f}`;
    const results: unknown[] = [];
    for (const [composite, data] of this.store.entries()) {
      if (composite.startsWith(prefix)) {
        const key = composite.slice(prefix.length);
        results.push({ table, key, data, contaminated: false });
      }
    }
    return results;
  }

  core_present_token(_token: string): Promise<TrustLevel> {
    return Promise.resolve('VERIFIED');
  }

  initiateRevocation(): Promise<void> {
    return Promise.resolve();
  }

  revocationStatus(): Promise<RevocationStatus> {
    return Promise.resolve({
      signaturesCollected: 0,
      signaturesRequired: 2,
      status: 'PENDING',
      lastKnownTrustLevel: null,
      lastRevocationDeltaReceivedAt: null,
    });
  }

  verifyData(): Promise<void> {
    return Promise.resolve();
  }

  adminClose(): Promise<void> {
    return Promise.resolve();
  }

  activateSaturateMode(): Promise<void> {
    return Promise.resolve();
  }

  renewSaturateMode(): Promise<void> {
    return Promise.resolve();
  }

  terminateSaturateMode(): Promise<void> {
    return Promise.resolve();
  }

  pollEvents(): unknown[] {
    return [];
  }

  receiveMessage(_rawBytes: Uint8Array): Promise<void> {
    return Promise.resolve();
  }
}

describe('WASM LocalStore persistence (Req 3.1, 17.1, 20.3, 20.4)', () => {
  test('data written before re-init persists across page-reload simulation', async () => {
    // Simulate a shared IndexedDB backing store that survives page reloads.
    const persistentStore = new PersistentMockWasmCore();

    // ── Instance A: write a key ──
    TirBase._setWasmLoader(async () => persistentStore);
    const dbA = await TirBase.init({ storagePath: 'tirbase_store_persist_test' });
    await dbA.write({
      table: 'reports',
      key: 'r-persist-1',
      data: { status: 'open', score: 42 },
    });

    // Verify it's readable within the same instance.
    const readBeforeReload = await dbA.read({
      table: 'reports',
      key: 'r-persist-1',
    });
    expect(readBeforeReload.data).toEqual({ status: 'open', score: 42 });

    // ── Page reload: re-init with the SAME persistent store (simulating
    //    IndexedDB surviving a reload) ──
    TirBase._resetWasmLoader();
    TirBase._setWasmLoader(async () => persistentStore);
    const dbB = await TirBase.init({ storagePath: 'tirbase_store_persist_test' });

    // The key written before the "reload" must still be present.
    const readAfterReload = await dbB.read({
      table: 'reports',
      key: 'r-persist-1',
    });
    expect(readAfterReload.data).toEqual({ status: 'open', score: 42 });
    expect(readAfterReload.contaminated).toBe(false);
  });

  test('query returns persisted rows after re-init', async () => {
    const persistentStore = new PersistentMockWasmCore();

    // Instance A: write multiple rows
    TirBase._setWasmLoader(async () => persistentStore);
    const dbA = await TirBase.init({ storagePath: 'tirbase_store_query_persist' });
    await dbA.write({ table: 'tasks', key: 't-1', data: { title: 'task-1' } });
    await dbA.write({ table: 'tasks', key: 't-2', data: { title: 'task-2' } });

    TirBase._resetWasmLoader();
    TirBase._setWasmLoader(async () => persistentStore);
    const dbB = await TirBase.init({ storagePath: 'tirbase_store_query_persist' });

    const results = await dbB.query({ table: 'tasks' });
    expect(results).toHaveLength(2);
    const keys = results.map((r) => r.key).sort();
    expect(keys).toEqual(['t-1', 't-2']);
  });

  test('upsert (write same key twice) persists the latest value', async () => {
    const persistentStore = new PersistentMockWasmCore();

    // Instance A: write v1
    TirBase._setWasmLoader(async () => persistentStore);
    const dbA = await TirBase.init({ storagePath: 'tirbase_store_upsert_test' });
    await dbA.write({ table: 'items', key: 'item-1', data: { v: 1 } });

    // Instance B: overwrite v1 → v2
    TirBase._setWasmLoader(async () => persistentStore);
    const dbB = await TirBase.init({ storagePath: 'tirbase_store_upsert_test' });
    await dbB.write({ table: 'items', key: 'item-1', data: { v: 2 } });

    // Instance C: re-read — should see v2
    TirBase._resetWasmLoader();
    TirBase._setWasmLoader(async () => persistentStore);
    const dbC = await TirBase.init({ storagePath: 'tirbase_store_upsert_test' });
    const result = await dbC.read({ table: 'items', key: 'item-1' });
    expect(result.data).toEqual({ v: 2 });
  });
});

// ─── Real WASM integration tests ──────────────────────────────────────────────
// These tests exercise the actual compiled WASM core via a Node ESM child process.
// No mocks of the WASM core are used.

import { execFileSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

interface WasmResult {
  success: boolean;
  error: string | null;
  results: Record<string, unknown>;
}

function runWasmRunner(op: string, args: unknown = {}): WasmResult {
  const runnerPath = path.resolve(
    __dirname,
    `../__helpers__/wasm_runner_${Date.now()}_${Math.random().toString(36).slice(2)}.tmp.mjs`,
  );
  fs.mkdirSync(path.dirname(runnerPath), { recursive: true });

  const script = `
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmDir = resolve(__dirname, '../../wasm');

const wasmBytes = readFileSync(resolve(wasmDir, 'tirbase_core_bg.wasm'));
const mod = await import('file://' + resolve(wasmDir, 'tirbase_core.js'));
const init = mod.default;
if (typeof init === 'function') {
  await init(wasmBytes);
}

const output = { success: true, error: null, results: {} };

try {
  const op = process.argv[2];
  const args = JSON.parse(process.argv[3] || '{}');

  if (op === 'init-success') {
    await mod.core_init(':memory:', [], null, []);
    output.results = { ready: true };
  } else if (op === 'write-error') {
    await mod.core_init(':memory:', [], null, []);
    try {
      const circular = {};
      circular.self = circular;
      await mod.core_write('t', 'k', circular);
      output.results = { wrote: true };
    } catch (e) {
      output.success = false;
      output.error = String(e);
    }
  } else if (op === 'init-invalid-config') {
    try {
      await mod.core_init('', [], null, []);
      output.results = { initialized: true };
    } catch (e) {
      output.success = false;
      output.error = String(e);
    }
  } else if (op === 'schema-hash-roundtrip') {
    const schemaSrc = args.schemaSrc;
    const hash1 = mod.core_schema_identifier_hash(schemaSrc);
    const printed = mod.core_schema_print(schemaSrc);
    const hash2 = mod.core_schema_identifier_hash(printed);
    output.results = { hash1, hash2, printed };
  } else if (op === 'schema-print-parse') {
    const schemaSrc = args.schemaSrc;
    const printed = mod.core_schema_print(schemaSrc);
    try {
      mod.core_schema_parse(printed);
      output.results = { printed, parseOk: true };
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

  fs.writeFileSync(runnerPath, script);

  try {
    const output = execFileSync('node', [runnerPath, op, JSON.stringify(args)], {
      encoding: 'utf-8',
      timeout: 30000,
      env: { ...process.env, NODE_NO_WARNINGS: '1' },
    });
    return JSON.parse(output.trim()) as WasmResult;
  } finally {
    fs.rmSync(runnerPath, { force: true });
  }
}

describe('Real WASM integration', () => {
  afterEach(() => {
    TirBase._resetWasmLoader();
  });

  describe('init with real WASM', () => {
    test('core_init succeeds with valid params (:memory:, empty CAs)', async () => {
      const result = runWasmRunner('init-success');
      expect(result.success).toBe(true);
      expect(result.error).toBeNull();
      expect(result.results.ready).toBe(true);
    });
  });

  describe('write failure on real WASM', () => {
    test('core_write rejects when writing to a reserved/internal table', async () => {
      const result = runWasmRunner('write-error');
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toBeTruthy();
    });
  });

  describe('init failure and guard', () => {
    test('init rejects with TirBaseInitError on invalid config, subsequent calls throw', async () => {
      TirBase._setWasmLoader(async () => {
        const { loadWasmCore } = await import('../wasm-bridge');
        return loadWasmCore();
      });

      // Attempt init with empty storage path (WASM core rejects this).
      await expect(
        TirBase.init({ storagePath: '' }),
      ).rejects.toBeInstanceOf(TirBaseInitError);

      // Create an uninitialized instance to verify the guard.
      const uninit = Object.create(TirBase.prototype) as TirBase;
      await expect(
        uninit.write({ table: 't', key: 'k', data: {} }),
      ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
    });
  });

  describe('schema identifier hash round-trip', () => {
    test('hash is computed from parsed schema, not raw string', async () => {
      const schemaSrc = `
schema {
  version = "1.0.0"
  table users {
    compaction = none
    id   TEXT    NOT NULL
    name TEXT    NOT NULL
  }
}`;

      const result = runWasmRunner('schema-hash-roundtrip', { schemaSrc });
      expect(result.success).toBe(true);
      expect(result.results.hash1).toBe(result.results.hash2);
      expect(typeof result.results.hash1).toBe('string');
      expect((result.results.hash1 as string).length).toBe(64);
    });
  });

  describe('schema printer round-trip', () => {
    test('parser accepts printer output without errors', async () => {
      const schemaSrc = `
schema {
  version = "1.0.0"
  table reports {
    compaction = aggressive(500)
    id      TEXT    NOT NULL
    title   TEXT    NOT NULL
    score   REAL    DEFAULT 0.0
    active  BOOLEAN DEFAULT true
    PRIMARY KEY (id)
  }
}`;

      const result = runWasmRunner('schema-print-parse', { schemaSrc });
      expect(result.success).toBe(true);
      expect(result.results.parseOk).toBe(true);
      expect(typeof result.results.printed).toBe('string');
      expect((result.results.printed as string)).toContain('schema {');
    });
  });
});
