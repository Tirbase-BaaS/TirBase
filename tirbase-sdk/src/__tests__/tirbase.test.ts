/**
 * Unit tests for the TirBase SDK.
 *
 * All tests use MockWasmCore — no real WASM binary is required.
 * The WASM loader is overridden via TirBase._setWasmLoader() before each
 * relevant test and reset via TirBase._resetWasmLoader() in afterEach.
 */

import { TirBase } from '../tirbase';
import { MockWasmCore } from '../wasm-bridge';
import type { IncidentContextObject, TrustLevel } from '../types';
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
      db.verifyData({ contaminationRootDeltaId: 'abc', managerToken: 't' }),
    ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
    await expect(
      db.adminClose({ incidentId: 'uuid', managerToken: 't' }),
    ).rejects.toBeInstanceOf(TirBaseNotInitializedError);
    await expect(
      db.activateSaturateMode({ disasterAlertPayload: 'alert', managerToken: 't' }),
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
    });

    const db = await TirBase.init(DEFAULT_CONFIG);
    const status = await db.revocationStatus({ targetDid: 'did:key:z6Mk' });

    expect(status.signaturesCollected).toBe(1);
    expect(status.signaturesRequired).toBe(2);
    expect(status.status).toBe('PENDING');
  });

  test('verifyData delegates to WASM', async () => {
    const mock = installMock();
    const spy = jest.fn().mockResolvedValue(undefined);
    mock.verifyDataImpl = spy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    await db.verifyData({ contaminationRootDeltaId: 'abc', managerToken: 'tok' });

    expect(spy).toHaveBeenCalledWith('abc', 'tok');
  });

  test('adminClose delegates to WASM', async () => {
    const mock = installMock();
    const spy = jest.fn().mockResolvedValue(undefined);
    mock.adminCloseImpl = spy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    await db.adminClose({ incidentId: 'uuid-123', managerToken: 'tok' });

    expect(spy).toHaveBeenCalledWith('uuid-123', 'tok');
  });

  test('activateSaturateMode delegates to WASM', async () => {
    const mock = installMock();
    const spy = jest.fn().mockResolvedValue(undefined);
    mock.activateSaturateModeImpl = spy;

    const db = await TirBase.init(DEFAULT_CONFIG);
    await db.activateSaturateMode({ disasterAlertPayload: 'alert-payload', managerToken: 'tok' });

    expect(spy).toHaveBeenCalledWith('alert-payload', 'tok');
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
