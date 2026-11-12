// SPDX-License-Identifier: Apache-2.0

/**
 * Real-WASM end-to-end tests for every SDK manager operation.
 *
 * Each device is a real compiled `tirbase-core` WASM instance (Node-target
 * build of the same crate/feature set, loaded by the SDK's production loader).
 * Devices talk to each other only through the production transport contract:
 * `drainOutboundMessages()` returns the framed `GossipMessage` payloads the
 * DRR scheduler produced, and `receivePeerMessage()` feeds them into the
 * peer's real inbound pipeline (signature verification → schema gate → CRDT
 * merge → store projection → CCE tagging).
 *
 * Nothing on the asserted path is a `MockWasmCore`, an injected inbound
 * message, or a test-only core branch. Token and co-signature fixtures are
 * produced by `tirbase-core/examples/wasm_e2e_fixtures.rs` using the
 * production Biscuit/identity helpers; the WASM module verifies them itself.
 */

import {
  broadcast,
  deviceConfig,
  fixtures,
  openDevice,
  type WasmFixtures,
} from '../__helpers__/real-core';
import { TirBase } from '../tirbase';
import type {
  IncidentContextObject,
  TrustLevelChangedEvent,
  UnverifiedWarning,
} from '../types';

jest.setTimeout(600_000);

const REVOCATION_M = 2;
const REVOCATION_N = 3;

let F: WasmFixtures;
let deployment: {
  rootCaPublicKeys: string[];
  revocationM: number;
  revocationN: number;
};

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

/** Open one real WASM device with the shared deployment configuration. */
async function device(name: string): Promise<TirBase> {
  return openDevice(deviceConfig(deployment), name);
}

interface RevocationScene {
  target: TirBase;
  manager1: TirBase;
  manager2: TirBase;
  rowKeys: string[];
  deltaIds: string[];
}

/**
 * Build the real two-manager revocation scene:
 *
 * 1. `target` writes two rows and gossips them to both managers (so each
 *    manager's per-author index knows the target's Deltas).
 * 2. `manager1` produces the first partial RevocationDelta and gossips it.
 * 3. `manager2` receives that partial delta and contributes its own signature,
 *    reaching the 2-of-3 threshold.
 */
async function revocationScene(): Promise<RevocationScene> {
  const [target, manager1, manager2] = await Promise.all([
    device('target'),
    device('manager1'),
    device('manager2'),
  ]);
  await manager2.presentToken(F.managerTokenHex);
  expect(manager2.trustLevel).toBe('VERIFIED');

  const rowKeys = ['k1', 'k2'];
  const deltaIds: string[] = [];
  for (const [index, key] of rowKeys.entries()) {
    const write = await target.write({
      table: 'reports',
      key,
      data: { value: index + 1 },
    });
    deltaIds.push(write.deltaId);
  }

  const delivered = await broadcast(target, [manager1, manager2]);
  expect(delivered).toBeGreaterThanOrEqual(2);
  const projected = await manager2.read({ table: 'reports', key: 'k1' });
  expect(projected.data).toEqual({ value: 1 });

  await manager1.initiateRevocation({
    targetDid: target.localDid,
    managerToken: F.managerTokenHex,
  });
  await broadcast(manager1, [manager2]);

  return { target, manager1, manager2, rowKeys, deltaIds };
}

describe('TirBase SDK — real WASM manager operations', () => {
  beforeAll(() => {
    F = fixtures();
    deployment = {
      rootCaPublicKeys: [F.rootCaPublicHex],
      revocationM: REVOCATION_M,
      revocationN: REVOCATION_N,
    };
  });

  afterEach(() => {
    TirBase._resetWasmLoader();
  });

  test('init runs the real core with the deployment thresholds', async () => {
    const db = await device('init');
    expect(db.trustLevel).toBe('UNVERIFIED');
    expect(db.localDid).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
    expect(db.meshStatus.peerCount).toBe(0);
  });

  test('presentToken moves trust level and emits trust-level-changed', async () => {
    const db = await device('trust');
    const changes: TrustLevelChangedEvent[] = [];
    db.on('trust-level-changed', (event) => changes.push(event));

    await expect(db.presentToken(F.managerTokenHex)).resolves.toBe('VERIFIED');
    expect(db.trustLevel).toBe('VERIFIED');
    expect(changes).toHaveLength(1);
    expect(changes[0].previousLevel).toBe('UNVERIFIED');
    expect(changes[0].newLevel).toBe('VERIFIED');
  });

  test('a stale/invalid token yields UNVERIFIED and unverified warnings', async () => {
    const db = await device('stale');
    await expect(db.presentToken(F.managerTokenHex)).resolves.toBe('VERIFIED');

    // Not a valid Biscuit token: verification fails without a state transition
    // (Req 8.8), so the SDK reports the stale UNVERIFIED level.
    await expect(db.presentToken('00ff00ff')).resolves.toBe('UNVERIFIED');
    expect(db.trustLevel).toBe('UNVERIFIED');

    const warnings: UnverifiedWarning[] = [];
    db.on('unverified-warning', (warning) => warnings.push(warning));
    const write = await db.write({
      table: 'warn',
      key: 'r1',
      data: { ok: true },
    });
    expect(warnings).toHaveLength(1);
    expect(warnings[0].unverifiedSince).toBeInstanceOf(Date);
    expect(write.unverifiedWarning).toBeDefined();
  });

  test('initiateRevocation persists a real partial RevocationDelta', async () => {
    const [target, manager1] = await Promise.all([
      device('partial-target'),
      device('partial-manager'),
    ]);

    await manager1.initiateRevocation({
      targetDid: target.localDid,
      managerToken: F.managerTokenHex,
    });

    const status = await manager1.revocationStatus({
      targetDid: target.localDid,
    });
    expect(status.status).toBe('PENDING');
    expect(status.signaturesRequired).toBe(REVOCATION_M);
    expect(status.signaturesCollected).toBe(1);
    expect(status.lastKnownTrustLevel).toBeNull();
    expect(status.lastRevocationDeltaReceivedAt).toBeNull();

    // The partial delta really left the transport as a peer frame.
    expect(manager1.drainOutboundMessages().length).toBeGreaterThan(0);
  });

  test('two manager identities accumulate to the threshold and revoke the target', async () => {
    const { target, manager1, manager2 } = await revocationScene();

    const beforeOwnSignature = await manager2.revocationStatus({
      targetDid: target.localDid,
    });
    expect(beforeOwnSignature.status).toBe('PENDING');
    expect(beforeOwnSignature.signaturesCollected).toBe(1);

    await manager2.initiateRevocation({
      targetDid: target.localDid,
      managerToken: F.managerTokenHex,
    });

    const applied = await manager2.revocationStatus({
      targetDid: target.localDid,
    });
    expect(applied.status).toBe('APPLIED');
    expect(applied.signaturesCollected).toBe(REVOCATION_M);
    expect(applied.lastKnownTrustLevel).toBe('REVOKED');
    expect(applied.lastRevocationDeltaReceivedAt).not.toBeNull();

    // The revocation targeted the peer, never this manager: its own trust
    // level must stay VERIFIED (the WASM trust event carries the target DID).
    expect(manager2.trustLevel).toBe('VERIFIED');

    // manager1 only contributed its own signature, so it is still pending.
    const pending = await manager1.revocationStatus({
      targetDid: target.localDid,
    });
    expect(pending.status).toBe('PENDING');
    expect(pending.signaturesCollected).toBe(1);
  });

  test('revocation creates contamination incidents observed by pollEvents and the emitter', async () => {
    const { target, manager2 } = await revocationScene();

    const emitted: IncidentContextObject[] = [];
    manager2.on('incident-created', (ico) => emitted.push(ico));

    await manager2.initiateRevocation({
      targetDid: target.localDid,
      managerToken: F.managerTokenHex,
    });
    // Force a drain of any queued WASM events through the public read path.
    await manager2.query({ table: 'reports' });

    expect(emitted.length).toBeGreaterThanOrEqual(2);
    for (const ico of emitted) {
      expect(ico.id).toMatch(/^[0-9a-f-]{36}$/);
      expect(ico.taintSource.type).toBe('DEVICE_REVOCATION');
      expect(ico.contaminationRoots).toHaveLength(1);
      expect(ico.contaminationRoots[0]).toMatch(/^[0-9a-f]{64}$/);
      expect(ico.affectedRowCount).toBeGreaterThanOrEqual(1);
      expect(ico.auditLog).toEqual([]);
    }

    // The rows projected from the revoked device are flagged contaminated.
    const rows = await manager2.query({ table: 'reports' });
    expect(rows.map((row) => row.contaminated)).toEqual([true, true]);
  });

  test('verifyData resolves the real root and emits incident-closed', async () => {
    const { target, manager2 } = await revocationScene();
    const created: IncidentContextObject[] = [];
    manager2.on('incident-created', (ico) => created.push(ico));
    const closed: IncidentContextObject[] = [];
    manager2.on('incident-closed', (ico) => closed.push(ico));

    await manager2.initiateRevocation({
      targetDid: target.localDid,
      managerToken: F.managerTokenHex,
    });
    await manager2.query({ table: 'reports' });
    expect(created).toHaveLength(2);

    const incident = created.find((ico) =>
      ico.affectedRows.some((row) => row.rowKey === 'k1'),
    );
    expect(incident).toBeDefined();
    const root = incident!.contaminationRoots[0];

    await manager2.verifyData({
      contaminationRootDeltaId: root,
      managerToken: F.managerTokenHex,
      nowSecs: nowSecs(),
    });

    expect(closed).toHaveLength(1);
    expect(closed[0].contaminationRoots).toContain(root);

    const resolvedRow = await manager2.read({ table: 'reports', key: 'k1' });
    expect(resolvedRow.contaminated).toBe(false);
    const unresolvedRow = await manager2.read({ table: 'reports', key: 'k2' });
    expect(unresolvedRow.contaminated).toBe(true);

    const queried = await manager2.query({ table: 'reports' });
    expect(
      queried.find((row) => row.key === 'k1')?.contaminated,
    ).toBe(false);
  });

  test('adminClose archives an incident without certifying integrity', async () => {
    const { target, manager2 } = await revocationScene();
    const created: IncidentContextObject[] = [];
    manager2.on('incident-created', (ico) => created.push(ico));
    const closed: IncidentContextObject[] = [];
    manager2.on('incident-closed', (ico) => closed.push(ico));

    await manager2.initiateRevocation({
      targetDid: target.localDid,
      managerToken: F.managerTokenHex,
    });
    await manager2.query({ table: 'reports' });
    expect(created).toHaveLength(2);

    const incident = created.find((ico) =>
      ico.affectedRows.some((row) => row.rowKey === 'k2'),
    )!;

    await manager2.adminClose({
      incidentId: incident.id,
      managerToken: F.managerTokenHex,
      nowSecs: nowSecs(),
    });

    expect(closed).toHaveLength(1);
    expect(closed[0].id).toBe(incident.id);
    expect(closed[0].state).toBe('CLOSED');
    expect(closed[0].auditLog.map((entry) => entry.operation)).toEqual([
      'ADMIN_CLOSE',
    ]);

    // Archiving is not a VERIFY_DATA: the row stays contaminated because
    // integrity was never certified.
    const row = await manager2.read({ table: 'reports', key: 'k2' });
    expect(row.contaminated).toBe(true);
    expect(closed[0].auditLog[0].affectedDeltaIds).toEqual([]);
  });

  test('untrusted and expired manager tokens are rejected', async () => {
    const { target, manager2 } = await revocationScene();
    const created: IncidentContextObject[] = [];
    manager2.on('incident-created', (ico) => created.push(ico));
    await manager2.initiateRevocation({
      targetDid: target.localDid,
      managerToken: F.managerTokenHex,
    });
    await manager2.query({ table: 'reports' });
    const root = created[0].contaminationRoots[0];

    // Token minted by a CA this deployment does not trust.
    await expect(
      manager2.verifyData({
        contaminationRootDeltaId: root,
        managerToken: F.foreignTokenHex,
        nowSecs: nowSecs(),
      }),
    ).rejects.toThrow(/token verification failed|invalid root CA|Authorisation/i);

    // Valid token evaluated after its expiry.
    await expect(
      manager2.verifyData({
        contaminationRootDeltaId: root,
        managerToken: F.managerTokenHex,
        nowSecs: nowSecs() + 7_200,
      }),
    ).rejects.toThrow(/expired|verification failed|Authorisation/i);

    // Nothing was resolved by the rejected calls.
    const row = await manager2.read({ table: 'reports', key: 'k1' });
    expect(row.contaminated).toBe(true);
  });

  test('saturate mode: activate, renew, threshold termination, insufficient signatures', async () => {
    const db = await device('saturate');
    await db.presentToken(F.managerTokenHex);
    const token = { biscuitTokenHex: F.disasterAlertTokenHex };

    await expect(db.activateSaturateMode(token)).resolves.toBeUndefined();
    await expect(db.renewSaturateMode(token)).resolves.toBeUndefined();

    // One signature (this device's own) is below the 2-of-3 threshold.
    await expect(
      db.terminateSaturateMode({
        terminationMessageHex: F.terminationMessageHex,
        coManagerSignatures: [],
      }),
    ).rejects.toThrow(/Threshold not met|ThresholdNotMet/i);

    // The failed termination preserved SATURATE mode: renewal still works.
    await expect(db.renewSaturateMode(token)).resolves.toBeUndefined();

    // Two distinct valid Manager signatures meet the threshold.
    await expect(
      db.terminateSaturateMode({
        terminationMessageHex: F.terminationMessageHex,
        coManagerSignatures: [F.coManagers[0]!],
      }),
    ).resolves.toBeUndefined();

    // Termination left SATURATE mode: heartbeat renewal is now rejected.
    await expect(db.renewSaturateMode(token)).rejects.toThrow(
      /not in SATURATE mode/i,
    );
  });

  test('receivePeerMessage merges and projects a second device\'s signed Delta', async () => {
    const [writer, reader] = await Promise.all([
      device('mesh-writer'),
      device('mesh-reader'),
    ]);

    await expect(
      reader.read({ table: 'mesh', key: 'row-1' }),
    ).rejects.toThrow(/not found/i);

    const write = await writer.write({
      table: 'mesh',
      key: 'row-1',
      data: { sensor: 'temp', value: 7 },
    });
    expect(write.deltaId).toMatch(/^[0-9a-f]{64}$/);

    const frames = await broadcast(writer, [reader]);
    expect(frames).toBeGreaterThanOrEqual(1);

    const projected = await reader.read({ table: 'mesh', key: 'row-1' });
    expect(projected.data).toEqual({ sensor: 'temp', value: 7 });
    expect(projected.contaminated).toBe(false);

    const queried = await reader.query({ table: 'mesh' });
    expect(queried).toHaveLength(1);
    expect(queried[0].key).toBe('row-1');
  });
});
