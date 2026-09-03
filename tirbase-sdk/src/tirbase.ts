/**
 * TirBase — main SDK class.
 *
 * Wraps the WASM-compiled tirbase-core crate and exposes a Promise-based
 * TypeScript API for reading, writing, querying, and managing a TirBase
 * instance (Req 2.1–2.6).
 *
 * Usage:
 *   const db = await TirBase.init({ storagePath: './local.db' });
 *   const result = await db.write({ table: 'reports', key: 'r-1', data: {...} });
 */

import EventEmitter from 'eventemitter3';

import type { WasmCore } from './wasm-bridge';
import { loadWasmCore } from './wasm-bridge';

import type {
  AffectedRow,
  DeploymentConfig,
  DurabilityTierChangedEvent,
  IncidentContextObject,
  InitConfig,
  MeshStatus,
  QueryResult,
  RevocationStatus,
  TaintSource,
  TirBaseEvents,
  TrustLevel,
  TrustLevelChangedEvent,
  UnverifiedWarning,
  WriteResult,
} from './types';
import { TirBaseInitError, TirBaseNotInitializedError } from './types';

// ─── Internal raw WASM result shapes ─────────────────────────────────────────
// These match what the Rust WASM module serialises over the JS boundary.
// They are private to this file; callers only see the typed SDK types.

interface RawWriteResult {
  deltaId?: string;
  delta_id?: string;
  durabilityTier?: string;
  durability_tier?: string;
  unverifiedWarningSince?: number;
  unverified_warning_since?: number;
}

interface RawQueryResult {
  table: string;
  key: string;
  data: Record<string, unknown>;
  contaminated: boolean;
  unverifiedWarningSince?: number;
  unverified_warning_since?: number;
}

// ─── TirBase class ────────────────────────────────────────────────────────────

/**
 * The primary handle to a TirBase instance.
 *
 * Obtain via `TirBase.init()`. All methods throw `TirBaseNotInitializedError`
 * when called before a successful `init()` (Req 2.6).
 */
export class TirBase {
  // ── private state ─────────────────────────────────────────────────────────

  private _initialized: boolean = false;
  private _wasm!: WasmCore;
  private _trustLevel: TrustLevel = 'VERIFIED';
  private _meshStatus: MeshStatus = { status: 'disconnected', peerCount: 0 };
  private _unverifiedSince: Date | null = null;

  /** Internal event emitter (eventemitter3). */
  private readonly _emitter = new EventEmitter<TirBaseEvents>();

  /**
   * Injected WASM loader, overridable in tests.
   * Defaults to the real `loadWasmCore` from the bridge module.
   */
  private static _wasmLoader: (
    config: InitConfig,
  ) => Promise<WasmCore> = async (_config) => loadWasmCore();

  // ── constructor (private) ─────────────────────────────────────────────────

  private constructor() {}

  // ── Static init ───────────────────────────────────────────────────────────

  /**
   * Initialise TirBase — loads and instantiates the WASM module, then
   * configures the Rust Core with the supplied `InitConfig` (Req 2.2).
   *
   * Resolves with a ready `TirBase` instance on success.
   * Rejects with `TirBaseInitError` on failure; the returned (failed)
   * instance has `_initialized = false` so all subsequent calls throw
   * `TirBaseNotInitializedError` until `init()` is called again (Req 2.6).
   *
   * @param config  Storage path and optional deployment settings.
   * @returns       A fully initialised `TirBase` instance.
   */
  static async init(config: InitConfig): Promise<TirBase> {
    const instance = new TirBase();
    try {
      instance._wasm = await TirBase._wasmLoader(config);
      instance._trustLevel = instance._wasm.trustLevel();
      instance._meshStatus = instance._wasm.meshStatus();
      instance._initialized = true;
      return instance;
    } catch (err) {
      // Leave _initialized = false so all API calls throw (Req 2.6).
      throw new TirBaseInitError(
        `TirBase initialisation failed: ${
          err instanceof Error ? err.message : String(err)
        }`,
        'WASM_INIT_FAILED',
      );
    }
  }

  /**
   * Override the WASM loader.  Used in tests to inject a `MockWasmCore`.
   *
   * @param loader  A function that returns a `WasmCore` instance (or throws).
   */
  static _setWasmLoader(
    loader: (config: InitConfig) => Promise<WasmCore>,
  ): void {
    TirBase._wasmLoader = loader;
  }

  /**
   * Reset the WASM loader back to the production implementation.
   * Call in test `afterEach` / `afterAll` to avoid test pollution.
   */
  static _resetWasmLoader(): void {
    TirBase._wasmLoader = async (_config) => loadWasmCore();
  }

  // ── Guard ─────────────────────────────────────────────────────────────────

  private _assertInitialized(): void {
    if (!this._initialized) {
      throw new TirBaseNotInitializedError();
    }
  }

  // ── UNVERIFIED helpers ────────────────────────────────────────────────────

  private _buildUnverifiedWarning(): UnverifiedWarning | undefined {
    if (this._trustLevel !== 'UNVERIFIED') return undefined;
    return { unverifiedSince: this._unverifiedSince ?? new Date() };
  }

  private _maybeEmitUnverifiedWarning(): void {
    if (this._trustLevel === 'UNVERIFIED') {
      const warning = this._buildUnverifiedWarning()!;
      this._emitter.emit('unverified-warning', warning);
    }
  }

  // ── Core data API ─────────────────────────────────────────────────────────

  /**
   * Write a row to the Local Store (Req 2.1, 2.3).
   *
   * Returns a `WriteResult` that includes `durabilityTier` and, when the
   * device is UNVERIFIED, an `unverifiedWarning` (Req 8.4).
   */
  async write(params: {
    table: string;
    key: string;
    data: Record<string, unknown>;
  }): Promise<WriteResult> {
    this._assertInitialized();
    this._maybeEmitUnverifiedWarning();

    const raw = (await this._wasm.write(
      params.table,
      params.key,
      params.data,
    )) as RawWriteResult;

    const warning = this._buildUnverifiedWarning();
    const result: WriteResult = {
      deltaId: raw.deltaId ?? raw.delta_id ?? '',
      durabilityTier:
        (raw.durabilityTier as WriteResult['durabilityTier']) ??
        (raw.durability_tier as WriteResult['durabilityTier']) ??
        'UNCOMMITTED',
      ...(warning !== undefined ? { unverifiedWarning: warning } : {}),
    };

    this._pollWasmEvents();
    return result;
  }

  /**
   * Read a single row by (table, key) (Req 2.1).
   *
   * Attaches an `unverifiedWarning` when the device is UNVERIFIED (Req 8.4).
   */
  async read(params: { table: string; key: string }): Promise<QueryResult> {
    this._assertInitialized();
    this._maybeEmitUnverifiedWarning();

    const raw = (await this._wasm.read(
      params.table,
      params.key,
    )) as RawQueryResult;

    const warning = this._buildUnverifiedWarning();
    const readResult: QueryResult = {
      table: raw.table,
      key: raw.key,
      data: raw.data ?? {},
      contaminated: raw.contaminated ?? false,
      ...(warning !== undefined ? { unverifiedWarning: warning } : {}),
    };

    this._pollWasmEvents();
    return readResult;
  }

  /**
   * Query rows from a table with an optional filter (Req 2.1).
   *
   * Attaches an `unverifiedWarning` on each result when UNVERIFIED (Req 8.4).
   */
  async query(params: {
    table: string;
    filter?: Record<string, unknown>;
  }): Promise<QueryResult[]> {
    this._assertInitialized();
    this._maybeEmitUnverifiedWarning();

    const rawItems = (await this._wasm.query(
      params.table,
      params.filter ?? null,
    )) as RawQueryResult[];

    const warning = this._buildUnverifiedWarning();
    const queryResults = rawItems.map((raw) => ({
      table: raw.table,
      key: raw.key,
      data: raw.data ?? {},
      contaminated: raw.contaminated ?? false,
      ...(warning !== undefined ? { unverifiedWarning: warning } : {}),
    }));

    this._pollWasmEvents();
    return queryResults;
  }

  // ── Readable properties ───────────────────────────────────────────────────

  /**
   * The current Trust_Level of the local device (Req 2.4).
   * Synchronously readable; mirrors Rust Core state.
   */
  get trustLevel(): TrustLevel {
    return this._trustLevel;
  }

  /**
   * Mesh connection status and peer count (Req 2.5).
   * Synchronously readable; mirrors Rust Core state.
   */
  get meshStatus(): MeshStatus {
    return this._meshStatus;
  }

  // ── Event emitter wrappers ────────────────────────────────────────────────

  /**
   * Register a typed event listener.
   *
   * Supported events:
   * - `'unverified-warning'`      — fired on every operation while UNVERIFIED
   * - `'trust-level-changed'`     — fired when Trust_Level transitions
   * - `'durability-tier-changed'` — fired when a Delta set reaches Tier-1 or Tier-2
   * - `'incident-created'`        — new ICO opened by the Contamination Engine
   * - `'incident-updated'`        — ICO fields updated
   * - `'incident-closed'`         — ICO transitioned to CLOSED
   */
  on<E extends keyof TirBaseEvents>(
    event: E,
    handler: TirBaseEvents[E],
  ): this {
    this._emitter.on(event, handler as EventEmitter.ListenerFn);
    return this;
  }

  /**
   * Remove a previously registered typed event listener.
   */
  off<E extends keyof TirBaseEvents>(
    event: E,
    handler: TirBaseEvents[E],
  ): this {
    this._emitter.off(event, handler as EventEmitter.ListenerFn);
    return this;
  }

  /**
   * Emit a typed event.
   *
   * This is internal-facing and also exposed for the test harness so that
   * tests can simulate events emitted by the Rust Core (e.g., trust-level
   * changes, incident notifications) without a real WASM module.
   *
   * @internal — not part of the public API contract.
   */
  _emit<E extends keyof TirBaseEvents>(
    event: E,
    ...args: Parameters<TirBaseEvents[E]>
  ): void {
    // Cast to any[] to work around eventemitter3's overloaded emit signature.
    // The type safety is enforced by the Parameters<TirBaseEvents[E]> constraint above.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (this._emitter.emit as (event: E, ...args: any[]) => void)(event, ...args);
  }

  /**
   * Internal helper used by the WASM event bridge to update Trust_Level
   * state and emit the `'trust-level-changed'` event.
   *
   * @internal
   */
  _applyTrustLevelChange(newLevel: TrustLevel): void {
    if (newLevel === this._trustLevel) return;
    const event: TrustLevelChangedEvent = {
      previousLevel: this._trustLevel,
      newLevel,
      timestamp: new Date(),
    };
    this._trustLevel = newLevel;
    if (newLevel === 'UNVERIFIED' && !this._unverifiedSince) {
      this._unverifiedSince = new Date();
    } else if (newLevel !== 'UNVERIFIED') {
      this._unverifiedSince = null;
    }
    this._emitter.emit('trust-level-changed', event);
  }

  /**
   * Internal helper used by the WASM event bridge to update MeshStatus.
   *
   * @internal
   */
  _applyMeshStatusChange(newStatus: MeshStatus): void {
    this._meshStatus = newStatus;
  }

  /**
   * Internal helper used by the WASM event bridge to propagate ICO events.
   *
   * @internal
   */
  _applyIncidentEvent(
    kind: 'incident-created' | 'incident-updated' | 'incident-closed',
    ico: IncidentContextObject,
  ): void {
    this._emitter.emit(kind, ico);
  }

  /**
   * Internal helper for durability tier change notifications (Req 14.7).
   *
   * @internal
   */
  _applyDurabilityTierChanged(event: DurabilityTierChangedEvent): void {
    this._emitter.emit('durability-tier-changed', event);
  }

  // ── WASM event bridge ─────────────────────────────────────────────────────

  /**
   * Drain pending WASM events and dispatch each to the correct internal helper.
   *
   * Called at the end of `write()`, `read()`, and `query()` to surface
   * Rust-side side-effects (trust-level changes, contamination incidents,
   * durability tier promotions) to the application layer without requiring
   * a separate polling loop (Task 31).
   */
  private _pollWasmEvents(): void {
    if (!this._wasm.pollEvents) return;
    const events: unknown[] = this._wasm.pollEvents() ?? [];
    for (const raw of events) {
      const event = raw as Record<string, unknown>;
      const type = event['type'] as string | undefined;
      switch (type) {
        case 'trustLevelChanged': {
          const newLevel = String(event['new']).toUpperCase() as TrustLevel;
          this._applyTrustLevelChange(newLevel);
          break;
        }
        case 'incidentCreated':
          if (event['ico']) {
            this._applyIncidentEvent(
              'incident-created',
              this._parseIco(event['ico']),
            );
          }
          break;
        case 'incidentUpdated':
          if (event['ico']) {
            this._applyIncidentEvent(
              'incident-updated',
              this._parseIco(event['ico']),
            );
          }
          break;
        case 'incidentClosed':
          if (event['ico']) {
            this._applyIncidentEvent(
              'incident-closed',
              this._parseIco(event['ico']),
            );
          }
          break;
        case 'durabilityTierChanged': {
          const evt: DurabilityTierChangedEvent = {
            deltaSetId: String(event['delta_id'] ?? ''),
            previousTier: String(
              event['previous_tier'] ?? 'UNCOMMITTED',
            ).toUpperCase() as DurabilityTierChangedEvent['previousTier'],
            newTier: String(
              event['new_tier'] ?? 'UNCOMMITTED',
            ).toUpperCase() as DurabilityTierChangedEvent['newTier'],
            timestamp: new Date(),
          };
          this._applyDurabilityTierChanged(evt);
          break;
        }
        default:
          break;
      }
    }
  }

  /**
   * Convert a raw JSON object from WASM into a TypeScript `IncidentContextObject`.
   * Handles snake_case → camelCase field name differences.
   */
  private _parseIco(raw: unknown): IncidentContextObject {
    const r = raw as Record<string, unknown>;
    const compositeOf = r['composite_of'] as string[] | null | undefined;
    const ico: IncidentContextObject = {
      id: String(r['id'] ?? ''),
      state:
        String(r['state'] ?? 'Open').toLowerCase() === 'closed'
          ? 'CLOSED'
          : 'OPEN',
      taintSource: this._parseTaintSource(
        r['taint_source'] ?? r['taintSource'],
      ),
      contaminationRoots: (
        (r['contamination_roots'] ?? r['contaminationRoots'] ?? []) as string[]
      ),
      affectedTableCount: Number(
        r['affected_table_count'] ?? r['affectedTableCount'] ?? 0,
      ),
      affectedRowCount: Number(
        r['affected_row_count'] ?? r['affectedRowCount'] ?? 0,
      ),
      affectedRows: (
        (r['affected_rows'] ?? r['affectedRows'] ?? []) as AffectedRow[]
      ),
      createdAt: new Date(
        Number(r['created_at'] ?? r['createdAt'] ?? 0) / 1000,
      ),
      updatedAt: new Date(
        Number(r['updated_at'] ?? r['updatedAt'] ?? 0) / 1000,
      ),
      auditLog: [],
    };
    if (compositeOf != null) {
      ico.compositeOf = compositeOf;
    }
    return ico;
  }

  /**
   * Convert a raw taint_source JSON object to a typed `TaintSource`.
   */
  private _parseTaintSource(raw: unknown): TaintSource {
    const r = (raw ?? {}) as Record<string, unknown>;
    const tag = String(r['tag'] ?? r['type'] ?? 'DeviceRevocation');
    if (tag === 'BadMigration' || tag === 'BAD_MIGRATION') {
      return {
        type: 'BAD_MIGRATION',
        migrationId: String(r['migration_id'] ?? ''),
      };
    }
    if (tag === 'HumanReaction' || tag === 'HUMAN_REACTION') {
      return {
        type: 'HUMAN_REACTION',
        triggeredByIncidentId: String(r['triggered_by_incident_id'] ?? ''),
      };
    }
    return {
      type: 'DEVICE_REVOCATION',
      revocationDeltaId: String(r['revocation_delta_id'] ?? ''),
    };
  }

  // ── Manager operations ────────────────────────────────────────────────────

  /**
   * Gossip a partial RevocationDelta for the target DID.
   *
   * The mesh accumulates signatures until M-of-N threshold is reached
   * (design §Manager Operations — mesh-accumulated signature model).
   */
  async initiateRevocation(params: {
    targetDid: string;
    managerToken: string;
  }): Promise<void> {
    this._assertInitialized();
    await this._wasm.initiateRevocation(params.targetDid, params.managerToken);
  }

  /**
   * Return the current accumulation state for a pending revocation (Req 9.1–9.4).
   */
  async revocationStatus(params: {
    targetDid: string;
  }): Promise<RevocationStatus> {
    this._assertInitialized();
    return this._wasm.revocationStatus(params.targetDid);
  }

  /**
   * Submit a VERIFY_DATA operation for a contamination root Delta (Req 11.1).
   */
  async verifyData(params: {
    contaminationRootDeltaId: string;
    managerToken: string;
  }): Promise<void> {
    this._assertInitialized();
    await this._wasm.verifyData(
      params.contaminationRootDeltaId,
      params.managerToken,
    );
  }

  /**
   * Archive an incident without certifying data integrity (Req 11.2).
   */
  async adminClose(params: {
    incidentId: string;
    managerToken: string;
  }): Promise<void> {
    this._assertInitialized();
    await this._wasm.adminClose(params.incidentId, params.managerToken);
  }

  /**
   * Activate Saturate_Mode with a signed DISASTER_ALERT (Req 13.1).
   *
   * The `managerToken` must carry the `disaster-alert` Biscuit caveat.
   */
  async activateSaturateMode(params: {
    disasterAlertPayload: string;
    managerToken: string;
  }): Promise<void> {
    this._assertInitialized();
    await this._wasm.activateSaturateMode(
      params.disasterAlertPayload,
      params.managerToken,
    );
  }

  /**
   * Forward raw peer message bytes to the WASM inbound pipeline (Req 5, Req 1.4).
   *
   * The JS transport layer (WebRTC `RTCDataChannel`, BLE bridge, or any
   * browser-compatible transport) calls this when raw bytes arrive from a
   * remote peer.  TirBase deserialises the bytes, verifies the embedded
   * signature, applies the schema-hash gate, and merges the payload into the
   * local in-memory store.
   *
   * After calling this method you should call `write()`, `read()`, or `query()`
   * to trigger `_pollWasmEvents()` so any side-effect events produced by the
   * merge (e.g. `incident-created`, `trust-level-changed`) are surfaced.
   *
   * @param bytes  Raw `GossipMessage` bytes as produced by `GossipMessage::to_bytes()`
   *               on the Rust side.  Must be a `Uint8Array`.
   */
  receivePeerMessage(bytes: Uint8Array): void {
    if (!this._initialized) {
      // Silently ignore if not yet initialised — the SDK may not be set up yet
      // when transport bytes arrive.  Callers that need error visibility can
      // wrap in a try/catch after calling this method.
      return;
    }
    // Fire-and-forget: the underlying WASM call is async but we expose a
    // synchronous entry point matching the WebRTC `ondatachannel` pattern.
    // Errors are logged inside receive_inbound_wasm; they don't propagate here.
    void this._wasm.receiveMessage?.(bytes);
  }

  // ── Deployment config helpers ─────────────────────────────────────────────

  /**
   * Normalise an `InitConfig` for passing to the Rust Core.
   * Fills in default DeploymentConfig values where omitted.
   */
  static _normaliseConfig(config: InitConfig): Required<InitConfig> {
    const defaults: Required<DeploymentConfig> = {
      revocationM: 2,
      revocationN: 3,
      biscuitTtlSecs: 3600,
      anchorAttestedLocation: false,
      spatialDiversityMin: 2,
      quorumK: 2,
      quorumN: 3,
    };
    return {
      storagePath: config.storagePath,
      deploymentConfig: { ...defaults, ...config.deploymentConfig },
    };
  }
}
