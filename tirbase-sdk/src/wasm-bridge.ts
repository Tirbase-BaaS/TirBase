/**
 * WASM bridge abstraction layer.
 *
 * `WasmCore` is the interface that the compiled tirbase-core WASM module
 * (produced by wasm-pack) must satisfy. It mirrors the `CoreHandle` public
 * API in `tirbase-core/src/api/mod.rs`.
 *
 * During tests (or before the WASM artefact is compiled) a `MockWasmCore`
 * implementation is used so that the TypeScript layer can be tested in
 * isolation without a real WASM build.
 */

import type {
  InitConfig,
  MeshStatus,
  QueryResult,
  RevocationStatus,
  TrustLevel,
  WriteResult,
} from './types';

// ─── WasmCore interface ───────────────────────────────────────────────────────

/**
 * Interface satisfied by the wasm-pack–generated JS glue code AND by
 * `MockWasmCore`. All methods map 1-to-1 to `CoreHandle` methods in Rust.
 *
 * Return types use `unknown` for the raw WASM values; the bridge adapter
 * (in `TirBase`) casts them to the typed SDK types before returning to callers.
 */
export interface WasmCore {
  /** Read a single row by (table, key). */
  read(table: string, key: string): Promise<unknown>;

  /** Write a row to (table, key) with the given data payload. */
  write(table: string, key: string, data: unknown): Promise<unknown>;

  /** Query rows from a table with an optional filter. */
  query(table: string, filter: unknown): Promise<unknown[]>;

  /** Returns the current TrustLevel string. */
  trustLevel(): TrustLevel;

  /** Returns the current MeshStatus object. */
  meshStatus(): MeshStatus;

  // ── Manager operations ────────────────────────────────────────────────────

  /** Gossip a partial RevocationDelta for the target DID. */
  initiateRevocation(targetDid: string, managerToken: string): Promise<void>;

  /** Return the current accumulation state for a pending revocation. */
  revocationStatus(targetDid: string): Promise<RevocationStatus>;

  /** Append a RESOLVED tag to a contamination root Delta. */
  verifyData(
    contaminationRootDeltaId: string,
    managerToken: string,
  ): Promise<void>;

  /** Archive an incident without certifying data integrity. */
  adminClose(incidentId: string, managerToken: string): Promise<void>;

  /** Activate Saturate Mode with a DISASTER_ALERT payload. */
  activateSaturateMode(
    disasterAlertPayload: string,
    managerToken: string,
  ): Promise<void>;

  /** Drain and return queued WASM events. Optional — absent on older builds. */
  pollEvents?(): unknown[];

  /**
   * Accept raw peer message bytes from the JS transport layer.
   *
   * The JS transport (WebRTC `RTCDataChannel`, BLE bridge, etc.) must call
   * this when raw bytes arrive from a remote peer.  The bytes are deserialised
   * into a `GossipMessage` and routed through the WASM-side inbound pipeline
   * (signature verification → schema-hash gate → in-memory merge).
   *
   * Optional — absent on builds that pre-date Task 40.
   */
  receiveMessage?(rawBytes: Uint8Array): Promise<void>;
}

// ─── Loader function ──────────────────────────────────────────────────────────

/**
 * Load the WASM-compiled tirbase-core and return a `WasmCore` instance.
 *
 * In production this function is responsible for fetching and instantiating
 * the `.wasm` binary produced by `wasm-pack build --features wasm`.
 *
 * @param wasmUrl  Optional URL override for the `.wasm` binary.  When omitted
 *                 the loader resolves the binary relative to `wasm/`.
 * @throws {Error} If the WASM module cannot be fetched or instantiated.
 */
export async function loadWasmCore(wasmUrl?: string): Promise<WasmCore> {
  // The actual wasm-pack artefact path.  A real build places it at
  // `wasm/tirbase_core.js` (note: wasm-pack uses underscores).
  const jsPath = wasmUrl ?? './wasm/tirbase_core.js';

  try {
    // Dynamic import — works in Node (≥ 22 with ESM or via CJS require) and
    // modern bundlers (Webpack/Vite/Rollup).
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const wasmModule = await import(/* webpackIgnore: true */ jsPath);

    // wasm-pack generates a default-exported init() that returns the module
    // after loading the .wasm binary.
    if (typeof wasmModule.default === 'function') {
      await wasmModule.default();
    }

    // The wasm-bindgen glue exposes the Rust struct methods on the module
    // namespace.  Wrap them in the WasmCore interface shape.
    return buildBridgeFromWasmModule(wasmModule);
  } catch (err) {
    throw new Error(
      `Failed to load tirbase-core WASM module from "${jsPath}": ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

/**
 * Thin adapter that wraps the raw wasm-pack module exports into the
 * `WasmCore` interface.  The WASM module exports free functions whose
 * names match the #[wasm_bindgen] exports in lib.rs.
 */
function buildBridgeFromWasmModule(mod: Record<string, unknown>): WasmCore {
  function required(name: string): (...args: unknown[]) => unknown {
    if (typeof mod[name] !== 'function') {
      throw new Error(
        `tirbase-core WASM module is missing expected export: "${name}"`,
      );
    }
    return mod[name] as (...args: unknown[]) => unknown;
  }

  return {
    read: (table, key) =>
      (required('core_read') as (t: string, k: string) => Promise<unknown>)(
        table,
        key,
      ),
    write: (table, key, data) =>
      (
        required('core_write') as (
          t: string,
          k: string,
          d: unknown,
        ) => Promise<unknown>
      )(table, key, data),
    query: (table, filter) =>
      (
        required('core_query') as (
          t: string,
          f: unknown,
        ) => Promise<unknown[]>
      )(table, filter),
    trustLevel: () =>
      (required('core_trust_level') as () => TrustLevel)(),
    meshStatus: () =>
      (required('core_mesh_status') as () => MeshStatus)(),
    initiateRevocation: (targetDid, managerToken) =>
      (
        required('core_initiate_revocation') as (
          d: string,
          t: string,
        ) => Promise<void>
      )(targetDid, managerToken),
    revocationStatus: (targetDid) =>
      (
        required('core_revocation_status') as (
          d: string,
        ) => Promise<RevocationStatus>
      )(targetDid),
    verifyData: (rootDeltaId, managerToken) =>
      (
        required('core_verify_data') as (
          r: string,
          t: string,
        ) => Promise<void>
      )(rootDeltaId, managerToken),
    adminClose: (incidentId, managerToken) =>
      (
        required('core_admin_close') as (
          i: string,
          t: string,
        ) => Promise<void>
      )(incidentId, managerToken),
    activateSaturateMode: (payload, managerToken) =>
      (
        required('core_activate_saturate_mode') as (
          p: string,
          t: string,
        ) => Promise<void>
      )(payload, managerToken),
    pollEvents: () => {
      if (typeof mod['core_poll_events'] === 'function') {
        return (mod['core_poll_events'] as () => unknown[])();
      }
      return [];
    },
    ...(typeof mod['core_receive_peer_message'] === 'function'
      ? {
          receiveMessage: (rawBytes: Uint8Array) =>
            (
              mod['core_receive_peer_message'] as (
                b: Uint8Array,
              ) => Promise<void>
            )(rawBytes),
        }
      : {}),
  };
}

// ─── MockWasmCore ─────────────────────────────────────────────────────────────

/**
 * Configurable in-process mock of the WASM layer, for use in unit tests.
 *
 * Individual method overrides can be set directly on the instance or via
 * the constructor options to simulate success, failure, and state changes.
 */
export class MockWasmCore implements WasmCore {
  // Override these in tests to control behaviour.
  readImpl: (table: string, key: string) => Promise<unknown> =
    async (table, key) => ({
      table,
      key,
      data: {},
      contaminated: false,
    });

  writeImpl: (
    table: string,
    key: string,
    data: unknown,
  ) => Promise<unknown> = async (_table, _key, _data) => ({
    deltaId: 'a'.repeat(64),
    durabilityTier: 'UNCOMMITTED',
  });

  queryImpl: (table: string, filter: unknown) => Promise<unknown[]> =
    async (table, _filter) => [
      { table, key: 'key-0', data: {}, contaminated: false },
    ];

  trustLevelImpl: () => TrustLevel = () => 'VERIFIED';

  meshStatusImpl: () => MeshStatus = () => ({
    status: 'connected',
    peerCount: 0,
  });

  initiateRevocationImpl: (
    targetDid: string,
    managerToken: string,
  ) => Promise<void> = async () => undefined;

  revocationStatusImpl: (targetDid: string) => Promise<RevocationStatus> =
    async (_did) => ({
      signaturesCollected: 0,
      signaturesRequired: 2,
      status: 'PENDING',
    });

  verifyDataImpl: (
    rootDeltaId: string,
    managerToken: string,
  ) => Promise<void> = async () => undefined;

  adminCloseImpl: (
    incidentId: string,
    managerToken: string,
  ) => Promise<void> = async () => undefined;

  activateSaturateModeImpl: (
    payload: string,
    managerToken: string,
  ) => Promise<void> = async () => undefined;

  pollEventsImpl: () => unknown[] = () => [];

  /** Stub for the WASM inbound peer message path (Task 40). Override in tests. */
  receiveMessageImpl: (rawBytes: Uint8Array) => Promise<void> =
    async (_bytes) => undefined;

  // ── WasmCore implementation ───────────────────────────────────────────────

  read(table: string, key: string): Promise<unknown> {
    return this.readImpl(table, key);
  }

  write(table: string, key: string, data: unknown): Promise<unknown> {
    return this.writeImpl(table, key, data);
  }

  query(table: string, filter: unknown): Promise<unknown[]> {
    return this.queryImpl(table, filter);
  }

  trustLevel(): TrustLevel {
    return this.trustLevelImpl();
  }

  meshStatus(): MeshStatus {
    return this.meshStatusImpl();
  }

  initiateRevocation(targetDid: string, managerToken: string): Promise<void> {
    return this.initiateRevocationImpl(targetDid, managerToken);
  }

  revocationStatus(targetDid: string): Promise<RevocationStatus> {
    return this.revocationStatusImpl(targetDid);
  }

  verifyData(rootDeltaId: string, managerToken: string): Promise<void> {
    return this.verifyDataImpl(rootDeltaId, managerToken);
  }

  adminClose(incidentId: string, managerToken: string): Promise<void> {
    return this.adminCloseImpl(incidentId, managerToken);
  }

  activateSaturateMode(
    payload: string,
    managerToken: string,
  ): Promise<void> {
    return this.activateSaturateModeImpl(payload, managerToken);
  }

  pollEvents(): unknown[] {
    return this.pollEventsImpl();
  }

  receiveMessage(rawBytes: Uint8Array): Promise<void> {
    return this.receiveMessageImpl(rawBytes);
  }
}

/**
 * Factory for a `MockWasmCore` configured to throw on every call.
 * Useful for testing the init-failure path.
 */
export function makeBrokenWasmLoader(): () => Promise<WasmCore> {
  return async () => {
    throw new Error('WASM module failed to load');
  };
}
