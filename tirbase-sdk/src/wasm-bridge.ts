// SPDX-License-Identifier: Apache-2.0

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
  DeploymentConfig,
  InitConfig,
  MeshStatus,
  QueryResult,
  RevocationStatus,
  SaturateManagerSignature,
  TrustLevel,
  WriteResult,
} from './types';
import { createRequire } from 'module';
import { dirname, resolve } from 'path';

// Resolve the directory of this file for locating the WASM artefacts.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const _moduleFile = (<any>module).filename || resolve('.', 'index.js');
const _dirname = dirname(_moduleFile);
const _require = createRequire(_moduleFile);

/**
 * Resolve the separately published AGPL core package.
 *
 * The SDK wrapper is Apache-2.0 and does not bundle the WASM core. The core is
 * published as `@tirbase/core-wasm` under AGPL-3.0-only. Fall back to the local
 * workspace build when the package is not installed (development/tests).
 */
function defaultCoreWasmEntry(): string {
  try {
    return _require.resolve('@tirbase/core-wasm');
  } catch {
    return resolve(_dirname, '../wasm/tirbase_core.js');
  }
}

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

  /**
   * Present a hex-encoded Biscuit token for TrustLevel verification (Req 8.3, 8.4, 8.8).
   *
   * Delegates to `core_present_token` in the Rust WASM module.
   * Returns the resulting TrustLevel string.
   * Throws if no root CA keys are registered (AuthorisationFailed).
   */
  core_present_token(token: string): Promise<TrustLevel>;

  // ── Manager operations ────────────────────────────────────────────────────

  /** Gossip a partial RevocationDelta for the target DID. */
  initiateRevocation(targetDid: string, managerToken: string): Promise<void>;

  /** Return the current accumulation state for a pending revocation. */
  revocationStatus(targetDid: string): Promise<RevocationStatus>;

  /** Append a RESOLVED tag to a contamination root Delta. */
  verifyData(
    contaminationRootDeltaId: string,
    managerToken: string,
    nowSecs: number,
  ): Promise<void>;

  /** Archive an incident without certifying data integrity. */
  adminClose(incidentId: string, managerToken: string, nowSecs: number): Promise<void>;

  /** Activate Saturate Mode with a DISASTER_ALERT payload. */
  activateSaturateMode(
    biscuitTokenHex: string,
  ): Promise<void>;

  /** Renew a Saturate Mode Lease with a heartbeat DISASTER_ALERT token (Req 13.4). */
  renewSaturateMode(
    biscuitTokenHex: string,
  ): Promise<void>;

  /**
   * Terminate Saturate Mode with an M-of-N Manager signature set (Req 13.6).
   *
   * `terminationMessageHex` is the hex-encoded canonical message every
   * Manager signed; `coManagerSignatures` are the signatures already
   * collected from the other Managers (this device adds its own).
   */
  terminateSaturateMode(
    terminationMessageHex: string,
    coManagerSignatures: SaturateManagerSignature[],
  ): Promise<void>;

  /**
   * Drain the DRR scheduler and return the wire frames to hand to peers.
   *
   * Delegates to `core_drain_outbound_messages` in the Rust WASM module. Each
   * returned `Uint8Array` is a framed `GossipMessage` payload produced by the
   * production transport; a JS transport sends them to the remote peer, whose
   * SDK calls `receiveMessage` with the same bytes.
   *
   * @param linkCapacityBytes  DRR epoch budget (defaults to one MTU-sized batch).
   */
  drainOutboundMessages(linkCapacityBytes?: number): Uint8Array[];

  /**
   * Return this device's `did:key:` DID.
   *
   * Delegates to `core_local_did`. Manager operations that target the local
   * identity (e.g. proving the REVOKED write gate) need it.
   */
  localDid(): string;

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
 * Load the WASM-compiled tirbase-core, run `core_init` with the supplied
 * configuration, and return a `WasmCore` bound to that initialised instance.
 *
 * In production this function fetches and instantiates the `.wasm` binary
 * produced by `wasm-pack build --features wasm` and then initialises the core
 * state from the caller's [`InitConfig`]. Without this step the WASM module's
 * thread-local `CORE` slot is empty and every operation fails with
 * `core_init() must be called first`.
 *
 * @param config   Storage path and deployment settings from `TirBase.init`.
 * @param wasmUrl  Optional URL override for the WASM glue module.  When
 *                 omitted the loader resolves `@tirbase/core-wasm`.
 * @throws {Error} If the WASM module cannot be fetched, instantiated or
 *                 initialised.
 */
export async function loadWasmCore(
  config?: InitConfig,
  wasmUrl?: string,
): Promise<WasmCore> {
  const defaultJsPath = defaultCoreWasmEntry();
  const jsPath = wasmUrl ?? defaultJsPath;

  try {
    const wasmModule = await import(/* webpackIgnore: true */ jsPath);

    if (typeof wasmModule.default === 'function') {
      await wasmModule.default();
    }

    return await initialiseCore(wasmModule, config);
  } catch (err) {
    throw new Error(
      `Failed to load tirbase-core WASM module from "${jsPath}": ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

/**
 * Map the SDK's camelCase [`DeploymentConfig`] onto the snake_case JSON object
 * `core_init` accepts. Only explicitly configured values are sent so the Rust
 * spec defaults stay in force for everything the caller omitted.
 */
function deploymentOverridesJson(
  deployment: DeploymentConfig,
): Record<string, unknown> {
  const overrides: Record<string, unknown> = {};
  const put = (key: string, value: unknown): void => {
    if (value !== undefined) overrides[key] = value;
  };
  put('revocation_m', deployment.revocationM);
  put('revocation_n', deployment.revocationN);
  put('biscuit_ttl_secs', deployment.biscuitTtlSecs);
  put('anchor_attested_location', deployment.anchorAttestedLocation);
  put('spatial_diversity_min', deployment.spatialDiversityMin);
  put('quorum_k', deployment.quorumK);
  put('quorum_n', deployment.quorumN);
  return overrides;
}

/**
 * Run `core_init` on an already-instantiated wasm-pack module and return the
 * `WasmCore` bridge.
 *
 * Exported so the real-WASM test harness can use the production initialisation
 * logic with a Node-target artefact (the loader above is browser/ESM shaped).
 * There is no test-specific behaviour here: the same call, config mapping and
 * error propagation run in production.
 */
export async function initialiseCore(
  mod: Record<string, unknown>,
  config?: InitConfig,
): Promise<WasmCore> {
  if (config !== undefined) {
    const coreInit = mod['core_init'];
    if (typeof coreInit !== 'function') {
      throw new Error(
        'tirbase-core WASM module is missing expected export: "core_init"',
      );
    }
    const deployment = config.deploymentConfig ?? {};
    const overrides = deploymentOverridesJson(deployment);
    await (
      coreInit as (
        storagePath: string,
        rootCaKeys: string[],
        migrationCaKey: string | null,
        schemaVersionPath: string[],
        deploymentJson: string | null,
      ) => Promise<void>
    )(
      config.storagePath,
      deployment.rootCaPublicKeys ?? [],
      deployment.migrationCaPublicKey ?? null,
      deployment.schemaVersionPath ?? [],
      Object.keys(overrides).length > 0 ? JSON.stringify(overrides) : null,
    );
  }
  return buildBridgeFromWasmModule(mod);
}

/**
 * Thin adapter that wraps the raw wasm-pack module exports into the
 * `WasmCore` interface.  The WASM module exports free functions whose
 * names match the #[wasm_bindgen] exports in lib.rs.
 */
/**
 * Normalise a trust-level string from the WASM module to the SDK's capitalised
 * `TrustLevel` union. `core_trust_level` returns the Rust `Debug` spelling
 * (`Unverified`), while `core_present_token` returns the uppercase union member.
 */
export function normalizeTrustLevel(raw: string): TrustLevel {
  const upper = raw.toUpperCase();
  if (upper === 'VERIFIED' || upper === 'REVOKED') return upper;
  return 'UNVERIFIED';
}

/**
 * Convert a WASM-boundary failure into a JavaScript `Error`.
 *
 * `#[wasm_bindgen]` functions returning `Result<_, JsValue>` throw the
 * `JsValue` itself; `to_js_err` builds it from the Rust error's `Display`
 * string, so callers would otherwise see a bare string rejection. The SDK's
 * contract is that failures surface as `Error` objects (with the core's
 * message preserved verbatim), so every export is wrapped once here.
 */
function asCoreError(failure: unknown): Error {
  if (failure instanceof Error) return failure;
  const error = new Error(String(failure));
  error.name = 'TirBaseCoreError';
  return error;
}

export function buildBridgeFromWasmModule(mod: Record<string, unknown>): WasmCore {
  function required(name: string): (...args: unknown[]) => unknown {
    if (typeof mod[name] !== 'function') {
      throw new Error(
        `tirbase-core WASM module is missing expected export: "${name}"`,
      );
    }
    return mod[name] as (...args: unknown[]) => unknown;
  }

  /** Call an export, normalising sync throws and async rejections. */
  function call(name: string, ...args: unknown[]): unknown {
    try {
      return required(name)(...args);
    } catch (failure) {
      throw asCoreError(failure);
    }
  }

  /** Call an async export, normalising sync throws and async rejections. */
  async function callAsync(name: string, ...args: unknown[]): Promise<unknown> {
    try {
      return await required(name)(...args);
    } catch (failure) {
      throw asCoreError(failure);
    }
  }

  return {
    read: (table, key) => callAsync('core_read', table, key),
    write: (table, key, data) => callAsync('core_write', table, key, data),
    query: (table, filter) =>
      callAsync('core_query', table, filter) as Promise<unknown[]>,
    trustLevel: () =>
      normalizeTrustLevel(call('core_trust_level') as string),
    localDid: () => call('core_local_did') as string,
    drainOutboundMessages: (linkCapacityBytes = 1_048_576) => {
      const frames = call(
        'core_drain_outbound_messages',
        linkCapacityBytes,
      ) as Array<Uint8Array>;
      return Array.from(frames ?? [], (frame) =>
        frame instanceof Uint8Array ? frame : new Uint8Array(frame),
      );
    },
    meshStatus: () => call('core_mesh_status') as MeshStatus,
    core_present_token: (token) =>
      callAsync('core_present_token', token) as Promise<TrustLevel>,
    initiateRevocation: (targetDid, managerToken) =>
      callAsync('core_initiate_revocation', targetDid, managerToken) as Promise<void>,
    revocationStatus: (targetDid) =>
      callAsync('core_revocation_status', targetDid) as Promise<RevocationStatus>,
    // wasm-bindgen represents Rust `i64` as JavaScript `BigInt`; passing a
    // number throws before the call reaches the core.
    verifyData: (rootDeltaId, managerToken, nowSecs) =>
      callAsync(
        'core_verify_data',
        rootDeltaId,
        managerToken,
        BigInt(nowSecs),
      ) as Promise<void>,
    adminClose: (incidentId, managerToken, nowSecs) =>
      callAsync(
        'core_admin_close_ico',
        incidentId,
        managerToken,
        BigInt(nowSecs),
      ) as Promise<void>,
    activateSaturateMode: (biscuitTokenHex) =>
      callAsync('core_activate_saturate_mode', biscuitTokenHex) as Promise<void>,
    renewSaturateMode: (biscuitTokenHex) =>
      callAsync('core_renew_saturate_mode', biscuitTokenHex) as Promise<void>,
    terminateSaturateMode: (terminationMessageHex, coManagerSignatures) =>
      callAsync(
        'core_terminate_saturate_mode',
        terminationMessageHex,
        coManagerSignatures,
      ) as Promise<void>,
    pollEvents: () =>
      typeof mod['core_poll_events'] === 'function'
        ? (call('core_poll_events') as unknown[])
        : [],
    ...(typeof mod['core_receive_peer_message'] === 'function'
      ? {
          receiveMessage: (rawBytes: Uint8Array) =>
            callAsync('core_receive_peer_message', rawBytes) as Promise<void>,
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

  /** Stub for `core_present_token`. Override in tests to simulate token verification results. */
  corePresentTokenImpl: (token: string) => Promise<TrustLevel> =
    async (_token: string) => 'VERIFIED';

  initiateRevocationImpl: (
    targetDid: string,
    managerToken: string,
  ) => Promise<void> = async () => undefined;

  revocationStatusImpl: (targetDid: string) => Promise<RevocationStatus> =
    async (_did) => ({
      signaturesCollected: 0,
      signaturesRequired: 2,
      status: 'PENDING',
      lastKnownTrustLevel: null,
      lastRevocationDeltaReceivedAt: null,
    });

  verifyDataImpl: (
    rootDeltaId: string,
    managerToken: string,
    nowSecs: number,
  ) => Promise<void> = async () => undefined;

  adminCloseImpl: (
    incidentId: string,
    managerToken: string,
    nowSecs: number,
  ) => Promise<void> = async () => undefined;

  activateSaturateModeImpl: (
    biscuitTokenHex: string,
  ) => Promise<void> = async () => undefined;

  renewSaturateModeImpl: (
    biscuitTokenHex: string,
  ) => Promise<void> = async () => undefined;

  terminateSaturateModeImpl: (
    terminationMessageHex: string,
    coManagerSignatures: SaturateManagerSignature[],
  ) => Promise<void> = async () => undefined;

  drainOutboundMessagesImpl: (linkCapacityBytes?: number) => Uint8Array[] =
    () => [];

  localDidImpl: () => string = () => 'did:key:zMockLocalDevice';

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

  core_present_token(token: string): Promise<TrustLevel> {
    return this.corePresentTokenImpl(token);
  }

  initiateRevocation(targetDid: string, managerToken: string): Promise<void> {
    return this.initiateRevocationImpl(targetDid, managerToken);
  }

  revocationStatus(targetDid: string): Promise<RevocationStatus> {
    return this.revocationStatusImpl(targetDid);
  }

  verifyData(rootDeltaId: string, managerToken: string, nowSecs: number): Promise<void> {
    return this.verifyDataImpl(rootDeltaId, managerToken, nowSecs);
  }

  adminClose(incidentId: string, managerToken: string, nowSecs: number): Promise<void> {
    return this.adminCloseImpl(incidentId, managerToken, nowSecs);
  }

  activateSaturateMode(
    biscuitTokenHex: string,
  ): Promise<void> {
    return this.activateSaturateModeImpl(biscuitTokenHex);
  }

  renewSaturateMode(biscuitTokenHex: string): Promise<void> {
    return this.renewSaturateModeImpl(biscuitTokenHex);
  }

  terminateSaturateMode(
    terminationMessageHex: string,
    coManagerSignatures: SaturateManagerSignature[],
  ): Promise<void> {
    return this.terminateSaturateModeImpl(
      terminationMessageHex,
      coManagerSignatures,
    );
  }

  drainOutboundMessages(linkCapacityBytes?: number): Uint8Array[] {
    return this.drainOutboundMessagesImpl(linkCapacityBytes);
  }

  localDid(): string {
    return this.localDidImpl();
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
