/**
 * @tirbase/sdk — public package entry point.
 *
 * Re-exports the `TirBase` class and all public types so that consumers
 * can import everything they need from a single location:
 *
 *   import { TirBase, TrustLevel, WriteResult } from '@tirbase/sdk';
 */

// ─── Main class ───────────────────────────────────────────────────────────────
export { TirBase } from './tirbase';

// ─── Types ────────────────────────────────────────────────────────────────────
export type {
  // Core operational types
  TrustLevel,
  DurabilityTier,
  ConnectionStatus,
  MeshStatus,
  UnverifiedWarning,
  WriteResult,
  QueryResult,

  // Contamination / Incident types
  TaintSource,
  AffectedRow,
  AuditEntry,
  IncidentContextObject,

  // Event payload types
  DurabilityTierChangedEvent,
  TrustLevelChangedEvent,

  // Manager types
  RevocationStatus,

  // Config types
  InitConfig,
  DeploymentConfig,

  // Event map (for typed event listener registration)
  TirBaseEvents,
} from './types';

// ─── Error classes (need value export, not just type) ─────────────────────────
export { TirBaseInitError, TirBaseNotInitializedError } from './types';

// ─── WASM bridge interface (for advanced users / testing) ─────────────────────
export type { WasmCore } from './wasm-bridge';
export { MockWasmCore } from './wasm-bridge';
