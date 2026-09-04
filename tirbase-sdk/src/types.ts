/**
 * Core TypeScript types for the @tirbase/sdk public API.
 *
 * These types mirror the Rust public API surface in tirbase-core (Req 1.2, 1.5)
 * and are the canonical TypeScript representations of the WASM-exposed types.
 */

// ─── Trust Level ─────────────────────────────────────────────────────────────

/**
 * The trust state of a device's identity (Req 8.2, 2.4).
 *
 * - VERIFIED:   Device holds a valid Biscuit token within its Epoch.
 * - UNVERIFIED: Token has expired but no Revocation_Delta received;
 *               all operations carry an `unverifiedWarning`.
 * - REVOKED:    Device has been revoked; all Deltas from it are rejected.
 */
export type TrustLevel = 'VERIFIED' | 'UNVERIFIED' | 'REVOKED';

// ─── Durability Tier ─────────────────────────────────────────────────────────

/**
 * The durability tier of a committed set of Deltas (Req 14.1, 14.7).
 *
 * - UNCOMMITTED: Committed to local SQLite only.
 * - TIER1:       K peers returned signed Durability_Receipts spanning spatial diversity.
 * - TIER2:       The Cloud_Ledger has acknowledged the Delta set.
 */
export type DurabilityTier = 'UNCOMMITTED' | 'TIER1' | 'TIER2';

// ─── Mesh Status ─────────────────────────────────────────────────────────────

/** Connection state for the local mesh interface (Req 2.5). */
export type ConnectionStatus = 'connected' | 'connecting' | 'disconnected';

/**
 * Mesh connectivity status of the local device (Req 2.5).
 */
export interface MeshStatus {
  /** Overall connection state. */
  status: ConnectionStatus;
  /** Number of currently active mesh peers. */
  peerCount: number;
}

// ─── Warnings ─────────────────────────────────────────────────────────────────

/**
 * Delivered on every operation while a device's Trust_Level is UNVERIFIED (Req 8.4).
 */
export interface UnverifiedWarning {
  /** When the device first became UNVERIFIED. */
  unverifiedSince: Date;
}

// ─── Write / Read / Query Results ────────────────────────────────────────────

/**
 * Result returned from a successful write operation (Req 2.3).
 */
export interface WriteResult {
  /** Hex-encoded SHA-256 Delta ID. */
  deltaId: string;
  /** Durability tier at the time the write was acknowledged. */
  durabilityTier: DurabilityTier;
  /** Present when the device's Trust_Level is UNVERIFIED (Req 8.4). */
  unverifiedWarning?: UnverifiedWarning;
}

/**
 * Result returned from a read or query operation.
 */
export interface QueryResult {
  /** Table name. */
  table: string;
  /** Row key. */
  key: string;
  /** Row data as a plain object. */
  data: Record<string, unknown>;
  /** Present when the device's Trust_Level is UNVERIFIED (Req 8.4). */
  unverifiedWarning?: UnverifiedWarning;
  /** Whether this row is tagged CONTAMINATED by the Causal Contamination Engine. */
  contaminated: boolean;
}

// ─── Contamination / Incident types ──────────────────────────────────────────

/**
 * Discriminated union of the three supported taint sources (Req 10.1).
 */
export type TaintSource =
  | { type: 'DEVICE_REVOCATION'; revocationDeltaId: string }
  | { type: 'BAD_MIGRATION'; migrationId: string }
  | { type: 'HUMAN_REACTION'; triggeredByIncidentId: string };

/**
 * A Local Store row whose current value was derived from a contaminated Delta.
 */
export interface AffectedRow {
  table: string;
  rowKey: string;
  /** Hex-encoded Delta ID of the most recent contaminated Delta that set this row. */
  deltaId: string;
}

/**
 * An immutable audit record appended on VERIFY_DATA or ADMIN_CLOSE (Req 11.4).
 */
export interface AuditEntry {
  operation: 'VERIFY_DATA' | 'ADMIN_CLOSE';
  managerDid: string;
  utcTimestamp: Date;
  /** Hex-encoded Delta IDs (or incident ID for ADMIN_CLOSE). */
  affectedDeltaIds: string[];
}

/**
 * Aggregated record grouping all Deltas and rows involved in a single
 * contamination incident (Req 10.7).
 */
export interface IncidentContextObject {
  /** UUID v7 string. */
  id: string;
  state: 'OPEN' | 'CLOSED';
  taintSource: TaintSource;
  /** Hex-encoded contamination root Delta IDs. */
  contaminationRoots: string[];
  /** Number of distinct tables containing contaminated rows. */
  affectedTableCount: number;
  /** Total number of contaminated rows across all tables. */
  affectedRowCount: number;
  affectedRows: AffectedRow[];
  /** Present when this is a Composite_Incident_Instance (Req 10.5). */
  compositeOf?: string[];
  createdAt: Date;
  updatedAt: Date;
  auditLog: AuditEntry[];
}

// ─── Event payload types ──────────────────────────────────────────────────────

/**
 * Emitted whenever a Delta set moves to a new durability tier (Req 14.7).
 */
export interface DurabilityTierChangedEvent {
  /** Identifier for the Delta set. */
  deltaSetId: string;
  previousTier: DurabilityTier;
  newTier: DurabilityTier;
  timestamp: Date;
}

/**
 * Emitted whenever the local device's Trust_Level changes.
 */
export interface TrustLevelChangedEvent {
  previousLevel: TrustLevel;
  newLevel: TrustLevel;
  timestamp: Date;
}

// ─── Manager operations ───────────────────────────────────────────────────────

/**
 * Current state of a mesh-accumulated revocation for a target DID
 * (design §Manager Operations — mesh-accumulated signature model).
 *
 * `signaturesCollected` / `signaturesRequired` / `status` describe the
 * in-flight M-of-N accumulation. `lastKnownTrustLevel` and
 * `lastRevocationDeltaReceivedAt` are the Req 9.5 last-known device status:
 * both are `null` until a RevocationDelta for the target has been applied
 * (the subsystem has no record before that point).
 */
export interface RevocationStatus {
  signaturesCollected: number;
  signaturesRequired: number;
  status: 'PENDING' | 'APPLIED';
  /** Last-known TrustLevel of the target device (Req 9.5); null if no RevocationDelta has ever been applied for it. */
  lastKnownTrustLevel: TrustLevel | null;
  /** UTC microseconds of the last RevocationDelta receipt (Req 9.5); null if none. */
  lastRevocationDeltaReceivedAt: number | null;
}

// ─── Initialisation config ────────────────────────────────────────────────────

/**
 * Deployment-specific configuration matching Rust `DeploymentConfig`.
 */
export interface DeploymentConfig {
  /** Revocation threshold M (signatures required). */
  revocationM?: number;
  /** Revocation threshold N (total manager DIDs). */
  revocationN?: number;
  /** Biscuit token TTL in seconds (1h–24h). */
  biscuitTtlSecs?: number;
  /** Whether Anchor_Attested_Location subsystem is enabled. */
  anchorAttestedLocation?: boolean;
  /** Minimum distinct spatial tags required for Quorum. */
  spatialDiversityMin?: number;
  /** K-of-N quorum (K receipts required). */
  quorumK?: number;
  /** N candidate peers for quorum. */
  quorumN?: number;
}

/**
 * Configuration supplied to `TirBase.init()` (Req 2.2).
 */
export interface InitConfig {
  /** Path to the local SQLite database file (or IndexedDB key in browser). */
  storagePath: string;
  /** Optional deployment-specific settings. */
  deploymentConfig?: DeploymentConfig;
}

// ─── Error types ──────────────────────────────────────────────────────────────

/**
 * Thrown when `TirBase.init()` fails (Req 2.6).
 */
export class TirBaseInitError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'TirBaseInitError';
    this.code = code;
    // Maintain proper stack trace in V8
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TirBaseInitError);
    }
  }
}

/**
 * Thrown when an API call is made before `TirBase.init()` succeeds (Req 2.6).
 */
export class TirBaseNotInitializedError extends Error {
  constructor() {
    super('TirBase is not initialized. Call TirBase.init() first.');
    this.name = 'TirBaseNotInitializedError';
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TirBaseNotInitializedError);
    }
  }
}

// ─── Event map ────────────────────────────────────────────────────────────────

/**
 * Typed event map for the TirBase event emitter.
 * Each key is an event name; the value is the handler signature.
 */
export interface TirBaseEvents {
  'unverified-warning': (warning: UnverifiedWarning) => void;
  'trust-level-changed': (event: TrustLevelChangedEvent) => void;
  'durability-tier-changed': (event: DurabilityTierChangedEvent) => void;
  'incident-created': (ico: IncidentContextObject) => void;
  'incident-updated': (ico: IncidentContextObject) => void;
  'incident-closed': (ico: IncidentContextObject) => void;
}
