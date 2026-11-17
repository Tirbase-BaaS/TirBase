// SPDX-License-Identifier: Apache-2.0

// Typed client for the gateway's reporting audit surface. It talks through the
// generated Apache-2.0 SDK's documented HTTP methods only; no server code is
// imported. Endpoint contracts are in docs/reporting.md.

import { GatewayAdminClient } from '@tirbase/gateway-admin-sdk';
import type { ConsoleConfig } from './config';
import { ConsoleApiError } from './api';

export type ReportKind =
  | 'excursion_history'
  | 'quarantine_aging'
  | 'disposition'
  | 'calibration_due'
  | 'lot_traceability'
  | 'export_verification';

export type AlcoaCheck = { satisfied: boolean; detail: string };

export type AlcoaAssessment = {
  attributable: AlcoaCheck;
  legible: AlcoaCheck;
  contemporaneous: AlcoaCheck;
  original: AlcoaCheck;
  accurate: AlcoaCheck;
  complete: AlcoaCheck;
  consistent: AlcoaCheck;
  enduring: AlcoaCheck;
  available: AlcoaCheck;
};

export type SourceRef = { kind: string; id: string; digest: string };

export type ReportRow = {
  key: string;
  cells: Record<string, string>;
  sources: SourceRef[];
};

export type ReportSummary = {
  report_id: string;
  kind: ReportKind;
  tenant: string;
  generated_est: number;
  generated_by: string;
  row_count: number;
  content_sha256: string;
  alcoa_satisfied: boolean;
};

export type Report = ReportSummary & {
  range: [number, number] | null;
  columns: string[];
  rows: ReportRow[];
  totals: Record<string, string>;
  sources: SourceRef[];
  alcoa: AlcoaAssessment;
};

export type EsignSignature = {
  signature_id: string;
  ceremony_id: string;
  report_id: string;
  signer_id: string;
  reason: string;
  record_sha256: string;
  nonce: string;
  signed_est: number;
  signature: string;
  signer_public_key: string;
};

export type AuditEntry = {
  seq: number;
  prev_hash: string;
  entry_hash: string;
  at_est: number;
  actor_did: string;
  action: string;
  subject: string;
  detail: unknown;
};

export type AuditVerification = {
  valid: boolean;
  entries: number;
  head_hash: string;
  reasons: string[];
};

type Result<T> = {
  status: number;
  items?: T[];
  report?: T;
  signatures?: EsignSignature[];
  entries?: AuditEntry[];
  verification?: AuditVerification;
  error?: { error?: string; code?: string };
};

export class AuditApi {
  private readonly client: GatewayAdminClient;

  constructor(config: Pick<ConsoleConfig, 'baseUrl' | 'token'>) {
    this.client = new GatewayAdminClient({
      baseUrl: config.baseUrl,
      token: config.token || undefined,
    });
  }

  private unwrap<T>(result: { ok: boolean; status: number; data?: T; error?: { code?: string; error?: string } }): T {
    if (result.ok && result.data !== undefined) return result.data as T;
    throw new ConsoleApiError(
      result.error?.error ?? `Admin API returned ${result.status}`,
      result.status,
      result.error?.code,
    );
  }

  async listReports(tenant: string, kind?: ReportKind, limit = 50): Promise<ReportSummary[]> {
    const result = await this.client.get<Result<ReportSummary>>('/admin/reporting/reports', {
      tenant,
      kind,
      limit,
    });
    return this.unwrap(result).items ?? [];
  }

  async getReport(reportId: string): Promise<Report> {
    const result = await this.client.get<Result<Report>>(
      `/admin/reporting/reports/${encodeURIComponent(reportId)}`,
    );
    return this.unwrap(result).report as Report;
  }

  async listSignatures(reportId: string): Promise<EsignSignature[]> {
    const result = await this.client.get<Result<never>>(
      `/admin/reporting/reports/${encodeURIComponent(reportId)}/signatures`,
    );
    return this.unwrap(result).signatures ?? [];
  }

  async listAudit(limit = 50): Promise<AuditEntry[]> {
    const result = await this.client.get<Result<never>>('/admin/reporting/audit', { limit });
    return this.unwrap(result).entries ?? [];
  }

  async verifyAuditChain(): Promise<AuditVerification> {
    const result = await this.client.get<Result<never>>('/admin/reporting/audit/verify');
    return this.unwrap(result).verification as AuditVerification;
  }
}
