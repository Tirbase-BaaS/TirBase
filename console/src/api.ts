// SPDX-License-Identifier: Apache-2.0

// Thin adapter over the Apache-2.0 generated gateway SDK. The console imports
// no upstream server implementation; this module is the only data source for
// screens and talks only through the generated OpenAPI client.
import { GatewayAdminClient } from '@tirbase/gateway-admin-sdk';
import type { ConsoleConfig } from './config';

export type VerticalObject<T> = {
  id: string;
  vertical: string;
  kind: string;
  tenant: string;
  parent_id?: string | null;
  revision: number;
  created_est: number;
  updated_est: number;
  data: T;
};

type ObjectEnvelope<T> = {
  status: number;
  idempotent_replay?: boolean;
  object: VerticalObject<T>;
};

type ObjectList<T> = {
  status: number;
  vertical: string;
  kind: string;
  tenant: string;
  items: VerticalObject<T>[];
  total: number;
  next_cursor?: string | null;
};

export type Site = VerticalObject<{ name: string }>;
export type Reading = VerticalObject<{ celsius_milli: number; recorded_est?: number }>;
export type Order = VerticalObject<{
  currency: string;
  total_minor: number;
  status?: string;
}>;
export type OrderLine = VerticalObject<{
  sku: string;
  quantity: number;
  unit_price_minor: number;
}>;
export type Venue = VerticalObject<{ name: string; capacity?: number }>;
export type Gate = VerticalObject<{ name: string; opens_at_est?: number }>;

export class ConsoleApiError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'ConsoleApiError';
    this.status = status;
    this.code = code;
  }
}

export type ConsoleApiLike = Pick<
  ConsoleApi,
  | 'listSites'
  | 'createSite'
  | 'listReadings'
  | 'createReading'
  | 'listOrders'
  | 'createOrder'
  | 'listLines'
  | 'createLine'
  | 'listVenues'
  | 'createVenue'
  | 'listGates'
  | 'createGate'
>;

const PAGE_SIZE = 200;

export class ConsoleApi implements ConsoleApiLike {
  private readonly client: GatewayAdminClient;

  constructor(config: Pick<ConsoleConfig, 'baseUrl' | 'token'>) {
    this.client = new GatewayAdminClient({
      baseUrl: config.baseUrl,
      token: config.token || undefined,
    });
  }

  private unwrap<T>(result: {
    ok: boolean;
    status: number;
    data?: T;
    error?: { code?: string; error?: string };
  }): T {
    if (result.ok && result.data !== undefined) return result.data;
    throw new ConsoleApiError(
      result.error?.error ?? `Admin API returned ${result.status}`,
      result.status,
      result.error?.code,
    );
  }

  async listSites(tenant: string): Promise<ObjectList<Site['data']>> {
    return this.unwrap(
      await this.client.listColdChainSites({ tenant, limit: PAGE_SIZE }),
    ) as ObjectList<Site['data']>;
  }

  async createSite(tenant: string, name: string): Promise<Site> {
    const result = this.unwrap(
      await this.client.createColdChainSite({ tenant, name }),
    ) as ObjectEnvelope<Site['data']>;
    return result.object as Site;
  }

  async listReadings(tenant: string, siteId: string): Promise<ObjectList<Reading['data']>> {
    return this.unwrap(
      await this.client.listColdChainReadings(siteId, {
        tenant,
        limit: PAGE_SIZE,
      }),
    ) as ObjectList<Reading['data']>;
  }

  async createReading(
    tenant: string,
    siteId: string,
    celsiusMilli: number,
  ): Promise<Reading> {
    const result = this.unwrap(
      await this.client.createColdChainReading(siteId, {
        tenant,
        celsius_milli: celsiusMilli,
      }),
    ) as ObjectEnvelope<Reading['data']>;
    return result.object as Reading;
  }

  async listOrders(tenant: string): Promise<ObjectList<Order['data']>> {
    return this.unwrap(
      await this.client.listPosOrders({ tenant, limit: PAGE_SIZE }),
    ) as ObjectList<Order['data']>;
  }

  async createOrder(
    tenant: string,
    currency: string,
    totalMinor: number,
  ): Promise<Order> {
    const result = this.unwrap(
      await this.client.createPosOrder({ tenant, currency, total_minor: totalMinor }),
    ) as ObjectEnvelope<Order['data']>;
    return result.object as Order;
  }

  async listLines(tenant: string, orderId: string): Promise<ObjectList<OrderLine['data']>> {
    return this.unwrap(
      await this.client.listPosLines(orderId, { tenant, limit: PAGE_SIZE }),
    ) as ObjectList<OrderLine['data']>;
  }

  async createLine(
    tenant: string,
    orderId: string,
    line: { sku: string; quantity: number; unit_price_minor: number },
  ): Promise<OrderLine> {
    const result = this.unwrap(
      await this.client.createPosLine(orderId, { tenant, ...line }),
    ) as ObjectEnvelope<OrderLine['data']>;
    return result.object as OrderLine;
  }

  async listVenues(tenant: string): Promise<ObjectList<Venue['data']>> {
    return this.unwrap(
      await this.client.listVenues({ tenant, limit: PAGE_SIZE }),
    ) as ObjectList<Venue['data']>;
  }

  async createVenue(
    tenant: string,
    venue: { name: string; capacity?: number },
  ): Promise<Venue> {
    const result = this.unwrap(
      await this.client.createVenue({ tenant, ...venue }),
    ) as ObjectEnvelope<Venue['data']>;
    return result.object as Venue;
  }

  async listGates(tenant: string, venueId: string): Promise<ObjectList<Gate['data']>> {
    return this.unwrap(
      await this.client.listVenueGates(venueId, { tenant, limit: PAGE_SIZE }),
    ) as ObjectList<Gate['data']>;
  }

  async createGate(tenant: string, venueId: string, name: string): Promise<Gate> {
    const result = this.unwrap(
      await this.client.createVenueGate(venueId, { tenant, name }),
    ) as ObjectEnvelope<Gate['data']>;
    return result.object as Gate;
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof ConsoleApiError) {
    return `${error.message} (${error.status}${error.code ? ` ${error.code}` : ''})`;
  }
  if (error instanceof Error) return error.message;
  return String(error);
}
