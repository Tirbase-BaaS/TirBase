// SPDX-License-Identifier: Apache-2.0
import { expect, type Page, type Route } from '@playwright/test';
import { ADMIN_PATHS } from '@tirbase/gateway-admin-sdk';

type Row = {
  id: string;
  vertical: string;
  kind: string;
  tenant: string;
  parent_id: string | null;
  revision: number;
  created_est: number;
  updated_est: number;
  data: Record<string, unknown>;
};

type Store = {
  sites: Row[];
  readings: Row[];
  orders: Row[];
  lines: Row[];
  venues: Row[];
  gates: Row[];
};

const documented = ADMIN_PATHS.map(
  (template) =>
    new RegExp(`^${template.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\{id\\\}/g, '[^/]+')}$`),
);

/** Every request the console makes must match a documented OpenAPI path. */
export function assertDocumentedPath(pathname: string): void {
  expect(
    documented.some((pattern) => pattern.test(pathname)),
    `undocumented console request: ${pathname}`,
  ).toBe(true);
}

export async function installMockGateway(page: Page) {
  const store: Store = {
    sites: [],
    readings: [],
    orders: [],
    lines: [],
    venues: [],
    gates: [],
  };
  const requests: string[] = [];
  let sequence = 0;
  const now = 1_710_000_000;

  const object = (
    vertical: string,
    kind: string,
    data: Record<string, unknown>,
    parent: string | null = null,
    tenant = 'default',
  ): Row => {
    sequence += 1;
    return {
      id: `${kind.slice(0, -1)}-${sequence}`,
      vertical,
      kind,
      tenant,
      parent_id: parent,
      revision: 1,
      created_est: now + sequence,
      updated_est: now + sequence,
      data,
    };
  };

  const list = (rows: Row[]) => ({
    status: 200,
    vertical: rows[0]?.vertical ?? '',
    kind: rows[0]?.kind ?? '',
    tenant: rows[0]?.tenant ?? 'default',
    items: rows,
    total: rows.length,
    next_cursor: null,
  });

  async function handle(route: Route) {
    const request = route.request();
    const url = new URL(request.url());
    requests.push(url.pathname);
    assertDocumentedPath(url.pathname);
    const body =
      request.method() === 'GET' || request.method() === 'DELETE'
        ? {}
        : (request.postDataJSON() as Record<string, unknown>);
    const tenant = typeof body.tenant === 'string' ? body.tenant : url.searchParams.get('tenant') ?? 'default';
    const json = (status: number, payload: unknown) =>
      route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(payload) });

    const method = request.method();
    const pathname = url.pathname;

    if (pathname === '/admin/venues') {
      if (method === 'GET') return json(200, list(store.venues));
      if (method === 'POST') {
        const row = object('venues', 'venues', {
          name: String(body.name),
          capacity: body.capacity,
        }, null, tenant);
        store.venues.push(row);
        return json(201, { status: 201, object: row });
      }
    }

    const gateMatch = /^\/admin\/venues\/([^/]+)\/gates$/.exec(pathname);
    if (gateMatch) {
      const venueId = gateMatch[1]!;
      if (method === 'GET') return json(200, list(store.gates.filter((g) => g.parent_id === venueId)));
      if (method === 'POST') {
        const row = object('venues', 'gates', { name: String(body.name) }, venueId, tenant);
        store.gates.push(row);
        return json(201, { status: 201, object: row });
      }
    }

    const venueMatch = /^\/admin\/venues\/([^/]+)$/.exec(pathname);
    if (venueMatch && method === 'GET') {
      const venue = store.venues.find((row) => row.id === venueMatch[1]);
      return venue
        ? json(200, { status: 200, object: venue })
        : json(404, { status: 404, code: 'VERTICAL_NOT_FOUND', error: 'not found' });
    }

    const siteMatch = /^\/admin\/cold-chain\/sites$/.exec(pathname);
    if (siteMatch) {
      if (method === 'GET') return json(200, list(store.sites));
      if (method === 'POST') {
        const row = object('cold-chain', 'sites', { name: String(body.name) }, null, tenant);
        store.sites.push(row);
        return json(201, { status: 201, object: row });
      }
    }

    const readingMatch = /^\/admin\/cold-chain\/sites\/([^/]+)\/readings$/.exec(pathname);
    if (readingMatch) {
      const siteId = readingMatch[1]!;
      if (method === 'GET') return json(200, list(store.readings.filter((r) => r.parent_id === siteId)));
      if (method === 'POST') {
        const row = object('cold-chain', 'readings', { celsius_milli: Number(body.celsius_milli) }, siteId, tenant);
        store.readings.push(row);
        return json(201, { status: 201, object: row });
      }
    }

    if (pathname === '/admin/pos/orders') {
      if (method === 'GET') return json(200, list(store.orders));
      if (method === 'POST') {
        const row = object('pos', 'orders', {
          currency: String(body.currency),
          total_minor: Number(body.total_minor),
          status: 'open',
        }, null, tenant);
        store.orders.push(row);
        return json(201, { status: 201, object: row });
      }
    }

    const lineMatch = /^\/admin\/pos\/orders\/([^/]+)\/lines$/.exec(pathname);
    if (lineMatch) {
      const orderId = lineMatch[1]!;
      if (method === 'GET') return json(200, list(store.lines.filter((l) => l.parent_id === orderId)));
      if (method === 'POST') {
        const row = object('pos', 'lines', {
          sku: String(body.sku),
          quantity: Number(body.quantity),
          unit_price_minor: Number(body.unit_price_minor),
        }, orderId, tenant);
        store.lines.push(row);
        return json(201, { status: 201, object: row });
      }
    }

    return json(404, { status: 404, error: 'unknown mock endpoint' });
  }

  await page.route('**/admin/**', handle);
  return { store, requests };
}

export async function login(page: Page) {
  await page.goto('/');
  await page.getByLabel('Bearer token').fill('test-auditor-token');
  await page.getByRole('button', { name: 'Open console' }).click();
  await expect(page.getByRole('heading', { name: 'Cold chain', level: 1 })).toBeVisible();
}
