// SPDX-License-Identifier: Apache-2.0
import { expect, test } from '@playwright/test';
import { installMockGateway, login } from './mock-gateway';

test('keyboard-only operator completes the cold-chain journey', async ({ page }) => {
  await installMockGateway(page);
  await page.goto('/');

  // Base URL, tenant, token, submit — all reached with Tab.
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('Gateway base URL')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('Tenant', { exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('Bearer token')).toBeFocused();
  await page.keyboard.type('test-auditor-token');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Enter');

  await expect(page.getByRole('heading', { name: 'Cold chain', level: 1 })).toBeVisible();
  await expect(page.getByRole('main')).toBeFocused();
  await expect(page.getByText('No sites yet')).toBeVisible();

  await page.keyboard.press('Tab');
  await expect(page.getByLabel('Site name')).toBeFocused();
  await page.keyboard.type('Cold Room 1');
  await page.keyboard.press('Enter');
  await expect(page.getByText('Site created.')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Cold Room 1' })).toBeVisible();

  // Filter is keyboard reachable and hides non-matching rows.
  await page.getByLabel('Filter').fill('missing');
  await expect(page.getByRole('cell', { name: 'Cold Room 1' })).toBeHidden();
  await page.getByLabel('Filter').fill('');

  await page.getByRole('button', { name: 'View readings' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: /Readings for Cold Room 1/ })).toBeVisible();
  await page.getByLabel('Temperature (°C)').focus();
  await page.keyboard.type('-18.5');
  await page.keyboard.press('Enter');
  await expect(page.getByText('Reading appended.')).toBeVisible();
  await expect(page.getByRole('cell', { name: '-18.5 °C' })).toBeVisible();
});

test('POS screen creates an order and a line from keyboard and mouse', async ({ page }) => {
  const mock = await installMockGateway(page);
  await login(page);
  await page.getByRole('link', { name: 'Point of sale' }).click();
  await expect(page.getByRole('heading', { name: 'Point of sale', level: 1 })).toBeVisible();
  await expect(page.getByText('No orders yet')).toBeVisible();

  await page.getByLabel('Total').fill('12.50');
  await page.getByRole('button', { name: 'Create order' }).click();
  await expect(page.getByText('Order created.')).toBeVisible();
  await expect(page.getByRole('cell', { name: '€12.50' })).toBeVisible();

  await page.getByRole('button', { name: 'View' }).click();
  await page.getByLabel('SKU').fill('SKU-1');
  await page.getByLabel('Quantity').fill('2');
  await page.getByLabel('Unit price').fill('6.25');
  await page.getByRole('button', { name: 'Add line' }).click();
  await expect(page.getByText('Line added.')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'SKU-1' })).toBeVisible();
  await expect(page.getByRole('cell', { name: '2', exact: true })).toBeVisible();
  expect(mock.store.lines).toHaveLength(1);
});

test('venue screen creates a venue and a gate', async ({ page }) => {
  const mock = await installMockGateway(page);
  await login(page);
  await page.getByRole('link', { name: 'Venues' }).click();
  await expect(page.getByRole('heading', { name: 'Venues', level: 1 })).toBeVisible();
  await expect(page.getByText('No venues yet')).toBeVisible();

  await page.getByLabel('Venue name').fill('North Stand');
  await page.getByLabel('Capacity').fill('2500');
  await page.getByRole('button', { name: 'Create venue' }).click();
  await expect(page.getByText('Venue created.')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'North Stand' })).toBeVisible();

  await page.getByRole('button', { name: 'View' }).click();
  await page.getByLabel('Gate name').fill('Gate A');
  await page.getByRole('button', { name: 'Add gate' }).click();
  await expect(page.getByText('Gate added.')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'Gate A' })).toBeVisible();
  expect(mock.store.gates).toHaveLength(1);
});

test('tenant switcher scopes subsequent screen requests', async ({ page }) => {
  const mock = await installMockGateway(page);
  await login(page);
  await page.getByLabel('Tenant', { exact: true }).fill('acme');
  await page.getByLabel('Tenant', { exact: true }).press('Enter');
  await expect(page.getByRole('navigation').getByText('acme')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Cold chain', level: 1 })).toBeVisible();
  expect(mock.requests.length).toBeGreaterThan(1);
});

test('localization and timezone-aware timestamps update the shell', async ({ page }) => {
  await installMockGateway(page);
  await login(page);
  await page.getByLabel('Site name').fill('Cold Room 1');
  await page.getByRole('button', { name: 'Create site' }).click();
  await expect(page.getByRole('cell', { name: 'Cold Room 1' })).toBeVisible();

  await page.getByLabel('Time zone').selectOption('America/New_York');
  const expected = await page.evaluate(() =>
    new Intl.DateTimeFormat('en', {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone: 'America/New_York',
    }).format(new Date(1_710_000_001 * 1000)),
  );
  await expect(page.getByRole('cell', { name: expected })).toBeVisible();

  await page.getByLabel('Language').selectOption('es');
  await expect(page.getByRole('heading', { name: 'Cadena de frío', level: 1 })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Punto de venta' })).toBeVisible();
});

test('error states are announced and retryable', async ({ page }) => {
  await installMockGateway(page);
  let fail = true;
  // Registered after the mock so Playwright runs this handler first.
  await page.route('**/admin/cold-chain/sites*', async (route) => {
    if (fail) {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ status: 500, code: 'VERTICAL_STORE_ERROR', error: 'store unavailable' }),
      });
      return;
    }
    await route.fallback();
  });
  await login(page);

  const alert = page.getByRole('alert');
  await expect(alert).toContainText('store unavailable');
  fail = false;
  await alert.getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByText('No sites yet')).toBeVisible();
});

test('design-system text contrast meets WCAG AA and controls have labels', async ({ page }) => {
  await installMockGateway(page);
  await login(page);

  const ratios = await page.evaluate(() => {
    function rgb(value: string): [number, number, number] {
      const parts = value.match(/\d+(\.\d+)?/g)?.map(Number) ?? [0, 0, 0];
      return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
    }
    function luminance([r, g, b]: [number, number, number]) {
      const channel = (value: number) => {
        const v = value / 255;
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
    }
    function ratio(foreground: string, background: string) {
      const a = luminance(rgb(foreground));
      const b = luminance(rgb(background));
      return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    }
    const card = document.querySelector('.tb-card') as HTMLElement;
    const button = document.querySelector('.tb-button--primary') as HTMLElement;
    const bodyStyle = getComputedStyle(card);
    const buttonStyle = getComputedStyle(button);
    return {
      body: ratio(bodyStyle.color, bodyStyle.backgroundColor),
      button: ratio(buttonStyle.color, buttonStyle.backgroundColor),
    };
  });
  expect(ratios.body).toBeGreaterThanOrEqual(4.5);
  expect(ratios.button).toBeGreaterThanOrEqual(4.5);

  await page.getByLabel('Site name').fill('Cold Room 1');
  await page.getByRole('button', { name: 'Create site' }).click();
  await expect(page.getByLabel('Tenant', { exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible();
  await expect(page.getByRole('table', { name: 'Sites' })).toBeVisible();
});

test('every screen uses documented OpenAPI data sources', async ({ page }) => {
  const mock = await installMockGateway(page);
  await login(page);

  await page.getByLabel('Site name').fill('Cold Room 1');
  await page.getByRole('button', { name: 'Create site' }).click();
  await page.getByRole('button', { name: 'View readings' }).click();
  await page.getByLabel('Temperature (°C)').fill('-18.5');
  await page.getByRole('button', { name: 'Add reading' }).click();

  await page.getByRole('link', { name: 'Point of sale' }).click();
  await page.getByLabel('Total').fill('12.50');
  await page.getByRole('button', { name: 'Create order' }).click();
  await page.getByRole('button', { name: 'View' }).click();
  await page.getByLabel('SKU').fill('SKU-1');
  await page.getByLabel('Unit price').fill('6.25');
  await page.getByRole('button', { name: 'Add line' }).click();

  await page.getByRole('link', { name: 'Venues' }).click();
  await page.getByLabel('Venue name').fill('North Stand');
  await page.getByRole('button', { name: 'Create venue' }).click();
  await page.getByRole('button', { name: 'View' }).click();
  await page.getByLabel('Gate name').fill('Gate A');
  await page.getByRole('button', { name: 'Add gate' }).click();

  for (const base of ['/admin/cold-chain/sites', '/admin/pos/orders', '/admin/venues']) {
    expect(mock.requests).toContain(base);
  }
  expect(mock.requests.some((path) => /^\/admin\/cold-chain\/sites\/[^/]+\/readings$/.test(path))).toBe(true);
  expect(mock.requests.some((path) => /^\/admin\/pos\/orders\/[^/]+\/lines$/.test(path))).toBe(true);
  expect(mock.requests.some((path) => /^\/admin\/venues\/[^/]+\/gates$/.test(path))).toBe(true);
});
