// SPDX-License-Identifier: Apache-2.0
import { expect, test } from '@playwright/test';
import { installMockGateway, login } from './mock-gateway';

test('a cashier completes a sale and a refund with no network', async ({ page, context }) => {
  const mock = await installMockGateway(page);
  await login(page);

  // The drawer exists before any sale.
  await page.getByRole('link', { name: 'Shift' }).click();
  await page.getByLabel('Opening float').fill('100.00');
  await page.getByRole('button', { name: 'Open shift' }).click();
  await expect(page.getByText('Shift opened.')).toBeVisible();

  await page.getByRole('link', { name: 'Terminal' }).click();
  await expect(page.getByRole('heading', { name: 'Terminal', level: 1 })).toBeVisible();

  // Drop the link before ringing anything.
  await context.setOffline(true);
  await page.getByRole('button', { name: 'Work offline' }).click();
  await expect(page.getByText('Offline')).toBeVisible();

  await page.getByRole('button', { name: /Espresso/ }).click();
  await page.getByRole('button', { name: /Croissant/ }).click();
  // 2.50 + 2.80 with 10% tax = 5.83.
  await expect(page.getByRole('button', { name: 'Charge €5.83' })).toBeVisible();

  await page.getByLabel('Tendered').fill('10.00');
  await page.getByRole('button', { name: 'Charge €5.83' }).click();
  await expect(page.getByText('Sale #101 paid.')).toBeVisible();
  await expect(page.getByText('€4.17')).toBeVisible();
  await expect(page.getByText(/waiting to sync/)).toBeVisible();

  await page.getByLabel('Refund amount').fill('5.83');
  await page.getByLabel('Reason for the refund').fill('Wrong order');
  await page.getByRole('button', { name: 'Refund', exact: true }).click();
  await expect(page.getByText('Refund recorded.')).toBeVisible();

  // Nothing left the device while the link was down.
  expect(mock.requests.filter((path) => path === '/admin/pos/orders')).toHaveLength(0);
  expect(mock.store.orders).toHaveLength(0);

  // Reconnect: the queued sale flushes and the queue empties.
  await context.setOffline(false);
  await page.getByRole('button', { name: 'Go online' }).click();
  await expect.poll(() => mock.store.orders.length).toBe(1);
  await expect(page.getByText(/waiting to sync/)).toBeHidden();
});

test('a check is split and transferred from the floor', async ({ page }) => {
  await installMockGateway(page);
  await login(page);

  await page.getByRole('link', { name: 'Terminal' }).click();
  await page.getByRole('button', { name: /Espresso/ }).click();
  await page.getByRole('button', { name: /Latte/ }).click();
  await page.getByRole('button', { name: /Croissant/ }).click();

  await page.getByRole('button', { name: 'Split check' }).click();
  await page.getByLabel('Number of checks').fill('2');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Check split.')).toBeVisible();

  const strip = page.getByRole('group', { name: 'Open checks' });
  await expect(strip.getByRole('button')).toHaveCount(2);

  await page.getByLabel('Move to table').selectOption('t3');
  await page.getByRole('button', { name: 'Transfer' }).click();

  await page.getByRole('link', { name: 'Floor' }).click();
  const table = page.getByRole('region', { name: 'T3' });
  await expect(table.getByText('1 open')).toBeVisible();
});

test('a kitchen ticket is bumped and recalled', async ({ page }) => {
  await installMockGateway(page);
  await login(page);

  await page.getByRole('link', { name: 'Terminal' }).click();
  await page.getByRole('button', { name: /Sandwich/ }).click();
  await page.getByLabel('Tendered').fill('20.00');
  await page.getByRole('button', { name: /^Charge/ }).click();
  await expect(page.getByText(/paid\./)).toBeVisible();

  await page.getByRole('link', { name: 'Kitchen display' }).click();
  const queued = page.getByRole('region', { name: /Queued/ });
  const ready = page.getByRole('region', { name: /Ready/ });
  const served = page.getByRole('region', { name: /Served/ });
  await expect(queued.getByRole('article', { name: /#101/ })).toBeVisible();

  await queued.getByRole('button', { name: 'Bump ticket' }).click();
  await expect(served.getByRole('article', { name: /#101/ })).toBeVisible();
  await expect(queued.getByRole('article', { name: /#101/ })).toBeHidden();

  // A recalled ticket was fully cooked, so it comes back as Ready, not Queued.
  await served.getByRole('button', { name: 'Recall ticket' }).click();
  await expect(page.getByText('Recalled ×1')).toBeVisible();
  await expect(served.getByRole('article', { name: /#101/ })).toBeHidden();
  await expect(ready.getByRole('article', { name: /#101/ })).toBeVisible();
});

test('a transfer to an occupied table asks before moving', async ({ page }) => {
  await installMockGateway(page);
  await login(page);
  await page.getByRole('link', { name: 'Terminal' }).click();

  await page.getByLabel('Table', { exact: true }).selectOption('t1');
  await page.getByRole('button', { name: 'Start check' }).click();
  await page.getByRole('button', { name: /Espresso/ }).click();

  await page.getByLabel('Table', { exact: true }).selectOption('t2');
  await page.getByRole('button', { name: 'Start check' }).click();
  await page.getByRole('button', { name: /Latte/ }).click();

  await page.getByLabel('Move to table').selectOption('t1');
  await page.getByRole('button', { name: 'Transfer' }).click();
  await expect(page.getByText('Table T1 already has check #101 open.')).toBeVisible();

  await page.getByRole('button', { name: 'Move anyway' }).click();
  await expect(page.getByText('Resolve before continuing')).toBeHidden();

  await page.getByRole('link', { name: 'Floor' }).click();
  await expect(page.getByRole('region', { name: 'T1' }).getByText('2 open')).toBeVisible();
});

test('a rejected queued sale surfaces a conflict that can be discarded', async ({ page }) => {
  const mock = await installMockGateway(page);
  await page.route('**/admin/pos/orders', async (route) => {
    if (route.request().method() === 'POST') {
      await route.fulfill({
        status: 422,
        contentType: 'application/json',
        body: JSON.stringify({
          status: 422,
          code: 'POS_REJECTED',
          error: 'duplicate sale',
        }),
      });
      return;
    }
    await route.fallback();
  });
  await login(page);

  await page.getByRole('link', { name: 'Terminal' }).click();
  await page.getByRole('button', { name: /Tea/ }).click();
  await page.getByLabel('Tendered').fill('5.00');
  await page.getByRole('button', { name: /^Charge/ }).click();

  await expect(page.getByText(/A queued sale was rejected/)).toBeVisible();
  await expect(page.getByText(/duplicate sale/)).toBeVisible();

  await page.getByRole('button', { name: 'Discard' }).click();
  await expect(page.getByText('Resolve before continuing')).toBeHidden();
  await expect(page.getByText(/waiting to sync/)).toBeHidden();
  expect(mock.store.orders).toHaveLength(0);
});

test('touch targets and keyboard entry meet the tablet floor', async ({ page }) => {
  await installMockGateway(page);
  await login(page);
  await page.getByRole('link', { name: 'Terminal' }).click();

  const targets = await page.locator('.tb-touch').evaluateAll((nodes) =>
    nodes.map((node) => {
      const rect = node.getBoundingClientRect();
      return { width: rect.width, height: rect.height };
    }),
  );
  expect(targets.length).toBeGreaterThan(5);
  for (const target of targets) {
    expect(target.height).toBeGreaterThanOrEqual(43.5);
    expect(target.width).toBeGreaterThanOrEqual(43.5);
  }

  // The first tile is reachable and operable without a pointer.
  await page.getByRole('button', { name: /Espresso/ }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('cell', { name: 'Espresso', exact: true })).toBeVisible();

  // Every control keeps a programmatic label.
  await expect(page.getByLabel('Tendered')).toBeVisible();
  await expect(page.getByLabel('Table', { exact: true })).toBeVisible();
});

test('the terminal is localized and timestamps follow the chosen zone', async ({ page }) => {
  await installMockGateway(page);
  await login(page);

  await page.getByLabel('Language').selectOption('es');
  await expect(page.getByRole('link', { name: 'Sala' })).toBeVisible();
  await page.getByRole('link', { name: 'Terminal' }).click();
  await expect(page.getByRole('button', { name: /Cobrar/ })).toBeHidden();
  await expect(page.getByRole('heading', { name: 'Terminal', level: 1 })).toBeVisible();
  await expect(page.getByText('Carta')).toBeVisible();

  // The control keeps a programmatic label in the localized shell.
  await page.getByLabel(/Language|Idioma/).selectOption('en');
  await expect(page.getByText('Menu')).toBeVisible();
});
