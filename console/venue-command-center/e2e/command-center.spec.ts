// SPDX-License-Identifier: Apache-2.0
import { expect, test } from '@playwright/test';

async function selectRole(page: import('@playwright/test').Page, role: string, actor: string) {
  await page.getByTestId('role-select').selectOption(role);
  await expect(page.locator('#actor-label')).toHaveText(actor);
}

async function commandLockdown(page: import('@playwright/test').Page, reason: string) {
  await page.getByTestId('lockdown-reason').fill(reason);
  await page.getByTestId('approver-custodian-1').check();
  await page.getByTestId('approver-custodian-2').check();
  await page.getByTestId('request-lockdown').click();
}

test('operator acknowledges, dispatches and attributes an incident', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByTestId('mode-banner')).toContainText('LIVE VENUE');
  await selectRole(page, 'operator', 'ops-1');

  const incident = page.getByTestId('incident-inc-1');
  await expect(page.getByTestId('status-inc-1')).toHaveText('open');
  await incident.locator('[data-note-for="inc-1"]').fill('Steward team sent to the turnstiles.');
  await page.getByTestId('inc-1-acknowledge').click();
  await expect(page.getByTestId('status-inc-1')).toHaveText('acknowledged');

  await incident
    .locator('[data-note-for="inc-1"]')
    .fill('North response team, two stewards.');
  await page.getByTestId('inc-1-dispatch').click();
  await expect(page.getByTestId('status-inc-1')).toHaveText('dispatched');

  await expect(page.getByTestId('incident-inc-1')).toContainText('ops-1');
  await expect(page.getByTestId('audit-list')).toContainText('incident.dispatch');
  await expect(page.getByTestId('audit-list')).toContainText('ops-1');
});

test('supervisor initiates and releases a lockdown with two approvals', async ({ page }) => {
  await page.goto('/');
  await selectRole(page, 'supervisor', 'sup-1');

  await commandLockdown(page, 'Smoke reported in the north service corridor');
  await expect(page.getByTestId('lockdown-active')).toContainText('venue:venue-1 locked');
  await expect(page.getByTestId('gate-gate-n1')).toHaveAttribute('data-posture', 'locked');
  await expect(page.getByTestId('audit-list')).toContainText('lockdown.engaged');
  await expect(page.getByTestId('audit-list')).toContainText('custodian-1, custodian-2');

  await page.getByTestId('release-lockdown').click();
  await expect(page.getByTestId('lockdown-active')).toBeEmpty();
  await expect(page.getByTestId('gate-gate-n1')).toHaveAttribute('data-posture', 'normal');
  await expect(page.getByTestId('audit-list')).toContainText('lockdown.released');
});

test('drill lockdown is isolated and the after-action report proves live gates unchanged', async ({
  page,
}) => {
  await page.goto('/');
  await selectRole(page, 'safety_officer', 'safety-1');

  await page.getByTestId('start-drill').click();
  await expect(page.getByTestId('mode-banner')).toContainText('DRILL MODE');
  await commandLockdown(page, 'Drill: simulated smoke event');
  await expect(page.getByTestId('lockdown-active')).toContainText('locked');
  await expect(page.getByTestId('gate-gate-n1')).toHaveAttribute('data-posture', 'locked');

  await page.getByTestId('end-drill').click();
  await expect(page.getByTestId('mode-banner')).toContainText('LIVE VENUE');
  await expect(page.getByTestId('gate-gate-n1')).toHaveAttribute('data-posture', 'normal');
  await expect(page.getByTestId('lockdown-active')).toBeEmpty();
  await expect(page.getByTestId('reports')).toContainText('Drill completed');
  await expect(page.getByTestId('drill-safety')).toContainText('unchanged');
});

test('auditor gets a read-only view with the audit trail', async ({ page }) => {
  await page.goto('/');
  await selectRole(page, 'auditor', 'auditor-1');

  await expect(page.getByTestId('role-note')).toContainText('Read-only auditor view');
  await expect(page.getByTestId('request-lockdown')).toBeDisabled();
  await expect(page.getByTestId('release-lockdown')).toBeDisabled();
  await expect(page.getByTestId('start-drill')).toBeDisabled();
  await expect(page.getByTestId('incidents')).toContainText('Read-only role');
  await expect(page.getByTestId('audit-list')).toContainText('ops-1');
});
