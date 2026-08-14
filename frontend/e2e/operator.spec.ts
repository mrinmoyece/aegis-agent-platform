import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: 'Start synthetic demo' }).click();
  await expect(page.getByRole('heading', { name: 'Health & SLOs' })).toBeVisible();
});

test('investigates cited evidence and preserves model uncertainty', async ({
  page,
}) => {
  await page.getByRole('link', { name: /Incident overview/ }).click();
  await expect(page.getByText('Synthetic deployment recorded')).toBeVisible();
  await expect(page.getByText('Pool saturation is causal')).toBeVisible();
  await expect(
    page.getByRole('definition').filter({ hasText: 'Model claim' }),
  ).toBeVisible();
  await expect(page.getByText(/conflicting evidence remains visible/i)).toBeVisible();
});

test('records an exact approval without false action success', async ({ page }) => {
  await page.getByRole('link', { name: /Approval inbox/ }).click();
  await page.getByRole('button', { name: 'Review exact scope' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText('Plan digest')).toBeVisible();
  await dialog.getByLabel(/Type APPROVE to confirm/).fill('APPROVE');
  await dialog.getByRole('button', { name: 'Record grant' }).click();
  await expect(dialog.getByText('Decision recorded')).toBeVisible();
  await expect(dialog.getByText(/Verification is pending/)).toBeVisible();
  await expect(dialog.getByText(/not an action-success signal/)).toBeVisible();
});

test('quarantines only the exact digest-pinned protocol peer', async ({ page }) => {
  await page.getByRole('link', { name: /MCP & A2A trust/ }).click();
  const peer = page
    .getByRole('article')
    .filter({ hasText: 'Curated MCP evidence server' });
  await expect(peer.getByText('Fails closed outside local demo')).toBeVisible();
  await peer.getByRole('button', { name: 'Review trust' }).click();

  const dialog = page.getByRole('dialog');
  const confirm = dialog.getByLabel(/Type peer-mcp-deterministic to confirm/);
  await expect(
    dialog.getByRole('button', { name: 'Record quarantine' }),
  ).toBeDisabled();
  await confirm.fill('peer-mcp-deterministic');
  await dialog.getByRole('button', { name: 'Record quarantine' }).click();

  await expect(
    page.getByRole('status').filter({ hasText: /is quarantined/ }),
  ).toContainText('Network effects remain independently verified');
});

test('remains operable at a narrow responsive viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('link', { name: /Controlled actions/ }).click();
  await expect(page.getByRole('heading', { name: 'Controlled actions' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('not success');
});
