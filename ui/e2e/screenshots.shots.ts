import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test, type Browser, type Page } from '@playwright/test';
import { DEFAULT_STATE, HISTORY_STATE, PASSWORD, QUOTA_STATE, USER, login, setState } from './support.ts';

const OUT = join(import.meta.dirname, '.run', 'shots');
mkdirSync(OUT, { recursive: true });

type Theme = 'code' | 'code-light';
const SIZES = {
  desktop: { width: 1280, height: 900 },
  mobile: { width: 360, height: 780 },
} as const;

async function open(browser: Browser, size: keyof typeof SIZES, theme: Theme): Promise<Page> {
  const context = await browser.newContext({ viewport: SIZES[size], locale: 'de-DE', timezoneId: 'Europe/Berlin' });
  await context.addInitScript((id) => {
    localStorage.setItem('wai-theme', id);
  }, theme);
  return context.newPage();
}

test.beforeEach(() => {
  setState(DEFAULT_STATE);
});

for (const size of ['desktop', 'mobile'] as const) {
  for (const theme of ['code', 'code-light'] as const) {
    const name = `${size}-${theme === 'code' ? 'dark' : 'light'}`;

    test(`dashboard ${name}`, async ({ browser }) => {
      const page = await open(browser, size, theme);
      await login(page);
      await expect(page.getByText('Gemini OK')).toBeVisible();
      await page.waitForTimeout(500);
      await page.screenshot({ path: join(OUT, `dashboard-${name}.png`) });
      await page.context().close();
    });

    test(`detail ${name}`, async ({ browser }) => {
      const page = await open(browser, size, theme);
      await login(page);
      await page.getByRole('table').locator('tbody tr').nth(1).getByRole('button').click();
      await expect(page.getByText('Zusammenfassung des Batches')).toBeVisible();
      await page.waitForTimeout(500);
      await page.screenshot({ path: join(OUT, `detail-${name}.png`) });
      await page.context().close();
    });

    test(`banners ${name}`, async ({ browser }) => {
      setState({
        ...QUOTA_STATE(new Date(Date.now() + 300_000).toISOString()),
        quota: {
          ...(QUOTA_STATE('')['quota'] as Record<string, unknown>),
          retry_at: new Date(Date.now() + 300_000).toISOString(),
          last_error: 'Resource has been exhausted (e.g. check quota).',
        },
        runtime: HISTORY_STATE['runtime'],
      });
      const page = await open(browser, size, theme);
      await login(page);
      await expect(page.getByRole('alert').filter({ hasText: 'Quota erschöpft' })).toBeVisible();
      await page.waitForTimeout(500);
      await page.screenshot({ path: join(OUT, `banners-${name}.png`) });
      await page.context().close();
    });

    test(`login ${name}`, async ({ browser }) => {
      const page = await open(browser, size, theme);
      await page.goto('/login');
      await page.getByLabel('Benutzername').fill(USER);
      await page.getByLabel('Passwort').fill(`${PASSWORD}-wrong`);
      await page.getByRole('button', { name: 'Anmelden' }).click();
      await expect(page.getByRole('alert')).toBeVisible();
      await page.waitForTimeout(300);
      await page.screenshot({ path: join(OUT, `login-${name}.png`) });
      await page.context().close();
    });
  }
}

test('keyboard focus on the filter and on a row', async ({ browser }) => {
  const page = await open(browser, 'desktop', 'code');
  await login(page);
  await page.getByRole('radio', { name: 'Kritisch' }).focus();
  await page.keyboard.press('ArrowRight');
  await page.waitForTimeout(400);
  await page.screenshot({ path: join(OUT, 'focus-filter-dark.png'), clip: { x: 0, y: 250, width: 1280, height: 330 } });
  await page.getByRole('table').locator('tbody tr').nth(1).getByRole('button').focus();
  await page.screenshot({ path: join(OUT, 'focus-row-dark.png'), clip: { x: 0, y: 330, width: 1280, height: 330 } });
  await page.context().close();
});

test('toast after a failed refresh, and the empty and error states', async ({ browser }) => {
  const page = await open(browser, 'desktop', 'code');
  await login(page);
  await page.route('**/api/stats', (route) => route.fulfill({ status: 502, body: '{}' }));
  await page.getByRole('button', { name: 'Neu laden' }).click();
  await expect(page.getByText('Aktualisierung fehlgeschlagen')).toBeVisible();
  await page.waitForTimeout(400);
  await page.screenshot({ path: join(OUT, 'toast-dark.png') });
  await page.unroute('**/api/stats');
  await page.route('**/api/findings?*', (route) => route.fulfill({ status: 502, body: '{}' }));
  await page.getByRole('radio', { name: 'Hoch' }).check({ force: true });
  await expect(page.getByRole('heading', { name: 'Backend nicht erreichbar' })).toBeVisible();
  await page.screenshot({ path: join(OUT, 'error-state-dark.png') });
  await page.unroute('**/api/findings?*');
  await page.route('**/api/findings?*', (route) =>
    route.fulfill({ json: { findings: [], total: 0, limit: 30, offset: 0 } }),
  );
  await page.getByRole('radio', { name: 'Alle' }).first().check({ force: true });
  await expect(page.getByRole('heading', { name: 'Keine Findings' })).toBeVisible();
  await page.screenshot({ path: join(OUT, 'empty-state-dark.png') });
  await page.context().close();
});
