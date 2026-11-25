import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import {
  DEFAULT_STATE,
  HISTORY_STATE,
  HOSTILE,
  PASSWORD,
  QUOTA_STATE,
  USER,
  expectClean,
  login,
  setState,
  watch,
} from './support.ts';

test.beforeEach(() => {
  setState(DEFAULT_STATE);
});

async function pwned(page: Page): Promise<unknown> {
  return page.evaluate(() => (window as unknown as { __pwned?: unknown }).__pwned);
}

test.describe('login, session and logout', () => {
  test('a visitor without a session is sent to the login page, which loads under the CSP', async ({
    page,
    baseURL,
  }) => {
    const found = await watch(page);
    await page.goto('/');
    await expect(page).toHaveURL(/\/login\?next=%2F$/);
    await expect(page.getByRole('heading', { name: 'Wazuh AI Analyzer', level: 1 })).toBeVisible();
    await expect(page.getByLabel('Benutzername')).toBeFocused();
    // Fonts and styles of the login page came without a session: nothing was redirected.
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'code');
    expectClean(found, baseURL ?? '');
  });

  test('the CSP header allows exactly the hash of the theme script and nothing inline', async ({ request }) => {
    const response = await request.get('/login');
    const csp = response.headers()['content-security-policy'] ?? '';
    expect(csp).toMatch(/script-src 'self' 'sha256-[A-Za-z0-9+/]{43}='(;|$)/);
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).toContain("style-src 'self';");
    const html = await response.text();
    const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)];
    expect(scripts).toHaveLength(1);
  });

  test('a wrong password shows the remaining attempts, the right one opens the dashboard', async ({
    page,
    baseURL,
  }) => {
    const found = await watch(page);
    await page.goto('/login');
    await page.getByLabel('Benutzername').fill(USER);
    await page.getByLabel('Passwort').fill('wrong-password');
    await page.getByRole('button', { name: 'Anmelden' }).click();
    await expect(page.getByRole('alert')).toContainText('Falscher Benutzername oder Passwort');
    await page.getByLabel('Passwort').fill(PASSWORD);
    await page.getByRole('button', { name: 'Anmelden' }).click();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('table')).toBeVisible();
    // 401 on the failed login is an expected answer, not a page problem.
    expect(found.problems.filter((p) => !p.includes('401'))).toEqual([]);
    expect([...found.origins]).toEqual([new URL(baseURL ?? '').origin]);
  });

  test('login comes back to the page the visitor wanted, and only to a local one', async ({ page }) => {
    await page.goto('/login?next=%2Ffindings%2F3');
    await page.getByLabel('Benutzername').fill(USER);
    await page.getByLabel('Passwort').fill(PASSWORD);
    await page.getByRole('button', { name: 'Anmelden' }).click();
    await expect(page).toHaveURL(/\/findings\/3$/);
    // An SPA route is the dashboard.
    await expect(page.getByRole('table')).toBeVisible();

    await page.context().clearCookies();
    await page.goto('/login?next=https%3A%2F%2Fevil.example%2F');
    await page.getByLabel('Benutzername').fill(USER);
    await page.getByLabel('Passwort').fill(PASSWORD);
    await page.getByRole('button', { name: 'Anmelden' }).click();
    await expect(page).toHaveURL(/127\.0\.0\.1:\d+\/$/);
  });

  test('logout is a POST: the session is gone afterwards and the API answers 401', async ({ page }) => {
    await login(page);
    const posts: string[] = [];
    page.on('request', (request) => {
      if (request.method() !== 'GET') posts.push(`${request.method()} ${new URL(request.url()).pathname}`);
    });
    await page.getByRole('button', { name: 'Abmelden' }).click();
    await expect(page).toHaveURL(/\/login$/);
    expect(posts).toEqual(['POST /api/logout']);
    const stats = await page.request.get('/api/stats');
    expect(stats.status()).toBe(401);
    await page.goto('/');
    await expect(page).toHaveURL(/\/login\?next=%2F$/);
  });

  test('GET /logout only asks for confirmation; the button logs out', async ({ page }) => {
    await login(page);
    await page.goto('/logout');
    await expect(page.getByRole('heading', { name: 'Wirklich abmelden?' })).toBeVisible();
    expect((await page.request.get('/api/stats')).status()).toBe(200);
    await page.getByRole('button', { name: 'Abmelden' }).click();
    await expect(page).toHaveURL(/\/login$/);
    expect((await page.request.get('/api/stats')).status()).toBe(401);
  });

  test('an expired session ends in the login page, not in an empty dashboard', async ({ page }) => {
    await login(page);
    await page.context().clearCookies();
    await page.getByRole('button', { name: 'Neu laden' }).click();
    await expect(page).toHaveURL(/\/login/);
  });
});

test.describe('the dashboard', () => {
  test('shows every view of the old dashboard and stays clean under the CSP', async ({ page, baseURL }) => {
    const found = await watch(page);
    await login(page);
    await expect(page.getByText('Gemini OK')).toBeVisible();
    await expect(page.getByText('4 gepuffert')).toBeVisible();
    await expect(page.getByText('2 warten')).toBeVisible();
    await expect(page.getByText(/Letzte Analyse/)).toBeVisible();
    // Summary banner of the newest batch, marked as AI generated.
    const summary = page.getByRole('region', { name: /KI-Zusammenfassung/ });
    await expect(summary).toContainText('KI-generiert, nicht verifiziert');
    // Tiles per severity (66 + 1 findings: 67).
    const tiles = page.getByRole('list', { name: 'Findings nach Schweregrad' });
    await expect(tiles.getByRole('listitem')).toHaveCount(6);
    await expect(tiles).toContainText('67');
    // 30 rows per page, pagination with three pages.
    await expect(page.getByRole('table').locator('tbody tr')).toHaveCount(30);
    await expect(page.getByRole('navigation', { name: 'Seiten der Findings' })).toBeVisible();
    await expect(page.locator('#list-title')).toContainText('67 Einträge');
    expectClean(found, baseURL ?? '');
  });

  test('hostile text from the API is shown as text and never becomes markup or script', async ({
    page,
    baseURL,
  }) => {
    const found = await watch(page);
    await login(page);
    // The summary banner holds a hostile model summary.
    await expect(page.getByRole('region', { name: /KI-Zusammenfassung/ })).toContainText('<img src=x onerror=');
    // Finding #3 of the fixture has hostile title, texts, agents and rules: filter to its page.
    await page.getByRole('navigation', { name: 'Seiten der Findings' }).getByRole('button', { name: /3/ }).click();
    const hostileRow = page.getByRole('button', { name: new RegExp(HOSTILE.slice(0, 20).replace(/[<>]/g, '.')) });
    await hostileRow.first().click();
    const drawer = page.getByRole('dialog');
    await expect(drawer).toBeVisible();
    await expect(drawer).toContainText('<script>window.__pwned=2</script>');
    await expect(drawer).toContainText('KI-generiert, vor Umsetzung prüfen');
    expect(await page.locator('img[src="x"]').count()).toBe(0);
    expect(await pwned(page)).toBeUndefined();
    expectClean(found, baseURL ?? '');
  });

  test('the severity filter asks the server and the table shows only that level', async ({ page }) => {
    await login(page);
    const request = page.waitForRequest((r) => r.url().includes('severity=critical'));
    await page.getByRole('radio', { name: 'Kritisch' }).check({ force: true });
    expect(new URL((await request).url()).searchParams.get('offset')).toBe('0');
    const badges = page.getByRole('table').locator('tbody tr td:first-child');
    await expect(badges.first()).toContainText('Kritisch');
    for (const text of await badges.allTextContents()) expect(text).toContain('Kritisch');
    await expect(page.locator('#list-title')).toContainText('14 Einträge');
    await page.getByRole('radio', { name: 'Historisch' }).check({ force: true });
    await expect(page.getByRole('table').locator('tbody tr').first()).toContainText('Historisch');
    await page.getByRole('radio', { name: 'Alle' }).first().check({ force: true });
    await page.getByRole('radio', { name: 'Alle' }).last().check({ force: true });
    await expect(page.locator('#list-title')).toContainText('67 Einträge');
  });

  test('paging is server-side with offset and limit', async ({ page }) => {
    await login(page);
    const request = page.waitForRequest((r) => r.url().includes('offset=30'));
    await page.getByRole('navigation', { name: 'Seiten der Findings' }).getByRole('button', { name: /2/ }).first().click();
    const url = new URL((await request).url());
    expect(url.searchParams.get('limit')).toBe('30');
    await expect(page.getByRole('table').locator('tbody tr')).toHaveCount(30);
    await page.getByRole('navigation', { name: 'Seiten der Findings' }).getByRole('button', { name: /3/ }).first().click();
    await expect(page.getByRole('table').locator('tbody tr')).toHaveCount(7);
  });

  test('the detail opens in a drawer, shows the AI marks, closes with Escape and returns focus', async ({
    page,
  }) => {
    await login(page);
    const opener = page.getByRole('table').locator('tbody tr').nth(1).getByRole('button');
    await opener.focus();
    await page.keyboard.press('Enter');
    const drawer = page.getByRole('dialog');
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole('heading', { name: 'Handlungsempfehlung' })).toBeVisible();
    await expect(drawer).toContainText('Dieser Text stammt von einem KI-Modell und wurde nicht verifiziert.');
    await expect(drawer).toContainText('Betroffene Systeme');
    await expect(drawer).toContainText('Wazuh-Regel-IDs');
    // The batch summary comes from /api/findings/<id> and is marked too.
    await expect(drawer.getByText('Zusammenfassung des Batches')).toBeVisible();
    await expect(drawer.getByText('KI-generiert, nicht verifiziert')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(drawer).toBeHidden();
    await expect(opener).toBeFocused();
  });

  test('the quota banner counts down and never puts server text through markup', async ({ page, baseURL }) => {
    setState(QUOTA_STATE(new Date(Date.now() + 300_000).toISOString()));
    const found = await watch(page);
    await login(page);
    const banner = page.getByRole('alert').filter({ hasText: 'Quota erschöpft' });
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('<img src=x onerror=');
    await expect(banner).toContainText(/Nächster Versuch in\s*[0-4] min/);
    await expect(page.getByText('Quota leer')).toBeVisible();
    await expect(banner.getByRole('progressbar')).toBeVisible();
    expect(await pwned(page)).toBeUndefined();
    expectClean(found, baseURL ?? '');
  });

  test('the history banner shows the progress of the backlog scan', async ({ page }) => {
    setState(HISTORY_STATE);
    await login(page);
    const banner = page.getByRole('status').filter({ hasText: 'Historische Logs werden analysiert' });
    await expect(banner).toContainText('Datei 7 von 20 gescannt');
    await expect(banner.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '35');
  });

  test('reload re-reads the live state and announces it', async ({ page }) => {
    await login(page);
    await expect(page.getByText('4 gepuffert')).toBeVisible();
    setState({ ...DEFAULT_STATE, buffered: 9 });
    await page.getByRole('button', { name: 'Neu laden' }).click();
    await expect(page.getByText('9 gepuffert')).toBeVisible();
  });

  test('a backend error keeps the page usable and tells the user in a toast', async ({ page }) => {
    await login(page);
    await page.route('**/api/stats', (route) => route.fulfill({ status: 502, body: '{}' }));
    await page.getByRole('button', { name: 'Neu laden' }).click();
    await expect(page.getByText('Aktualisierung fehlgeschlagen')).toBeVisible();
    await expect(page.getByRole('table')).toBeVisible();
  });

  test('the theme toggle switches between dark and light and remembers the choice', async ({ page }) => {
    await login(page);
    const html = page.locator('html');
    await expect(html).toHaveAttribute('data-theme', 'code');
    await page.getByRole('button', { name: 'Dunkelmodus' }).click();
    await expect(html).toHaveAttribute('data-theme', 'code-light');
    await page.reload();
    await expect(html).toHaveAttribute('data-theme', 'code-light');
    await page.getByRole('button', { name: 'Dunkelmodus' }).click();
    await expect(html).toHaveAttribute('data-theme', 'code');
  });
});

test.describe('empty database', () => {
  test('is not an error: the empty state explains what happens next', async ({ page }) => {
    // Served by the same backend: an offset beyond the data (no filter) is the closest we
    // have without a second server, so use a filter that matches nothing instead.
    await login(page);
    await page.route('**/api/findings?*', (route) =>
      route.fulfill({ json: { findings: [], total: 0, limit: 30, offset: 0 } }),
    );
    await page.getByRole('button', { name: 'Neu laden' }).click();
    await expect(page.getByRole('heading', { name: 'Keine Findings' })).toBeVisible();
  });

  test('an unreachable findings endpoint shows the backend-unreachable state with a retry', async ({
    page,
  }) => {
    await login(page);
    await page.route('**/api/findings?*', (route) => route.fulfill({ status: 502, body: '{}' }));
    await page.getByRole('radio', { name: 'Hoch' }).check({ force: true });
    await expect(page.getByRole('heading', { name: 'Backend nicht erreichbar' })).toBeVisible();
    await page.unroute('**/api/findings?*');
    await page.getByRole('button', { name: 'Erneut versuchen' }).click();
    await expect(page.getByRole('table')).toBeVisible();
  });
});

test.describe('keyboard and mobile', () => {
  test('the skip link is the first stop and moves focus to the main content', async ({ page }) => {
    await login(page);
    await page.keyboard.press('Tab');
    const skip = page.getByRole('link', { name: /Zum Inhalt springen|Skip/ });
    await expect(skip).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('#main')).toBeFocused();
  });

  test('360 px: no horizontal scroll on the dashboard, the drawer or the login page', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 360, height: 740 }, locale: 'de-DE' });
    const page = await context.newPage();
    const overflow = (): Promise<number> =>
      page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    await page.goto('/login');
    expect(await overflow()).toBeLessThanOrEqual(0);
    await login(page);
    expect(await overflow()).toBeLessThanOrEqual(0);
    await page.getByRole('table').locator('tbody tr').first().getByRole('button').click();
    await expect(page.getByRole('dialog')).toBeVisible();
    expect(await overflow()).toBeLessThanOrEqual(0);
    await context.close();
  });

  test('360 px: long unbroken values wrap instead of widening the page', async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 360, height: 740 }, locale: 'de-DE' });
    const page = await context.newPage();
    await login(page);
    const pages = page.getByRole('navigation', { name: 'Seiten der Findings' });
    await pages.getByRole('button', { name: 'Weiter' }).click();
    await expect(page.getByText('Seite 2 von 3')).toBeVisible();
    await pages.getByRole('button', { name: 'Weiter' }).click();
    await expect(page.getByText('Seite 3 von 3')).toBeVisible();
    const listOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(listOverflow).toBeLessThanOrEqual(0);
    await page.getByRole('table').locator('tbody tr').nth(2).getByRole('button').click();
    const drawer = page.getByRole('dialog');
    await expect(drawer).toBeVisible();
    const pageOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(pageOverflow).toBeLessThanOrEqual(0);
    const widths = await drawer.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }));
    expect(widths.scroll).toBeLessThanOrEqual(widths.client);
    await context.close();
  });
});

test.describe('accessibility (axe, WCAG 2.2 AA rules)', () => {
  const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

  for (const theme of ['code', 'code-light']) {
    test(`login page, dashboard and drawer in ${theme}`, async ({ page }) => {
      await page.addInitScript((id) => {
        localStorage.setItem('wai-theme', id);
      }, theme);
      const scan = async (label: string): Promise<void> => {
        const result = await new AxeBuilder({ page }).withTags(TAGS).analyze();
        const summary = result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(' | ')}`);
        expect(summary, `${label} in ${theme}`).toEqual([]);
      };
      await page.goto('/login');
      await expect(page.getByLabel('Benutzername')).toBeVisible();
      await scan('login');
      await login(page);
      await scan('dashboard');
      await page.getByRole('table').locator('tbody tr').nth(1).getByRole('button').click();
      await expect(page.getByRole('dialog')).toBeVisible();
      await expect(page.getByText('Zusammenfassung des Batches')).toBeVisible();
      await scan('drawer');
    });
  }

  test('dashboard with both banners in dark', async ({ page }) => {
    setState({
      ...QUOTA_STATE(new Date(Date.now() + 300_000).toISOString()),
      runtime: HISTORY_STATE['runtime'],
    });
    await login(page);
    await expect(page.getByRole('alert').filter({ hasText: 'Quota erschöpft' })).toBeVisible();
    const result = await new AxeBuilder({ page }).withTags(TAGS).analyze();
    expect(result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(' | ')}`)).toEqual(
      [],
    );
  });
});
