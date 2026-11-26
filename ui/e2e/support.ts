import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, type Page } from '@playwright/test';

export const USER = 'admin';
export const PASSWORD = 'e2e-dummy-password-not-a-secret';
export const HOSTILE = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>"\'&amp;';
const STATE_FILE = join(import.meta.dirname, '.run', 'state.json');

export interface Watch {
  /** Every problem the CSP or the page reported. Must stay empty. */
  problems: string[];
  /** Origins of every request the page made. */
  origins: Set<string>;
}

/** Collects CSP violations, console errors, page errors and failed requests of a page. */
export async function watch(page: Page): Promise<Watch> {
  const found: Watch = { problems: [], origins: new Set() };
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (event) => {
      console.error(`CSP violation: ${event.violatedDirective} ${event.blockedURI}`);
    });
  });
  page.on('console', (message) => {
    if (message.type() === 'error' || message.type() === 'warning') {
      found.problems.push(`console ${message.type()}: ${message.text()}`);
    }
  });
  page.on('pageerror', (error) => found.problems.push(`page error: ${error.message}`));
  page.on('request', (request) => found.origins.add(new URL(request.url()).origin));
  page.on('requestfailed', (request) => {
    found.problems.push(`request failed: ${request.url()} ${request.failure()?.errorText ?? ''}`);
  });
  return found;
}

export function expectClean(found: Watch, baseURL: string): void {
  expect(found.problems).toEqual([]);
  expect([...found.origins]).toEqual([new URL(baseURL).origin]);
}

export async function login(page: Page): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Benutzername').fill(USER);
  await page.getByLabel('Passwort').fill(PASSWORD);
  await page.getByRole('button', { name: 'Anmelden' }).click();
  await expect(page.getByRole('table')).toBeVisible();
}

/** Changes what the fixture backend reports as live state (quota, history, buffer). */
export function setState(state: Record<string, unknown>): void {
  writeFileSync(STATE_FILE, JSON.stringify(state), 'utf8');
}

export const QUOTA_STATE = (retryAt: string): Record<string, unknown> => ({
  buffered: 12,
  quota: {
    exhausted: true,
    exhausted_since: new Date(Date.now() - 600_000).toISOString(),
    retry_at: retryAt,
    retry_in_seconds: 300,
    retry_count: 3,
    last_error: HOSTILE,
    last_success_at: null,
  },
  runtime: { history_done: true },
});

export const HISTORY_STATE: Record<string, unknown> = {
  buffered: 0,
  quota: { exhausted: false },
  runtime: { history_done: false, history_alerts: 4210, history_files_total: 20, history_files_done: 7 },
};

export const DEFAULT_STATE: Record<string, unknown> = {
  buffered: 4,
  quota: { exhausted: false },
  runtime: { history_done: true },
};
