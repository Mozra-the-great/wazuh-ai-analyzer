import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { Dashboard, PAGE_SIZE } from './dashboard.svelte.ts';

type Routes = Record<string, () => Response>;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function finding(id: number): Record<string, unknown> {
  return { id, batch_id: id, title: `T${id}`, severity: 'high', source: 'live', affected_agents: [], rule_ids: [] };
}

const STATS = { total_findings: 70, by_severity: { high: 70 }, gemini_ok: true, quota: {}, history: {} };

function install(routes: Routes): { calls: string[]; assign: Mock<(url: string) => void> } {
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? 'GET'} ${path}`);
      const key = Object.keys(routes).find((prefix) => path.startsWith(prefix));
      const route = key === undefined ? undefined : routes[key];
      return Promise.resolve(route === undefined ? json(404, {}) : route());
    }),
  );
  return { calls, assign: vi.fn<(url: string) => void>() };
}

const baseRoutes: Routes = {
  '/api/session': () => json(200, { authenticated: true, csrf_token: 'csrf-1' }),
  '/api/stats': () => json(200, STATS),
  '/api/batches': () => json(200, []),
  '/api/findings?': () => json(200, { findings: [finding(1), finding(2)], total: 70, limit: PAGE_SIZE, offset: 0 }),
  '/api/findings/': () => json(200, { ...finding(1), batch_summary: 'sum', alert_count: 7 }),
  '/api/logout': () => json(200, { ok: true }),
};

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('Dashboard', () => {
  it('loads stats, summary and the first page after the session check', async () => {
    const { calls, assign } = install(baseRoutes);
    const dash = new Dashboard({ assign });
    await dash.start();
    dash.stop();
    expect(calls[0]).toBe('GET /api/session');
    expect(calls).toContain('GET /api/stats');
    expect(calls).toContain(`GET /api/findings?limit=${PAGE_SIZE}&offset=0`);
    expect(dash.listState).toBe('ready');
    expect(dash.total).toBe(70);
    expect(dash.pageCount).toBe(3);
    expect(assign).not.toHaveBeenCalled();
  });

  it('goes to the login page without a session', async () => {
    const { calls, assign } = install({
      ...baseRoutes,
      '/api/session': () => json(200, { authenticated: false, csrf_token: 'pre' }),
    });
    const dash = new Dashboard({ assign });
    await dash.start();
    expect(assign).toHaveBeenCalledWith('/login');
    expect(calls).not.toContain('GET /api/stats');
  });

  it('goes to the login page when the API answers 401', async () => {
    const { assign } = install({ ...baseRoutes, '/api/stats': () => json(401, { error: 'Unauthorized' }) });
    const dash = new Dashboard({ assign });
    await dash.start();
    dash.stop();
    expect(assign).toHaveBeenCalled();
    expect(String(assign.mock.calls[0]?.[0])).toMatch(/^\/login/);
  });

  it('a filter resets the page and asks the server for exactly that filter', async () => {
    const { calls } = install(baseRoutes);
    const dash = new Dashboard({ assign: vi.fn<(url: string) => void>() });
    await dash.start();
    dash.setPage(3);
    expect(dash.offset).toBe(2 * PAGE_SIZE);
    dash.setSeverity('critical');
    expect(dash.offset).toBe(0);
    dash.setSource('history');
    await vi.waitFor(() => {
      expect(calls).toContain(`GET /api/findings?limit=${PAGE_SIZE}&offset=0&severity=critical&source=history`);
    });
    dash.stop();
  });

  it('shows the error state when the first load fails and keeps rows when a refresh fails', async () => {
    let failing = true;
    install({
      ...baseRoutes,
      '/api/findings?': () =>
        failing ? json(502, {}) : json(200, { findings: [finding(1)], total: 1, limit: PAGE_SIZE, offset: 0 }),
    });
    const dash = new Dashboard({ assign: vi.fn<(url: string) => void>() });
    await dash.start();
    expect(dash.listState).toBe('error');
    failing = false;
    await dash.refresh();
    expect(dash.listState).toBe('ready');
    failing = true;
    await dash.refresh();
    expect(dash.listState).toBe('ready');
    expect(dash.findings).toHaveLength(1);
    dash.stop();
  });

  it('opens a detail from the list data at once and adds the batch summary', async () => {
    install(baseRoutes);
    const dash = new Dashboard({ assign: vi.fn<(url: string) => void>() });
    await dash.start();
    const row = dash.findings[0];
    expect(row).toBeDefined();
    if (row === undefined) return;
    dash.open(row);
    expect(dash.selected?.id).toBe(row.id);
    expect(dash.detail).toBeNull();
    await vi.waitFor(() => {
      expect(dash.detail?.batchSummary).toBe('sum');
    });
    dash.close();
    expect(dash.selected).toBeNull();
    dash.stop();
  });

  it('does not reload the list in the background while a detail is open', async () => {
    const { calls } = install(baseRoutes);
    const dash = new Dashboard({ assign: vi.fn<(url: string) => void>() });
    await dash.start();
    const row = dash.findings[0];
    if (row === undefined) throw new Error('no row');
    dash.open(row);
    const before = calls.filter((call) => call.startsWith('GET /api/findings?')).length;
    await vi.advanceTimersByTimeAsync(20_000);
    expect(calls.filter((call) => call.startsWith('GET /api/findings?')).length).toBe(before);
    expect(calls.filter((call) => call === 'GET /api/stats').length).toBeGreaterThan(1);
    dash.close();
    await vi.advanceTimersByTimeAsync(20_000);
    expect(calls.filter((call) => call.startsWith('GET /api/findings?')).length).toBeGreaterThan(before);
    dash.stop();
  });

  it('logs out with POST and the CSRF token of the session, then leaves for the login page', async () => {
    const { calls, assign } = install(baseRoutes);
    const dash = new Dashboard({ assign });
    await dash.start();
    await dash.logout();
    expect(calls).toContain('POST /api/logout');
    const call = vi.mocked(fetch).mock.calls.find(([path]) => path === '/api/logout');
    expect((call?.[1]?.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-1');
    expect(assign).toHaveBeenCalledWith('/login');
  });

  it('stays on the page when the logout fails for another reason than a gone session', async () => {
    const { assign } = install({ ...baseRoutes, '/api/logout': () => json(500, {}) });
    const dash = new Dashboard({ assign });
    await dash.start();
    await dash.logout();
    dash.stop();
    expect(assign).not.toHaveBeenCalled();
  });
});
