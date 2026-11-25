import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ApiError,
  UnauthorizedError,
  findingsPath,
  getFindings,
  getSession,
  getStats,
  login,
  loginUrl,
  logout,
} from './api.ts';

function answer(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('api', () => {
  it('builds the login URL with a local next path only', () => {
    expect(loginUrl('/')).toBe('/login');
    expect(loginUrl('/findings/3')).toBe('/login?next=%2Ffindings%2F3');
    expect(loginUrl('//evil.example')).toBe('/login');
    expect(loginUrl('https://evil.example')).toBe('/login');
  });

  it('builds the findings query', () => {
    expect(findingsPath({ limit: 30, offset: 60, severity: '', source: '' })).toBe('/api/findings?limit=30&offset=60');
    expect(findingsPath({ limit: 30, offset: 0, severity: 'high', source: 'live' })).toBe(
      '/api/findings?limit=30&offset=0&severity=high&source=live',
    );
  });

  it('sends cookies and no CSRF token on reads, and turns a 401 into UnauthorizedError', async () => {
    const fetchMock = vi.fn().mockResolvedValue(answer(401, { error: 'Unauthorized' }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(getStats()).rejects.toBeInstanceOf(UnauthorizedError);
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(init.credentials).toBe('same-origin');
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined();
  });

  it('reports other errors with their status and body', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(answer(400, { error: 'Bad request', detail: 'x' })));
    const error = await getFindings({ limit: 30, offset: 0, severity: '', source: '' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(400);
    expect((error as ApiError).body['detail']).toBe('x');
  });

  it('logs in with JSON, the CSRF header and a local next path', async () => {
    const fetchMock = vi.fn().mockResolvedValue(answer(200, { ok: true, next: '/x', csrf_token: 's' }));
    vi.stubGlobal('fetch', fetchMock);
    const result = await login('pre-token', 'admin', 'pw', '/x');
    expect(result).toEqual({ next: '/x', csrfToken: 's' });
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/login');
    expect(init.method).toBe('POST');
    const headers = init.headers as Record<string, string>;
    expect(headers['X-CSRF-Token']).toBe('pre-token');
    expect(headers['Content-Type']).toBe('application/json');
    expect(JSON.parse(init.body as string)).toEqual({ username: 'admin', password: 'pw', next: '/x' });
  });

  it('never follows a foreign next from the server', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(answer(200, { ok: true, next: 'https://evil.example' })));
    expect((await login('t', 'a', 'b', '/')).next).toBe('/');
  });

  it('a 401 of the login is an ordinary error with the remaining attempts', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(answer(401, { error: 'Invalid credentials', remaining_attempts: 3 })),
    );
    const error = await login('t', 'a', 'b', '/').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).not.toBeInstanceOf(UnauthorizedError);
    expect((error as ApiError).body['remaining_attempts']).toBe(3);
  });

  it('logs out with POST and the session token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(answer(200, { ok: true }));
    vi.stubGlobal('fetch', fetchMock);
    await logout('session-token');
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe('/api/logout');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('session-token');
  });

  it('passes a JSON array through (the batches list)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(answer(200, [{ id: 1, status: 'done', summary: 'S' }])));
    const { getLatestSummary } = await import('./api.ts');
    expect((await getLatestSummary())?.summary).toBe('S');
  });

  it('reads the session without redirecting on 401', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(answer(200, { authenticated: false, csrf_token: 'c' })));
    expect(await getSession()).toEqual({ authenticated: false, csrfToken: 'c' });
  });
});
