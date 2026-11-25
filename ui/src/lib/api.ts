// The JSON API of the backend (docs/web.md). Cookies are sent automatically (same origin);
// state-changing requests carry the session's CSRF token in `X-CSRF-Token`.
import {
  latestSummary,
  parseFindingDetail,
  parseFindingsPage,
  parseSession,
  parseStats,
} from './parse.ts';
import type {
  BatchSummary,
  FindingDetail,
  FindingsPage,
  Session,
  Severity,
  Source,
  Stats,
} from './types.ts';

export class ApiError extends Error {
  readonly status: number;
  /** Only ever shown as text. */
  readonly body: Record<string, unknown>;

  constructor(status: number, body: Record<string, unknown> = {}) {
    super(`HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

/** The session is gone: the caller leaves for the login page. */
export class UnauthorizedError extends ApiError {
  constructor() {
    super(401);
    this.name = 'UnauthorizedError';
  }
}

export const LOGIN_PATH = '/login';

/** `/login?next=<local path>`; the server reduces `next` to a local path again. */
export function loginUrl(next: string): string {
  const local = next.startsWith('/') && !next.startsWith('//') ? next : '/';
  return local === '/' ? LOGIN_PATH : `${LOGIN_PATH}?next=${encodeURIComponent(local)}`;
}

async function json(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function asObject(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

interface Options {
  method?: 'GET' | 'POST';
  csrf?: string;
  body?: unknown;
  /** false: a 401 is an ordinary error (login and session calls) instead of `UnauthorizedError`. */
  redirectOn401?: boolean;
  signal?: AbortSignal;
}

async function call(path: string, options: Options = {}): Promise<unknown> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.csrf !== undefined) headers['X-CSRF-Token'] = options.csrf;
  const init: RequestInit = { method: options.method ?? 'GET', credentials: 'same-origin', headers };
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  if (options.signal !== undefined) init.signal = options.signal;
  const response = await fetch(path, init);
  if (response.status === 401 && options.redirectOn401 !== false) throw new UnauthorizedError();
  const body = await json(response);
  if (!response.ok) throw new ApiError(response.status, asObject(body));
  return body;
}

export async function getSession(): Promise<Session> {
  return parseSession(await call('/api/session', { redirectOn401: false }));
}

export interface LoginResult {
  next: string;
  csrfToken: string;
}

export async function login(
  csrf: string,
  username: string,
  password: string,
  next: string,
): Promise<LoginResult> {
  const body = asObject(await call('/api/login', {
    method: 'POST',
    csrf,
    body: { username, password, next },
    redirectOn401: false,
  }));
  const target = body['next'];
  return {
    next: typeof target === 'string' && target.startsWith('/') && !target.startsWith('//') ? target : '/',
    csrfToken: typeof body['csrf_token'] === 'string' ? body['csrf_token'] : '',
  };
}

export async function logout(csrf: string): Promise<void> {
  await call('/api/logout', { method: 'POST', csrf, body: {}, redirectOn401: false });
}

export async function getStats(signal?: AbortSignal): Promise<Stats> {
  return parseStats(await call('/api/stats', signal === undefined ? {} : { signal }));
}

export async function getLatestSummary(signal?: AbortSignal): Promise<BatchSummary | null> {
  return latestSummary(await call('/api/batches', signal === undefined ? {} : { signal }));
}

export interface FindingsQuery {
  limit: number;
  offset: number;
  severity: Severity | '';
  source: Source | '';
}

export function findingsPath(query: FindingsQuery): string {
  const params = new URLSearchParams({ limit: String(query.limit), offset: String(query.offset) });
  if (query.severity !== '') params.set('severity', query.severity);
  if (query.source !== '') params.set('source', query.source);
  return `/api/findings?${params.toString()}`;
}

export async function getFindings(query: FindingsQuery, signal?: AbortSignal): Promise<FindingsPage> {
  return parseFindingsPage(await call(findingsPath(query), signal === undefined ? {} : { signal }));
}

export async function getFinding(id: number, signal?: AbortSignal): Promise<FindingDetail> {
  return parseFindingDetail(
    await call(`/api/findings/${String(Math.trunc(id))}`, signal === undefined ? {} : { signal }),
  );
}
