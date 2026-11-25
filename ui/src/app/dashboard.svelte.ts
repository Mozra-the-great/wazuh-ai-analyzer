// State and data loading of the dashboard (Svelte 5 runes).
import { announce, toast } from '@mozra-the-great/kern';
import {
  ApiError,
  getFinding,
  getFindings,
  getLatestSummary,
  getSession,
  getStats,
  loginUrl,
  logout,
  UnauthorizedError,
} from '../lib/api.ts';
import { SEVERITY_LABEL, SOURCE_LABEL, T } from '../lib/strings.ts';
import type { BatchSummary, Finding, FindingDetail, Severity, Source, Stats } from '../lib/types.ts';

export const PAGE_SIZE = 30;
export const POLL_MS = 20_000;

export type LoadState = 'loading' | 'ready' | 'error';

/** Where the browser goes; replaceable in tests. */
export interface Navigator {
  assign(url: string): void;
}

export class Dashboard {
  stats = $state<Stats | null>(null);
  summary = $state<BatchSummary | null>(null);
  findings = $state<Finding[]>([]);
  total = $state(0);
  severity = $state<Severity | ''>('');
  source = $state<Source | ''>('');
  offset = $state(0);
  listState = $state<LoadState>('loading');
  refreshing = $state(false);
  selected = $state<Finding | null>(null);
  detail = $state<FindingDetail | null>(null);
  detailFailed = $state(false);

  #csrf = '';
  #timer: ReturnType<typeof setInterval> | null = null;
  #listAbort: AbortController | null = null;
  #detailAbort: AbortController | null = null;
  readonly #nav: Navigator;

  constructor(nav: Navigator = { assign: (url) => location.assign(url) }) {
    this.#nav = nav;
  }

  get page(): number {
    return Math.floor(this.offset / PAGE_SIZE) + 1;
  }

  get pageCount(): number {
    return Math.max(1, Math.ceil(this.total / PAGE_SIZE));
  }

  /** A 401 anywhere ends in the login page, which brings the user back here. */
  #handle(error: unknown): boolean {
    if (error instanceof UnauthorizedError) {
      this.stop();
      this.#nav.assign(loginUrl(location.pathname));
      return true;
    }
    return error instanceof DOMException && error.name === 'AbortError';
  }

  async start(): Promise<void> {
    try {
      const session = await getSession();
      if (!session.authenticated) {
        this.#nav.assign(loginUrl(location.pathname));
        return;
      }
      this.#csrf = session.csrfToken;
    } catch {
      this.listState = 'error';
      return;
    }
    await Promise.all([this.#loadStats(), this.#loadSummary()]);
    await this.loadFindings();
    this.#timer = setInterval(() => void this.#poll(), POLL_MS);
  }

  stop(): void {
    if (this.#timer !== null) clearInterval(this.#timer);
    this.#timer = null;
    this.#listAbort?.abort();
    this.#detailAbort?.abort();
  }

  async #poll(): Promise<void> {
    // The list stays as it is while a detail is open, so the user does not lose the place.
    await this.#loadStats();
    await this.#loadSummary();
    if (this.selected === null) await this.loadFindings({ quiet: true });
  }

  async #loadStats(): Promise<void> {
    try {
      this.stats = await getStats();
    } catch (error) {
      if (!this.#handle(error)) this.#failed();
    }
  }

  async #loadSummary(): Promise<void> {
    try {
      this.summary = await getLatestSummary();
    } catch (error) {
      if (!this.#handle(error)) this.#failed();
    }
  }

  #failedAt = 0;
  /** One toast per burst of failures, not one per request. */
  #failed(): void {
    const now = Date.now();
    if (now - this.#failedAt < 5_000) return;
    this.#failedAt = now;
    toast.danger(T.toast.loadFailed, { key: 'load-failed', duration: 10_000 });
  }

  /** `quiet`: a background refresh keeps the rows on screen and shows no skeleton. */
  async loadFindings(options: { quiet?: boolean } = {}): Promise<void> {
    this.#listAbort?.abort();
    const abort = new AbortController();
    this.#listAbort = abort;
    if (options.quiet !== true) this.listState = 'loading';
    try {
      const page = await getFindings(
        { limit: PAGE_SIZE, offset: this.offset, severity: this.severity, source: this.source },
        abort.signal,
      );
      this.findings = page.findings;
      this.total = page.total;
      // A filter or a deletion can leave the offset behind the last page.
      if (page.findings.length === 0 && page.total > 0 && this.offset > 0) {
        this.offset = Math.max(0, (Math.ceil(page.total / PAGE_SIZE) - 1) * PAGE_SIZE);
        await this.loadFindings(options);
        return;
      }
      this.listState = 'ready';
    } catch (error) {
      if (this.#handle(error)) return;
      if (options.quiet === true && this.listState === 'ready') this.#failed();
      else this.listState = 'error';
    }
  }

  /** The user pressed "Neu laden". */
  async refresh(): Promise<void> {
    if (this.refreshing) return;
    this.refreshing = true;
    try {
      await Promise.all([this.#loadStats(), this.#loadSummary()]);
      await this.loadFindings({ quiet: this.listState === 'ready' });
      if (this.listState === 'ready') announce(T.toast.refreshed, 'polite');
    } finally {
      this.refreshing = false;
    }
  }

  setSeverity(value: Severity | ''): void {
    this.severity = value;
    this.#filtered();
  }

  setSource(value: Source | ''): void {
    this.source = value;
    this.#filtered();
  }

  #filtered(): void {
    this.offset = 0;
    this.selected = null;
    void this.loadFindings().then(() => {
      if (this.listState !== 'ready') return;
      const parts = [T.list.count(this.total)];
      if (this.severity !== '') parts.push(SEVERITY_LABEL[this.severity]);
      if (this.source !== '') parts.push(SOURCE_LABEL[this.source]);
      announce(parts.join(', '), 'polite');
    });
  }

  setPage(page: number): void {
    const next = Math.min(Math.max(1, Math.trunc(page)), this.pageCount);
    this.offset = (next - 1) * PAGE_SIZE;
    this.selected = null;
    void this.loadFindings();
  }

  /** Opens the detail of a finding; the list data shows at once, the batch summary follows. */
  open(finding: Finding): void {
    this.#detailAbort?.abort();
    const abort = new AbortController();
    this.#detailAbort = abort;
    this.selected = finding;
    this.detail = null;
    this.detailFailed = false;
    void getFinding(finding.id, abort.signal)
      .then((detail) => {
        if (this.selected?.id === finding.id) this.detail = detail;
      })
      .catch((error: unknown) => {
        if (this.#handle(error)) return;
        if (this.selected?.id === finding.id) this.detailFailed = true;
      });
  }

  close(): void {
    this.#detailAbort?.abort();
    this.selected = null;
    this.detail = null;
    this.detailFailed = false;
  }

  async logout(): Promise<void> {
    try {
      await logout(this.#csrf);
    } catch (error) {
      if (!(error instanceof ApiError && error.status === 401)) {
        toast.danger(T.toast.logoutFailed, { key: 'logout-failed', duration: 10_000 });
        return;
      }
    }
    this.stop();
    this.#nav.assign(loginUrl('/'));
  }
}
