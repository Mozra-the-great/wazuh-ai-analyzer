// Display helpers (German). Pure functions, no DOM.

/** A timestamp of the API. Text without an offset counts as UTC, as the old dashboard did. */
export function parseTime(iso: string | null | undefined): Date | null {
  if (typeof iso !== 'string' || iso === '') return null;
  const date = new Date(/(Z|[+-]\d\d:?\d\d)$/.test(iso) ? iso : `${iso}Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

const DATE_TIME = new Intl.DateTimeFormat('de-DE', {
  day: '2-digit',
  month: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
});

export function formatTime(iso: string | null | undefined): string {
  const date = parseTime(iso);
  return date === null ? '–' : DATE_TIME.format(date);
}

/** Epoch milliseconds for kern's RelativeTime, or null for an invalid timestamp. */
export function epochMs(iso: string | null | undefined): number | null {
  return parseTime(iso)?.getTime() ?? null;
}

/** "bald", "42 s", "3 min 05 s", "2 h 10 min". */
export function formatDuration(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  if (total <= 0) return 'bald';
  if (total < 60) return `${total} s`;
  const minutes = Math.floor(total / 60);
  const rest = total % 60;
  if (minutes < 60) return `${minutes} min ${String(rest).padStart(2, '0')} s`;
  return `${Math.floor(minutes / 60)} h ${String(minutes % 60).padStart(2, '0')} min`;
}

/** Whole seconds until `retryAt` (never negative); null when there is no valid time. */
export function secondsUntil(retryAt: string | null, now: number): number | null {
  const date = parseTime(retryAt);
  return date === null ? null : Math.max(0, Math.floor((date.getTime() - now) / 1000));
}

/** 0..100, rounded; 0 for an empty total. */
export function percent(done: number, total: number): number {
  if (total <= 0) return 0;
  return Math.min(100, Math.max(0, Math.round((done / total) * 100)));
}

export function formatConfidence(value: number | null): string | null {
  if (value === null) return null;
  return `${Math.round(Math.min(1, Math.max(0, value)) * 100)} %`;
}

/** Only the first characters of a server error text go on the screen. */
export function clip(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}
