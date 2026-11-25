// Turns API answers (`unknown`) into the typed shapes of types.ts. A wrong or missing field
// gets a harmless default instead of breaking the page; text stays text.
import {
  SEVERITIES,
  type BatchSummary,
  type Finding,
  type FindingDetail,
  type FindingsPage,
  type HistoryProgress,
  type Quota,
  type Session,
  type Severity,
  type Source,
  type Stats,
} from './types.ts';

type Obj = Record<string, unknown>;

export function isObject(value: unknown): value is Obj {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const obj = (value: unknown): Obj => (isObject(value) ? value : {});
const text = (value: unknown, fallback = ''): string => (typeof value === 'string' ? value : fallback);
const textOrNull = (value: unknown): string | null => (typeof value === 'string' && value !== '' ? value : null);
const num = (value: unknown, fallback = 0): number =>
  typeof value === 'number' && Number.isFinite(value) ? value : fallback;
const numOrNull = (value: unknown): number | null =>
  typeof value === 'number' && Number.isFinite(value) ? value : null;
const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

/** An unknown severity is shown as `info`, the lowest level. */
export const severityOf = (value: unknown): Severity => (isSeverity(value) ? value : 'info');

export function parseSession(value: unknown): Session {
  const data = obj(value);
  return { authenticated: data['authenticated'] === true, csrfToken: text(data['csrf_token']) };
}

export function parseFinding(value: unknown): Finding {
  const data = obj(value);
  const source: Source = data['source'] === 'history' ? 'history' : 'live';
  return {
    id: num(data['id']),
    batchId: num(data['batch_id']),
    title: text(data['title']),
    severity: severityOf(data['severity']),
    description: text(data['description']),
    recommendation: text(data['recommendation']),
    agents: strings(data['affected_agents']),
    ruleIds: strings(data['rule_ids']),
    batchTime: textOrNull(data['batch_time']),
    source,
    confidence: numOrNull(data['confidence']),
    mode: text(data['mode'], 'llm'),
  };
}

export function parseFindingDetail(value: unknown): FindingDetail {
  const data = obj(value);
  return {
    ...parseFinding(value),
    batchSummary: textOrNull(data['batch_summary']),
    alertCount: numOrNull(data['alert_count']),
  };
}

export function parseFindingsPage(value: unknown): FindingsPage {
  const data = obj(value);
  const rows = Array.isArray(data['findings']) ? data['findings'] : [];
  return {
    findings: rows.map(parseFinding),
    total: num(data['total']),
    limit: num(data['limit'], 30),
    offset: num(data['offset']),
  };
}

function parseQuota(value: unknown): Quota {
  const data = obj(value);
  return {
    exhausted: data['exhausted'] === true,
    exhaustedSince: textOrNull(data['exhausted_since']),
    retryAt: textOrNull(data['retry_at']),
    retryInSeconds: num(data['retry_in_seconds']),
    retryCount: num(data['retry_count']),
    lastError: text(data['last_error']),
  };
}

function parseHistory(value: unknown): HistoryProgress {
  const data = obj(value);
  return {
    done: data['done'] !== false,
    filesTotal: num(data['files_total']),
    filesDone: num(data['files_done']),
    alertsScanned: num(data['alerts_scanned']),
    batchesDone: num(data['batches_done']),
  };
}

export function parseStats(value: unknown): Stats {
  const data = obj(value);
  const counts = obj(data['by_severity']);
  const bySeverity = Object.fromEntries(SEVERITIES.map((level) => [level, num(counts[level])])) as Record<
    Severity,
    number
  >;
  return {
    totalFindings: num(data['total_findings']),
    bySeverity,
    lastAnalysis: textOrNull(data['last_analysis']),
    bufferedAlerts: num(data['buffered_alerts']),
    retryQueueSize: num(data['retry_queue_size']),
    geminiOk: data['gemini_ok'] === true,
    quota: parseQuota(data['quota']),
    history: parseHistory(data['history']),
  };
}

/** The newest finished batch that has a summary, from `/api/batches` (newest first). */
export function latestSummary(value: unknown): BatchSummary | null {
  if (!Array.isArray(value)) return null;
  for (const entry of value) {
    const data = obj(entry);
    const summary = text(data['summary']);
    if (data['status'] === 'done' && summary !== '') {
      return {
        id: num(data['id']),
        status: 'done',
        summary,
        overallRisk: isSeverity(data['overall_risk']) ? data['overall_risk'] : null,
      };
    }
  }
  return null;
}
