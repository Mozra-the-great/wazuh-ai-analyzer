// The shapes the UI uses. Every string in here that came from the model or from an alert log
// (titles, descriptions, recommendations, agents, rule ids, summaries, error texts) is
// attacker-influenced text: it is rendered as text only, never as markup.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export type Source = 'live' | 'history';

export interface Finding {
  id: number;
  batchId: number;
  title: string;
  severity: Severity;
  description: string;
  recommendation: string;
  agents: string[];
  ruleIds: string[];
  /** ISO 8601 text of the batch, or null. */
  batchTime: string | null;
  source: Source;
  /** 0..1, or null when the mode has none. */
  confidence: number | null;
  mode: string;
}

export interface FindingDetail extends Finding {
  batchSummary: string | null;
  alertCount: number | null;
}

export interface FindingsPage {
  findings: Finding[];
  total: number;
  limit: number;
  offset: number;
}

export interface Quota {
  exhausted: boolean;
  exhaustedSince: string | null;
  retryAt: string | null;
  retryInSeconds: number;
  retryCount: number;
  lastError: string;
}

export interface HistoryProgress {
  done: boolean;
  filesTotal: number;
  filesDone: number;
  alertsScanned: number;
  batchesDone: number;
}

export interface Stats {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  lastAnalysis: string | null;
  bufferedAlerts: number;
  retryQueueSize: number;
  geminiOk: boolean;
  quota: Quota;
  history: HistoryProgress;
}

export interface BatchSummary {
  id: number;
  status: string;
  summary: string;
  overallRisk: Severity | null;
}

export interface Session {
  authenticated: boolean;
  csrfToken: string;
}
