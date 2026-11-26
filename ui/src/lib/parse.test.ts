import { describe, expect, it } from 'vitest';
import { latestSummary, parseFinding, parseFindingsPage, parseSession, parseStats, severityOf } from './parse.ts';

describe('parse', () => {
  it('keeps hostile text as plain strings', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const finding = parseFinding({
      id: 1,
      batch_id: 2,
      title: hostile,
      severity: 'high',
      description: hostile,
      recommendation: hostile,
      affected_agents: [hostile, 3, null],
      rule_ids: ['5710'],
      batch_time: '2026-11-25T10:00:00+00:00',
      source: 'history',
      confidence: 0.75,
      mode: 'decision',
    });
    expect(finding.title).toBe(hostile);
    expect(finding.agents).toEqual([hostile]);
    expect(finding.source).toBe('history');
    expect(finding.confidence).toBe(0.75);
  });

  it('falls back to harmless values for malformed input', () => {
    const finding = parseFinding({ severity: 'catastrophic', source: 'elsewhere', title: 7, affected_agents: 'x' });
    expect(finding.severity).toBe('info');
    expect(finding.source).toBe('live');
    expect(finding.title).toBe('');
    expect(finding.agents).toEqual([]);
    expect(finding.mode).toBe('llm');
    expect(parseFinding(null).id).toBe(0);
  });

  it('knows exactly five severities', () => {
    expect(['critical', 'high', 'medium', 'low', 'info'].map(severityOf)).toEqual([
      'critical',
      'high',
      'medium',
      'low',
      'info',
    ]);
    expect(severityOf('CRITICAL')).toBe('info');
    expect(severityOf(undefined)).toBe('info');
  });

  it('parses a page and tolerates rows that are not objects', () => {
    const page = parseFindingsPage({ findings: [{ id: 1 }, 'x', null], total: 3, limit: 30, offset: 0 });
    expect(page.findings).toHaveLength(3);
    expect(page.total).toBe(3);
    expect(parseFindingsPage('nope').findings).toEqual([]);
  });

  it('parses the stats with defaults for every missing block', () => {
    const empty = parseStats({});
    expect(empty.totalFindings).toBe(0);
    expect(empty.bySeverity).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    expect(empty.quota.exhausted).toBe(false);
    expect(empty.history.done).toBe(true);
    expect(empty.geminiOk).toBe(false);

    const stats = parseStats({
      total_findings: 5,
      by_severity: { critical: 2, high: 3 },
      gemini_ok: true,
      buffered_alerts: 4,
      retry_queue_size: 1,
      last_analysis: '2026-11-25T10:00:00+00:00',
      quota: { exhausted: true, retry_at: '2026-11-25T11:00:00+00:00', retry_count: 2, last_error: 'quota' },
      history: { done: false, files_total: 10, files_done: 4, alerts_scanned: 99, batches_done: 3 },
    });
    expect(stats.bySeverity.high).toBe(3);
    expect(stats.quota.retryCount).toBe(2);
    expect(stats.history).toMatchObject({ done: false, filesTotal: 10, filesDone: 4 });
  });

  it('reads the session', () => {
    expect(parseSession({ authenticated: true, csrf_token: 't' })).toEqual({ authenticated: true, csrfToken: 't' });
    expect(parseSession([])).toEqual({ authenticated: false, csrfToken: '' });
  });

  it('picks the newest finished batch that has a summary', () => {
    const summary = latestSummary([
      { id: 9, status: 'pending', summary: 'x' },
      { id: 8, status: 'done', summary: '' },
      { id: 7, status: 'done', summary: 'All quiet', overall_risk: 'low' },
      { id: 6, status: 'done', summary: 'Older' },
    ]);
    expect(summary).toEqual({ id: 7, status: 'done', summary: 'All quiet', overallRisk: 'low' });
    expect(latestSummary([{ id: 1, status: 'done', summary: 'x', overall_risk: 'odd' }])?.overallRisk).toBeNull();
    expect(latestSummary({})).toBeNull();
  });
});
