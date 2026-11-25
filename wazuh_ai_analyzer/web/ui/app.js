// Interim dashboard (until the kern UI of #87 replaces it).
//
// Rules this file follows, and the kern UI must follow too:
//  * Every string from the API (finding texts, agents, rule ids, summary, last_error,
//    quota and upstream messages) was written by a model or taken from an alert log: it
//    is attacker-influenced. It is only ever put into the page with textContent or
//    setAttribute on a fixed attribute, never through an HTML-parsing API and never as Markdown/HTML.
//  * Recommendations and summaries are AI generated and unverified: they are labelled.
//  * No inline script, style attribute or event-handler attribute (strict CSP).
'use strict';

const PER = 30;
const state = { filter: '', source: '', offset: 0, total: 0, open: null, findings: [], csrf: '' };

let countdownTimer = null;
let quotaRetryAt = null;
let refreshing = false;
let toastTimer = null;

const SEV_LABEL = { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig', info: 'Info' };
const SEVERITIES = Object.keys(SEV_LABEL);

// ── DOM helpers ─────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.cls) node.className = options.cls;
  if (options.text !== undefined) node.textContent = options.text;
  for (const [name, value] of Object.entries(options.attrs || {})) node.setAttribute(name, value);
  for (const child of children) node.append(child);
  return node;
}

function knownSeverity(value) {
  return SEVERITIES.includes(value) ? value : 'info';
}

function sevBadge(severity) {
  const sev = knownSeverity(severity);
  return el('span', { cls: 'sev-badge', text: SEV_LABEL[sev], attrs: { 'data-sev': sev } });
}

function riskPill(risk) {
  if (!SEVERITIES.includes(risk)) return null;
  return el('span', { cls: 'risk-pill', text: SEV_LABEL[risk], attrs: { 'data-sev': risk } });
}

function parseTime(iso) {
  if (typeof iso !== 'string' || !iso) return null;
  const date = new Date(/(Z|[+-]\d\d:?\d\d)$/.test(iso) ? iso : iso + 'Z');
  return Number.isNaN(date.getTime()) ? null : date;
}

function fmtTime(iso) {
  const date = parseTime(iso);
  if (!date) return '–';
  return date.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function relTime(iso) {
  const date = parseTime(iso);
  if (!date) return '';
  const minutes = Math.floor((Date.now() - date.getTime()) / 60000);
  if (minutes < 1) return 'gerade eben';
  if (minutes < 60) return `vor ${minutes} Min.`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `vor ${hours} Std.`;
  return `vor ${Math.floor(hours / 24)} Tag(en)`;
}

function fmtDuration(seconds) {
  if (seconds <= 0) return 'bald';
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return `${m}m ${s}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function toast(message, isError = false) {
  const node = $('toast');
  node.textContent = message;
  node.classList.toggle('toast-error', isError);
  node.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove('show'), 3500);
}

// ── API ─────────────────────────────────────────────────────────────────────
class ApiError extends Error {}

async function api(path) {
  const response = await fetch(path, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  if (response.status === 401) {
    location.assign('/login?next=' + encodeURIComponent(location.pathname));
    throw new ApiError('401');
  }
  if (!response.ok) throw new ApiError(String(response.status));
  return response.json();
}

// ── stats ───────────────────────────────────────────────────────────────────
async function loadStats() {
  const s = await api('/api/stats');
  const dot = $('gemini-dot');
  const label = $('gemini-label');
  if (!s.gemini_ok) {
    dot.className = 'dot err';
    label.textContent = 'Kein API Key';
  } else if (s.quota && s.quota.exhausted) {
    dot.className = 'dot err';
    label.textContent = 'Quota leer';
  } else {
    dot.className = 'dot ok';
    label.textContent = 'Gemini OK';
  }
  $('buf-count').textContent = String(s.buffered_alerts);
  $('retry-queue-label').hidden = !(s.retry_queue_size > 0);
  $('rq-count').textContent = String(s.retry_queue_size);
  $('last-label').textContent = s.last_analysis ? `Letzte Analyse ${relTime(s.last_analysis)}` : 'Noch keine Analyse';
  $('stat-total').textContent = String(s.total_findings);
  for (const sev of SEVERITIES) $(`stat-${sev}`).textContent = String((s.by_severity || {})[sev] || 0);
  updateQuotaBanner(s.quota, s.retry_queue_size);
  updateHistoryBanner(s.history);
}

function updateQuotaBanner(quota, queueSize) {
  const banner = $('quota-banner');
  if (!quota || !quota.exhausted) {
    banner.hidden = true;
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
    return;
  }
  banner.hidden = false;
  const retryAt = parseTime(quota.retry_at);
  quotaRetryAt = retryAt ? retryAt.getTime() / 1000 : null;
  $('quota-since').textContent = fmtTime(quota.exhausted_since);
  $('rq-size').textContent = String(queueSize);
  $('quota-retries').hidden = !(quota.retry_count > 1);
  $('quota-retry-count').textContent = String(quota.retry_count);
  $('quota-body').textContent = quota.last_error
    ? `Gemini-Fehlermeldung: "${String(quota.last_error).slice(0, 200)}" — Neue Alerts werden gepuffert und automatisch analysiert, sobald das Kontingent wieder verfügbar ist.`
    : 'Das Gemini-Kontingent ist vorübergehend aufgebraucht. Neue Alerts werden gepuffert und automatisch analysiert, sobald es wieder verfügbar ist.';
  if (countdownTimer) clearInterval(countdownTimer);
  const tick = () => {
    if (quotaRetryAt === null) return;
    const remaining = Math.max(0, Math.floor(quotaRetryAt - Date.now() / 1000));
    $('quota-countdown').textContent = fmtDuration(remaining);
    const total = quota.retry_count <= 1 ? 65 : 3600;
    $('quota-progress-bar').style.width = Math.min(100, Math.round((remaining / total) * 100)) + '%';
  };
  tick();
  countdownTimer = setInterval(tick, 1000);
}

function updateHistoryBanner(history) {
  const banner = $('history-banner');
  if (!history || history.done) {
    banner.hidden = true;
    return;
  }
  banner.hidden = false;
  const total = history.files_total || 1;
  const done = history.files_done || 0;
  const pct = Math.round((done / total) * 100);
  $('hist-pct').textContent = pct + '%';
  $('hist-progress-bar').style.width = pct + '%';
  $('hist-body').textContent =
    `Datei ${done} von ${total} gescannt · ${history.alerts_scanned} Alerts verarbeitet · ${history.batches_done} Batches analysiert`;
}

async function loadSummary() {
  try {
    const batches = await api('/api/batches');
    const last = batches.find((b) => b.status === 'done');
    if (!last || !last.summary) return;
    $('sb-text').textContent = String(last.summary);
    const holder = $('sb-risk-pill');
    holder.replaceChildren();
    const pill = riskPill(last.overall_risk);
    if (pill) holder.append(pill);
    $('summary-banner').hidden = false;
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
  }
}

// ── findings ────────────────────────────────────────────────────────────────
async function loadFindings() {
  const list = $('findings-list');
  list.replaceChildren(...Array.from({ length: 4 }, () => el('div', { cls: 'skeleton' })));
  const query = new URLSearchParams({ limit: String(PER), offset: String(state.offset) });
  if (state.filter) query.set('severity', state.filter);
  if (state.source) query.set('source', state.source);
  const data = await api(`/api/findings?${query}`);
  state.findings = data.findings;
  state.total = data.total;
  renderFindings();
  renderPagination();
  $('count-label').textContent = data.total ? `${data.total} Einträge` : '';
}

function listItem(text) {
  return el('span', { text });
}

function renderFindings() {
  const list = $('findings-list');
  if (!state.findings.length) {
    list.replaceChildren(
      el('div', { cls: 'empty-state' }, [
        el('div', { cls: 'icon', text: '🔍' }),
        el('h3', { text: 'Keine Findings' }),
        el('p', { text: 'Wazuh-Alerts werden gesammelt und automatisch analysiert, sobald sie eintreffen.' }),
      ]),
    );
    return;
  }
  const nodes = [];
  for (const f of state.findings) {
    const isOpen = f.id === state.open;
    const meta = el('div', { cls: 'fc-meta' }, [
      listItem(fmtTime(f.batch_time)),
      el('span', {}, [el('span', { cls: `src-pip ${f.source === 'history' ? 'history' : 'live'}`, text: f.source === 'history' ? 'Historisch' : 'Live' })]),
    ]);
    if (f.affected_agents && f.affected_agents.length) meta.append(listItem(f.affected_agents.join(', ')));
    if (f.rule_ids && f.rule_ids.length) meta.append(listItem(`Regel ${f.rule_ids.join(', ')}`));
    const card = el(
      'div',
      {
        cls: 'finding-card' + (isOpen ? ' expanded' : ''),
        attrs: { 'data-sev': knownSeverity(f.severity), role: 'button', tabindex: '0', 'aria-expanded': String(isOpen) },
      },
      [sevBadge(f.severity), el('div', { cls: 'fc-body' }, [el('div', { cls: 'fc-title', text: f.title }), meta]), el('span', { cls: 'fc-arrow', text: '›', attrs: { 'aria-hidden': 'true' } })],
    );
    onActivate(card, () => toggleDetail(f.id));
    nodes.push(card);
    if (isOpen) nodes.push(makeDetail(f));
  }
  list.replaceChildren(...nodes);
}

function section(labelText, body) {
  return el('div', { cls: 'ds' }, [el('label', { text: labelText }), body]);
}

function tagList(values) {
  return el('div', { cls: 'tag-list' }, values.map((v) => el('span', { cls: 'tag', text: v })));
}

function makeDetail(f) {
  const panel = el('div', { cls: 'detail-panel' });
  panel.append(el('h3', {}, [sevBadge(f.severity), el('span', { text: f.title })]));
  panel.append(section('🔍 Was ist das Problem?', el('p', { text: f.description })));
  const recommendation = section('✅ Handlungsempfehlung (KI-generiert, vor Umsetzung prüfen)', el('div', { cls: 'rec-block', text: f.recommendation }));
  recommendation.append(el('div', { cls: 'ai-note', text: 'Dieser Text stammt von einem KI-Modell und wurde nicht verifiziert.' }));
  panel.append(recommendation);
  if (f.affected_agents && f.affected_agents.length) panel.append(section('🖥 Betroffene Systeme', tagList(f.affected_agents)));
  if (f.rule_ids && f.rule_ids.length) panel.append(section('📋 Wazuh Regel-IDs', tagList(f.rule_ids)));
  const meta = el('div', { cls: 'detail-meta', text: `Analysiert ${fmtTime(f.batch_time)} · Batch #${f.batch_id}` });
  if (f.source === 'history') meta.append(document.createTextNode(' · historischer Scan'));
  panel.append(meta);
  return panel;
}

function toggleDetail(id) {
  state.open = state.open === id ? null : id;
  renderFindings();
}

function renderPagination() {
  const holder = $('pagination');
  const pages = Math.ceil(state.total / PER);
  const current = Math.floor(state.offset / PER);
  if (pages <= 1) {
    holder.replaceChildren();
    return;
  }
  const nodes = [];
  if (current > 0) nodes.push(pageButton('← Zurück', current - 1));
  nodes.push(el('span', { cls: 'page-info', text: `Seite ${current + 1}/${pages}` }));
  if (current < pages - 1) nodes.push(pageButton('Weiter →', current + 1));
  holder.replaceChildren(...nodes);
}

function pageButton(label, page) {
  const button = el('button', { cls: 'btn', text: label, attrs: { type: 'button' } });
  button.addEventListener('click', () => goPage(page));
  return button;
}

function goPage(page) {
  state.offset = page * PER;
  state.open = null;
  loadFindings().catch(showLoadError);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── filters ─────────────────────────────────────────────────────────────────
function setFilter(severity) {
  state.filter = SEVERITIES.includes(severity) ? severity : '';
  state.offset = 0;
  state.open = null;
  for (const card of document.querySelectorAll('.stat-card')) {
    card.classList.toggle('active', card.dataset.filter === state.filter);
  }
  $('section-title').textContent = state.filter ? `${SEV_LABEL[state.filter]} Findings` : 'Alle Findings';
  loadFindings().catch(showLoadError);
}

function setSource(source) {
  state.source = source === 'live' || source === 'history' ? source : '';
  state.offset = 0;
  state.open = null;
  for (const tab of document.querySelectorAll('.tab')) {
    tab.classList.toggle('active', tab.dataset.source === state.source);
  }
  loadFindings().catch(showLoadError);
}

function onActivate(node, handler) {
  node.addEventListener('click', handler);
  node.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      handler();
    }
  });
}

// ── refresh, logout, start ──────────────────────────────────────────────────
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    await Promise.all([loadStats(), loadSummary()]);
    await loadFindings();
  } catch (error) {
    if (!(error instanceof ApiError && error.message === '401')) toast('Fehler: ' + error.message, true);
  } finally {
    refreshing = false;
  }
}

function showLoadError() {
  $('findings-list').replaceChildren(
    el('div', { cls: 'empty-state' }, [
      el('div', { cls: 'icon', text: '⚠️' }),
      el('h3', { text: 'Backend nicht erreichbar' }),
      el('p', { text: 'systemctl status wazuh-ai-analyzer' }),
      el('p', { text: 'journalctl -u wazuh-ai-analyzer -f' }),
    ]),
  );
}

async function logout() {
  try {
    await fetch('/api/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': state.csrf, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: '{}',
    });
  } finally {
    location.assign('/login');
  }
}

async function init() {
  for (const card of document.querySelectorAll('.stat-card')) onActivate(card, () => setFilter(card.dataset.filter));
  for (const tab of document.querySelectorAll('.tab')) onActivate(tab, () => setSource(tab.dataset.source));
  $('refresh-btn').addEventListener('click', refresh);
  $('logout-btn').addEventListener('click', logout);
  $('stat-all').classList.add('active');
  try {
    const session = await api('/api/session');
    if (!session.authenticated) {
      location.assign('/login');
      return;
    }
    state.csrf = session.csrf_token;
    await Promise.all([loadStats(), loadSummary()]);
    await loadFindings();
  } catch (error) {
    if (!(error instanceof ApiError && error.message === '401')) showLoadError();
  }
  setInterval(() => {
    loadStats().catch(() => {});
    if (state.open === null) loadFindings().catch(() => {});
  }, 20000);
}

init();
