/** ProxyCheck frontend orchestrator. Developed by Diwas Khatri. */

import './theme.js';
import { api, subscribeJob } from './api.js';
import { state, resetResults, upsertResults, applyGeo, allResults, notify } from './state.js';
import { summarize } from './parserClient.js';
import { createTable, updateSortHeader } from './table.js';
import { renderStats } from './dashboard.js';
import { latencyHistogram, aliveDonut, protocolDonut, countryBars } from './charts.js';
import { applyFilters, refreshFilterOptions, resetFilters } from './filters.js';
import { renderProgress } from './progress.js';
import { openDrawer, closeDrawer } from './detail.js';
import { wireExportModal, scopedRows } from './exporter.js';
import { generateDemoResults } from './demo.js';
import { debounce, esc, toast, fmtNum } from './util.js';

const $ = (id) => document.getElementById(id);

// Surface unexpected UI errors as visible toasts instead of a broken page.
window.addEventListener('error', (e) => {
  try { toast(els.toasts, `UI error: ${e.message || 'unknown'} (hard-refresh: Ctrl+Shift+R)`, 'err'); } catch { /* noop */ }
});
window.addEventListener('unhandledrejection', (e) => {
  const m = e.reason && e.reason.message ? e.reason.message : String(e.reason || 'unknown');
  try { toast(els.toasts, `Error: ${m}`, 'err'); } catch { /* noop */ }
});

const els = {
  input: $('proxy-input'), parseSummary: $('parse-summary'),
  upload: $('upload-btn'), file: $('file-input'), clear: $('clear-btn'), demo: $('demo-btn'),
  demoBanner: $('demo-banner'),
  protocol: $('set-protocol'), timeout: $('set-timeout'), concurrency: $('set-concurrency'),
  retries: $('set-retries'), https: $('set-https'),
  start: $('start-btn'), startHint: $('start-hint'),
  progress: {
    card: $('progress-card'), heading: document.querySelector('#progress-card h2'),
    pct: $('progress-pct'), count: $('progress-count'), status: $('progress-status'),
    fill: $('progress-fill'), bar: $('progress-bar'),
    alive: $('pc-alive'), dead: $('pc-dead'), timeout: $('pc-timeout'), errors: $('pc-errors'),
    avg: $('pc-avg'), eta: $('pc-eta'), conc: $('pc-conc'), jobId: $('job-id-label'),
    pause: $('pause-btn'), resume: $('resume-btn'), cancel: $('cancel-btn'), restart: $('restart-btn'),
  },
  dashboard: $('dashboard-card'), stats: $('stat-grid'),
  chartLatency: $('chart-latency'), chartAlive: $('chart-alive'),
  chartProtocol: $('chart-protocol'), chartCountry: $('chart-country'),
  resultsCard: $('results-card'), meta: $('results-meta'),
  header: $('tbl-header'), scroller: $('tbl-scroller'), spacer: $('tbl-spacer'), empty: $('tbl-empty'),
  f: {
    status: $('f-status'), protocol: $('f-protocol'), speed: $('f-speed'), https: $('f-https'),
    anon: $('f-anon'), auth: $('f-auth'), country: $('f-country'), asn: $('f-asn'),
    q: $('f-search'), clear: $('f-clear'),
  },
  selectAll: $('select-all'),
  exportBtn: $('export-btn'),
  recheckSel: $('recheck-selected-btn'), recheckFailed: $('recheck-failed-btn'),
  drawer: {
    drawer: $('drawer'), backdrop: $('drawer-backdrop'), body: $('drawer-body'),
    close: $('drawer-close'), copy: $('d-copy'), export: $('d-export'), recheck: $('d-recheck'),
  },
  exportModal: {
    modal: $('export-modal'), close: $('export-close'),
    download: $('export-download'), copy: $('export-copy'),
    creds: $('exp-creds'), scheme: $('exp-scheme'), credNote: $('exp-cred-note'),
  },
  toasts: $('toasts'),
  connDot: $('conn-dot'), connLabel: $('conn-label'),
};

let live = null; // active SSE/poll subscription
let updateTimer = null;
let cfg = null;

// ---------------------------------------------------------------- rendering
function scheduleUpdate(immediate = false) {
  if (immediate) return doUpdate();
  if (updateTimer) return;
  updateTimer = setTimeout(() => { updateTimer = null; doUpdate(); }, 280);
}

function doUpdate() {
  const rows = applyFilters(allResults());
  table.setRows(rows);
  renderStats(els.stats, allResults(), state.snapshot);
  renderProgress(els.progress, state.snapshot, Boolean(live));
  if (state.results.length || state.demo) {
    els.dashboard.hidden = false;
    els.resultsCard.hidden = false;
    latencyHistogram(els.chartLatency, allResults());
    aliveDonut(els.chartAlive, allResults());
    protocolDonut(els.chartProtocol, allResults());
    countryBars(els.chartCountry, allResults());
  }
  const alive = rows.filter((r) => r.alive).length;
  els.meta.textContent = `Showing ${fmtNum(rows.length)} of ${fmtNum(allResults().length)} results · ${fmtNum(alive)} alive in view`;
  refreshFilterOptions(els.f);
  const authed = allResults().some((r) => r.hasAuth);
  exportUi.syncCredNote(authed, state.demo);
  els.recheckSel.disabled = state.selected.size === 0 || !state.jobId;
  els.recheckFailed.disabled = !state.jobId || !allResults().some((r) => !r.alive);
}

const table = createTable({
  scroller: els.scroller, spacer: els.spacer, empty: els.empty, header: els.header, state,
});
table.onOpenRow((seq) => openDrawer(els.drawer, seq));

// ------------------------------------------------------------ live handling
function handleResults(rows, opts) {
  upsertResults(rows, opts);
  if (state.openSeq != null && !opts?.merge) {
    const r = state.results[state.openSeq];
    if (r) import('./detail.js').then((m) => m.renderDetail(els.drawer.body, r));
  }
  scheduleUpdate();
}

function subscribe(jobId) {
  if (live) live.stop();
  state.jobId = jobId;
  live = subscribeJob(jobId, {
    onSnapshot: (snap) => {
      state.snapshot = { ...(state.snapshot || {}), ...snap };
      renderProgress(els.progress, state.snapshot, Boolean(live));
    },
    onResults: handleResults,
    onGeo: (updates) => {
      applyGeo(updates);
      if (state.openSeq != null) {
        const r = state.results[state.openSeq];
        if (r) import('./detail.js').then((m) => m.renderDetail(els.drawer.body, r));
      }
      scheduleUpdate();
    },
    onDone: (snap) => {
      state.snapshot = snap;
      doUpdate();
      const alive = snap.counts ? snap.counts.alive : 0;
      toast(els.toasts, `Job ${snap.status}: ${fmtNum(alive)} alive of ${fmtNum(snap.total)}.`, snap.status === 'completed' ? 'ok' : '');
      live = null;
      els.recheckSel.disabled = state.selected.size === 0;
    },
    onError: () => {},
  }, {
    onStatus: (s) => {
      els.connDot.className = `conn-dot ${s === 'live' ? 'on' : ''}`;
      els.connLabel.textContent = s === 'live' ? 'Live stream connected'
        : s === 'polling' ? 'Polling updates' : 'Reconnecting…';
    },
  });
}

// ----------------------------------------------------------------- actions
async function startCheck() {
  const text = els.input.value;
  if (!text.trim()) {
    toast(els.toasts, 'Paste some proxies first — one per line.', 'err');
    els.input.focus();
    return;
  }
  const payload = {
    text,
    protocol: els.protocol.value,
    timeout: Number(els.timeout.value) * 1000,
    concurrency: Number(els.concurrency.value),
    retries: Number(els.retries.value),
    httpsTest: els.https.checked,
  };
  state.lastStartPayload = payload;
  els.start.disabled = true;
  els.start.textContent = 'QUEUING…';
  try {
    const res = await api.startCheck(payload);
    if (state.demo) exitDemo();
    resetResults();
    els.connDot.className = 'conn-dot';
    els.connLabel.textContent = 'Connecting…';
    state.snapshot = { id: res.jobId, status: 'queued', total: res.total, checked: 0, counts: { alive: 0, timeout: 0, refused: 0, auth: 0, other: 0 } };
    scheduleUpdate(true);
    subscribe(res.jobId);
    const dupNote = res.duplicatesRemoved ? ` ${fmtNum(res.duplicatesRemoved)} duplicates removed.` : '';
    const invNote = res.invalidCount ? ` ${fmtNum(res.invalidCount)} invalid lines skipped.` : '';
    toast(els.toasts, `Job started: ${fmtNum(res.total)} unique proxies.${dupNote}${invNote}`, 'ok');
  } catch (e) {
    if (e.details && e.details.parse) {
      toast(els.toasts, `${e.message} (${fmtNum(e.details.parse.invalidCount || 0)} invalid lines)`, 'err');
    } else {
      toast(els.toasts, e.message || 'Failed to start check.', 'err');
    }
  } finally {
    els.start.disabled = false;
    els.start.textContent = 'START CHECK';
  }
}

function exitDemo() {
  state.demo = false;
  els.demoBanner.classList.remove('active');
  els.demo.disabled = false;
}

function loadDemo() {
  if (live) { live.stop(); live = null; }
  resetResults();
  exitDemo();
  state.demo = true;
  state.snapshot = {
    id: 'demo', status: 'completed', total: 600, checked: 600,
    counts: { alive: 0, timeout: 0, refused: 0, auth: 0, other: 0 },
  };
  upsertResults(generateDemoResults(600));
  els.demoBanner.classList.add('active');
  els.demo.disabled = true;
  els.connLabel.textContent = 'Demo mode (no live job)';
  doUpdate();
  toast(els.toasts, 'Demo data loaded — generated sample results, not live checks.');
}

async function recheck(body, label) {
  if (!state.jobId || state.demo) {
    toast(els.toasts, 'Recheck requires a live server job.', 'err');
    return;
  }
  try {
    const res = await api.recheck(state.jobId, body);
    resetResults();
    els.connLabel.textContent = 'Connecting…';
    state.snapshot = { id: res.jobId, status: 'queued', total: res.total, checked: 0, counts: { alive: 0, timeout: 0, refused: 0, auth: 0, other: 0 } };
    subscribe(res.jobId);
    scheduleUpdate(true);
    toast(els.toasts, `${label}: new job ${res.jobId} (${fmtNum(res.total)} proxies).`, 'ok');
  } catch (e) {
    toast(els.toasts, e.message || 'Recheck failed.', 'err');
  }
}

// ------------------------------------------------------------------ wiring
els.start.addEventListener('click', startCheck);
els.input.addEventListener('input', debounce(() => {
  const s = summarize(els.input.value);
  els.parseSummary.innerHTML = !s.totalLines ? '' :
    `<span>Lines: <b>${fmtNum(s.totalLines)}</b></span>` +
    `<span>Unique: <b>${fmtNum(s.unique)}</b></span>` +
    `<span>Duplicates: <b>${fmtNum(s.duplicates)}</b></span>` +
    (s.invalid ? `<span class="invalid">Invalid: <b>${fmtNum(s.invalid)}</b></span>` : '');
}, 180));

els.clear.addEventListener('click', () => {
  els.input.value = '';
  els.parseSummary.innerHTML = '';
  els.input.focus();
});

els.upload.addEventListener('click', () => els.file.click());
els.file.addEventListener('change', async () => {
  const f = els.file.files && els.file.files[0];
  if (!f) return;
  if (f.size > 20 * 1024 * 1024) {
    toast(els.toasts, 'File too large (limit 20 MB).', 'err');
    els.file.value = '';
    return;
  }
  const text = await f.text();
  els.input.value = text;
  els.input.dispatchEvent(new Event('input'));
  toast(els.toasts, `Loaded ${f.name} (${fmtNum(text.split('\n').length)} lines).`, 'ok');
  els.file.value = '';
});

// drag & drop
document.addEventListener('dragover', (e) => { e.preventDefault(); els.input.classList.add('dropzone-active'); });
document.addEventListener('dragleave', (e) => {
  if (e.target === document || e.relatedTarget === null) els.input.classList.remove('dropzone-active');
});
document.addEventListener('drop', async (e) => {
  e.preventDefault();
  els.input.classList.remove('dropzone-active');
  const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (!f) return;
  if (!/\.(txt|csv|list|log)$/i.test(f.name) && f.type !== 'text/plain') {
    toast(els.toasts, 'Only plain-text (.txt) proxy lists are accepted.', 'err');
    return;
  }
  if (f.size > 20 * 1024 * 1024) {
    toast(els.toasts, 'File too large (limit 20 MB).', 'err');
    return;
  }
  const text = await f.text();
  els.input.value = text;
  els.input.dispatchEvent(new Event('input'));
  toast(els.toasts, `Loaded ${esc(f.name)}.`, 'ok');
});

els.demo.addEventListener('click', loadDemo);

els.progress.pause.addEventListener('click', async () => {
  if (!state.jobId) return;
  try { state.snapshot = await api.pause(state.jobId); doUpdate(); } catch (e) { toast(els.toasts, e.message, 'err'); }
});
els.progress.resume.addEventListener('click', async () => {
  if (!state.jobId) return;
  try { state.snapshot = await api.resume(state.jobId); doUpdate(); } catch (e) { toast(els.toasts, e.message, 'err'); }
});
els.progress.cancel.addEventListener('click', async () => {
  if (!state.jobId) return;
  try { state.snapshot = await api.cancel(state.jobId); doUpdate(); } catch (e) { toast(els.toasts, e.message, 'err'); }
});
els.progress.restart.addEventListener('click', () => {
  if (state.lastStartPayload) {
    els.input.value = state.lastStartPayload.text;
    startCheck();
  }
});

// filters
const filterEls = { status: els.f.status, protocol: els.f.protocol, speed: els.f.speed, https: els.f.https, anon: els.f.anon, auth: els.f.auth, country: els.f.country, asn: els.f.asn, q: els.f.q };
const bindFilter = (el, key) => el.addEventListener('input', () => { state.filters[key] = el.value; scheduleUpdate(true); });
Object.entries({ status: 'status', protocol: 'protocol', speed: 'speed', https: 'https', anon: 'anonymity', auth: 'auth', country: 'country', asn: 'asn', q: 'q' }).forEach(([elKey, fKey]) => bindFilter(filterEls[elKey], fKey));
els.f.clear.addEventListener('click', () => resetFilters(filterEls));

// sorting
els.header.addEventListener('click', (e) => {
  const cell = e.target.closest('.h-cell[data-sort]');
  if (!cell) return;
  const key = cell.dataset.sort;
  state.sort = state.sort.key === key
    ? { key, dir: state.sort.dir === 'asc' ? 'desc' : 'asc' }
    : { key, dir: 'asc' };
  updateSortHeader(els.header, state.sort);
  scheduleUpdate(true);
});
els.header.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    const cell = e.target.closest('.h-cell[data-sort]');
    if (cell) { e.preventDefault(); cell.click(); }
  }
});

els.selectAll.addEventListener('change', () => {
  const rows = applyFilters(allResults());
  if (els.selectAll.checked) rows.forEach((r) => state.selected.add(r.seq));
  else rows.forEach((r) => state.selected.delete(r.seq));
  scheduleUpdate(true);
});

// drawer
const closeDrawerFn = () => closeDrawer(els.drawer);
els.drawer.close.addEventListener('click', closeDrawerFn);
els.drawer.backdrop.addEventListener('click', closeDrawerFn);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (els.drawer.classList.contains('open')) closeDrawerFn();
    if (els.exportModal.modal.classList.contains('open')) els.exportModal.modal.classList.remove('open');
  }
});
els.drawer.copy.addEventListener('click', async () => {
  const r = state.openSeq != null ? state.results[state.openSeq] : null;
  if (!r) return;
  try {
    await navigator.clipboard.writeText(`${r.host}:${r.port}`);
    toast(els.toasts, 'Copied host:port to clipboard.', 'ok');
  } catch { toast(els.toasts, 'Clipboard unavailable.', 'err'); }
});
els.drawer.export.addEventListener('click', () => {
  els.exportModal.modal.classList.add('open');
});
els.drawer.recheck.addEventListener('click', () => {
  if (state.openSeq != null) {
    closeDrawerFn();
    recheck({ scope: 'selected', keys: [state.openSeq] }, 'Recheck proxy');
  }
});

els.recheckSel.addEventListener('click', () => recheck({ scope: 'selected', keys: [...state.selected] }, `Rechecking ${state.selected.size} selected`));
els.recheckFailed.addEventListener('click', () => recheck({ scope: 'failed' }, 'Rechecking failed proxies'));

// export modal
const exportUi = wireExportModal({
  els: els.exportModal,
  api,
  toastEl: els.toasts,
  jobId: () => state.jobId,
  hasAuthResults: false,
  isDemo: state.demo,
});
els.exportBtn.addEventListener('click', () => els.exportModal.modal.classList.add('open'));

window.addEventListener('beforeunload', (e) => {
  if (live && state.snapshot && ['running', 'paused', 'queued'].includes(state.snapshot.status)) {
    e.preventDefault();
    e.returnValue = '';
  }
});

// -------------------------------------------------------------------- boot
(async function boot() {
  try {
    cfg = await api.config();
    els.timeout.value = cfg.defaults.timeoutMs / 1000;
    els.concurrency.value = cfg.defaults.concurrency;
    els.retries.value = cfg.defaults.retries;
    els.timeout.max = cfg.limits.timeoutMs[1] / 1000;
    els.concurrency.max = cfg.limits.concurrency[1];
    els.retries.max = cfg.limits.retries[1];
    els.startHint.textContent = `Limits: up to ${fmtNum(cfg.limits.maxProxiesPerJob)} proxies per job · up to ${cfg.limits.activeJobsPerIp} active jobs per client`;
    await api.health();
    els.connDot.className = 'conn-dot on';
    els.connLabel.textContent = 'API connected';
  } catch {
    els.connDot.className = 'conn-dot off';
    els.connLabel.textContent = 'API unreachable — is the server running?';
  }
})();
