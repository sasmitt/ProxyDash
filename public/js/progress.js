/** Progress card rendering. */

import { fmtEta, fmtMs, fmtNum } from './util.js';

export function renderProgress(els, snapshot, jobActive) {
  if (!snapshot) return;
  const pct = snapshot.total ? Math.min(100, Math.round((snapshot.checked / snapshot.total) * 100)) : 0;
  els.card.classList.add('active');
  els.pct.textContent = `${pct}%`;
  els.count.textContent = `${fmtNum(snapshot.checked)} / ${fmtNum(snapshot.total)} checked`;
  els.fill.style.width = `${pct}%`;
  els.bar.setAttribute('aria-valuenow', String(pct));

  const c = snapshot.counts;
  const dead = snapshot.checked - c.alive;
  const errors = dead - c.timeout - c.refused - c.auth;
  els.alive.textContent = fmtNum(c.alive);
  els.dead.textContent = fmtNum(Math.max(dead - c.timeout, 0));
  els.timeout.textContent = fmtNum(c.timeout);
  els.errors.textContent = fmtNum(Math.max(errors, 0));
  els.avg.textContent = snapshot.avgLatencyMs != null ? fmtMs(snapshot.avgLatencyMs) : '—';
  els.eta.textContent = fmtEta(snapshot.etaMs);
  els.conc.textContent = snapshot.concurrency ? snapshot.concurrency.current : '0';

  const statusText = {
    queued: 'Queued…',
    running: jobActive ? 'Checking…' : 'Checking…',
    paused: 'Paused',
    completed: 'Completed',
    cancelled: 'Cancelled',
    failed: 'Failed',
  }[snapshot.status] || snapshot.status;
  els.status.textContent = statusText + (snapshot.degraded && snapshot.status === 'running' ? ' · test targets unreachable from server, partial verification only' : '');
  els.heading.textContent = snapshot.status === 'completed' ? 'Check complete'
    : snapshot.status === 'cancelled' ? 'Check cancelled'
      : snapshot.status === 'paused' ? 'Check paused' : 'Checking proxies…';
  els.jobId.textContent = `job: ${snapshot.id}`;

  els.pause.disabled = snapshot.status !== 'running';
  els.resume.disabled = snapshot.status !== 'paused';
  els.cancel.disabled = !['running', 'paused', 'queued'].includes(snapshot.status);
  els.restart.disabled = !['completed', 'cancelled', 'failed'].includes(snapshot.status);
}
