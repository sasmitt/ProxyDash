/** API client: REST + Server-Sent Events with automatic polling fallback. */

async function handle(res) {
  let body = null;
  try { body = await res.json(); } catch { /* non-JSON error */ }
  if (!res.ok) {
    const err = new Error(body && body.error ? body.error.message : `HTTP ${res.status}`);
    err.code = body && body.error ? body.error.code : 'HTTP_ERROR';
    err.status = res.status;
    err.details = body;
    throw err;
  }
  return body;
}

export const api = {
  config: () => fetch('/api/config').then(handle),
  health: () => fetch('/api/health').then(handle),

  startCheck(payload) {
    return fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }).then(handle);
  },

  job: (id) => fetch(`/api/jobs/${encodeURIComponent(id)}`).then(handle),
  results: (id, params) => fetch(`/api/jobs/${encodeURIComponent(id)}/results?${new URLSearchParams(params)}`).then(handle),
  cancel: (id) => fetch(`/api/jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST' }).then(handle),
  pause: (id) => fetch(`/api/jobs/${encodeURIComponent(id)}/pause`, { method: 'POST' }).then(handle),
  resume: (id) => fetch(`/api/jobs/${encodeURIComponent(id)}/resume`, { method: 'POST' }).then(handle),
  recheck: (id, body) => fetch(`/api/jobs/${encodeURIComponent(id)}/recheck`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).then(handle),

  exportUrl(id, params) {
    return `/api/jobs/${encodeURIComponent(id)}/export?${new URLSearchParams(params)}`;
  },
};

/**
 * Subscribe to a job's live events.
 * Uses SSE; if EventSource errors before delivering anything (or the proxy
 * strips streams), falls back to REST polling so the UI still updates.
 */
export function subscribeJob(jobId, handlers, { onStatus }) {
  let es = null;
  let pollTimer = null;
  let lastSeq = -1;
  let gotAnySse = false;
  let closed = false;

  const mergeResults = (results) => {
    if (!results || !results.length) return;
    lastSeq = Math.max(lastSeq, results[results.length - 1].seq);
    handlers.onResults(results);
  };

  const pollOnce = async () => {
    try {
      // robust approach: pull the bounded result set each poll and merge
      const all = await api.results(jobId, { limit: 5000, offset: 0, sort: 'seq' });
      if (all.rows && all.rows.length) {
        const fresh = all.rows.filter((r) => r.seq > lastSeq);
        mergeResults(fresh);
        handlers.onResults(all.rows.filter((r) => r.seq <= lastSeq), { merge: true });
      }
      handlers.onSnapshot(all.snapshot);
      if (['completed', 'cancelled', 'failed'].includes(all.snapshot.status)) {
        stop();
        handlers.onDone(all.snapshot);
        return;
      }
    } catch (e) {
      if (handlers.onError) handlers.onError(e);
    }
    if (!closed) pollTimer = setTimeout(pollOnce, 1200);
  };

  const startPolling = () => {
    if (pollTimer || closed) return;
    onStatus && onStatus('polling');
    pollOnce();
  };

  try {
    es = new EventSource(`/api/jobs/${encodeURIComponent(jobId)}/events`);
    es.addEventListener('open', () => { gotAnySse = true; onStatus && onStatus('live'); });
    es.addEventListener('snapshot', (ev) => {
      const d = JSON.parse(ev.data);
      handlers.onSnapshot(d.snapshot);
    });
    es.addEventListener('results', (ev) => {
      gotAnySse = true;
      const d = JSON.parse(ev.data);
      mergeResults(d.results);
      handlers.onTotal && handlers.onTotal(d.total);
    });
    es.addEventListener('geo', (ev) => {
      const d = JSON.parse(ev.data);
      handlers.onGeo(d.updates);
    });
    es.addEventListener('status', (ev) => {
      handlers.onSnapshot({ status: JSON.parse(ev.data).status });
    });
    es.addEventListener('start', (ev) => {
      const d = JSON.parse(ev.data);
      handlers.onStart && handlers.onStart(d);
    });
    es.addEventListener('done', (ev) => {
      const d = JSON.parse(ev.data);
      handlers.onSnapshot(d.snapshot);
      handlers.onDone(d.snapshot);
      stop();
    });
    es.addEventListener('error', () => {
      // EventSource auto-reconnects; if the stream never worked, poll instead
      if (!gotAnySse) startPolling();
      else onStatus && onStatus('reconnecting');
    });
  } catch {
    startPolling();
  }

  // watchdog: if no SSE message arrives shortly after connect, fall back
  const watchdog = setTimeout(() => { if (!gotAnySse) startPolling(); }, 4000);

  function stop() {
    closed = true;
    clearTimeout(watchdog);
    if (es) es.close();
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
  }

  return { stop };
}
