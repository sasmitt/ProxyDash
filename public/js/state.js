/** Central client state with a tiny pub/sub. */

export const state = {
  jobId: null,
  snapshot: null,
  results: [], // indexed by seq
  selected: new Set(),
  filters: {
    status: 'all', protocol: 'all', speed: 'all', https: 'all',
    anonymity: 'all', auth: 'all', country: '', asn: '', q: '',
  },
  sort: { key: 'seq', dir: 'asc' },
  demo: false,
  lastStartPayload: null,
  openSeq: null, // seq currently open in the drawer
};

const listeners = new Set();
export function subscribe(fn) { listeners.add(fn); }
export function notify(topic) { for (const fn of listeners) fn(topic); }

export function resetResults() {
  state.results = [];
  state.selected.clear();
  state.snapshot = null;
  state.jobId = null;
}

export function upsertResults(rows, { merge = false } = {}) {
  for (const r of rows) {
    if (merge && state.results[r.seq]) {
      // polling merge: take the fresher copy but keep geo if the new one lacks it
      const old = state.results[r.seq];
      state.results[r.seq] = { ...old, ...r, geo: r.geo && r.geo.state !== 'pending' ? r.geo : old.geo };
    } else {
      state.results[r.seq] = r;
    }
  }
}

export function applyGeo(updates) {
  for (const u of updates) {
    const r = state.results[u.seq];
    if (r) r.geo = u.geo;
  }
}

export function allResults() {
  return state.results.filter(Boolean);
}
