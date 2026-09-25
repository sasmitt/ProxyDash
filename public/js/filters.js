/** Filter toolbar logic (mirrors the server-side filter semantics). */

import { state, allResults, notify } from './state.js';

export function applyFilters(results, f = state.filters, sort = state.sort) {
  let out = results.filter((r) => {
    if (f.status !== 'all' && r.status !== f.status) return false;
    if (f.protocol !== 'all' && r.protocol !== f.protocol) return false;
    if (f.https === 'supported' && !(r.https && r.https.supported === true)) return false;
    if (f.https === 'failed' && !(r.https && r.https.supported === false)) return false;
    if (f.anonymity !== 'all' && r.anonymity.level !== f.anonymity) return false;
    if (f.auth === 'required' && !(r.auth.required || r.hasAuth)) return false;
    if (f.auth === 'no' && (r.auth.required || r.hasAuth)) return false;
    if (f.auth === 'failed' && r.auth.ok !== false) return false;
    if (f.speed === 'fast' && !(r.alive && r.latency.totalMs != null && r.latency.totalMs <= 300)) return false;
    if (f.speed === 'moderate' && !(r.alive && r.latency.totalMs > 300 && r.latency.totalMs <= 700)) return false;
    if (f.speed === 'slow' && !(r.alive && r.latency.totalMs > 700)) return false;
    if (f.country) {
      const g = r.geo || {};
      if (!`${g.country || ''} ${g.countryCode || ''}`.toLowerCase().includes(f.country.toLowerCase())) return false;
    }
    if (f.asn && !String((r.geo && r.geo.asn) || '').toLowerCase().includes(f.asn.toLowerCase())) return false;
    if (f.q) {
      const g = r.geo || {};
      const hay = [r.input, r.host, r.exitIp, r.protocol, g.country, g.countryCode, g.city, g.asn, g.isp]
        .filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(f.q.toLowerCase())) return false;
    }
    return true;
  });

  const dir = sort.dir === 'desc' ? -1 : 1;
  const get = (r) => {
    switch (sort.key) {
      case 'latency': return r.latency.totalMs == null ? Infinity : r.latency.totalMs;
      case 'input': return r.input.toLowerCase();
      case 'exitIp': return r.exitIp || '~';
      case 'country': return (r.geo && (r.geo.country || r.geo.countryCode)) || '~';
      case 'checkedAt': return r.checkedAt;
      case 'httpStatus': return r.httpStatus || 0;
      case 'protocol': return r.protocol || '~';
      default: return r.seq;
    }
  };
  out = out.map((r, idx) => [r, idx]);
  out.sort((a, b) => {
    const x = get(a[0]); const y = get(b[0]);
    return (x < y ? -1 : x > y ? 1 : a[1] - b[1]) * dir;
  });
  return out.map((p) => p[0]);
}

/** Populate country / ASN dropdowns from results (top values). */
export function refreshFilterOptions(els) {
  const counts = { country: new Map(), asn: new Map() };
  for (const r of allResults()) {
    if (r.geo && r.geo.country) {
      const key = r.geo.countryCode || r.geo.country;
      counts.country.set(key, (counts.country.get(key) || 0) + 1);
    }
    if (r.geo && r.geo.asn) counts.asn.set(r.geo.asn, (counts.asn.get(r.geo.asn) || 0) + 1);
  }
  fillSelect(els.country, counts.country, 60);
  fillSelect(els.asn, counts.asn, 60);
}

function fillSelect(sel, counts, max) {
  const cur = sel.value;
  const opts = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, max);
  sel.innerHTML = '<option value="">All</option>' + opts.map(([v]) => `<option value="${v.replace(/"/g, '&quot;')}">${v}</option>`).join('');
  if ([...counts.keys()].includes(cur)) sel.value = cur;
}

export function resetFilters(els) {
  state.filters = { status: 'all', protocol: 'all', speed: 'all', https: 'all', anonymity: 'all', auth: 'all', country: '', asn: '', q: '' };
  els.status.value = 'all';
  els.protocol.value = 'all';
  els.speed.value = 'all';
  els.https.value = 'all';
  els.anon.value = 'all';
  els.auth.value = 'all';
  els.country.value = '';
  els.asn.value = '';
  els.q.value = '';
  notify('filters');
}
