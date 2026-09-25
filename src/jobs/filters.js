'use strict';
/**
 * Shared filter/sort engine for result queries and exports.
 * A single implementation keeps /results and /export perfectly consistent.
 */

const PROTOCOLS = new Set(['http', 'https', 'socks4', 'socks4a', 'socks5']);
const ANONYMITY = new Set(['transparent', 'anonymous', 'elite', 'unknown']);

function parseQuery(q = {}) {
  return {
    status: q.status === 'alive' || q.status === 'dead' ? q.status : 'all',
    protocol: PROTOCOLS.has(q.protocol) ? q.protocol : 'all',
    https: q.https === 'supported' || q.https === 'failed' ? q.https : 'all',
    anonymity: ANONYMITY.has(q.anonymity) ? q.anonymity : 'all',
    auth: q.auth === 'required' || q.auth === 'no' || q.auth === 'failed' ? q.auth : 'all',
    speed: q.speed === 'fast' || q.speed === 'slow' || q.speed === 'moderate' ? q.speed : 'all',
    aliveOnly: q.aliveOnly === 'true' || q.aliveOnly === true,
    country: typeof q.country === 'string' ? q.country.slice(0, 80) : null,
    asn: typeof q.asn === 'string' ? q.asn.slice(0, 40) : null,
    isp: typeof q.isp === 'string' ? q.isp.slice(0, 120) : null,
    q: typeof q.q === 'string' ? q.q.slice(0, 120).toLowerCase() : null,
    maxLatencyMs: Number.isFinite(Number(q.maxLatencyMs)) ? Number(q.maxLatencyMs) : null,
  };
}

function match(result, f) {
  if (f.status !== 'all' && result.status !== f.status) return false;
  if (f.aliveOnly && !result.alive) return false;
  if (f.protocol !== 'all' && result.protocol !== f.protocol) return false;
  if (f.https === 'supported' && !(result.https && result.https.supported === true)) return false;
  if (f.https === 'failed' && !(result.https && result.https.supported === false)) return false;
  if (f.anonymity !== 'all' && result.anonymity.level !== f.anonymity) return false;
  if (f.auth === 'required' && !(result.auth.required || result.hasAuth)) return false;
  if (f.auth === 'no' && (result.auth.required || result.hasAuth)) return false;
  if (f.auth === 'failed' && result.auth.ok !== false) return false;
  if (f.speed === 'fast' && !(result.alive && result.latency.totalMs != null && result.latency.totalMs <= 300)) return false;
  if (f.speed === 'moderate' && !(result.alive && result.latency.totalMs > 300 && result.latency.totalMs <= 700)) return false;
  if (f.speed === 'slow' && !(result.alive && result.latency.totalMs > 700)) return false;
  if (f.maxLatencyMs != null && !(result.alive && result.latency.totalMs != null && result.latency.totalMs <= f.maxLatencyMs)) return false;
  if (f.country) {
    const g = result.geo || {};
    const c = `${g.country || ''} ${g.countryCode || ''}`.toLowerCase();
    if (!c.includes(f.country.toLowerCase())) return false;
  }
  if (f.asn && !String((result.geo && result.geo.asn) || '').toLowerCase().includes(f.asn.toLowerCase())) return false;
  if (f.isp && !String((result.geo && result.geo.isp) || '').toLowerCase().includes(f.isp.toLowerCase())) return false;
  if (f.q) {
    const g = result.geo || {};
    const hay = [
      result.input, result.host, result.exitIp, result.protocol,
      g.country, g.countryCode, g.city, g.asn, g.isp,
    ].filter(Boolean).join(' ').toLowerCase();
    if (!hay.includes(f.q)) return false;
  }
  return true;
}

const SORTABLE = new Set(['seq', 'latency', 'input', 'exitIp', 'country', 'checkedAt', 'httpStatus', 'protocol']);

function sortResults(rows, sort = 'seq', dir = 'asc') {
  if (!SORTABLE.has(sort)) return rows;
  const mul = dir === 'desc' ? -1 : 1;
  const get = (r) => {
    switch (sort) {
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
  return [...rows].sort((a, b) => {
    const x = get(a);
    const y = get(b);
    if (x < y) return -1 * mul;
    if (x > y) return 1 * mul;
    return a.seq - b.seq;
  });
}

/** Apply filters + sort + paging. Returns {rows, total, filtered} */
function queryResults(results, q) {
  const f = parseQuery(q);
  const filtered = results.filter((r) => match(r, f));
  const sorted = sortResults(filtered, q.sort, q.dir === 'desc' ? 'desc' : 'asc');
  const limit = Math.min(Math.max(Number(q.limit) || 500, 1), 5000);
  const offset = Math.max(Number(q.offset) || 0, 0);
  return {
    rows: sorted.slice(offset, offset + limit),
    total: results.length,
    filtered: filtered.length,
  };
}

module.exports = { parseQuery, match, sortResults, queryResults, SORTABLE };
