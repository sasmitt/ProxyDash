'use strict';
/**
 * Geolocation enrichment for exit IPs.
 *
 * - Batched provider requests (ip-api /batch) with a client-side rate limit.
 * - LRU+TTL cache shared across jobs so repeated lookups cost nothing.
 * - Per-IP fallback provider when the batch provider is unavailable.
 * - Never throws at the caller; unavailable data is reported as state
 *   'unavailable' and the UI displays "Unknown".
 */
const http = require('http');
const https = require('https');
const config = require('../config');
const logger = require('../logger');
const { classifyAddress } = require('../validation');

const EMPTY_GEO = () => ({
  state: 'unavailable',
  country: null,
  countryCode: null,
  region: null,
  city: null,
  latitude: null,
  longitude: null,
  timezone: null,
  asn: null,
  asOrg: null,
  isp: null,
  org: null,
  reverse: null,
  source: null,
});

function fetchRaw(url, { method = 'GET', body = null, headers = {}, timeoutMs = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(url);
    } catch (e) {
      return reject(e);
    }
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, { method, headers, timeout: timeoutMs }, (res) => {
      const chunks = [];
      let len = 0;
      res.on('data', (d) => {
        len += d.length;
        if (len > 2 * 1024 * 1024) { req.destroy(); reject(new Error('response too large')); return; }
        chunks.push(d);
      });
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function normalizeIpApi(item) {
  if (!item || item.status !== 'success') return null;
  const geo = { ...EMPTY_GEO(), state: 'ok', source: 'ip-api' };
  geo.country = item.country || null;
  geo.countryCode = item.countryCode || null;
  geo.region = item.regionName || null;
  geo.city = item.city || null;
  if (Number.isFinite(item.lat)) geo.latitude = item.lat;
  if (Number.isFinite(item.lon)) geo.longitude = item.lon;
  geo.timezone = item.timezone || null;
  if (typeof item.as === 'string' && item.as) {
    const m = /^(AS\d+)\s*(.*)$/.exec(item.as);
    geo.asn = m ? m[1] : item.as.split(' ')[0];
    geo.asOrg = m && m[2] ? m[2] : item.as;
  }
  geo.isp = item.isp || item.org || null;
  geo.org = item.org || null;
  geo.reverse = item.reverse || null;
  return geo;
}

function normalizeIpWho(j) {
  if (!j || j.success === false || !j.ip) return null;
  const geo = { ...EMPTY_GEO(), state: 'ok', source: 'ipwho.is' };
  geo.country = j.country || null;
  geo.countryCode = j.country_code || null;
  geo.region = j.region || null;
  geo.city = j.city || null;
  if (Number.isFinite(j.latitude)) geo.latitude = j.latitude;
  if (Number.isFinite(j.longitude)) geo.longitude = j.longitude;
  geo.timezone = j.timezone && j.timezone.id ? j.timezone.id : null;
  const c = j.connection || {};
  if (c.asn != null) geo.asn = `AS${c.asn}`;
  geo.asOrg = c.org || null;
  geo.isp = c.isp || c.org || null;
  geo.org = c.org || null;
  geo.reverse = j.domain ? j.domain : null;
  return geo;
}

class GeoClient {
  constructor(cfg = config.geo) {
    this.cfg = cfg;
    this.cache = new Map(); // ip -> {geo, expires}
    this.pending = new Map(); // ip -> {cbs: []}
    this.rateStamps = [];
    this.timer = null;
    this.stopped = false;
    this.stats = { requests: 0, batchFailures: 0, fallbackUsed: 0 };
  }

  /** Register interest in an IP. cb is invoked once with the geo result. */
  lookup(ip, cb) {
    if (!ip || this.stopped || !this.cfg.enabled) return cb({ ...EMPTY_GEO() });
    const c = classifyAddress(ip);
    if (c.isBlocked || c.kind !== 'public') {
      return cb({ ...EMPTY_GEO(), state: 'skipped' });
    }
    const hit = this.cache.get(ip);
    const now = Date.now();
    if (hit && hit.expires > now) return cb(hit.geo);
    if (hit) this.cache.delete(ip);

    let entry = this.pending.get(ip);
    if (!entry) {
      entry = { cbs: [] };
      this.pending.set(ip, entry);
      this.scheduleFlush();
    }
    entry.cbs.push(cb);
  }

  scheduleFlush() {
    if (this.timer || this.stopped) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      this.flush();
    }, this.cfg.batchFlushMs);
    this.timer.unref();
  }

  underRateLimit() {
    const now = Date.now();
    this.rateStamps = this.rateStamps.filter((t) => now - t < 60 * 1000);
    return this.rateStamps.length < this.cfg.maxRequestsPerMin;
  }

  async flush() {
    if (this.stopped || this.pending.size === 0) return;
    if (!this.underRateLimit()) {
      this.timer = setTimeout(() => { this.timer = null; this.flush(); }, 1500);
      this.timer.unref();
      return;
    }
    // Take ownership of the batch entries (callbacks travel with them).
    const taken = new Map(); // ip -> {cbs}
    for (const ip of [...this.pending.keys()].slice(0, this.cfg.batchSize)) {
      taken.set(ip, this.pending.get(ip));
      this.pending.delete(ip);
    }
    const batch = [...taken.keys()];

    let results = null;
    try {
      this.rateStamps.push(Date.now());
      this.stats.requests++;
      const body = JSON.stringify(batch.map((query) => ({ query, lang: 'en', fields: 'status,message,query,country,countryCode,region,regionName,city,lat,lon,timezone,as,org,isp,reverse,mobile,proxy,hosting' })));
      const res = await fetchRaw(this.cfg.providerUrl, {
        method: 'POST',
        body,
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'ProxyCheck/1.0' },
        timeoutMs: this.cfg.requestTimeoutMs,
      });
      if (res.status !== 200) throw new Error(`provider status ${res.status}`);
      const arr = JSON.parse(res.text);
      if (!Array.isArray(arr)) throw new Error('unexpected provider payload');
      results = new Map();
      for (const item of arr) {
        const geo = normalizeIpApi(item);
        if (geo) results.set(item.query, geo);
      }
    } catch (err) {
      this.stats.batchFailures++;
      logger.debug('geo batch failed, falling back per-IP', { error: err.message });
    }

    const missing = [];
    for (const ip of batch) {
      const geo = results && results.get(ip);
      if (geo) this.deliver(ip, geo, taken.get(ip));
      else missing.push(ip);
    }
    if (missing.length) await this.fallbackMany(missing, taken);

    if (this.pending.size) this.scheduleFlush();
  }

  async fallbackMany(ips, taken = null, concurrency = 4) {
    let idx = 0;
    const workers = Array.from({ length: Math.min(concurrency, ips.length) }, async () => {
      while (idx < ips.length && !this.stopped) {
        const ip = ips[idx++];
        const geo = await this.fallbackOne(ip).catch(() => null);
        this.stats.fallbackUsed++;
        this.deliver(ip, geo || { ...EMPTY_GEO() }, taken ? taken.get(ip) : undefined);
      }
    });
    await Promise.all(workers);
  }

  async fallbackOne(ip) {
    if (!this.underRateLimit()) return null;
    this.rateStamps.push(Date.now());
    const url = this.cfg.fallbackUrl.replace('{ip}', encodeURIComponent(ip));
    const res = await fetchRaw(url, {
      headers: { 'User-Agent': 'ProxyCheck/1.0', Accept: 'application/json' },
      timeoutMs: this.cfg.requestTimeoutMs,
    });
    if (res.status !== 200) return null;
    return normalizeIpWho(JSON.parse(res.text));
  }

  deliver(ip, geo, entry) {
    if (!entry) entry = this.pending.get(ip);
    this.pending.delete(ip);
    const ttl = geo && geo.state === 'ok' ? this.cfg.ttlMs : this.cfg.negativeTtlMs;
    this.cache.set(ip, { geo, expires: Date.now() + ttl });
    if (this.cache.size > this.cfg.maxCacheEntries) {
      const first = this.cache.keys().next().value;
      this.cache.delete(first);
    }
    if (entry) for (const cb of entry.cbs) { try { cb(geo); } catch { /* cb errors must not break others */ } }
  }

  snapshot() {
    return { cacheSize: this.cache.size, queueSize: this.pending.size, ...this.stats };
  }

  stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
  }
}

module.exports = { GeoClient, EMPTY_GEO, normalizeIpApi, normalizeIpWho, fetchRaw };
