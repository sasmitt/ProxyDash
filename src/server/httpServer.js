'use strict';
/**
 * HTTP API + static file server (zero dependencies).
 *
 * Security posture:
 * - strict CSP and hardening headers (no inline script/style allowed)
 * - JSON body size cap and type checks
 * - per-IP token-bucket rate limiting + job-creation limits
 * - SSRF guard is enforced inside the checker itself (see src/validation.js)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const config = require('../config');
const logger = require('../logger');
const { ApiError } = require('../errors');
const { queryResults, parseQuery } = require('../jobs/filters');
const { formatExport } = require('../jobs/exporter');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2',
  '.webmanifest': 'application/manifest+json',
};

// ---------------------------------------------------------------- rate limit
class RateLimiter {
  constructor() {
    this.buckets = new Map(); // key -> {tokens, last}
    this.jobStamps = new Map(); // key -> [timestamps]
    this.sweep = setInterval(() => this.sweepOld(), 5 * 60 * 1000);
    this.sweep.unref();
  }

  bucketKey(req) {
    return (config.trustProxy && req.headers['x-forwarded-for'])
      ? String(req.headers['x-forwarded-for']).split(',')[0].trim()
      : req.socket.remoteAddress || 'unknown';
  }

  allow(req, max = config.limits.rateLimit.max, windowMs = config.limits.rateLimit.windowMs) {
    const key = this.bucketKey(req);
    const now = Date.now();
    let b = this.buckets.get(key);
    if (!b) { b = { tokens: max, last: now }; this.buckets.set(key, b); }
    b.tokens = Math.min(max, b.tokens + ((now - b.last) / windowMs) * max);
    b.last = now;
    if (b.tokens < 1) return { ok: false, retryAfter: Math.ceil((1 - b.tokens) * (windowMs / max) / 1000) };
    b.tokens -= 1;
    return { ok: true };
  }

  allowJob(req) {
    const key = this.bucketKey(req);
    const now = Date.now();
    let stamps = this.jobStamps.get(key) || [];
    stamps = stamps.filter((t) => now - t < config.limits.rateLimit.jobWindowMs);
    if (stamps.length >= config.limits.rateLimit.jobMax) {
      return { ok: false, retryAfter: Math.ceil((config.limits.rateLimit.jobWindowMs - (now - stamps[0])) / 1000) };
    }
    stamps.push(now);
    this.jobStamps.set(key, stamps);
    return { ok: true };
  }

  sweepOld() {
    const now = Date.now();
    for (const [k, b] of this.buckets) if (now - b.last > 30 * 60 * 1000) this.buckets.delete(k);
    for (const [k, s] of this.jobStamps) if (!s.length || now - s[s.length - 1] > 30 * 60 * 1000) this.jobStamps.delete(k);
  }
}

// -------------------------------------------------------------------- helpers
function sendJson(res, status, obj, extraHeaders = {}) {
  if (res.headersSent || res.writableEnded) {
    // a response (e.g. the body reader's 413) was already sent
    if (!res.writableEnded) res.end();
    return;
  }
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

function readJsonBody(req, res, maxBytes = config.limits.maxBodyBytes) {
  return new Promise((resolve, reject) => {
    const ct = (req.headers['content-type'] || '').toLowerCase();
    if (ct && !ct.includes('application/json')) {
      return reject(new ApiError(415, 'BAD_CONTENT_TYPE', 'Content-Type must be application/json.'));
    }
    let size = 0;
    const chunks = [];
    req.on('data', (d) => {
      size += d.length;
      if (size > maxBytes) {
        // Answer politely, then drop the socket so the oversized upload stops.
        reject(new ApiError(413, 'BODY_TOO_LARGE', `Request body exceeds the ${Math.round(maxBytes / (1024 * 1024))} MB limit.`));
        try {
          sendJson(res, 413, { error: { code: 'BODY_TOO_LARGE', message: 'Request body exceeds the size limit.' } });
          req.pause();
          setTimeout(() => req.destroy(), 120);
        } catch { /* noop */ }
        return;
      }
      chunks.push(d);
    });
    req.on('end', () => {
      if (!chunks.length) return reject(new ApiError(400, 'BAD_JSON', 'Request body is empty — provide a JSON object.'));
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new ApiError(400, 'BAD_JSON', 'Request body is not valid JSON.'));
      }
    });
    req.on('error', () => reject(new ApiError(400, 'BODY_READ_ERROR', 'Failed to read request body.')));
  });
}

function securityHeaders(res, req) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'",
  );
  if (req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
}

function intInRange(v, min, max, name) {
  if (v === undefined || v === null || v === '') return undefined;
  const n = Number(v);
  if (!Number.isInteger(n)) throw new ApiError(400, 'BAD_PARAM', `"${name}" must be an integer.`);
  if (n < min || n > max) throw new ApiError(400, 'BAD_PARAM', `"${name}" must be between ${min} and ${max}.`);
  return n;
}

const PROTOCOLS = new Set(['auto', 'http', 'https', 'socks4', 'socks4a', 'socks5']);

function validateCheckBody(body) {
  let text;
  if (typeof body.text === 'string') {
    text = body.text;
  } else if (Array.isArray(body.proxies)) {
    if (body.proxies.length > config.limits.maxProxiesPerJob) {
      throw new ApiError(413, 'TOO_MANY_PROXIES', `"proxies" array exceeds the limit of ${config.limits.maxProxiesPerJob}.`);
    }
    text = body.proxies.map((p) => String(p).replace(/[\r\n]+/g, ' ').slice(0, 400)).join('\n');
  } else {
    throw new ApiError(400, 'BAD_REQUEST', 'Provide "text" (raw list) or "proxies" (array of strings).');
  }
  if (text.length > config.limits.maxBodyBytes) {
    throw new ApiError(413, 'BODY_TOO_LARGE', 'Proxy list exceeds the size limit.');
  }
  return {
    text,
    timeoutMs: intInRange(body.timeout, config.checker.minTimeoutMs, config.checker.maxTimeoutMs, 'timeout'),
    concurrency: intInRange(body.concurrency, 1, config.checker.maxConcurrency, 'concurrency'),
    retries: intInRange(body.retries, 0, config.checker.maxRetries, 'retries'),
    protocol: body.protocol !== undefined
      ? (PROTOCOLS.has(body.protocol) ? body.protocol : (() => { throw new ApiError(400, 'BAD_PARAM', `"protocol" must be one of: ${[...PROTOCOLS].join(', ')}`); })())
      : 'auto',
    httpsTest: body.httpsTest === undefined ? true : Boolean(body.httpsTest),
  };
}

// ----------------------------------------------------------------------- SSE
function handleSse(req, res, job, manager) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 3000\n\n');

  let lastSeq = -1;
  const lastEventId = req.headers['last-event-id'];
  if (lastEventId && /^\d+$/.test(String(lastEventId).trim())) {
    lastSeq = parseInt(lastEventId, 10);
  }

  const send = (event, data, id) => {
    if (res.writableEnded) return;
    res.write(`event: ${event}\n`);
    if (id !== undefined) res.write(`id: ${id}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  // initial snapshot
  send('snapshot', { snapshot: job.snapshot(), resultsTotal: job.results.length });

  // catch-up: results the client missed (or everything on a fresh open)
  const missed = lastSeq >= 0 ? job.results.slice(lastSeq + 1) : job.results;
  for (let i = 0; i < missed.length; i += 500) {
    const batch = missed.slice(i, i + 500);
    send('results', { results: batch, total: job.results.length }, batch[batch.length - 1].seq);
    lastSeq = Math.max(lastSeq, batch[batch.length - 1].seq);
  }
  const geoUpdates = [];
  job.results.forEach((r) => { if (r.geo && r.geo.state !== 'pending') geoUpdates.push({ seq: r.seq, geo: r.geo }); });
  for (let i = 0; i < geoUpdates.length; i += 500) {
    send('geo', { updates: geoUpdates.slice(i, i + 500) });
  }

  let resultBuf = [];
  let geoBuf = [];
  let flushTimer = null;
  const flush = () => {
    flushTimer = null;
    if (resultBuf.length) {
      const batch = resultBuf;
      resultBuf = [];
      send('results', { results: batch, total: job.results.length }, batch[batch.length - 1].seq);
      lastSeq = Math.max(lastSeq, batch[batch.length - 1].seq);
    }
    if (geoBuf.length) {
      const updates = geoBuf;
      geoBuf = [];
      send('geo', { updates });
    }
  };
  const scheduleFlush = () => {
    if (!flushTimer) flushTimer = setTimeout(flush, 250);
    if (flushTimer.unref) flushTimer.unref();
  };

  const onEvent = ({ event, payload }) => {
    if (event === 'result') {
      resultBuf.push(payload.result);
      scheduleFlush();
    } else if (event === 'geo') {
      geoBuf.push(payload);
      scheduleFlush();
    } else if (event === 'status' || event === 'start') {
      send(event, payload);
    } else if (event === 'done') {
      flush();
      send('done', payload);
      send('snapshot', { snapshot: job.snapshot(), resultsTotal: job.results.length });
    }
  };
  job.emitter.on('event', onEvent);

  const heartbeat = setInterval(() => {
    if (!res.writableEnded) res.write(': ka\n\n');
  }, 15000);
  heartbeat.unref();

  req.on('close', () => {
    job.emitter.off('event', onEvent);
    clearInterval(heartbeat);
    if (flushTimer) clearTimeout(flushTimer);
  });
}

// ------------------------------------------------------------------- static
function serveStatic(req, res, urlPath) {
  let p = decodeURIComponent(urlPath.split('?')[0]);
  if (p === '/' || p === '') p = '/index.html';
  const resolved = path.normalize(path.join(config.publicDir, p));
  if (!resolved.startsWith(config.publicDir + path.sep) && resolved !== config.publicDir) {
    return sendJson(res, 403, { error: { code: 'FORBIDDEN', message: 'Forbidden.' } });
  }
  fs.stat(resolved, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
      return res.end('404 — not found');
    }
    const ext = path.extname(resolved).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Content-Length': st.size,
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=300',
    });
    if (req.method === 'HEAD') return res.end();
    const stream = fs.createReadStream(resolved);
    stream.on('error', () => { res.destroy(); });
    stream.pipe(res);
  });
}

// ------------------------------------------------------------------ factory
function createServer({ manager, geo }) {
  const limiter = new RateLimiter();

  const server = http.createServer(async (req, res) => {
    securityHeaders(res, req);
    const urlPath = (req.url || '/').split('?')[0];
    const q = Object.fromEntries(new URLSearchParams((req.url || '').split('?')[1] || ''));

    try {
      // ---- API routes ----
      if (urlPath === '/api/health' && (req.method === 'GET' || req.method === 'HEAD')) {
        return sendJson(res, 200, {
          ok: true,
          status: 'ok',
          version: config.version,
          uptimeSec: Math.round(process.uptime()),
          node: process.version,
          jobs: manager.stats(),
          geo: geo.snapshot(),
          targets: config.targets.echoUrls,
        });
      }

      if (urlPath === '/api/config' && req.method === 'GET') {
        return sendJson(res, 200, {
          version: config.version,
          defaults: {
            concurrency: config.checker.defaultConcurrency,
            timeoutMs: config.checker.defaultTimeoutMs,
            retries: config.checker.defaultRetries,
            protocol: 'auto',
            httpsTest: config.checker.httpsTest,
          },
          limits: {
            concurrency: [1, config.checker.maxConcurrency],
            timeoutMs: [config.checker.minTimeoutMs, config.checker.maxTimeoutMs],
            retries: [0, config.checker.maxRetries],
            maxProxiesPerJob: config.limits.maxProxiesPerJob,
            maxBodyBytes: config.limits.maxBodyBytes,
            jobTtlMs: config.limits.jobTtlMs,
            activeJobsPerIp: config.limits.maxJobsPerIp,
          },
          echoTargets: config.targets.echoUrls,
          allowPrivateProxies: config.checker.allowPrivateProxies,
        });
      }

      if (urlPath === '/api/check' && req.method === 'POST') {
        const rl = limiter.allow(req);
        if (!rl.ok) return sendJson(res, 429, { error: { code: 'RATE_LIMITED', message: 'Too many requests.' } }, { 'Retry-After': String(rl.retryAfter) });
        const jrl = limiter.allowJob(req);
        if (!jrl.ok) return sendJson(res, 429, { error: { code: 'JOB_RATE_LIMITED', message: `Job creation limit reached (${config.limits.rateLimit.jobMax} per ${config.limits.rateLimit.jobWindowMs / 60000} min).` } }, { 'Retry-After': String(jrl.retryAfter) });
        const body = await readJsonBody(req, res);
        const opts = validateCheckBody(body);
        const clientMeta = { ip: limiter.bucketKey(req), userAgent: String(req.headers['user-agent'] || '').slice(0, 200) };
        const { job, parse } = manager.createJob(opts.text, opts, clientMeta);
        logger.info('job created', {
          jobId: job.id, total: job.total, ip: clientMeta.ip,
          concurrency: job.cfg.concurrency, timeoutMs: job.cfg.timeoutMs,
        });
        return sendJson(res, 202, {
          jobId: job.id,
          total: job.total,
          status: job.status,
          totalLines: parse.totalLines,
          duplicatesRemoved: parse.duplicateCount,
          uniqueCount: parse.uniqueCount,
          invalidCount: parse.invalid.length,
          invalid: parse.invalid.slice(0, config.limits.maxInvalidReported),
        });
      }

      let m;
      if ((m = /^\/api\/jobs\/([A-Za-z0-9_-]{4,64})$/.exec(urlPath)) && req.method === 'GET') {
        const job = manager.getOr404(m[1]);
        return sendJson(res, 200, { snapshot: job.snapshot(), resultsTotal: job.results.length });
      }

      if ((m = /^\/api\/jobs\/([A-Za-z0-9_-]{4,64})\/results$/.exec(urlPath)) && req.method === 'GET') {
        const job = manager.getOr404(m[1]);
        const out = queryResults(job.results, q);
        return sendJson(res, 200, {
          ...out,
          snapshot: job.snapshot(),
        });
      }

      if ((m = /^\/api\/jobs\/([A-Za-z0-9_-]{4,64})\/events$/.exec(urlPath)) && req.method === 'GET') {
        const job = manager.getOr404(m[1]);
        return handleSse(req, res, job, manager);
      }

      if ((m = /^\/api\/jobs\/([A-Za-z0-9_-]{4,64})\/(cancel|pause|resume)$/.exec(urlPath)) && req.method === 'POST') {
        const job = manager.getOr404(m[1]);
        const snapshot = m[2] === 'cancel' ? manager.cancel(job.id) : m[2] === 'pause' ? manager.pause(job.id) : manager.resume(job.id);
        return sendJson(res, 200, { snapshot });
      }

      if ((m = /^\/api\/jobs\/([A-Za-z0-9_-]{4,64})\/recheck$/.exec(urlPath)) && req.method === 'POST') {
        const rl = limiter.allow(req);
        if (!rl.ok) return sendJson(res, 429, { error: { code: 'RATE_LIMITED', message: 'Too many requests.' } }, { 'Retry-After': String(rl.retryAfter) });
        const jrl = limiter.allowJob(req);
        if (!jrl.ok) return sendJson(res, 429, { error: { code: 'JOB_RATE_LIMITED', message: 'Job creation limit reached.' } }, { 'Retry-After': String(jrl.retryAfter) });
        const job = manager.getOr404(m[1]);
        const body = await readJsonBody(req, res);
        const scope = body.scope || 'all';
        let proxies;
        if (scope === 'selected') {
          const keys = Array.isArray(body.keys) ? body.keys.map(Number).filter(Number.isInteger) : [];
          if (!keys.length) throw new ApiError(400, 'BAD_PARAM', '"keys" must be a non-empty array of result seq numbers.');
          if (keys.length > config.limits.maxProxiesPerJob) throw new ApiError(413, 'TOO_MANY_PROXIES', 'Selection too large.');
          proxies = keys.map((seq) => job.proxies[job.results[seq] ? job.results[seq].i : -1]).filter(Boolean);
        } else if (scope === 'failed') {
          proxies = job.results.filter((r) => !r.alive).map((r) => job.proxies[r.i]);
        } else if (scope === 'all') {
          proxies = job.proxies;
        } else {
          throw new ApiError(400, 'BAD_PARAM', '"scope" must be all, failed or selected.');
        }
        if (!proxies.length) throw new ApiError(400, 'NOTHING_TO_CHECK', 'The selected scope contains no proxies.');
        // Rebuild input lines server-side (credentials preserved for the recheck only).
        const { txtLine } = require('../jobs/exporter');
        const text = proxies.map((p) => txtLine(p, { scheme: true, credentials: true })).join('\n');
        const clientMeta = { ip: limiter.bucketKey(req), userAgent: String(req.headers['user-agent'] || '').slice(0, 200) };
        const created = manager.createJob(text, job.cfg, clientMeta);
        return sendJson(res, 202, {
          jobId: created.job.id,
          total: created.job.total,
          status: created.job.status,
          recheckedFrom: job.id,
        });
      }

      if ((m = /^\/api\/jobs\/([A-Za-z0-9_-]{4,64})\/export$/.exec(urlPath)) && req.method === 'GET') {
        const job = manager.getOr404(m[1]);
        const format = ['txt', 'csv', 'json'].includes(q.format) ? q.format : 'txt';
        const includeCredentials = q.include === 'credentials' && q.confirm === 'yes';
        if (q.include === 'credentials' && !includeCredentials) {
          throw new ApiError(400, 'CONFIRM_REQUIRED', 'Credential export requires confirm=yes — it is intentionally explicit.');
        }
        const { rows } = queryResults(job.results, q);
        const proxyRecords = new Map(rows.map((r) => [r.seq, job.proxies[r.i]]));
        const payload = formatExport(rows, {
          format,
          includeCredentials,
          proxyRecords,
          scheme: q.scheme === 'true' || q.scheme === '1',
        });
        const ts = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
        res.writeHead(200, {
          'Content-Type': format === 'json' ? 'application/json; charset=utf-8' : format === 'csv' ? 'text/csv; charset=utf-8' : 'text/plain; charset=utf-8',
          'Content-Disposition': `attachment; filename="proxycheck-${job.id}-${ts}.${format}"`,
          'Cache-Control': 'no-store',
        });
        return res.end(payload);
      }

      if (urlPath.startsWith('/api/')) {
        return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Unknown API endpoint.' } });
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        return sendJson(res, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed.' } });
      }

      // ---- static ----
      return serveStatic(req, res, urlPath);
    } catch (err) {
      if (err instanceof ApiError) {
        return sendJson(res, err.status, {
          error: { code: err.code, message: err.message, details: err.details, parse: err.parse },
        });
      }
      logger.error('unhandled request error', { url: urlPath, error: err.message, stack: err.stack });
      return sendJson(res, 500, { error: { code: 'INTERNAL', message: 'Internal server error. See server logs for details.' } });
    }
  });

  server.keepAliveTimeout = 65000;
  server.requestTimeout = 0; // SSE stays open; body reads enforce their own caps
  server.headersTimeout = 30000;
  return server;
}

module.exports = { createServer, RateLimiter, securityHeaders };
