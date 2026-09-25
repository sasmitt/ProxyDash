'use strict';
/**
 * HTTP API integration tests: check → SSE stream → results → export →
 * recheck, plus validation, rate limits and error handling — all against
 * local mock infrastructure.
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('http');

process.env.ALLOW_PRIVATE_PROXIES = 'true';
process.env.RATE_LIMIT_MAX = '100000';
process.env.JOB_RATE_MAX = '1000';
process.env.MAX_BODY_BYTES = '200000'; // small on purpose, for the 413 test

const { startInfra } = require('./helpers/infra');
const { createHttpProxy, waitFor } = require('./helpers/mockProxy');

let infra;
let closeServer;
let base;

before(async () => {
  infra = await startInfra();
  const mock = createHttpProxy();
  const mockPort = await mock.ready;
  // keep a module-level handle for closing
  closeServer = async () => {
    await mock.close();
    await infra.close();
  };
  global.__mockPort = mockPort;
  const { createServer } = require('../src/server/httpServer');
  const { GeoClient } = require('../src/geo/geoClient');
  const { JobManager } = require('../src/jobs/manager');
  const geo = new GeoClient();
  const manager = new JobManager(geo);
  const server = createServer({ manager, geo });
  global.__manager = manager;
  global.__geo = geo;
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  base = `http://127.0.0.1:${port}`;
  server.on('close', () => manager.stop());
  global.__server = server;
});

after(async () => {
  global.__server.close();
  await closeServer();
});

function req(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body != null ? JSON.stringify(body) : null;
    const r = http.request(base + path, {
      method,
      headers: {
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
        ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* stream */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

test('health endpoint', async () => {
  const res = await req('GET', '/api/health');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.ok, true);
  assert.ok(res.json.targets.length > 0);
});

test('config endpoint exposes limits', async () => {
  const res = await req('GET', '/api/config');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.defaults.concurrency > 0, true);
  assert.ok(res.json.limits.maxProxiesPerJob > 0);
});

test('check → 202 with parse summary (dedup + invalid)', async () => {
  const proxies = [`127.0.0.1:${global.__mockPort}`, `127.0.0.1:${global.__mockPort}`, 'not a proxy', `u:p@127.0.0.1:${global.__mockPort}`];
  const res = await req('POST', '/api/check', { proxies, timeout: 3000, httpsTest: false });
  assert.strictEqual(res.status, 202);
  assert.ok(res.json.jobId.startsWith('job_'));
  assert.strictEqual(res.json.total, 2);
  assert.strictEqual(res.json.duplicatesRemoved, 1);
  assert.strictEqual(res.json.invalidCount, 1);
  global.__jobId = res.json.jobId;
});

test('job completes and results are queryable with filters', async () => {
  const manager = global.__manager;
  await waitFor(() => ['completed', 'cancelled', 'failed'].includes(manager.get(global.__jobId).status), 20000);
  const res = await req('GET', `/api/jobs/${global.__jobId}/results?status=alive`);
  assert.strictEqual(res.status, 200);
  assert.ok(res.json.rows.every((r) => r.status === 'alive'));
  const all = await req('GET', `/api/jobs/${global.__jobId}/results`);
  assert.strictEqual(all.json.total, 2);
  const sorted = await req('GET', `/api/jobs/${global.__jobId}/results?sort=latency&dir=asc`);
  const lats = sorted.json.rows.map((r) => (r.latency.totalMs == null ? Infinity : r.latency.totalMs));
  assert.deepStrictEqual([...lats].sort((a, b) => a - b), lats);
});

test('SSE stream delivers snapshot, results and done', async () => {
  const start = await req('POST', '/api/check', { proxies: [`127.0.0.1:${global.__mockPort}`], timeout: 4000, httpsTest: false });
  assert.strictEqual(start.status, 202);
  const events = [];
  await new Promise((resolve, reject) => {
    const r = http.get(`${base}/api/jobs/${start.json.jobId}/events`, (res) => {
      assert.strictEqual(res.headers['content-type'].startsWith('text/event-stream'), true);
      let buf = '';
      res.on('data', (d) => {
        buf += d.toString('utf8');
        let idx;
        while ((idx = buf.indexOf('\n\n')) !== -1) {
          const frame = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          const ev = {};
          for (const line of frame.split('\n')) {
            if (line.startsWith('event: ')) ev.event = line.slice(7);
            else if (line.startsWith('data: ')) ev.data = line.slice(6);
            else if (line.startsWith('id: ')) ev.id = line.slice(4);
          }
          if (ev.event) {
            ev.parsed = ev.data ? JSON.parse(ev.data) : null;
            events.push(ev);
            if (ev.event === 'done') { res.destroy(); resolve(); }
          }
        }
      });
      res.on('error', () => {});
    });
    r.on('error', reject);
    setTimeout(() => reject(new Error('SSE timeout — no done event')), 25000);
  });
  const names = events.map((e) => e.event);
  assert.ok(names.includes('snapshot'));
  assert.ok(names.includes('results'), `events: ${names.join(',')}`);
  assert.ok(names.includes('done'));
  const resultsEv = events.find((e) => e.event === 'results');
  assert.strictEqual(resultsEv.parsed.results.length, 1);
});

test('export txt/csv/json + credential gate', async () => {
  const manager = global.__manager;
  const created = manager.createJob(`alice:secret123@127.0.0.1:${global.__mockPort}\n127.0.0.1:1`, { timeoutMs: 4000, httpsTest: false }, { ip: 'export-client' });
  await waitFor(() => ['completed', 'failed'].includes(created.job.status), 20000);

  const txt = await req('GET', `/api/jobs/${created.job.id}/export?format=txt`);
  assert.strictEqual(txt.status, 200);
  assert.ok(!txt.text.includes('secret123'), 'txt export must not contain passwords by default');
  assert.match(txt.text, /127\.0\.0\.1:\d+/);

  const csv = await req('GET', `/api/jobs/${created.job.id}/export?format=csv`);
  assert.strictEqual(csv.status, 200);
  assert.ok(csv.text.startsWith('\ufeff'));
  const lines = csv.text.split('\n').filter(Boolean);
  assert.strictEqual(lines.length, 3, 'header + 2 rows');
  assert.ok(lines[0].includes('proxy,status,protocol'));

  const json = await req('GET', `/api/jobs/${created.job.id}/export?format=json`);
  assert.strictEqual(json.status, 200);
  assert.strictEqual(json.json.credentialsIncluded, false);

  const credBlocked = await req('GET', `/api/jobs/${created.job.id}/export?format=txt&include=credentials`);
  assert.strictEqual(credBlocked.status, 400);

  const credOk = await req('GET', `/api/jobs/${created.job.id}/export?format=txt&include=credentials&confirm=yes`);
  assert.strictEqual(credOk.status, 200);
  assert.ok(credOk.text.includes('alice:secret123@127.0.0.1'), 'explicit credential export includes user:pass');
  assert.ok(!credOk.text.includes('9.9.9.9:alice'), 'unauthenticated lines unchanged');
});

test('recheck creates a new job for all proxies', async () => {
  const res = await req('POST', `/api/jobs/${global.__jobId}/recheck`, { scope: 'all' });
  assert.strictEqual(res.status, 202);
  assert.ok(res.json.jobId.startsWith('job_'));
  assert.strictEqual(res.json.total, 2);

  const none = await req('POST', `/api/jobs/${global.__jobId}/recheck`, { scope: 'failed' });
  // both proxies were alive → nothing failed to recheck
  assert.strictEqual(none.status, 400);
  assert.strictEqual(none.json.error.code, 'NOTHING_TO_CHECK');
});

test('pause/resume/cancel endpoints respond with snapshots', async () => {
  const created = global.__manager.createJob(
    Array.from({ length: 6 }, (_, i) => `x${i}:y@127.0.0.1:${global.__mockPort}`).join('\n'),
    { timeoutMs: 4000, concurrency: 2, httpsTest: false },
    { ip: 'ctrl-client' },
  );
  const paused = await req('POST', `/api/jobs/${created.job.id}/pause`);
  assert.strictEqual(paused.status, 200);
  assert.ok(['paused', 'completed'].includes(paused.json.snapshot.status));
  const resumed = await req('POST', `/api/jobs/${created.job.id}/resume`);
  assert.strictEqual(resumed.status, 200);
  await waitFor(() => ['completed', 'failed'].includes(created.job.status), 20000);
  const cancelled = await req('POST', `/api/jobs/${created.job.id}/cancel`);
  assert.strictEqual(cancelled.status, 200);
  assert.strictEqual(cancelled.json.snapshot.status, 'completed');
});

test('request validation: bad params rejected with clear codes', async () => {
  const bad1 = await req('POST', '/api/check', { text: '1.2.3.4:80', timeout: 'abc' });
  assert.strictEqual(bad1.status, 400);
  assert.strictEqual(bad1.json.error.code, 'BAD_PARAM');

  const bad2 = await req('POST', '/api/check', { text: '1.2.3.4:80', concurrency: 100000 });
  assert.strictEqual(bad2.status, 400);

  const bad3 = await req('POST', '/api/check', { text: '1.2.3.4:80', protocol: 'gopher' });
  assert.strictEqual(bad3.status, 400);

  const noProxies = await req('POST', '/api/check', { text: 'hello\nworld' });
  assert.strictEqual(noProxies.status, 400);
  assert.strictEqual(noProxies.json.error.code, 'NO_VALID_PROXIES');
  assert.ok(noProxies.json.error.parse);

  const badJson = await req('POST', '/api/check', undefined, { 'Content-Type': 'application/json' });
  assert.strictEqual(badJson.status, 400);
  assert.strictEqual(badJson.json.error.code, 'BAD_JSON');

  const badCt = await req('POST', '/api/check', 'x=1', { 'Content-Type': 'application/x-www-form-urlencoded' });
  assert.strictEqual(badCt.status, 415);
});

test('body size limit enforced (413)', async () => {
  const big = 'x'.repeat(250 * 1024);
  const res = await req('POST', '/api/check', { text: big });
  assert.strictEqual(res.status, 413);
  assert.strictEqual(res.json.error.code, 'BODY_TOO_LARGE');
});

test('unknown endpoints and jobs return structured 404s', async () => {
  const unknownApi = await req('GET', '/api/definitely-not-a-thing');
  assert.strictEqual(unknownApi.status, 404);
  const unknownJob = await req('GET', '/api/jobs/job_doesnotexist');
  assert.strictEqual(unknownJob.status, 404);
  assert.strictEqual(unknownJob.json.error.code, 'JOB_NOT_FOUND');
});

test('static server serves index.html and blocks traversal', async () => {
  const home = await req('GET', '/');
  assert.strictEqual(home.status, 200);
  assert.ok(home.text.includes('ProxyCheck'));
  const trav = await req('GET', '/..%2f..%2fetc%2fpasswd');
  assert.ok(trav.status === 403 || trav.status === 404, `got ${trav.status}`);
  const csp = await req('GET', '/');
  assert.ok(csp.headers['content-security-policy'].includes("script-src 'self'"));
  assert.strictEqual(csp.headers['x-content-type-options'], 'nosniff');
});
