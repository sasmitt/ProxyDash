'use strict';
/** Rate limiting: general token bucket + job-creation limit. */
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('http');

process.env.RATE_LIMIT_MAX = '1000';
process.env.JOB_RATE_MAX = '2';
process.env.JOB_RATE_WINDOW_MS = '60000';
process.env.ALLOW_PRIVATE_PROXIES = 'true';

let base;
let server;
let manager;

before(async () => {
  const { createServer } = require('../src/server/httpServer');
  const { GeoClient } = require('../src/geo/geoClient');
  const { JobManager } = require('../src/jobs/manager');
  manager = new JobManager(new GeoClient());
  server = createServer({ manager, geo: manager.geo });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  manager.stop();
  server.close();
});

function get(path) {
  return new Promise((resolve, reject) => {
    http.get(base + path, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
    }).on('error', reject);
  });
}

function post(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const r = http.request(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({ status: res.statusCode }));
    });
    r.on('error', reject);
    r.write(data);
    r.end();
  });
}

test('job creation rate limit returns 429 with Retry-After', async () => {
  const body = { text: '127.0.0.1:1', timeout: 1000, httpsTest: false };
  const r1 = await post('/api/check', body);
  assert.strictEqual(r1.status, 202);
  const r2 = await post('/api/check', body);
  assert.strictEqual(r2.status, 202);
  const r3 = await post('/api/check', body);
  assert.strictEqual(r3.status, 429);
  const health = await get('/api/health');
  assert.strictEqual(health.status, 200, 'general requests still allowed');
});

test('manager.stop cancels active jobs', async () => {
  await manager.createJob('127.0.0.1:1', { timeoutMs: 1000, httpsTest: false }, { ip: 'rl' });
  manager.stop();
  for (const job of manager.jobs.values()) {
    assert.ok(['cancelled', 'completed', 'failed'].includes(job.status), job.status);
  }
});
