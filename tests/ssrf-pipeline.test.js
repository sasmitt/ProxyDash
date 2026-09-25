'use strict';
/**
 * SSRF protection in the full pipeline: private/loopback/metadata targets
 * submitted as "proxies" must be rejected with INVALID_PROXY before any
 * socket is opened. Note: this file intentionally does NOT set
 * ALLOW_PRIVATE_PROXIES.
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert');

delete process.env.ALLOW_PRIVATE_PROXIES;

const { GeoClient } = require('../src/geo/geoClient');
const { JobManager } = require('../src/jobs/manager');
const { waitFor } = require('./helpers/mockProxy');

let manager;
let geo;

before(() => {
  geo = new GeoClient();
  manager = new JobManager(geo);
});

after(() => {
  manager.stop();
  geo.stop();
});

test('private, loopback and metadata destinations are blocked by the engine', async () => {
  const text = [
    '127.0.0.1:8080',
    '10.0.0.1:8080',
    '192.168.1.50:3128',
    '172.16.0.9:1080',
    '169.254.169.254:80',
    'localhost:8080',
    'metadata.google.internal:80',
    '[::1]:8080',
    '0.0.0.0:8080',
  ].join('\n');
  const { job } = { job: manager.createJob(text, { timeoutMs: 3000, concurrency: 8, httpsTest: false }, { ip: 'ssrf-test' }).job };
  await waitFor(() => ['completed', 'failed'].includes(job.status), 20000);
  assert.strictEqual(job.total, 9);
  for (const r of job.results) {
    assert.strictEqual(r.alive, false, `${r.host} must not be alive`);
    assert.strictEqual(r.errorCategory, 'INVALID_PROXY', `${r.host}: ${r.errorCategory}`);
    assert.match(r.errorMessage, /SSRF/i, `${r.host} should mention SSRF protection`);
    assert.strictEqual(r.exitIp, null);
  }
});

test('public hostnames are NOT blocked by the guard', async () => {
  // example.com:1 refuses instantly (nothing listens) — the guard must not be
  // the reason for failure.
  const { job } = { job: manager.createJob('example.com:1', { timeoutMs: 4000, concurrency: 1, httpsTest: false }, { ip: 'ssrf-test-2' }).job };
  await waitFor(() => ['completed', 'failed'].includes(job.status), 20000);
  const r = job.results[0];
  assert.notStrictEqual(r.errorCategory, 'INVALID_PROXY', `unexpected guard block: ${r.errorMessage}`);
});
