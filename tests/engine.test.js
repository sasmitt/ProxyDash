'use strict';
/**
 * Integration tests for the full checking pipeline, entirely against local
 * mock servers (no third-party infrastructure).
 */
const { test, before, after } = require('node:test');
const assert = require('node:assert');

process.env.ALLOW_PRIVATE_PROXIES = 'true';
process.env.GEO_ENABLED = 'true';

const { startInfra } = require('./helpers/infra');
const { createHttpProxy, createSocks5Proxy, waitFor } = require('./helpers/mockProxy');
const config = require('../src/config');
const { GeoClient } = require('../src/geo/geoClient');
const { JobManager } = require('../src/jobs/manager');
const { checkProxy } = require('../src/checker/probe');

let infra;
let geo;
let manager;
let httpMock; let httpPort;
let authMock; let authPort;
let flakyMock; let flakyPort;
let stallMock; let stallPort;
let socksMock; let socksPort;
let deadPort = 1;

before(async () => {
  infra = await startInfra();
  httpMock = createHttpProxy();
  httpPort = await httpMock.ready;
  authMock = createHttpProxy({ user: 'alice', pass: 'secret123' });
  authPort = await authMock.ready;
  flakyMock = createHttpProxy({ failFirst: 1 });
  flakyPort = await flakyMock.ready;
  stallMock = createHttpProxy({ stall: true });
  stallPort = await stallMock.ready;
  socksMock = createSocks5Proxy();
  socksPort = await socksMock.ready;
  geo = new GeoClient();
  manager = new JobManager(geo);
});

after(async () => {
  manager.stop();
  geo.stop();
  await Promise.all([
    httpMock.close(), authMock.close(), flakyMock.close(), stallMock.close(), socksMock.close(), infra.close(),
  ]);
});

function runJob(text, opts = {}, { timeoutMs = 30000 } = {}) {
  const created = manager.createJob(text, { timeoutMs: 2000, concurrency: 8, retries: 0, httpsTest: false, ...opts }, { ip: 'test-client' });
  const done = waitFor(() => ['completed', 'cancelled', 'failed'].includes(created.job.status), timeoutMs, 60);
  return { ...created, done };
}

test('alive HTTP proxy: full result with exit IP, geo, ASN and elite classification', async () => {
  const { job, done } = runJob(`127.0.0.1:${httpPort}`);
  await done;
  assert.strictEqual(job.status, 'completed');
  const r = job.results[0];
  assert.ok(r, 'result exists');
  assert.strictEqual(r.alive, true);
  assert.strictEqual(r.status, 'alive');
  assert.strictEqual(r.protocol, 'http');
  assert.strictEqual(r.exitIp, '93.184.216.34');
  assert.strictEqual(r.httpStatus, 200);
  assert.strictEqual(r.anonymity.level, 'elite');
  assert.strictEqual(r.confidence, 'verified');
  assert.ok(r.latency.totalMs != null && r.latency.totalMs >= 0);
  // geo enrichment attached asynchronously
  await waitFor(() => r.geo && r.geo.state === 'ok', 8000);
  assert.strictEqual(r.geo.country, 'Narnia');
  assert.strictEqual(r.geo.asn, 'AS64512');
  assert.strictEqual(r.geo.isp, 'Mock ISP');
  assert.ok(!JSON.stringify(r).includes('secret'), 'no credentials leak');
});

test('protocol auto-detection picks SOCKS5 over HTTP', async () => {
  const { job, done } = runJob(`127.0.0.1:${socksPort}`);
  await done;
  const r = job.results[0];
  assert.strictEqual(r.alive, true);
  assert.strictEqual(r.protocol, 'socks5');
  assert.strictEqual(r.dns, 'n/a (IP destination)');
});

test('unreachable port → CONNECTION_REFUSED', async () => {
  const { job, done } = runJob(`127.0.0.1:${deadPort}`);
  await done;
  const r = job.results[0];
  assert.strictEqual(r.alive, false);
  assert.strictEqual(r.errorCategory, 'CONNECTION_REFUSED');
  assert.strictEqual(r.confidence, 'failed');
});

test('stalled proxy → TIMEOUT', async () => {
  const { job, done } = runJob(`127.0.0.1:${stallPort}`, { timeoutMs: 1500, retries: 0 });
  await done;
  const r = job.results[0];
  assert.strictEqual(r.alive, false);
  assert.strictEqual(r.errorCategory, 'TIMEOUT');
});

test('auth-required proxy without credentials → AUTH_FAILED with auth.required', async () => {
  const { job, done } = runJob(`127.0.0.1:${authPort}`);
  await done;
  const r = job.results[0];
  assert.strictEqual(r.alive, false);
  assert.strictEqual(r.errorCategory, 'AUTH_FAILED');
  assert.strictEqual(r.auth.required, true);
  assert.strictEqual(r.auth.ok, false);
  assert.strictEqual(r.protocol, 'http'); // peer unambiguously spoke HTTP proxy
});

test('auth proxy with correct credentials → alive, credentials masked', async () => {
  const { job, done } = runJob(`alice:secret123@127.0.0.1:${authPort}`);
  await done;
  const r = job.results[0];
  assert.strictEqual(r.alive, true);
  assert.strictEqual(r.hasAuth, true);
  assert.ok(r.input.includes('********'), `input masked: ${r.input}`);
  assert.ok(!JSON.stringify(job.results).includes('secret123'), 'password never serialized');
  assert.ok(!JSON.stringify(r).includes('secret123'));
});

test('flaky proxy retried and succeeds (attempts=2)', async () => {
  const { job, done } = runJob(`127.0.0.1:${flakyPort}`, { retries: 1 });
  await done;
  const r = job.results[0];
  assert.strictEqual(r.alive, true, `expected alive, got ${r.errorCategory}: ${r.errorMessage}`);
  assert.strictEqual(r.attempts, 2);
});

test('concurrency is bounded by configuration', async () => {
  const lines = Array.from({ length: 24 }, (_, i) => `u${i}:pw@127.0.0.1:${httpPort}`).join('\n');
  const { job, done } = runJob(lines, { concurrency: 4, timeoutMs: 8000 }, { timeoutMs: 40000 });
  await done;
  assert.strictEqual(job.checked, 24);
  assert.strictEqual(job.status, 'completed');
  // +1 tolerance: the previous socket's 'close' may land a tick after the
  // engine opens the next one — the engine's own `active` bound is what
  // matters and is exercised by the pause/cancel tests.
  assert.ok(httpMock.stats().maxActive <= 5, `maxActive=${httpMock.stats().maxActive} should be ~<= 4`);
});

test('pause stops progress; resume completes the job', async () => {
  const lines = Array.from({ length: 30 }, (_, i) => `pause${i}:pw@127.0.0.1:${stallPort}`).join('\n');
  const { job } = runJob(lines, { concurrency: 4, timeoutMs: 1100 }, { timeoutMs: 40000 });
  await waitFor(() => job.status === 'running', 5000);
  manager.pause(job.id);
  assert.strictEqual(job.status, 'paused');
  await new Promise((r) => setTimeout(r, 1600)); // let in-flight (≤4) finish
  const atPause = job.checked;
  await new Promise((r) => setTimeout(r, 900));
  assert.strictEqual(job.checked, atPause, `checked should stall while paused (at=${atPause}, now=${job.checked})`);
  manager.resume(job.id);
  await waitFor(() => job.status === 'completed', 30000);
  assert.strictEqual(job.checked, 30);
});

test('cancel destroys in-flight work quickly', async () => {
  const lines = Array.from({ length: 40 }, (_, i) => `c${i}:pw@127.0.0.1:${stallPort}`).join('\n');
  const started = Date.now();
  const { job } = runJob(lines, { concurrency: 10, timeoutMs: 20000 }, { timeoutMs: 30000 });
  await waitFor(() => job.active > 0, 5000);
  manager.cancel(job.id);
  await waitFor(() => job.active === 0, 4000);
  assert.strictEqual(job.status, 'cancelled');
  assert.ok(Date.now() - started < 8000, 'cancel should be prompt, not wait for timeouts');
});

test('adaptive concurrency reduces under high timeout rate', async () => {
  const lines = Array.from({ length: 60 }, (_, i) => `a${i}:pw@127.0.0.1:${stallPort}`).join('\n');
  const { job } = runJob(lines, { concurrency: 50, timeoutMs: 1500 }, { timeoutMs: 25000 });
  await waitFor(() => job.currentConcurrency < 50, 20000);
  assert.ok(job.currentConcurrency >= config.checker.minConcurrency);
  manager.cancel(job.id);
});

test('duplicate handling reported by the manager', async () => {
  const { job, parse } = runJob(`127.0.0.1:${httpPort}\n127.0.0.1:${httpPort}\n127.0.0.1:${httpPort}\n127.0.0.1:1`);
  await done0(job);
  assert.strictEqual(parse.duplicateCount, 2);
  assert.strictEqual(job.total, 2);
  assert.strictEqual(job.duplicatesRemoved, 2);
});

function done0(job) {
  return waitFor(() => ['completed', 'cancelled'].includes(job.status), 20000, 50);
}

// ------------------------------------------------------- probe-level checks
test('anonymity: transparent when client IP leaks into forwarding headers', async () => {
  const r = await checkProxy(
    { host: '127.0.0.1', port: httpPort, protocol: 'http', hasAuth: false, username: null, password: null },
    { timeoutMs: 5000, httpsTest: false, echoTargets: [`${infra.echoUrl}?leak=1`], allowPrivate: true, clientIp: '127.0.0.1' },
  );
  assert.strictEqual(r.alive, true);
  assert.strictEqual(r.anonymity.level, 'transparent');
  assert.ok(r.anonymity.reason.includes('client IP'));
});

test('anonymity: anonymous when forwarding headers present without client IP', async () => {
  const r = await checkProxy(
    { host: '127.0.0.1', port: httpPort, protocol: 'http', hasAuth: false, username: null, password: null },
    { timeoutMs: 5000, httpsTest: false, echoTargets: [`${infra.echoUrl}?via=1`], allowPrivate: true, clientIp: '198.51.100.7' },
  );
  assert.strictEqual(r.anonymity.level, 'anonymous');
});

test('HTTPS/TLS test succeeds against custom-CA target', async () => {
  const r = await checkProxy(
    { host: '127.0.0.1', port: httpPort, protocol: 'http', hasAuth: false, username: null, password: null },
    {
      timeoutMs: 8000, httpsTest: true, echoTargets: [infra.echoUrl], allowPrivate: true,
      clientIp: '127.0.0.1', tlsProbeHost: '127.0.0.1', tlsProbePort: Number(process.env.TARGET_TLS_PORT),
    },
  );
  assert.strictEqual(r.alive, true);
  assert.strictEqual(r.https.supported, true, `https error: ${r.https.error}`);
  assert.match(r.https.tlsVersion, /^TLSv1\.[23]$/);
  assert.strictEqual(r.https.certValid, true);
  assert.strictEqual(r.https.exitIpTls, '93.184.216.34');
});

test('HTTPS test reports TLS failure honestly (no cert bypass)', async () => {
  // target TLS host has a valid CA... break validation by pointing at a host
  // name that is NOT in the certificate SANs is not possible via env here;
  // instead use the plain HTTP proxy against TLS port with wrong SNI name.
  const r = await checkProxy(
    { host: '127.0.0.1', port: httpPort, protocol: 'http', hasAuth: false, username: null, password: null },
    { timeoutMs: 8000, httpsTest: true, echoTargets: [infra.echoUrl], allowPrivate: true, clientIp: '127.0.0.1', tlsProbeHost: 'wrong.host.example', tlsProbePort: Number(process.env.TARGET_TLS_PORT) },
  );
  assert.strictEqual(r.https.supported, false);
  assert.ok(r.https.error && /TLS|certificate/i.test(r.https.error), `got: ${r.https.error}`);
});
