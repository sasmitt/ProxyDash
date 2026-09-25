'use strict';
/** Unit tests: anonymity, echo adapters, exporter, filters, utils, geo. */
const { test } = require('node:test');
const assert = require('node:assert');

const { analyzeAnonymity } = require('../src/checker/anonymity');
const { parseEchoBody, assertSafeTargetUrl } = require('../src/checker/echo');
const { formatExport } = require('../src/jobs/exporter');
const { parseQuery, match, sortResults, queryResults } = require('../src/jobs/filters');
const { buildResultView } = require('../src/jobs/view');
const { withTimeout, clamp, latencyBucket, fmtEta, backoffMs } = require('../src/utils');
const { normalizeIpApi, normalizeIpWho } = require('../src/geo/geoClient');
const { CheckError } = require('../src/errors');

// ------------------------------------------------------------ anonymity
test('anonymity: transparent when client IP appears in headers', () => {
  const r = analyzeAnonymity({ 'x-forwarded-for': '198.51.100.7', via: '1.1 px' }, { clientIp: '198.51.100.7' });
  assert.strictEqual(r.level, 'transparent');
  assert.match(r.reason, /client IP/);
});

test('anonymity: anonymous with forwarding headers but no client IP', () => {
  const r = analyzeAnonymity({ via: '1.1 px', 'x-forwarded-for': '10.9.9.9' }, { clientIp: '198.51.100.7' });
  assert.strictEqual(r.level, 'anonymous');
});

test('anonymity: elite when no proxy headers at all', () => {
  const r = analyzeAnonymity({ host: 'echo.test', 'user-agent': 'x' }, { clientIp: '198.51.100.7' });
  assert.strictEqual(r.level, 'elite');
});

test('anonymity: unknown when headers unavailable', () => {
  const r = analyzeAnonymity(null, {});
  assert.strictEqual(r.level, 'unknown');
});

test('anonymity: anonymous when only suspicious x- headers present', () => {
  const r = analyzeAnonymity({ 'x-proxy-id': 'abc' }, {});
  assert.strictEqual(r.level, 'anonymous');
});

// ----------------------------------------------------------------- echo
test('echo adapter: httpbin shape', () => {
  const p = parseEchoBody(Buffer.from(JSON.stringify({ origin: '1.2.3.4', headers: { Host: 'x', Via: 'v' } })));
  assert.strictEqual(p.exitIp, '1.2.3.4');
  assert.strictEqual(p.headers.via, 'v');
  assert.strictEqual(p.geo, null);
});

test('echo adapter: ip-api shape yields geo', () => {
  const p = parseEchoBody(Buffer.from(JSON.stringify({ query: '5.6.7.8', country: 'Testland', countryCode: 'TL', regionName: 'R', city: 'C', lat: 1, lon: 2, timezone: 'T/Zone', as: 'AS12345 Test Networks Inc' })));
  assert.strictEqual(p.exitIp, '5.6.7.8');
  assert.strictEqual(p.geo.country, 'Testland');
  assert.strictEqual(p.geo.asn, 'AS12345');
});

test('echo adapter: ipwho.is shape', () => {
  const p = parseEchoBody(Buffer.from(JSON.stringify({ ip: '9.9.9.9', country: 'X', latitude: 3, longitude: 4, timezone: { id: 'X/Y' }, connection: { asn: 64512, org: 'Org', isp: 'Isp' } })));
  assert.strictEqual(p.exitIp, '9.9.9.9');
  assert.strictEqual(p.geo.timezone, 'X/Y');
  assert.strictEqual(p.geo.asn, 'AS64512');
});

test('echo adapter: non-JSON garbage returns null', () => {
  assert.strictEqual(parseEchoBody(Buffer.from('<html>hello</html>')), null);
  assert.strictEqual(parseEchoBody(Buffer.alloc(0)), null);
});

test('echo target allowlist validation', () => {
  assert.throws(() => assertSafeTargetUrl('ftp://x/y'), CheckError);
  assert.throws(() => assertSafeTargetUrl('not a url'), CheckError);
  const ok = assertSafeTargetUrl('https://example.com/get?x=1');
  assert.strictEqual(ok.host, 'example.com');
  assert.strictEqual(ok.port, 443);
});

// ------------------------------------------------------------- exporter
const sampleResult = {
  seq: 0, i: 0, input: 'alice:********@1.2.3.4:8080', host: '1.2.3.4', port: 8080,
  hasAuth: true, requestedProtocol: 'auto', protocol: 'http', status: 'alive', alive: true,
  partial: false, errorCategory: null, errorMessage: null, exitIp: '5.6.7.8',
  geo: { state: 'ok', country: 'Testland', countryCode: 'TL', region: 'R', city: 'C', latitude: 1, longitude: 2, timezone: 'TZ', asn: 'AS1', asOrg: 'O', isp: 'I', org: 'O', reverse: 'r.ptr', source: 't' },
  latency: { tcpMs: 10, handshakeMs: 20, requestMs: 30, totalMs: 40 }, bucket: 'fast',
  httpStatus: 200, responseHeaders: null,
  https: { supported: true, tlsVersion: 'TLSv1.3', certValid: true, error: null },
  anonymity: { level: 'elite', reason: 'r', evidence: [] },
  auth: { required: false, provided: true, ok: true },
  dns: null, confidence: 'verified', attempts: 1, checkedAt: '2026-01-01T00:00:00.000Z',
};

test('exporter: TXT default = ip:port, no credentials, no scheme', () => {
  const out = formatExport([sampleResult], { format: 'txt' });
  assert.strictEqual(out, '1.2.3.4:8080\n');
});

test('exporter: TXT with scheme and credentials (explicit records only)', () => {
  const records = new Map([[0, { host: '1.2.3.4', port: 8080, protocol: 'http', hasAuth: true, username: 'alice', password: 's3cret' }]]);
  const out = formatExport([sampleResult], { format: 'txt', scheme: true, includeCredentials: true, proxyRecords: records });
  assert.strictEqual(out, 'http://alice:s3cret@1.2.3.4:8080\n');
});

test('exporter: credential export without records is refused', () => {
  assert.throws(() => formatExport([sampleResult], { format: 'txt', includeCredentials: true }), /requires server-side/);
});

test('exporter: CSV columns and quoting', () => {
  const r2 = { ...sampleResult, seq: 1, errorMessage: 'has "quotes", and, commas' };
  const out = formatExport([sampleResult, r2], { format: 'csv' });
  const lines = out.replace(/^\ufeff/, '').split('\n').filter(Boolean);
  assert.strictEqual(lines.length, 3);
  assert.ok(lines[0].startsWith('proxy,status,protocol,exit_ip,country'));
  assert.ok(lines[2].includes('"has ""quotes"", and, commas"'));
});

test('exporter: JSON structure', () => {
  const out = JSON.parse(formatExport([sampleResult], { format: 'json' }));
  assert.strictEqual(out.count, 1);
  assert.strictEqual(out.credentialsIncluded, false);
  assert.strictEqual(out.results[0].geo.country, 'Testland');
});

// -------------------------------------------------------------- filters
test('filters: parseQuery sanitization', () => {
  const f = parseQuery({ status: 'alive', protocol: 'bogus', q: '<script>' });
  assert.strictEqual(f.status, 'alive');
  assert.strictEqual(f.protocol, 'all');
  assert.strictEqual(f.q, '<script>');
});

test('filters: match by status/protocol/https/anonymity/auth/speed/q', () => {
  const r = { ...sampleResult };
  assert.ok(match(r, parseQuery({ status: 'alive' })));
  assert.ok(!match(r, parseQuery({ status: 'dead' })));
  assert.ok(match(r, parseQuery({ protocol: 'http' })));
  assert.ok(!match(r, parseQuery({ protocol: 'socks5' })));
  assert.ok(match(r, parseQuery({ https: 'supported' })));
  assert.ok(match(r, parseQuery({ anonymity: 'elite' })));
  assert.ok(match(r, parseQuery({ auth: 'required' })));
  assert.ok(match(r, parseQuery({ speed: 'fast' })));
  assert.ok(!match(r, parseQuery({ speed: 'slow' })));
  assert.ok(match(r, parseQuery({ country: 'testland' })));
  assert.ok(match(r, parseQuery({ q: '5.6.7.8' })));
  assert.ok(!match(r, parseQuery({ q: 'nowhere' })));
  const dead = { ...sampleResult, status: 'dead', alive: false, latency: { tcpMs: null, handshakeMs: null, requestMs: null, totalMs: null } };
  assert.ok(!match(dead, parseQuery({ speed: 'fast' })));
});

test('filters: sortResults orders by latency with nulls last on desc', () => {
  const rows = [
    { ...sampleResult, seq: 2, latency: { totalMs: 500 } },
    { ...sampleResult, seq: 0, latency: { totalMs: 100 } },
    { ...sampleResult, seq: 1, latency: { totalMs: null } },
  ];
  const asc = sortResults(rows, 'latency', 'asc').map((r) => r.seq);
  assert.deepStrictEqual(asc, [0, 2, 1]);
});

test('filters: queryResults paging', () => {
  const rows = Array.from({ length: 30 }, (_, i) => ({ ...sampleResult, seq: i, latency: { totalMs: i } }));
  const page = queryResults(rows, { limit: '10', offset: '5', sort: 'latency' });
  assert.strictEqual(page.total, 30);
  assert.strictEqual(page.filtered, 30);
  assert.strictEqual(page.rows.length, 10);
  assert.strictEqual(page.rows[0].latency.totalMs, 5);
});

// ----------------------------------------------------------------- view
test('view: result masking + confidence', () => {
  const proxy = { input: 'alice:s3cret@1.2.3.4:8080', protocol: null, host: '1.2.3.4', port: 8080, username: 'alice', password: 's3cret', hasAuth: true };
  const raw = { status: 'alive', alive: true, protocol: 'http', latency: { tcpMs: 1.4, handshakeMs: null, requestMs: 2.6, totalMs: 9.9 }, echo: { exitIp: '5.6.7.8', headers: { host: 'x' } }, anonymity: { level: 'elite', reason: 'r', evidence: [] }, auth: { required: false, provided: true, ok: true }, attempts: 1 };
  const v = buildResultView(raw, proxy, 0, 0);
  assert.ok(!JSON.stringify(v).includes('s3cret'), 'password must never serialize');
  assert.strictEqual(v.latency.totalMs, 10, 'latency rounded');
  assert.strictEqual(v.confidence, 'verified');
  assert.strictEqual(v.bucket, 'excellent');
  const deadView = buildResultView({ ...raw, alive: false, errorCategory: 'TIMEOUT' }, proxy, 1, 1);
  assert.strictEqual(deadView.confidence, 'failed');
});

// ---------------------------------------------------------------- utils
test('utils: withTimeout rejects on deadline', async () => {
  await assert.rejects(() => withTimeout(new Promise(() => {}), 30, 'test'), /timed out/);
  await assert.doesNotReject(() => withTimeout(Promise.resolve(1), 30));
});

test('utils: latencyBucket thresholds', () => {
  assert.strictEqual(latencyBucket(50), 'excellent');
  assert.strictEqual(latencyBucket(150), 'fast');
  assert.strictEqual(latencyBucket(400), 'moderate');
  assert.strictEqual(latencyBucket(900), 'slow');
  assert.strictEqual(latencyBucket(2500), 'very-slow');
  assert.strictEqual(latencyBucket(null), 'unknown');
});

test('utils: clamp, backoff, eta', () => {
  assert.strictEqual(clamp(50, 1, 10), 10);
  assert.strictEqual(clamp(-5, 0, 10), 0);
  assert.ok(backoffMs(0) >= 200 && backoffMs(0) < 400);
  assert.strictEqual(fmtEta(61000), '01:01');
});

// ------------------------------------------------------------------ geo
test('geo: ip-api normalization splits ASN', () => {
  const g = normalizeIpApi({ status: 'success', query: '1.2.3.4', country: 'A', countryCode: 'AA', regionName: 'B', city: 'C', lat: 1.5, lon: 2.5, timezone: 'Z', as: 'AS15169 Google LLC', isp: 'Google LLC', org: 'Google', reverse: 'x' });
  assert.strictEqual(g.asn, 'AS15169');
  assert.strictEqual(g.asOrg, 'Google LLC');
  assert.strictEqual(g.state, 'ok');
  assert.strictEqual(normalizeIpApi({ status: 'fail' }), null);
});

test('geo: ipwho.is normalization', () => {
  const g = normalizeIpWho({ success: true, ip: '1.2.3.4', country: 'A', country_code: 'AA', connection: { asn: 123, org: 'O', isp: 'I' } });
  assert.strictEqual(g.asn, 'AS123');
  assert.strictEqual(g.isp, 'I');
  assert.strictEqual(normalizeIpWho({ success: false }), null);
});

// ------------------------------------------------------------- errors
test('error mapping: categories and retryability', () => {
  assert.strictEqual(new CheckError('TIMEOUT', 'x').category, 'TIMEOUT');
  assert.strictEqual(new CheckError('NOPE', 'x').category, 'UNKNOWN_ERROR');
  const { RETRYABLE } = require('../src/errors');
  assert.ok(RETRYABLE.has('TIMEOUT'));
  assert.ok(!RETRYABLE.has('AUTH_FAILED'));
});
