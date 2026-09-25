'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { parseProxyLine, parseProxyList, proxyKey, maskedLabel } = require('../src/parser');

test('IP:PORT basic', () => {
  const r = parseProxyLine('1.2.3.4:8080');
  assert.ok(r.ok);
  assert.deepStrictEqual([r.proxy.host, r.proxy.port, r.proxy.protocol, r.proxy.hasAuth], ['1.2.3.4', 8080, null, false]);
});

test('IP:PORT:USER:PASS', () => {
  const r = parseProxyLine('1.2.3.4:8080:alice:s3cret');
  assert.ok(r.ok);
  assert.strictEqual(r.proxy.username, 'alice');
  assert.strictEqual(r.proxy.password, 's3cret');
  assert.ok(r.proxy.hasAuth);
});

test('password containing colon in 4-part form', () => {
  const r = parseProxyLine('1.2.3.4:8080:alice:pa:ss:word');
  assert.ok(r.ok);
  assert.strictEqual(r.proxy.password, 'pa:ss:word');
});

test('USER:PASS@IP:PORT', () => {
  const r = parseProxyLine('bob:hunter2@5.6.7.8:3128');
  assert.ok(r.ok);
  assert.strictEqual(r.proxy.host, '5.6.7.8');
  assert.strictEqual(r.proxy.username, 'bob');
  assert.strictEqual(r.proxy.password, 'hunter2');
});

test('scheme forms', () => {
  for (const [line, proto] of [
    ['http://1.2.3.4:8080', 'http'],
    ['https://1.2.3.4:8443', 'https'],
    ['socks4://5.6.7.8:1080', 'socks4'],
    ['socks5://5.6.7.8:1080', 'socks5'],
    ['socks5://user:pw@5.6.7.8:1080', 'socks5'],
  ]) {
    const r = parseProxyLine(line);
    assert.ok(r.ok, line);
    assert.strictEqual(r.proxy.protocol, proto);
  }
});

test('bracketed IPv6', () => {
  const r = parseProxyLine('[2001:db8::1]:8080');
  assert.ok(r.ok);
  assert.strictEqual(r.proxy.host, '2001:db8::1');
  assert.strictEqual(r.proxy.port, 8080);
  const r2 = parseProxyLine('socks5://[fe80::1%25eth0]:1080');
  // zone id rejected by host validation
  assert.strictEqual(r2.ok, false);
});

test('bare IPv6 with unambiguous form', () => {
  const r = parseProxyLine('::1:8080');
  // ambiguous — parsed as host '::1' port 8080 via multi-segment IPv6 path
  assert.ok(r.ok);
  assert.strictEqual(r.proxy.host, '::1');
  assert.strictEqual(r.proxy.port, 8080);
});

test('hostnames accepted', () => {
  const r = parseProxyLine('proxy.example.com:8080');
  assert.ok(r.ok);
  assert.strictEqual(r.proxy.host, 'proxy.example.com');
});

test('malformed lines rejected with reasons', () => {
  const cases = [
    ['', 'empty'],
    ['1.2.3.4', 'missing port'],
    ['1.2.3.4:0', 'invalid port'],
    ['1.2.3.4:99999', 'invalid port'],
    ['1.2.3.4:abc', 'invalid port'],
    ['1.2.3.256:8080', 'invalid IP or hostname'],
    ['1.2.3.4.5:8080', 'invalid IP or hostname'],
    ['ftp://1.2.3.4:21', 'unsupported protocol'],
    [':8080', 'invalid IP or hostname'],
    ['a b c', 'contains whitespace'],
    ['user@:8080', 'invalid IP or hostname'],
  ];
  for (const [line] of cases) {
    const r = parseProxyLine(line);
    assert.strictEqual(r.ok, false, `expected reject: "${line}"`);
  }
  assert.strictEqual(parseProxyLine('1.2.3.4:0').reason, 'invalid port');
});

test('leading-zero IPv4 rejected (ambiguity)', () => {
  const r = parseProxyLine('010.0.0.1:8080');
  assert.strictEqual(r.ok, false);
});

test('inline comments and whitespace are stripped', () => {
  const r = parseProxyLine('  1.2.3.4:8080 # my proxy ');
  assert.ok(r.ok);
  assert.strictEqual(r.proxy.host, '1.2.3.4');
});

test('deduplication preserves unique proxies and counts duplicates', () => {
  const text = [
    '1.2.3.4:8080',
    '1.2.3.4:8080',
    '1.2.3.4:8080  ',
    '5.6.7.8:3128',
    'http://1.2.3.4:8080', // different requested protocol → NOT a duplicate
    'user:pw@1.2.3.4:8080', // different credentials → NOT a duplicate
    '',
    '# comment',
    'bad line here',
    '9.9.9.9:99',
    '9.9.9.9:99',
  ].join('\n');
  const res = parseProxyList(text);
  assert.strictEqual(res.totalLines, 9);
  assert.strictEqual(res.duplicateCount, 3);
  assert.strictEqual(res.uniqueCount, 5);
  assert.ok(res.invalid.length >= 1);
});

test('proxyKey is stable and credential-sensitive', () => {
  const a = parseProxyLine('1.2.3.4:8080').proxy;
  const b = parseProxyLine('1.2.3.4:8080').proxy;
  const c = parseProxyLine('u:p@1.2.3.4:8080').proxy;
  assert.strictEqual(proxyKey(a), proxyKey(b));
  assert.notStrictEqual(proxyKey(a), proxyKey(c));
});

test('junk-wrapped proxies are rescued (markdown/mailto/brackets/quotes)', () => {
  // exactly the format from user reports: rich-text editors turn
  // user:pass@host:port into markdown mailto links
  const r = parseProxyLine('xA9pe0xafP8jYjaS:[vkHOgJCOefT6pA0T@geo.floppydata.com:10080](mailto:vkHOgJCOefT6pA0T@geo.floppydata.com:10080)');
  assert.ok(r.ok, JSON.stringify(r));
  assert.strictEqual(r.rescued, true);
  assert.strictEqual(r.proxy.username, 'xA9pe0xafP8jYjaS');
  assert.strictEqual(r.proxy.password, 'vkHOgJCOefT6pA0T');
  assert.strictEqual(r.proxy.host, 'geo.floppydata.com');
  assert.strictEqual(r.proxy.port, 10080);

  const r2 = parseProxyLine('<203.0.113.9:8080>');
  assert.ok(r2.ok);
  assert.strictEqual(r2.proxy.host, '203.0.113.9');

  const r3 = parseProxyLine('"socks5://5.6.7.8:1080"');
  assert.ok(r3.ok);
  assert.strictEqual(r3.proxy.protocol, 'socks5');

  const r4 = parseProxyLine('proxy=9.9.9.9:3128.');
  assert.ok(r4.ok);
  assert.strictEqual(r4.proxy.host, '9.9.9.9');

  // ambiguous junk (two distinct host:port in one line) stays invalid
  assert.strictEqual(parseProxyLine('1.2.3.4:8080 and 5.6.7.8:3128').ok, false);
});

test('plain user:pass@host:port (floppydata-style) parses strictly', () => {
  const r = parseProxyLine('xA9pe0xafP8jYjaS:vkHOgJCOefT6pA0T@geo.floppydata.com:10080');
  assert.ok(r.ok);
  assert.strictEqual(r.proxy.username, 'xA9pe0xafP8jYjaS');
  assert.strictEqual(r.proxy.host, 'geo.floppydata.com');
  assert.strictEqual(r.proxy.port, 10080);
  assert.ok(r.proxy.hasAuth);
  assert.strictEqual(r.rescued, undefined);
});

test('comma/semicolon separated lists parse per entry', () => {
  const res = parseProxyList('1.2.3.4:8080,5.6.7.8:3128; 9.9.9.9:1080');
  assert.strictEqual(res.totalLines, 3);
  assert.strictEqual(res.uniqueCount, 3);
  assert.strictEqual(res.invalid.length, 0);
});

test('strict-only failures stay strict (no junk indicators)', () => {
  assert.strictEqual(parseProxyLine('1.2.3.4.5:8080').ok, false);
  assert.strictEqual(parseProxyLine('a b c').ok, false);
  assert.strictEqual(parseProxyLine('1.2.3.256:8080').ok, false);
});

test('masked labels never contain the password', () => {
  const p = parseProxyLine('socks5://alice:supersecret@1.2.3.4:1080').proxy;
  const label = maskedLabel(p);
  assert.ok(label.includes('alice:********@1.2.3.4:1080'), label);
  assert.ok(!label.includes('supersecret'));
  const p2 = parseProxyLine('1.2.3.4:8080:bob:hunter2').proxy;
  assert.ok(!maskedLabel(p2).includes('hunter2'));
});
