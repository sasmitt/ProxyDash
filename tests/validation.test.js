'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { classifyAddress, assertSafeProxyHost, isIPv4, isValidPort, isHostname, safeLookup, SsrfGuardError } = require('../src/validation');
const dns = require('dns').promises;

test('isIPv4 strict', () => {
  assert.ok(isIPv4('1.2.3.4'));
  assert.ok(isIPv4('255.255.255.255'));
  assert.ok(!isIPv4('256.1.1.1'));
  assert.ok(!isIPv4('1.2.3'));
  assert.ok(!isIPv4('1.2.3.4.5'));
  assert.ok(!isIPv4('01.2.3.4'));
  assert.ok(!isIPv4('a.b.c.d'));
});

test('isValidPort', () => {
  assert.ok(isValidPort(1));
  assert.ok(isValidPort(65535));
  assert.ok(!isValidPort(0));
  assert.ok(!isValidPort(65536));
  assert.ok(!isValidPort(-1));
  assert.ok(!isValidPort(1.5));
});

test('isHostname', () => {
  assert.ok(isHostname('example.com'));
  assert.ok(isHostname('a.b.c.example.co.uk'));
  assert.ok(isHostname('proxy_1'));
  assert.ok(!isHostname('-bad.example.com'));
  assert.ok(!isHostname('exa mple.com'));
  assert.ok(!isHostname(''));
});

test('classifyAddress flags private/reserved ranges', () => {
  const blocked = ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.1.1', '100.64.0.1', '0.0.0.0', '224.0.0.5', '240.0.0.1', '198.18.0.1'];
  for (const ip of blocked) {
    const c = classifyAddress(ip);
    assert.ok(c.isBlocked, `${ip} should be blocked`);
  }
  const publicIps = ['1.2.3.4', '8.8.8.8', '203.0.114.99'];
  for (const ip of publicIps) {
    assert.strictEqual(classifyAddress(ip).isBlocked, false, `${ip} should be public`);
  }
  // 172.32.x.x is public
  assert.strictEqual(classifyAddress('172.32.0.1').isBlocked, false);
});

test('classifyAddress flags cloud metadata endpoints (always)', () => {
  assert.strictEqual(classifyAddress('169.254.169.254').metadata, true);
  assert.strictEqual(classifyAddress('fd00:ec2::254').metadata, true);
});

test('classifyAddress handles IPv6', () => {
  assert.ok(classifyAddress('::1').isBlocked);
  assert.ok(classifyAddress('fe80::1').isBlocked);
  assert.ok(classifyAddress('fc00::1').isBlocked);
  assert.ok(classifyAddress('::ffff:127.0.0.1').isBlocked, 'v4-mapped loopback blocked');
  assert.strictEqual(classifyAddress('2606:4700::1111').isBlocked, false);
});

test('assertSafeProxyHost blocks loopback/private by default', () => {
  assert.throws(() => assertSafeProxyHost('127.0.0.1', false), SsrfGuardError);
  assert.throws(() => assertSafeProxyHost('10.0.0.5', false), SsrfGuardError);
  assert.throws(() => assertSafeProxyHost('192.168.1.1', false), SsrfGuardError);
  assert.throws(() => assertSafeProxyHost('localhost', false), SsrfGuardError);
  assert.throws(() => assertSafeProxyHost('169.254.169.254', true), SsrfGuardError, 'metadata blocked even when private allowed');
  assert.throws(() => assertSafeProxyHost('not a host!!', false), SsrfGuardError);
  assert.doesNotThrow(() => assertSafeProxyHost('127.0.0.1', true), 'private allowed in dev mode');
  assert.doesNotThrow(() => assertSafeProxyHost('proxy.example.com', false));
});

test('safeLookup rejects hostnames resolving to blocked addresses', async () => {
  const lookup = safeLookup(false);
  await assert.rejects(() => new Promise((resolve, reject) => {
    lookup('localhost', {}, (err, addr) => (err ? reject(err) : resolve(addr)));
  }), SsrfGuardError);
  // public hostname passes and returns an address
  const addr = await new Promise((resolve, reject) => {
    lookup('example.com', {}, (err, a) => (err ? reject(err) : resolve(a)));
  });
  assert.ok(addr);
  assert.strictEqual(classifyAddress(addr).isBlocked, false);
});

test('safeLookup rejects rebinding-style private results', async () => {
  // craft a lookup that "resolves" example.com to 127.0.0.1 by stubbing dns
  const real = dns.lookup;
  const lookup = safeLookup(false);
  const mod = require('dns');
  mod.promises; // touch
  const origLookup = mod.lookup;
  mod.lookup = (host, opts, cb) => cb(null, [{ address: '192.168.0.44', family: 4 }]);
  try {
    await assert.rejects(() => new Promise((resolve, reject) => {
      lookup('evil.example.com', {}, (err, addr) => (err ? reject(err) : resolve(addr)));
    }), SsrfGuardError);
  } finally {
    mod.lookup = origLookup;
  }
});
