'use strict';
/**
 * IP / address classification and SSRF destination guarding.
 *
 * The checker makes outbound connections by design, so every destination
 * (proxy host) is validated before a socket is opened:
 *  - loopback, private, link-local, CGNAT, reserved and multicast ranges are
 *    blocked by default;
 *  - cloud-metadata endpoints (169.254.169.254, fd00:ec2::254) are ALWAYS
 *    blocked, even when private ranges are explicitly allowed for tests;
 *  - the guard runs inside a custom dns.lookup so hostnames that RESOLVE to
 *    a blocked address are rejected too (no rebinding window).
 */
const dns = require('dns');

class SsrfGuardError extends Error {
  constructor(reason) {
    super(`Blocked by SSRF protection: ${reason}`);
    this.name = 'SsrfGuardError';
    this.reason = reason;
  }
}

const BLOCK_V4 = [
  ['0.0.0.0/8', 'this-network range'],
  ['10.0.0.0/8', 'private range (RFC1918)'],
  ['100.64.0.0/10', 'CGNAT range (RFC6598)'],
  ['127.0.0.0/8', 'loopback'],
  ['169.254.0.0/16', 'link-local range'],
  ['172.16.0.0/12', 'private range (RFC1918)'],
  ['192.0.0.0/24', 'IETF protocol assignments'],
  ['192.0.2.0/24', 'TEST-NET-1'],
  ['192.88.99.0/24', '6to4 relay anycast'],
  ['192.168.0.0/16', 'private range (RFC1918)'],
  ['198.18.0.0/15', 'benchmarking range'],
  ['198.51.100.0/24', 'TEST-NET-2'],
  ['203.0.113.0/24', 'TEST-NET-3'],
  ['224.0.0.0/4', 'multicast'],
  ['240.0.0.0/4', 'reserved'],
];

// Hostnames that are never accepted as a proxy destination.
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
]);

const METADATA_V4 = ['169.254.169.254', '169.254.170.2'];
const METADATA_V6 = ['fd00:ec2::254'];

function v4ToInt(ip) {
  const p = ip.split('.');
  return ((+p[0] << 24) | (+p[1] << 16) | (+p[2] << 8) | +p[3]) >>> 0;
}

function cidr4Match(ip, cidr) {
  const [range, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (v4ToInt(ip) & mask) === (v4ToInt(range) & mask);
}

/** Expand an IPv6 address to its 128-bit BigInt form (handles ::). */
function v6ToBigInt(ip) {
  let addr = ip;
  const zone = addr.indexOf('%');
  if (zone !== -1) addr = addr.slice(0, zone);
  let head = addr;
  let tail = '';
  const dc = addr.indexOf('::');
  if (dc !== -1) {
    head = addr.slice(0, dc);
    tail = addr.slice(dc + 2);
  }
  const hGroups = head ? head.split(':') : [];
  const tGroups = tail ? tail.split(':') : [];
  // Handle IPv4-mapped tail (::ffff:1.2.3.4)
  const last = tGroups.length ? tGroups[tGroups.length - 1] : '';
  if (last && last.includes('.')) {
    const n = v4ToInt(last);
    tGroups[tGroups.length - 1] = ((n >>> 16) & 0xffff).toString(16);
    tGroups.push((n & 0xffff).toString(16));
  }
  const missing = 8 - hGroups.length - tGroups.length;
  const groups = [...hGroups, ...Array(Math.max(missing, 0)).fill('0'), ...tGroups];
  let out = 0n;
  for (const g of groups) out = (out << 16n) | BigInt(parseInt(g || '0', 16));
  return out;
}

function cidr6Match(ip, cidr) {
  const [range, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const ipB = v6ToBigInt(ip);
  const rB = v6ToBigInt(range);
  if (bits === 0) return true;
  const shift = BigInt(128 - bits);
  return ipB >> shift === rB >> shift;
}

const V6_BLOCKED = [
  ['::1/128', 'loopback'],
  ['::/128', 'unspecified'],
  ['::ffff:0:0/96', 'IPv4-mapped'],
  ['fc00::/7', 'unique-local'],
  ['fe80::/10', 'link-local'],
  ['2001:db8::/32', 'documentation range'],
  ['ff00::/8', 'multicast'],
];

/**
 * Classify an address.
 * @returns {{kind: string, reason?: string, isBlocked: boolean, metadata: boolean}}
 */
function classifyAddress(ip) {
  const base = { kind: 'public', isBlocked: false, metadata: false };
  if (ip.includes('.') && !ip.includes(':')) {
    // metadata endpoints take precedence over the generic link-local range
    if (METADATA_V4.includes(ip)) {
      return { kind: 'metadata', reason: 'cloud metadata endpoint', isBlocked: true, metadata: true };
    }
    for (const [cidr, reason] of BLOCK_V4) {
      if (cidr4Match(ip, cidr)) {
        return { kind: reason.includes('loopback') ? 'loopback' : 'reserved', reason, isBlocked: true, metadata: false };
      }
    }
    return base;
  }
  const lower = ip.toLowerCase();
  for (const meta of METADATA_V6) {
    if (cidr6Match(lower, `${meta}/128`)) {
      return { kind: 'metadata', reason: 'cloud metadata endpoint', isBlocked: true, metadata: true };
    }
  }
  for (const [cidr, reason] of V6_BLOCKED) {
    if (cidr6Match(lower, cidr)) {
      const kind = reason === 'IPv4-mapped' ? 'public' : 'reserved';
      const mapped = v6ToBigInt(lower);
      if (reason === 'IPv4-mapped') {
        const v4 = [
          Number((mapped >> 24n) & 0xffn),
          Number((mapped >> 16n) & 0xffn),
          Number((mapped >> 8n) & 0xffn),
          Number(mapped & 0xffn),
        ].join('.');
        return classifyAddress(v4);
      }
      return { kind, reason, isBlocked: true, metadata: false };
    }
  }
  return base;
}

function isIPv4(host) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
  return host.split('.').every((o) => {
    if (!/^\d{1,3}$/.test(o)) return false;
    if (o.length > 1 && o[0] === '0') return false; // no ambiguous leading zeros
    return Number(o) <= 255;
  });
}

function isValidPort(port) {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.?$/i;

function isHostname(host) {
  if (isIPv4(host)) return true;
  // all-numeric dotted strings must be strict IPv4 — never fall through to
  // the looser hostname rules ('010.0.0.1', '1.2.3.256', '1.2.3.4.5' rejected)
  if (/\d/.test(host) && /^\d+(\.\d+)*$/.test(host)) return isIPv4(host);
  try {
    if (require('net').isIP(host) === 6) return true;
  } catch { /* noop */ }
  return HOSTNAME_RE.test(host);
}

/**
 * Validate a proxy destination host before connecting.
 * @param {string} host ip or hostname
 * @param {boolean} allowPrivate allow loopback/private ranges (dev & tests only)
 * @throws {SsrfGuardError}
 */
function assertSafeProxyHost(host, allowPrivate) {
  const lower = String(host).toLowerCase().replace(/\.$/, '');
  if (BLOCKED_HOSTNAMES.has(lower)) {
    throw new SsrfGuardError(`"${lower}" is a blocked destination`);
  }
  const net = require('net');
  const family = net.isIP(lower);
  if (family === 4 || family === 6) {
    const c = classifyAddress(lower);
    if (c.metadata) throw new SsrfGuardError(c.reason);
    if (c.isBlocked && !allowPrivate) throw new SsrfGuardError(c.reason);
    return;
  }
  if (!isHostname(lower)) {
    throw new SsrfGuardError('host is not a valid IP or hostname');
  }
}

/**
 * Custom dns.lookup for net.connect(): resolves the hostname, validates the
 * resulting address(es), then hands back a safe address. Closes the classic
 * DNS-rebinding TOCTOU window between validation and connect().
 */
function safeLookup(allowPrivate) {
  return function lookup(hostname, options, callback) {
    dns.lookup(hostname, { ...options, all: true, verbatim: true }, (err, addresses) => {
      if (err) return callback(err);
      if (!Array.isArray(addresses) || addresses.length === 0) {
        return callback(new Error('ENOTFOUND'));
      }
      for (const a of addresses) {
        let c;
        try {
          c = classifyAddress(a.address);
        } catch {
          continue;
        }
        if (c.metadata) return callback(new SsrfGuardError(c.reason));
        if (c.isBlocked && !allowPrivate) return callback(new SsrfGuardError(c.reason));
      }
      const pick = addresses[0];
      callback(null, pick.address, pick.family);
    });
  };
}

module.exports = {
  SsrfGuardError,
  classifyAddress,
  isIPv4,
  isValidPort,
  isHostname,
  assertSafeProxyHost,
  safeLookup,
  BLOCKED_HOSTNAMES,
  v6ToBigInt,
};
