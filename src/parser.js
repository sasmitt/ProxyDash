'use strict';
/**
 * Proxy list parser.
 *
 * Recognized formats (see docs/PROXY_FORMATS.md):
 *   IP:PORT
 *   IP:PORT:USERNAME:PASSWORD
 *   USERNAME:PASSWORD@IP:PORT
 *   http://IP:PORT            (also https, socks4, socks4a, socks5)
 *   scheme://USER:PASS@IP:PORT
 *   [IPv6]:PORT and scheme://[IPv6]:PORT   (bracketed IPv6)
 *
 * The parser never throws on bad input; malformed lines are reported with a
 * reason so the UI can show them, and the original raw line is preserved.
 */
const net = require('net');
const { isIPv4, isValidPort, isHostname } = require('./validation');

const SCHEMES = new Set(['http', 'https', 'socks4', 'socks4a', 'socks5']);

/**
 * Parse a single proxy line.
 * @returns {{ok: true, proxy: object}|{ok: false, reason: string}}
 */
function parseProxyLine(rawLine) {
  let line = String(rawLine).trim();
  // strip inline comments and surrounding quotes
  const hash = line.indexOf('#');
  if (hash === 0) return { ok: false, reason: 'comment', skipped: true };
  if (hash > 0) line = line.slice(0, hash).trim();
  if (!line) return { ok: false, reason: 'empty', skipped: true };
  if (/[\s]/.test(line)) return { ok: false, reason: 'contains whitespace' };
  if (line.length > 400) return { ok: false, reason: 'line too long' };

  let protocol = null;
  let rest = line;

  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//i.exec(line);
  if (schemeMatch) {
    protocol = schemeMatch[1].toLowerCase();
    if (!SCHEMES.has(protocol)) {
      return { ok: false, reason: `unsupported protocol "${protocol}"` };
    }
    rest = line.slice(schemeMatch[0].length);
    if (!rest) return { ok: false, reason: 'missing host' };
  }

  // Split credentials: userinfo@hostport (only if '@' appears before any bracket)
  let username = null;
  let password = null;
  const atIndex = rest.indexOf('@');
  if (atIndex !== -1) {
    const userinfo = rest.slice(0, atIndex);
    rest = rest.slice(atIndex + 1);
    if (!userinfo) return { ok: false, reason: 'empty credentials' };
    const cIdx = userinfo.indexOf(':');
    if (cIdx === -1) {
      username = userinfo;
    } else {
      username = userinfo.slice(0, cIdx);
      password = userinfo.slice(cIdx + 1);
    }
    if (!username) return { ok: false, reason: 'empty username' };
  }

  // Host + port (handle bracketed IPv6)
  let host;
  let portStr;
  let trailingAuth = null;
  if (rest.startsWith('[')) {
    const close = rest.indexOf(']');
    if (close === -1) return { ok: false, reason: 'unclosed IPv6 bracket' };
    host = rest.slice(1, close);
    let after = rest.slice(close + 1);
    if (after.startsWith(':')) {
      after = after.slice(1);
      const parts = after.split(':');
      portStr = parts[0];
      if (parts.length > 1) trailingAuth = parts.slice(1).join(':');
    } else if (after !== '') {
      return { ok: false, reason: 'unexpected characters after IPv6 address' };
    }
  } else {
    const parts = rest.split(':');
    if (parts.length === 2) {
      [host, portStr] = parts;
    } else if (parts.length > 2) {
      // bare (unbracketed) IPv6 — accept when the address portion is a valid IPv6
      const joinedV6 = parts.slice(0, -1).join(':');
      if (net.isIP(joinedV6) === 6) {
        host = joinedV6;
        portStr = parts[parts.length - 1];
      } else if (parts.length >= 4) {
        // IP:PORT:USER:PASS (passwords may contain ':')
        host = parts[0];
        portStr = parts[1];
        if (!username && !password) {
          username = parts[2];
          password = parts.slice(3).join(':');
        } else {
          trailingAuth = parts.slice(2).join(':');
        }
      } else {
        return { ok: false, reason: 'too many ":" segments — bracket IPv6 addresses' };
      }
    } else {
      return { ok: false, reason: 'missing port' };
    }
  }

  if (trailingAuth) return { ok: false, reason: 'unexpected trailing segments' };
  if (!host) return { ok: false, reason: 'missing host' };
  if (!/^[^%]*$/.test(host)) return { ok: false, reason: 'invalid host' };

  host = host.toLowerCase();
  if (!isHostname(host)) return { ok: false, reason: 'invalid IP or hostname' };

  const port = Number(portStr);
  if (!/^\d{1,5}$/.test(String(portStr)) || !isValidPort(port)) {
    return { ok: false, reason: 'invalid port' };
  }

  if ((username !== null && username.includes(' ')) || (password !== null && password.includes(' '))) {
    return { ok: false, reason: 'credentials contain whitespace' };
  }

  return {
    ok: true,
    proxy: {
      input: line,
      protocol, // null => auto-detect
      host,
      port,
      username: username || null,
      password: password || null,
      hasAuth: Boolean(username || password),
    },
  };
}

/** Stable identity of a proxy (used for dedup and lookup). */
function proxyKey(p) {
  return [p.protocol || 'auto', p.host, p.port, p.username || '', p.password || ''].join('|');
}

/**
 * Parse a whole list (textarea or file contents).
 * @returns {{proxies: object[], uniqueCount: number, duplicateCount: number,
 *            invalid: {line: string, lineNo: number, reason: string}[],
 *            totalLines: number}}
 */
function parseProxyList(text) {
  const lines = String(text).split(/\r?\n/);
  const seen = new Map();
  const proxies = [];
  const invalid = [];
  let duplicates = 0;
  let totalLines = 0;

  lines.forEach((raw, i) => {
    const res = parseProxyLine(raw);
    if (res.skipped && !res.ok && res.reason === 'comment') return;
    const nonEmpty = String(raw).trim() !== '';
    if (!nonEmpty) return;
    totalLines++;
    if (!res.ok) {
      if (invalid.length < 1000) invalid.push({ line: String(raw).trim().slice(0, 200), lineNo: i + 1, reason: res.reason });
      return;
    }
    const key = proxyKey(res.proxy);
    if (seen.has(key)) {
      duplicates++;
      return;
    }
    seen.set(key, true);
    proxies.push(res.proxy);
  });

  return {
    proxies,
    uniqueCount: proxies.length,
    duplicateCount: duplicates,
    invalid,
    totalLines,
  };
}

/** Public-safe view of a proxy: credentials masked, password dropped. */
function maskProxy(p) {
  let s = p.input;
  if (p.password) s = s.split(p.password).join('********');
  if (p.username && (s.includes(p.username + ':'))) {
    // keep username visible but mark password position if not already masked
  }
  return s;
}

function maskedLabel(p) {
  const scheme = p.protocol ? `${p.protocol}://` : '';
  const auth = p.hasAuth ? `${p.username || 'user'}:********@` : '';
  const host = net.isIP(p.host) === 6 ? `[${p.host}]` : p.host;
  return `${scheme}${auth}${host}:${p.port}`;
}

module.exports = { parseProxyLine, parseProxyList, proxyKey, maskProxy, maskedLabel, SCHEMES };
