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
 * A junk-tolerant rescue pass extracts proxies from lines mangled by
 * rich-text editors (markdown mailto links, angle brackets, quotes,
 * comma/semicolon separators).
 */
const net = require('net');
const { isIPv4, isValidPort, isHostname } = require('./validation');

const SCHEMES = new Set(['http', 'https', 'socks4', 'socks4a', 'socks5']);

/**
 * Strict parse of a single proxy line.
 * @returns {{ok: true, proxy: object}|{ok: false, reason: string}}
 */
function parseProxyLineStrict(rawLine) {
  let line = String(rawLine).trim();
  // strip inline comments
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

  // Split credentials: userinfo@hostport
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
      // bare (unbracketed) IPv6 — accept when the address portion is valid IPv6
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

// ---------------------------------------------------------------------------
// Junk-tolerant rescue pass.
//
// Rich-text editors, chats and web pages mangle proxy lists:
//   user:pass@host:port  →  user:[pass@host:port](mailto:pass@host:port)
// and proxies get wrapped in angle brackets, quotes, or separated by
// commas/semicolons. When a line fails the strict parse but contains exactly
// one recognizable proxy, extract it instead of rejecting the line.
// ---------------------------------------------------------------------------
const JUNK_RE = /[\[\]<>"'`=,;.]|\bmailto:/i;

const RESCUE_RE = /(?:([a-z][a-z0-9+.-]{2,7}):\/\/)?(?:([A-Za-z0-9.$%!*'~^_+-]{1,128}):([^@\s:[\]]{1,128})@)?((?:\d{1,3}(?:\.\d{1,3}){3})|(?:\[[0-9A-Fa-f:.]{1,45}\])|(?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)+)):(\d{1,5})(?!\d)/g;

function rescueProxyLine(line) {
  if (!JUNK_RE.test(line)) return null;
  let text = ' ' + String(line) + ' ';
  // Flatten markdown links: [label](url) — keep whichever side looks like a
  // proxy. This preserves credentials that sit OUTSIDE the link, e.g.
  //   user:[pass@host:port](mailto:pass@host:port) → user:pass@host:port
  text = text.replace(/\[([^\][()]{1,300})\]\(([^()]{1,300})\)/g, (mm, label, url) => {
    const l = String(label).trim();
    const u = String(url).replace(/^mailto:/i, '').trim();
    const proxyish = (x) => x.includes('@') || /:\d{1,5}$/.test(x);
    return proxyish(l) ? l : proxyish(u) ? u : l;
  });
  // strip wrapper punctuation that never appears inside a valid proxy
  text = text.replace(/[<>"'`]/g, ' ').replace(/\bmailto:/gi, ' ');

  // If the flattened text is now a clean single token, prefer a strict parse.
  const trimmed = text.trim();
  if (!/\s/.test(trimmed)) {
    const strict = parseProxyLineStrict(trimmed);
    if (strict.ok) return strict.proxy;
  }

  const candidates = new Map(); // host:port -> best proxy variant
  let m;
  RESCUE_RE.lastIndex = 0;
  while ((m = RESCUE_RE.exec(text)) !== null) {
    const scheme = m[1] ? m[1].toLowerCase() : null;
    if (scheme && !SCHEMES.has(scheme)) continue;
    let host = m[4].toLowerCase();
    if (host.startsWith('[')) host = host.slice(1, -1);
    const port = Number(m[5]);
    if (!isValidPort(port) || !isHostname(host)) continue;
    const username = m[2] || null;
    const password = m[3] || null;
    const p = { input: line, protocol: scheme, host, port, username, password, hasAuth: Boolean(username || password) };
    const key = `${host}:${port}`;
    const prev = candidates.get(key);
    if (!prev || (!prev.hasAuth && p.hasAuth) || (p.protocol && !prev.protocol)) {
      candidates.set(key, p);
    }
    if (m.index === RESCUE_RE.lastIndex) RESCUE_RE.lastIndex++; // safety
  }
  if (candidates.size === 1) return candidates.values().next().value;
  return null; // nothing found, or ambiguous (multiple distinct host:port)
}

/**
 * Public API: strict parse first, then junk-tolerant rescue.
 * @returns {{ok: true, proxy: object, rescued?: boolean}|{ok: false, reason: string}}
 */
function parseProxyLine(rawLine) {
  const r = parseProxyLineStrict(rawLine);
  if (r.ok || r.skipped) return r;
  const rescued = rescueProxyLine(String(rawLine).trim());
  if (rescued) return { ok: true, proxy: rescued, rescued: true };
  return r;
}

/** Stable identity of a proxy (used for dedup and lookup). */
function proxyKey(p) {
  return [p.protocol || 'auto', p.host, p.port, p.username || '', p.password || ''].join('|');
}

/**
 * Parse a whole list (textarea or file contents).
 * Lines are additionally split on commas/semicolons (never valid inside a
 * proxy string) so `ip:port,user:pass@host:port` lists just work.
 * @returns {{proxies: object[], uniqueCount: number, duplicateCount: number,
 *            invalid: {line: string, lineNo: number, reason: string}[],
 *            totalLines: number, rescuedCount: number}}
 */
function parseProxyList(text) {
  const lines = String(text).split(/\r?\n/);
  const seen = new Map();
  const proxies = [];
  const invalid = [];
  let duplicates = 0;
  let totalLines = 0;
  let rescuedCount = 0;

  lines.forEach((raw, i) => {
    const pieces = raw.split(/[,;]/);
    for (const piece of pieces) {
      const res = parseProxyLine(piece);
      if (res.skipped && !res.ok && res.reason === 'comment') continue;
      if (piece.trim() === '') continue;
      totalLines++;
      if (!res.ok) {
        if (invalid.length < 1000) invalid.push({ line: String(piece).trim().slice(0, 200), lineNo: i + 1, reason: res.reason });
        continue;
      }
      if (res.rescued) rescuedCount++;
      const key = proxyKey(res.proxy);
      if (seen.has(key)) {
        duplicates++;
        continue;
      }
      seen.set(key, true);
      proxies.push(res.proxy);
    }
  });

  return {
    proxies,
    uniqueCount: proxies.length,
    duplicateCount: duplicates,
    invalid,
    totalLines,
    rescuedCount,
  };
}

/** Public-safe view of a proxy: credentials masked, password dropped. */
function maskProxy(p) {
  let s = p.input;
  if (p.password) s = s.split(p.password).join('********');
  return s;
}

function maskedLabel(p) {
  const scheme = p.protocol ? `${p.protocol}://` : '';
  const auth = p.hasAuth ? `${p.username || 'user'}:********@` : '';
  const host = net.isIP(p.host) === 6 ? `[${p.host}]` : p.host;
  return `${scheme}${auth}${host}:${p.port}`;
}

module.exports = { parseProxyLine, parseProxyLineStrict, parseProxyList, proxyKey, maskProxy, maskedLabel, SCHEMES };
