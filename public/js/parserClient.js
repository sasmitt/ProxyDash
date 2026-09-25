/**
 * Client-side mirror of the server list parser (src/parser.js).
 * Used for instant pre-flight counts (unique / duplicates / invalid) while
 * typing. The server re-parses authoritatively on submit.
 */

const SCHEMES = new Set(['http', 'https', 'socks4', 'socks4a', 'socks5']);

function isIPv4(h) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return false;
  return h.split('.').every((o) => {
    if (!/^\d{1,3}$/.test(o)) return false;
    if (o.length > 1 && o[0] === '0') return false;
    return Number(o) <= 255;
  });
}

function isHostname(h) {
  if (isIPv4(h)) return true;
  return /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.?$/i.test(h);
}

export function parseLine(rawLine) {
  let line = String(rawLine).trim();
  const hash = line.indexOf('#');
  if (hash === 0) return { ok: false, reason: 'comment', skipped: true };
  if (hash > 0) line = line.slice(0, hash).trim();
  if (!line) return { ok: false, reason: 'empty', skipped: true };
  if (/\s/.test(line)) return { ok: false, reason: 'contains whitespace' };
  if (line.length > 400) return { ok: false, reason: 'line too long' };

  let protocol = null;
  let rest = line;
  const sm = /^([a-z][a-z0-9+.-]*):\/\//i.exec(line);
  if (sm) {
    protocol = sm[1].toLowerCase();
    if (!SCHEMES.has(protocol)) return { ok: false, reason: `unsupported protocol "${protocol}"` };
    rest = line.slice(sm[0].length);
    if (!rest) return { ok: false, reason: 'missing host' };
  }

  let username = null;
  let password = null;
  const at = rest.indexOf('@');
  if (at !== -1) {
    const userinfo = rest.slice(0, at);
    rest = rest.slice(at + 1);
    if (!userinfo) return { ok: false, reason: 'empty credentials' };
    const ci = userinfo.indexOf(':');
    if (ci === -1) username = userinfo;
    else { username = userinfo.slice(0, ci); password = userinfo.slice(ci + 1); }
    if (!username) return { ok: false, reason: 'empty username' };
  }

  let host; let portStr; let trailing = null;
  if (rest.startsWith('[')) {
    const close = rest.indexOf(']');
    if (close === -1) return { ok: false, reason: 'unclosed IPv6 bracket' };
    host = rest.slice(1, close);
    let after = rest.slice(close + 1);
    if (after.startsWith(':')) {
      after = after.slice(1);
      const parts = after.split(':');
      portStr = parts[0];
      if (parts.length > 1) trailing = parts.slice(1).join(':');
    } else if (after !== '') return { ok: false, reason: 'unexpected characters after IPv6 address' };
  } else {
    const parts = rest.split(':');
    if (parts.length === 2) { [host, portStr] = parts; }
    else if (parts.length === 4) {
      host = parts[0]; portStr = parts[1];
      if (!username && !password) { username = parts[2]; password = parts.slice(3).join(':'); }
      else trailing = parts.slice(2).join(':');
    } else return { ok: false, reason: parts.length < 2 ? 'missing port' : 'too many ":" segments — bracket IPv6 addresses' };
  }
  if (trailing) return { ok: false, reason: 'unexpected trailing segments' };
  if (!host) return { ok: false, reason: 'missing host' };
  host = host.toLowerCase();
  if (!isHostname(host)) return { ok: false, reason: 'invalid IP or hostname' };
  if (!/^\d{1,5}$/.test(String(portStr)) || Number(portStr) < 1 || Number(portStr) > 65535) {
    return { ok: false, reason: 'invalid port' };
  }
  return { ok: true, proxy: { protocol, host, port: Number(portStr), username, password, hasAuth: Boolean(username || password) } };
}

/** Quick list summary: {totalLines, unique, duplicates, invalid} */
export function summarize(text) {
  const seen = new Set();
  let totalLines = 0;
  let duplicates = 0;
  let invalid = 0;
  for (const raw of String(text).split(/\r?\n/)) {
    if (!raw.trim()) continue;
    const r = parseLine(raw);
    if (r.skipped) continue;
    totalLines++;
    if (!r.ok) { invalid++; continue; }
    const p = r.proxy;
    const key = [p.protocol || 'auto', p.host, p.port, p.username || '', p.password || ''].join('|');
    if (seen.has(key)) duplicates++;
    else seen.add(key);
  }
  return { totalLines, unique: seen.size, duplicates, invalid };
}
