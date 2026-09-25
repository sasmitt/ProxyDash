'use strict';
/**
 * Echo-target response adapter.
 *
 * The checker talks to a small allowlist of controlled "echo" endpoints that
 * report the caller's observed IP and (for some) the request headers it saw.
 * Different providers use slightly different JSON shapes; this adapter
 * normalizes them instead of trusting any single provider.
 *
 * Shapes understood:
 *   httpbin-like:        { origin: "1.2.3.4", headers: {...} }
 *   postman-echo-like:   { ip / origin, headers: {...} }
 *   ip-api-like:         { query: "1.2.3.4", country, ... }
 *   ipwho.is-like:       { ip: "1.2.3.4", country, ... }
 */
const { CheckError } = require('../errors');

function normalizeHeaders(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v === 'string') out[k.toLowerCase()] = v;
    else if (Array.isArray(v) && v.every((x) => typeof x === 'string')) out[k.toLowerCase()] = v.join(', ');
  }
  return Object.keys(out).length ? out : null;
}

/** Extract approximate geo fields present directly in an echo response. */
function extractGeo(body) {
  const g = {};
  const country = body.country || body.country_name;
  if (country) g.country = String(country);
  const cc = body.countryCode || body.country_code;
  if (cc) g.countryCode = String(cc).slice(0, 2).toUpperCase();
  const region = body.regionName || body.region;
  if (region && typeof region === 'string' && region.length < 100) g.region = region;
  if (body.city && typeof body.city === 'string') g.city = body.city;
  const lat = body.lat != null ? body.lat : body.latitude;
  const lon = body.lon != null ? body.lon : body.longitude;
  if (Number.isFinite(Number(lat))) g.latitude = Number(lat);
  if (Number.isFinite(Number(lon))) g.longitude = Number(lon);
  const tz = body.timezone && typeof body.timezone === 'object' ? body.timezone.id : body.timezone;
  if (tz && typeof tz === 'string') g.timezone = tz;

  // ASN / ISP (ip-api-like flat fields or ipwho.is-like nested connection)
  const conn = body.connection && typeof body.connection === 'object' ? body.connection : null;
  const asRaw = body.as || (conn && conn.asn != null ? `AS${conn.asn}` : null);
  if (typeof asRaw === 'string' && asRaw) {
    const m = /^(AS\d+)\s*(.*)$/.exec(asRaw);
    g.asn = m ? m[1] : asRaw.split(' ')[0];
    g.asOrg = (m && m[2]) || (conn && conn.org) || null;
  } else if (conn && conn.asn != null) {
    g.asn = `AS${conn.asn}`;
    g.asOrg = conn.org || null;
  }
  const isp = body.isp || (conn && conn.isp);
  if (isp && typeof isp === 'string') g.isp = isp;
  const org = body.org || (conn && conn.org);
  if (org && typeof org === 'string') g.org = org;
  if (typeof body.reverse === 'string' && body.reverse) g.reverse = body.reverse;

  return Object.keys(g).length ? g : null;
}

/**
 * Parse an echo response body.
 * @returns {{exitIp: ?string, headers: ?object<string,string>, geo: ?object}|null}
 */
function parseEchoBody(bodyBuffer) {
  if (!bodyBuffer || !bodyBuffer.length) return null;
  const text = bodyBuffer.toString('utf8').slice(0, 64 * 1024);
  const start = text.indexOf('{');
  if (start === -1) return null;
  let body;
  try {
    body = JSON.parse(text.slice(start));
  } catch {
    return null;
  }
  if (!body || typeof body !== 'object') return null;

  let exitIp = null;
  for (const key of ['origin', 'query', 'ip', 'ipAddress', 'yourIp']) {
    const v = body[key];
    if (typeof v === 'string' && v.length >= 7) {
      exitIp = v.split(',')[0].trim(); // some providers send "ip, ip"
      break;
    }
  }
  if (exitIp && !/^[\d.:a-fA-F]+$/.test(exitIp)) exitIp = null;

  return {
    exitIp,
    headers: normalizeHeaders(body.headers),
    geo: extractGeo(body),
  };
}

/** Assert a configured echo target URL is a sane allowlist entry. */
function assertSafeTargetUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new CheckError('TARGET_ERROR', `invalid echo target URL: ${url}`);
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new CheckError('TARGET_ERROR', 'echo target must be http(s)');
  }
  return { host: u.hostname, port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80), url };
}

module.exports = { parseEchoBody, normalizeHeaders, extractGeo, assertSafeTargetUrl };
