/**
 * Deterministic demo dataset so the full UI can be explored without live
 * checks. Clearly labeled in the UI as generated sample data — never mixed
 * into real job results and never exported as if real.
 */

let seed = 1337;
function rnd() {
  seed = (seed * 1103515245 + 12345) % 2147483648;
  return seed / 2147483648;
}
function pick(arr) { return arr[Math.floor(rnd() * arr.length)]; }

const COUNTRIES = [
  ['Germany', 'DE', 'Hesse', 'Frankfurt', 50.11, 8.68, 'Europe/Berlin', 'AS16509 Amazon.com, Inc.', 'Amazon.com', 'Amazon Technologies'],
  ['United States', 'US', 'California', 'Los Angeles', 34.05, -118.24, 'America/Los_Angeles', 'AS20473 Choopa, LLC', 'The Constant Company', 'Vultr Holdings'],
  ['Netherlands', 'NL', 'North Holland', 'Amsterdam', 52.37, 4.9, 'Europe/Amsterdam', 'AS60781 LeaseWeb Netherlands B.V.', 'LeaseWeb', 'LeaseWeb Netherlands'],
  ['Singapore', 'SG', '', 'Singapore', 1.35, 103.82, 'Asia/Singapore', 'AS9009 M247 Europe SRL', 'M247 Ltd', 'M247 Europe'],
  ['Brazil', 'BR', 'Sao Paulo', 'Sao Paulo', -23.55, -46.63, 'America/Sao_Paulo', 'AS28573 Claro NXT Telecomunicacoes', 'Claro NXT', 'Claro S.A.'],
  ['India', 'IN', 'Maharashtra', 'Mumbai', 19.08, 72.88, 'Asia/Kolkata', 'AS55836 Reliance Jio Infocomm', 'Reliance Jio', 'Jio Fiber'],
  ['Japan', 'JP', 'Tokyo', 'Tokyo', 35.68, 139.69, 'Asia/Tokyo', 'AS2516 KDDI CORPORATION', 'KDDI', 'KDDI Corporation'],
];
const PROTOS = ['http', 'http', 'http', 'socks5', 'socks5', 'socks4', 'https'];
const ERRORS = [
  ['TIMEOUT', 'proxy TCP connect timed out'],
  ['CONNECTION_REFUSED', 'Connection refused or reset by the proxy.'],
  ['AUTH_FAILED', 'Authentication required: proxy answered 407 and no credentials were provided.'],
  ['DNS_ERROR', 'Proxy hostname could not be resolved.'],
  ['TLS_ERROR', 'TLS handshake failed: self-signed certificate'],
];

export function generateDemoResults(n = 600) {
  seed = 1337;
  const out = [];
  const t0 = Date.now() - n * 8;
  for (let i = 0; i < n; i++) {
    const alive = rnd() < 0.42;
    const oct = () => 1 + Math.floor(rnd() * 254);
    const host = `${oct()}.${oct()}.${oct()}.${oct()}`;
    const port = pick([8080, 3128, 1080, 8888, 80, 9090, 9050]);
    const protocol = alive ? pick(PROTOS) : pick(PROTOS);
    const geo = COUNTRIES[Math.floor(rnd() * COUNTRIES.length)];
    const total = alive ? Math.round(40 + Math.exp(rnd() * 6.2)) : null;
    const https = alive && protocol !== 'socks4'
      ? (rnd() < 0.8
        ? { supported: true, tlsVersion: rnd() < 0.7 ? 'TLSv1.3' : 'TLSv1.2', certValid: rnd() > 0.06, error: null }
        : { supported: false, tlsVersion: null, certValid: null, error: 'Connect: proxy refused CONNECT tunnel (HTTP 403)' })
      : { supported: null, tlsVersion: null, certValid: null, error: null };
    const anonLevel = alive
      ? (protocol.startsWith('socks') ? 'elite' : pick(['elite', 'anonymous', 'anonymous', 'transparent', 'unknown']))
      : 'unknown';
    const err = !alive ? ERRORS[Math.floor(rnd() * ERRORS.length)] : [null, null];
    const bucket = total == null ? 'unknown' : total < 100 ? 'excellent' : total < 300 ? 'fast' : total < 700 ? 'moderate' : total < 1500 ? 'slow' : 'very-slow';
    out.push({
      seq: i,
      i,
      input: `${host}:${port}`,
      host,
      port,
      hasAuth: false,
      requestedProtocol: 'auto',
      protocol: alive ? protocol : null,
      status: alive ? 'alive' : 'dead',
      alive,
      partial: false,
      errorCategory: err[0],
      errorMessage: err[1],
      exitIp: alive ? `${oct()}.${oct()}.${oct()}.${oct()}` : null,
      geo: {
        state: alive && rnd() < 0.9 ? 'ok' : 'unavailable',
        country: alive ? geo[0] : null,
        countryCode: alive ? geo[1] : null,
        region: alive ? geo[2] : null,
        city: alive ? geo[3] : null,
        latitude: alive ? geo[4] : null,
        longitude: alive ? geo[5] : null,
        timezone: alive ? geo[6] : null,
        asn: alive && rnd() < 0.9 ? geo[7].split(' ')[0] : null,
        asOrg: alive ? geo[7].split(' ').slice(1).join(' ') : null,
        isp: alive ? geo[8] : null,
        org: alive ? geo[9] : null,
        reverse: null,
        source: 'demo',
      },
      latency: {
        tcpMs: alive ? Math.round(total * 0.4) : null,
        handshakeMs: alive && protocol.startsWith('socks') ? Math.round(total * 0.25) : null,
        requestMs: alive ? Math.round(total * 0.6) : null,
        totalMs: total,
      },
      bucket,
      httpStatus: alive ? 200 : null,
      responseHeaders: null,
      https,
      anonymity: {
        level: anonLevel,
        reason: anonLevel === 'elite' ? 'No proxy-related or forwarding headers were observed by the test endpoint.'
          : anonLevel === 'anonymous' ? 'Proxy forwarding headers were observed, but no client IP was exposed.'
            : anonLevel === 'transparent' ? 'The test endpoint observed the client IP inside forwarding header(s).'
              : 'Proxy was not reachable, so header behavior could not be observed.',
        evidence: [],
      },
      auth: { required: false, provided: false, ok: null },
      dns: alive && protocol === 'socks5' ? 'remote (hostname sent to proxy for resolution)' : null,
      confidence: alive ? 'verified' : 'failed',
      attempts: 1,
      checkedAt: new Date(t0 + i * 8).toISOString(),
    });
  }
  return out;
}
