'use strict';
/**
 * Anonymity classification for HTTP(S) proxies, based on headers the echo
 * endpoint actually observed. If headers were not observed, the result is
 * honestly reported as "unknown" — never guessed.
 */
const FORWARDING_HEADERS = [
  'via',
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-server',
  'x-real-ip',
  'client-ip',
  'x-client-ip',
  'x-proxy-id',
  'proxy-connection',
];

/**
 * @param {?object<string,string>} headers lowercase header map echoed by target
 * @param {?string} clientIp public IP of the checking server (control request)
 * @returns {{level: 'transparent'|'anonymous'|'elite'|'unknown', reason: string, evidence: string[]}}
 */
function analyzeAnonymity(headers, { clientIp } = {}) {
  if (!headers) {
    return {
      level: 'unknown',
      reason: 'The test endpoint did not echo request headers, so anonymity could not be classified.',
      evidence: [],
    };
  }
  const evidence = [];
  for (const name of FORWARDING_HEADERS) {
    if (headers[name] !== undefined) evidence.push(name);
  }

  if (clientIp) {
    const leaks = evidence.filter((name) => headers[name].includes(clientIp));
    if (leaks.length) {
      return {
        level: 'transparent',
        reason: `The test endpoint observed the client IP inside forwarding header(s): ${leaks.join(', ')}.`,
        evidence: leaks.map((n) => `${n}: ${truncate(headers[n], 120)}`),
      };
    }
  }

  if (evidence.length) {
    const ipish = evidence.filter((n) => looksLikeIpHeader(headers[n]));
    return {
      level: 'anonymous',
      reason: ipish.length
        ? `Forwarding headers were present (${ipish.join(', ')}) but the observed value did not match the known client IP. The proxy may still pass identifying information.`
        : `Proxy forwarding headers were observed (${evidence.join(', ')}), so the proxy identifies itself, but no client IP was exposed.`,
      evidence: evidence.map((n) => `${n}: ${truncate(headers[n], 120)}`),
    };
  }

  const suspicious = Object.keys(headers).filter((k) => k.startsWith('x-') || k.includes('proxy'));
  if (!suspicious.length) {
    return {
      level: 'elite',
      reason: 'No proxy-related or forwarding headers were observed by the test endpoint.',
      evidence: [],
    };
  }
  return {
    level: 'anonymous',
    reason: `No standard forwarding headers, but proxy-related headers were observed: ${suspicious.join(', ')}.`,
    evidence: suspicious.map((n) => `${n}: ${truncate(headers[n], 120)}`),
  };
}

function looksLikeIpHeader(value) {
  return /\b\d{1,3}(\.\d{1,3}){3}\b/.test(value) || /[0-9a-f:]{6,}/i.test(value);
}

function truncate(s, n) {
  s = String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

module.exports = { analyzeAnonymity, FORWARDING_HEADERS };
