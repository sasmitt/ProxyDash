'use strict';
/**
 * Controlled test targets.
 *
 * The checker only ever contacts this allowlist — never user-supplied URLs
 * (see docs/SECURITY.md "SSRF protection"). At job start we probe targets
 * directly (without a proxy) to (a) order them by reachability and
 * (b) learn the observer's own public IP, which powers transparency
 * detection in the anonymity classifier.
 */
const config = require('./config');
const { fetchRaw } = require('./geo/geoClient');
const { parseEchoBody } = require('./checker/echo');

async function probeEchoTargets(urls = config.targets.echoUrls, timeoutMs = 4000) {
  const working = [];
  let clientIp = null;
  for (const url of urls) {
    try {
      const res = await fetchRaw(url, {
        headers: { 'User-Agent': 'ProxyCheck/1.0', Accept: 'application/json' },
        timeoutMs,
      });
      if (res.status !== 200) continue;
      const parsed = parseEchoBody(Buffer.from(res.text, 'utf8'));
      if (!parsed) continue;
      working.push(url);
      if (!clientIp && parsed.exitIp) clientIp = parsed.exitIp;
    } catch {
      // target unreachable directly — keep it as a through-proxy candidate
    }
  }
  return { working, clientIp, allTargets: urls };
}

module.exports = { probeEchoTargets };
