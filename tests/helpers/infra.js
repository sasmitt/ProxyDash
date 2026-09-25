'use strict';
/**
 * Shared test infrastructure: boots the full mock stack (echo target, TLS
 * target with throwaway CA, geo provider) and points the app's allowlist at
 * them via env vars. Call BEFORE requiring src modules.
 */
const { createEchoServer, createTlsTarget, createGeoServer, generateCert } = require('./mockProxy');

async function startInfra({ geo = true } = {}) {
  const echo = createEchoServer({ originOverride: '93.184.216.34' });
  const echoPort = await echo.ready;
  const cert = generateCert();
  const tlsTarget = createTlsTarget(cert);
  const tlsPort = await tlsTarget.ready;
  process.env.TARGET_ECHO_URLS = `http://127.0.0.1:${echoPort}/echo`;
  process.env.TARGET_TLS_HOST = '127.0.0.1';
  process.env.TARGET_TLS_PORT = String(tlsPort);
  process.env.TLS_EXTRA_CA = cert.ca;
  if (geo) {
    const geoSrv = createGeoServer();
    const geoPort = await geoSrv.ready;
    process.env.GEO_PROVIDER_URL = `http://127.0.0.1:${geoPort}/batch`;
    process.env.GEO_FALLBACK_URL = `http://127.0.0.1:${geoPort}/ipwho/{ip}`;
    process.env.GEO_BATCH_FLUSH_MS = '40';
  }
  process.env.ALLOW_PRIVATE_PROXIES = 'true';
  return {
    echoPort,
    tlsPort,
    echoUrl: process.env.TARGET_ECHO_URLS,
    async close() {
      await echo.close();
      await tlsTarget.close();
    },
  };
}

module.exports = { startInfra };
