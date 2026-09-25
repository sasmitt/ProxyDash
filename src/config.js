'use strict';
/**
 * Centralized configuration. Every knob is an environment variable with a
 * safe default, so the app runs with zero configuration.
 */
const path = require('path');

function intEnv(name, def) {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : def;
}

function boolEnv(name, def) {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  return v === '1' || String(v).toLowerCase() === 'true';
}

function listEnv(name, def) {
  const v = process.env[name];
  if (!v) return def;
  return v.split(',').map((s) => s.trim()).filter(Boolean);
}

const config = {
  env: process.env.NODE_ENV || 'development',
  host: process.env.HOST || '0.0.0.0',
  port: intEnv('PORT', 3000),
  version: '1.0.0',
  logLevel: process.env.LOG_LEVEL || 'info',

  limits: {
    maxProxiesPerJob: intEnv('MAX_PROXIES_PER_JOB', 25000),
    maxBodyBytes: intEnv('MAX_BODY_BYTES', 10 * 1024 * 1024),
    maxJobsPerIp: intEnv('MAX_JOBS_PER_IP', 3),
    jobTtlMs: intEnv('JOB_TTL_MS', 2 * 60 * 60 * 1000),
    maxInvalidReported: 100,
    rateLimit: {
      windowMs: intEnv('RATE_LIMIT_WINDOW_MS', 60 * 1000),
      max: intEnv('RATE_LIMIT_MAX', 240),
      jobWindowMs: intEnv('JOB_RATE_WINDOW_MS', 10 * 60 * 1000),
      jobMax: intEnv('JOB_RATE_MAX', 20),
    },
  },

  checker: {
    get allowPrivateProxies() { return boolEnv('ALLOW_PRIVATE_PROXIES', false); },
    defaultConcurrency: intEnv('DEFAULT_CONCURRENCY', 100),
    maxConcurrency: intEnv('MAX_CONCURRENCY', 500),
    minConcurrency: intEnv('MIN_CONCURRENCY', 10),
    defaultTimeoutMs: intEnv('DEFAULT_TIMEOUT_MS', 8000),
    minTimeoutMs: 1000,
    maxTimeoutMs: 30000,
    defaultRetries: intEnv('DEFAULT_RETRIES', 1),
    maxRetries: 3,
    get httpsTest() { return boolEnv('HTTPS_TEST', true); },
    adaptIntervalMs: 2000,
    timeoutRateHigh: 0.5,
    timeoutRateLow: 0.1,
  },

  // Controlled validation endpoints. These are the ONLY destinations the
  // checker itself is allowed to contact (allowlist). Never point these at
  // arbitrary user-supplied URLs. Getters so tests can re-target dynamically.
  targets: {
    get echoUrls() {
      return listEnv('TARGET_ECHO_URLS', [
        'http://httpbin.org/get',
        'https://postman-echo.com/get',
      ]);
    },
    get tlsProbeHost() { return process.env.TARGET_TLS_HOST || 'cloudflare.com'; },
    get tlsProbePort() { return intEnv('TARGET_TLS_PORT', 443); },
  },

  geo: {
    get enabled() { return boolEnv('GEO_ENABLED', true); },
    get providerUrl() { return process.env.GEO_PROVIDER_URL || 'http://ip-api.com/batch'; },
    get fallbackUrl() { return process.env.GEO_FALLBACK_URL || 'https://ipwho.is/{ip}'; },
    ttlMs: intEnv('GEO_TTL_MS', 6 * 60 * 60 * 1000),
    negativeTtlMs: intEnv('GEO_NEG_TTL_MS', 5 * 60 * 1000),
    batchFlushMs: intEnv('GEO_BATCH_FLUSH_MS', 400),
    batchSize: intEnv('GEO_BATCH_SIZE', 100),
    get maxRequestsPerMin() { return intEnv('GEO_MAX_REQ_PER_MIN', 14); },
    requestTimeoutMs: intEnv('GEO_REQUEST_TIMEOUT_MS', 5000),
    maxCacheEntries: intEnv('GEO_MAX_CACHE', 50000),
  },

  publicDir: path.join(__dirname, '..', 'public'),
};

module.exports = config;
