'use strict';
/**
 * Structured JSON-lines logger with credential redaction.
 * Passwords / secrets must never reach the log stream.
 */
const config = require('./config');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const REDACT_KEYS = /pass|pwd|secret|token|credential|authorization|proxy-authorization/i;

function redact(value, depth = 0) {
  if (depth > 4) return '[depth]';
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = REDACT_KEYS.test(k) ? '[REDACTED]' : redact(v, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string' && value.length > 2000) return value.slice(0, 2000) + '…';
  return value;
}

function log(level, msg, meta) {
  const min = LEVELS[config.logLevel] || LEVELS.info;
  if ((LEVELS[level] || 0) < min) return;
  const entry = { ts: new Date().toISOString(), level, msg };
  if (meta !== undefined) entry.meta = redact(meta);
  try {
    process.stdout.write(JSON.stringify(entry) + '\n');
  } catch {
    /* logging must never crash the app */
  }
}

module.exports = {
  debug: (msg, meta) => log('debug', msg, meta),
  info: (msg, meta) => log('info', msg, meta),
  warn: (msg, meta) => log('warn', msg, meta),
  error: (msg, meta) => log('error', msg, meta),
  redact,
};
