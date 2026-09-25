'use strict';
/**
 * Small shared helpers: timeout wrapper, backoff, formatting.
 */
const { CheckError } = require('./errors');

/** Run `fn` and reject with a TIMEOUT CheckError if it exceeds `ms`. */
function withTimeout(promise, ms, label = 'operation') {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new CheckError('TIMEOUT', `${label} timed out after ${ms}ms`)), ms);
    promise.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); },
    );
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Retry delay with jittered backoff (kept small; checks are latency-bound). */
function backoffMs(attempt) {
  return Math.min(200 * 2 ** attempt, 1500) + Math.floor(Math.random() * 100);
}

/** Clamp helper. */
function clamp(n, min, max) {
  return Math.min(Math.max(n, min), max);
}

/** Latency → descriptive bucket (labels are descriptive only). */
function latencyBucket(ms) {
  if (ms == null) return 'unknown';
  if (ms < 100) return 'excellent';
  if (ms < 300) return 'fast';
  if (ms < 700) return 'moderate';
  if (ms < 1500) return 'slow';
  return 'very-slow';
}

/** Format ms as mm:ss. */
function fmtEta(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '--:--';
  const s = Math.round(ms / 1000);
  return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
}

module.exports = { withTimeout, sleep, backoffMs, clamp, latencyBucket, fmtEta };
