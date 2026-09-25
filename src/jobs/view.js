'use strict';
/**
 * Safe result serialization.
 *
 * Credentials NEVER appear in serialized results — inputs are rebuilt as
 * masked labels (user:********@host:port). Raw inputs with credentials only
 * ever exist server-side and are used solely by the explicit
 * include=credentials export option.
 */
const { maskedLabel } = require('../parser');
const { latencyBucket } = require('../utils');
const { EMPTY_GEO } = require('../geo/geoClient');

function computeConfidence(raw) {
  if (!raw.alive) return 'failed';
  if (raw.confidence) return 'partial';
  if (raw.echo && raw.echo.exitIp && raw.echo.headers) return 'verified';
  if (raw.echo && raw.echo.exitIp) return 'verified';
  return 'partial';
}

/**
 * Build the client-visible view of a raw probe result.
 * @param raw result from checker/probe
 * @param proxy parsed proxy (server-side, may contain credentials)
 */
function buildResultView(raw, proxy, seq, i) {
  const checkedAt = new Date().toISOString();
  const latency = {
    tcpMs: raw.latency && raw.latency.tcpMs != null ? Math.round(raw.latency.tcpMs) : null,
    handshakeMs: raw.latency && raw.latency.handshakeMs != null ? Math.round(raw.latency.handshakeMs) : null,
    requestMs: raw.latency && raw.latency.requestMs != null ? Math.round(raw.latency.requestMs) : null,
    totalMs: raw.latency && raw.latency.totalMs != null ? Math.round(raw.latency.totalMs) : null,
  };
  const confidence = computeConfidence(raw);
  return {
    seq,
    i,
    input: maskedLabel(proxy),
    host: proxy.host,
    port: proxy.port,
    hasAuth: Boolean(proxy.hasAuth),
    requestedProtocol: proxy.protocol || 'auto',
    protocol: raw.protocol || null,
    status: raw.alive ? 'alive' : 'dead',
    alive: Boolean(raw.alive),
    partial: Boolean(raw.confidence),
    errorCategory: raw.errorCategory || null,
    errorMessage: raw.errorMessage || null,
    exitIp: raw.exitIp || null,
    geo: raw.geo || { ...EMPTY_GEO(), state: 'pending' },
    latency,
    bucket: latencyBucket(latency.totalMs),
    httpStatus: raw.httpStatus || null,
    responseHeaders: raw.responseHeaders || null,
    https: raw.https || { supported: null, tlsVersion: null, certValid: null, error: null },
    anonymity: raw.anonymity || { level: 'unknown', reason: 'Not observed.', evidence: [] },
    auth: raw.auth || { required: false, provided: Boolean(proxy.hasAuth), ok: null },
    dns: raw.dns || null,
    confidence,
    attempts: raw.attempts || 1,
    checkedAt,
  };
}

module.exports = { buildResultView, computeConfidence };
