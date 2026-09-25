'use strict';
/**
 * Per-proxy checking pipeline.
 *
 * Stages: destination guard → connection → protocol probe (actual protocol
 * behavior, never just the input prefix) → exit-IP + header echo → HTTPS/TLS
 * tunnel test → result normalization.
 *
 * All work happens under a single per-proxy deadline; every socket is
 * destroyed when the deadline fires or the job is cancelled.
 */
const { CheckError, SsrfBlockedError } = require('../errors');
const { assertSafeProxyHost } = require('../validation');
const { requestViaProxy, connectViaProxy, upgradeTls, writeAndRead, shortTlsError } = require('./httpProxy');
const { socksConnect } = require('./socks');
const { parseEchoBody, assertSafeTargetUrl } = require('./echo');
const { analyzeAnonymity } = require('./anonymity');

const STRATEGY_ORDER = { http: ['http'], https: ['https'], socks4: ['socks4'], socks4a: ['socks4a'], socks5: ['socks5'], auto: ['http', 'socks5', 'socks4'] };
const AUTO_BUDGET_SPLIT = [0.6, 0.25, 0.15];

/** Cancel-aware socket registry so the engine can abort in-flight checks. */
function makeCancellation(signal) {
  const sockets = new Set();
  const track = (sock) => {
    sockets.add(sock);
    sock.once('close', () => sockets.delete(sock));
    return sock;
  };
  const untrackAll = () => {
    for (const s of sockets) { try { s.destroy(); } catch { /* noop */ } }
    sockets.clear();
  };
  if (signal) signal.onAbort(untrackAll);
  return { track, abort: untrackAll };
}

/**
 * Check a single proxy.
 * @returns normalized result object (see docs/API.md#result)
 */
async function checkProxy(proxy, opts) {
  const {
    timeoutMs = 8000,
    httpsTest = true,
    echoTargets = [],
    tlsProbeHost = 'cloudflare.com',
    tlsProbePort = 443,
    allowPrivate = false,
    clientIp = null,
    signal = null,
  } = opts;

  const result = {
    status: 'dead',
    alive: false,
    protocol: proxy.protocol || null, // confirmed protocol, filled on success
    requestedProtocol: proxy.protocol,
    exitIp: null,
    httpStatus: null,
    responseHeaders: null,
    latency: { tcpMs: null, handshakeMs: null, requestMs: null, totalMs: null },
    https: { supported: null, tlsVersion: null, certValid: null, error: null },
    anonymity: { level: 'unknown', reason: 'Proxy was not reachable, so header behavior could not be observed.', evidence: [] },
    auth: { required: false, provided: Boolean(proxy.hasAuth), ok: null },
    dns: null,
    errorCategory: null,
    errorMessage: null,
    geo: null,
    attempts: 0,
  };

  // Stage 0 — destination guard (SSRF).
  try {
    assertSafeProxyHost(proxy.host, allowPrivate);
  } catch (err) {
    if (err instanceof SsrfBlockedError || err.name === 'SsrfGuardError') {
      result.errorCategory = 'INVALID_PROXY';
      result.errorMessage = 'Blocked: the proxy points at a private, reserved or otherwise forbidden address (SSRF protection).';
    } else {
      result.errorCategory = 'INVALID_PROXY';
      result.errorMessage = 'Proxy destination failed validation.';
    }
    return result;
  }

  const cancel = makeCancellation(signal);
  const deadline = Date.now() + timeoutMs;
  const target = echoTargets.length ? assertSafeTargetUrl(echoTargets[0]) : null;
  if (!target) {
    result.errorCategory = 'TARGET_ERROR';
    result.errorMessage = 'No echo target configured.';
    return result;
  }

  const strategies = STRATEGY_ORDER[proxy.protocol] || STRATEGY_ORDER.auto;
  let lastError = null;
  let detected = null; // set when a peer unambiguously spoke a protocol

  for (let i = 0; i < strategies.length; i++) {
    const strategy = strategies[i];
    const share = strategies.length > 1 ? AUTO_BUDGET_SPLIT[Math.min(i, AUTO_BUDGET_SPLIT.length - 1)] : 1;
    const stageDeadline = Math.min(
      Date.now() + Math.max(Math.round((deadline - Date.now()) * (strategies.length > 1 ? share * 1.6 : 1)), 500),
      deadline,
    );
    result.attempts++;
    try {
      const partial = await runStrategy(proxy, strategy, target, stageDeadline, { allowPrivate, cancel, signal, clientIp });
      // Success — merge probe data.
      detected = strategy;
      result.status = partial.confidence ? 'dead' : 'alive';
      result.alive = !partial.confidence;
      result.protocol = strategy === 'https' ? 'https' : strategy;
      result.latency = partial.latency;
      result.exitIp = partial.echo.exitIp;
      result.echo = partial.echo; // internal: drives confidence classification
      result.httpStatus = partial.status;
      result.responseHeaders = partial.responseHeaders;
      result.dns = partial.dns;
      if (partial.confidence) {
        // Proxy answered but the controlled target failed behind it.
        result.errorCategory = partial.confidence.category;
        result.errorMessage = partial.confidence.message;
      }
      if (partial.anonymity) result.anonymity = partial.anonymity;
      if (partial.geo) result.geo = { ...partial.geo, state: 'ok', source: 'echo' };
      break;
    } catch (err) {
      const ce = err instanceof CheckError ? err : new CheckError('UNKNOWN_ERROR', 'unexpected check error', { cause: err });
      if (process.env.PC_DEBUG) console.error(`[dbg] strategy ${strategy} failed:`, ce.category, ce.message, ce.stack && ce.stack.split('\n').slice(1, 3).join(' | '));
      lastError = ce;
      if (signal && signal.aborted) {
        result.errorCategory = 'UNKNOWN_ERROR';
        result.errorMessage = 'Cancelled';
        return result;
      }
      if (ce.category === 'AUTH_FAILED') {
        // Peer spoke a known protocol and rejected credentials — conclusive.
        detected = strategy === 'socks5' || strategy.startsWith('socks') ? strategy : 'http';
        result.protocol = detected;
        result.auth.required = true;
        result.auth.ok = false;
        result.errorCategory = 'AUTH_FAILED';
        result.errorMessage = ce.message;
        break;
      }
      if (ce.ssrf) {
        result.errorCategory = 'INVALID_PROXY';
        result.errorMessage = `Blocked by SSRF protection (${ce.detail || ce.message}).`;
        break;
      }
      const hostLevel = ce.category === 'CONNECTION_REFUSED' || ce.category === 'TIMEOUT' || ce.category === 'DNS_ERROR';
      if (hostLevel) break; // other protocols on the same host:port cannot fare better
      if (ce.category === 'TARGET_ERROR') {
        // Tunnel opened — proxy works but controlled target failed behind it.
        detected = strategy;
        result.status = 'alive';
        result.alive = true;
        result.protocol = strategy === 'https' ? 'https' : strategy;
        result.latency = ce.detail && ce.detail.latency ? ce.detail.latency : result.latency;
        result.errorCategory = 'TARGET_ERROR';
        result.errorMessage = 'Proxy opened a connection, but the controlled test target could not be reached through it. Marked alive with partial verification.';
        break;
      }
      // UNSUPPORTED_PROTOCOL / NETWORK_ERROR → try the next strategy (auto).
      continue;
    }
  }

  if (!detected) {
    result.errorCategory = lastError ? lastError.category : 'UNKNOWN_ERROR';
    result.errorMessage = lastError ? lastError.message : 'Check failed.';
    return result;
  }

  if (result.alive) {
    if (!result.anonymity) {
      result.anonymity = {
        level: 'unknown',
        reason: 'The test endpoint response did not include request headers, so anonymity could not be classified.',
        evidence: [],
      };
    }

    // HTTPS/TLS tunnel test — never disables certificate validation.
    if (httpsTest) {
      const remaining = deadline - Date.now();
      if (remaining < 1200) {
        result.https = { supported: null, tlsVersion: null, certValid: null, error: 'Skipped: per-proxy time budget exhausted.' };
      } else {
        result.https = await runHttpsTest(proxy, detected, {
          tlsProbeHost,
          tlsProbePort,
          allowPrivate,
          cancel,
          deadline: Math.min(Date.now() + Math.round(remaining * 0.6), deadline),
          exitIp: result.exitIp,
        });
      }
    }
  }

  return result;
}

/** Probe one strategy end-to-end: connect → handshake → echo request. */
async function runStrategy(proxy, strategy, target, stageDeadline, { allowPrivate, cancel, signal, clientIp }) {
  const t0 = Date.now();
  let resp; let timings = {}; let dns = null;

  if (strategy === 'http' || strategy === 'https') {
    resp = await requestViaProxy({ ...proxy, tlsTransport: strategy === 'https' }, target.url, {
      deadline: stageDeadline,
      allowPrivate,
    });
    timings = resp.timings;
    dns = proxyHasHostname(proxy.host) ? 'remote (resolved by proxy)' : 'n/a (IP destination)';
  } else {
    try {
      const tun = await socksConnect(proxy, target.host, target.port, {
        version: strategy === 'socks4a' ? '4a' : strategy === 'socks4' ? 4 : 5,
        deadline: stageDeadline,
        allowPrivate,
      });
      cancel.track(tun.socket);
      const head = [
        `GET ${target.url} HTTP/1.1`,
        `Host: ${target.host}`,
        'User-Agent: ProxyCheck/1.0',
        'Accept: */*',
        'Connection: close',
        '',
        '',
      ].join('\r\n');
      resp = await writeAndRead(tun.socket, head, { deadline: stageDeadline, sentAt: Date.now() });
      timings = { tcpMs: null, handshakeMs: tun.handshakeMs, requestMs: resp.ttfbMs, totalMs: Date.now() - t0 };
      dns = describeSocksDns(tun.remoteResolve, strategy, proxy.host);
    } catch (e) {
      if (process.env.PC_DEBUG) console.error('[dbg:socks-stage]', e.constructor.name, e.message, '\n', e.stack && e.stack.split('\n').slice(1, 5).join('\n'));
      throw e;
    }
    if (resp.status === 407) throw new CheckError('AUTH_FAILED', 'proxy requested authentication through tunnel (407)');
  }

  // HTTP-layer interpretation (shared by http + socks strategies).
  if (resp.status === 407) {
    const e = new CheckError('AUTH_FAILED', proxy.hasAuth
      ? 'Authentication failed: proxy rejected the provided credentials (407).'
      : 'Authentication required: proxy answered 407 and no credentials were provided.');
    e.authHeaders = resp.headers;
    throw e;
  }

  const echo = parseEchoBody(resp.body) || {};
  const latency = {
    tcpMs: timings.tcpMs != null ? timings.tcpMs : null,
    handshakeMs: timings.handshakeMs || timings.tlsMs || (strategy === 'http' ? null : null),
    requestMs: timings.ttfbMs != null ? timings.ttfbMs : null,
    totalMs: timings.totalMs != null ? timings.totalMs : Date.now() - t0,
  };

  const echoParsed = Boolean(resp.body && echo !== null && (echo.exitIp || echo.headers));
  const out = {
    status: resp.status,
    latency,
    dns,
    echo: { exitIp: echo.exitIp || null, headers: echo.headers || null },
    responseHeaders: pickHeaders(resp.headers),
    anonymity: echo.headers ? analyzeAnonymity(echo.headers, { clientIp }) : null,
    geo: echo.geo || null,
    confidence: null,
  };

  if (!echoParsed) {
    // Proxy relayed *something* but we could not verify the controlled target.
    out.confidence = {
      category: 'TARGET_ERROR',
      message: 'Proxy relayed a response, but it did not contain the expected verification payload. Verification is partial.',
    };
  } else if (!out.echo.exitIp) {
    out.confidence = null;
  }
  if (resp.status >= 500 && !echoParsed) {
    out.confidence = {
      category: 'TARGET_ERROR',
      message: `Proxy relayed HTTP ${resp.status} from the controlled test target. Target may be temporarily unreachable through this proxy.`,
    };
  }
  return out;
}

function proxyHasHostname(host) {
  return !/^\d{1,3}(\.\d{1,3}){3}$/.test(host) && !host.includes(':');
}

function describeSocksDns(remoteResolve, strategy, host) {
  if (!proxyHasHostname(host) && !remoteResolve) return 'n/a (IP destination)';
  if (strategy === 'socks4') return 'local (client resolved the hostname for SOCKS4)';
  if (remoteResolve) return 'remote (hostname sent to proxy for resolution)';
  return 'local (IP sent to proxy)';
}

/** HTTPS/TLS tunnel test. Never disables certificate verification. */
async function runHttpsTest(proxy, strategy, { tlsProbeHost, tlsProbePort, allowPrivate, cancel, deadline, exitIp }) {
  const base = { supported: false, tlsVersion: null, certValid: null, error: null };
  let tunnel;
  try {
    if (strategy === 'http' || strategy === 'https') {
      tunnel = await connectViaProxy({ ...proxy, tlsTransport: strategy === 'https' }, tlsProbeHost, tlsProbePort, { deadline, allowPrivate });
    } else {
      tunnel = await socksConnect(proxy, tlsProbeHost, tlsProbePort, {
        version: strategy === 'socks4a' ? '4a' : strategy === 'socks4' ? 4 : 5,
        deadline,
        allowPrivate,
      });
    }
    cancel.track(tunnel.socket);
    const up = await upgradeTls(tunnel.socket, tlsProbeHost, { deadline });
    cancel.track(up.socket);
    const req = ['GET / HTTP/1.1', `Host: ${tlsProbeHost}`, 'User-Agent: ProxyCheck/1.0', 'Accept: */*', 'Connection: close', '', ''].join('\r\n');
    const resp = await writeAndRead(up.socket, req, { deadline, sentAt: Date.now(), maxBodyBytes: 16 * 1024 });
    const trace = resp.body.toString('latin1');
    const m = /^ip=([0-9a-fA-F.:]+)$/m.exec(trace);
    const result = {
      supported: true,
      tlsVersion: up.protocol,
      certValid: true,
      error: null,
      exitIpTls: m ? m[1] : null,
    };
    if (result.exitIpTls && exitIp && result.exitIpTls !== exitIp) {
      result.note = 'TLS exit IP differs from the HTTP exit IP (proxy may rotate egress IPs).';
    }
    return result;
  } catch (err) {
    const ce = err instanceof CheckError ? err : new CheckError('NETWORK_ERROR', 'HTTPS test failed');
    return {
      ...base,
      error: `${ce.category === 'TLS_ERROR' ? 'TLS' : ce.category === 'AUTH_FAILED' ? 'Auth' : 'Connect'}: ${ce.category === 'TLS_ERROR' ? stripPrefix(ce.message) : ce.message}`,
    };
  }
}

function stripPrefix(msg) {
  return msg.replace(/^TLS handshake failed: /, '');
}

/** Keep a compact, useful subset of response headers for display. */
function pickHeaders(headers) {
  if (!headers) return null;
  const keep = ['server', 'content-type', 'connection', 'via', 'forwarded', 'x-forwarded-for', 'proxy-authenticate', 'cache-control', 'date', 'content-length'];
  const out = {};
  for (const k of keep) if (headers[k] !== undefined) out[k] = String(headers[k]).slice(0, 200);
  return Object.keys(out).length ? out : null;
}

module.exports = { checkProxy };
