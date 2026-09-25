'use strict';
/**
 * HTTP proxy client: plain absolute-URI requests and CONNECT tunneling,
 * over raw sockets (optionally TLS transport for `https://` proxies).
 * Certificate validation is never disabled.
 */
const net = require('net');
const tls = require('tls');
const fs = require('fs');
const { CheckError, fromOsError } = require('../errors');
const { safeLookup } = require('../validation');

const MAX_HEADER_BYTES = 64 * 1024;
const DEFAULT_MAX_BODY = 256 * 1024;
const USER_AGENT = 'ProxyCheck/1.0';

/**
 * Optional extra CA bundle (TLS_EXTRA_CA=path.pem). This never DISABLES
 * validation — it only adds a trusted CA, e.g. for private test endpoints.
 */
function extraCa() {
  if (!process.env.TLS_EXTRA_CA) return undefined;
  try {
    return fs.readFileSync(process.env.TLS_EXTRA_CA);
  } catch {
    return undefined;
  }
}

function proxyAuthHeader(proxy) {
  if (!proxy.hasAuth) return null;
  return 'Basic ' + Buffer.from(`${proxy.username || ''}:${proxy.password || ''}`, 'utf8').toString('base64');
}

/** TCP (optionally TLS-wrapped) connection to the proxy itself. */
function connectToProxy(proxy, deadline, allowPrivate) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) return Promise.reject(new CheckError('TIMEOUT', 'deadline exhausted before connect'));
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const socket = net.connect({
      host: proxy.host,
      port: proxy.port,
      lookup: safeLookup(allowPrivate),
    });
    let settled = false;
    const done = (fn) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      fn();
    };
    const watchdog = setTimeout(() => {
      socket.destroy();
      done(() => reject(new CheckError('TIMEOUT', `proxy TCP connect timed out after ${remaining}ms`)));
    }, remaining);
    socket.once('error', (err) => done(() => reject(fromOsError(err, 'proxy TCP connect failed'))));
    socket.once('close', () => done(() => reject(new CheckError('CONNECTION_REFUSED', 'connection closed before proxy responded'))));
    socket.once('connect', () => {
      const tcpMs = Date.now() - started;
      if (!proxy.tlsTransport) return done(() => resolve({ socket, tcpMs, tlsMs: 0 }));
      // https:// proxy: TLS transport to the proxy itself (certs validated)
      const t0 = Date.now();
      const tlsSocket = tls.connect({ socket, servername: proxy.host, rejectUnauthorized: true, ca: extraCa() });
      const tlsWatchdog = setTimeout(() => {
        tlsSocket.destroy();
        socket.destroy();
        done(() => reject(new CheckError('TLS_ERROR', 'TLS handshake with proxy timed out')));
      }, Math.max(deadline - Date.now(), 1));
      tlsSocket.once('secureConnect', () => {
        clearTimeout(tlsWatchdog);
        done(() => resolve({ socket: tlsSocket, tcpMs, tlsMs: Date.now() - t0 }));
      });
      tlsSocket.once('error', (err) => {
        clearTimeout(tlsWatchdog);
        done(() => reject(new CheckError('TLS_ERROR', `TLS handshake with proxy failed: ${shortTlsError(err)}`)));
      });
    });
  });
}

function shortTlsError(err) {
  const raw = String((err && (err.code || err.message)) || '');
  const code = raw.split(':')[0].trim();
  const map = {
    CERT_HAS_EXPIRED: 'certificate has expired',
    DEPTH_ZERO_SELF_SIGNED_CERT: 'self-signed certificate',
    SELF_SIGNED_CERT_IN_CHAIN: 'self-signed certificate in chain',
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'unable to verify certificate',
    UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'unknown certificate issuer',
    ERR_TLS_CERT_ALTNAME_INVALID: 'certificate hostname mismatch',
    EPROTO: 'protocol error',
    ECONNRESET: 'connection reset during TLS',
  };
  return map[code] || code || 'TLS failure';
}

function parseHead(headLatin1) {
  const lines = headLatin1.split('\r\n');
  const m = /^HTTP\/(\d\.\d)\s+(\d{3})\s?(.*)$/.exec(lines[0]);
  if (!m) return null;
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(':');
    if (idx === -1) continue;
    const k = lines[i].slice(0, idx).trim().toLowerCase();
    const v = lines[i].slice(idx + 1).trim();
    headers[k] = headers[k] ? `${headers[k]}, ${v}` : v;
  }
  return { httpVersion: m[1], status: Number(m[2]), statusText: m[3] || '', headers };
}

function dechunk(buf) {
  const out = [];
  let rest = buf;
  for (;;) {
    const idx = rest.indexOf('\r\n');
    if (idx === -1) break;
    const size = parseInt(rest.slice(0, idx).toString('latin1').split(';')[0], 16);
    if (!Number.isFinite(size) || size === 0) break;
    if (idx + 2 + size > rest.length) break;
    out.push(rest.slice(idx + 2, idx + 2 + size));
    rest = rest.slice(idx + 2 + size + 2);
  }
  return Buffer.concat(out);
}

/**
 * Write `requestHead` on `socket` and read one full HTTP response.
 * Body is read per framing (content-length / chunked / connection-close) and
 * capped at maxBodyBytes. Rejects with CheckError on timeouts / protocol junk.
 */
function writeAndRead(socket, requestHead, { deadline, maxBodyBytes = DEFAULT_MAX_BODY, sentAt, headersOnly = false }) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    let settled = false;
    let head = null;
    let headEnd = -1;

    const done = (fn) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
      fn();
    };
    const watchdog = setTimeout(() => {
      socket.destroy();
      done(() => reject(new CheckError(head ? 'NETWORK_ERROR' : 'TIMEOUT', head ? 'response body timed out' : 'response timed out')));
    }, Math.max(deadline - Date.now(), 1));

    const finishResponse = (body, extra = {}) => {
      done(() => resolve({
        httpVersion: head.httpVersion,
        status: head.status,
        statusText: head.statusText,
        headers: head.headers,
        ttfbMs: head.ttfbMs,
        body,
        ...extra,
      }));
    };

    const check = () => {
      const idx = buf.indexOf('\r\n\r\n');
      if (idx === -1) {
        if (buf.length > MAX_HEADER_BYTES) {
          socket.destroy();
          done(() => reject(new CheckError('UNSUPPORTED_PROTOCOL', 'peer did not answer with valid HTTP (headers too large)')));
        }
        return;
      }
      if (!head) {
        head = parseHead(buf.slice(0, idx).toString('latin1'));
        if (!head) {
          socket.destroy();
          done(() => reject(new CheckError('UNSUPPORTED_PROTOCOL', 'peer did not answer with HTTP')));
          return;
        }
        head.ttfbMs = Date.now() - sentAt;
        headEnd = idx + 4;
        if (headersOnly) {
          // e.g. CONNECT: everything after the blank line is tunnel payload
          const leftover = buf.slice(headEnd);
          if (leftover.length) socket.unshift(leftover);
          return finishResponse(Buffer.alloc(0));
        }
      }
      const h = head.headers;
      const status = head.status;
      if (status === 204 || status === 304 || (status >= 100 && status < 200)) return finishResponse(Buffer.alloc(0));
      const contentLength = h['content-length'] != null ? Number(h['content-length']) : null;
      const chunked = /chunked/i.test(h['transfer-encoding'] || '');
      let body = buf.slice(headEnd);

      if (!chunked && contentLength != null) {
        if (contentLength === 0) return finishResponse(Buffer.alloc(0));
        if (body.length >= contentLength) return finishResponse(body.slice(0, contentLength));
        if (body.length > maxBodyBytes * 2) { socket.destroy(); return finishResponse(body.slice(0, maxBodyBytes), { bodyTruncated: true }); }
        return; // wait for more data
      }
      if (chunked) {
        const s = body.toString('latin1');
        if (/(^|\r\n)0(?:;[^\r\n]*)?\r\n\r\n$/.test(s.slice(-1024)) || /(^|\r\n)0(?:;[^\r\n]*)?\r\n\r\n/.test(s)) {
          return finishResponse(dechunk(body));
        }
        if (body.length > maxBodyBytes * 2) { socket.destroy(); return finishResponse(dechunk(body), { bodyTruncated: true }); }
        return;
      }
      // read-until-close framing
      if (body.length >= maxBodyBytes) {
        socket.destroy();
        return finishResponse(body.slice(0, maxBodyBytes), { bodyTruncated: true });
      }
    };

    const onData = (d) => {
      buf = buf.length ? Buffer.concat([buf, d]) : d;
      check();
    };
    const onError = (err) => done(() => reject(fromOsError(err, 'error while reading response')));
    const onClose = () => {
      if (!head) return done(() => reject(new CheckError('NETWORK_ERROR', 'connection closed before response')));
      const body = buf.slice(headEnd != null ? headEnd : buf.length);
      const h = head.headers;
      const chunked = /chunked/i.test(h['transfer-encoding'] || '');
      finishResponse(chunked ? dechunk(body) : body);
    };

    socket.on('data', onData);
    socket.once('error', onError);
    socket.once('close', onClose);
    socket.write(requestHead, () => { /* flushed */ });
    setImmediate(check); // handle servers answering within the same tick's buffer
    if (buf.length) check();
  });
}

/** Absolute-URI request via an HTTP proxy (plain HTTP targets). */
async function requestViaProxy(proxy, targetUrl, { method = 'GET', deadline, allowPrivate, extraHeaders = {} }) {
  let u;
  try {
    u = new URL(targetUrl);
  } catch {
    throw new CheckError('TARGET_ERROR', 'invalid test target URL configuration');
  }
  const { socket, tcpMs, tlsMs } = await connectToProxy(proxy, deadline, allowPrivate);
  const started = Date.now();
  try {
    const auth = proxyAuthHeader(proxy);
    const lines = [
      `${method} ${u.protocol}//${u.host}${u.pathname}${u.search} HTTP/1.1`,
      `Host: ${u.host}`,
      `User-Agent: ${USER_AGENT}`,
      'Accept: */*',
      'Connection: close',
    ];
    if (auth) lines.push(`Proxy-Authorization: ${auth}`);
    for (const [k, v] of Object.entries(extraHeaders)) lines.push(`${k}: ${v}`);
    lines.push('', '');
    const resp = await writeAndRead(socket, lines.join('\r\n'), { deadline, sentAt: started });
    socket.destroy(); // request was Connection: close — done with this socket
    return { ...resp, timings: { tcpMs, tlsMs, ttfbMs: resp.ttfbMs != null ? resp.ttfbMs : null, totalMs: Date.now() - started } };
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

/** CONNECT tunnel through an HTTP proxy. Returns the raw tunnel socket. */
async function connectViaProxy(proxy, destHost, destPort, { deadline, allowPrivate }) {
  const { socket, tcpMs, tlsMs } = await connectToProxy(proxy, deadline, allowPrivate);
  const started = Date.now();
  try {
    const auth = proxyAuthHeader(proxy);
    const lines = [
      `CONNECT ${destHost}:${destPort} HTTP/1.1`,
      `Host: ${destHost}:${destPort}`,
      `User-Agent: ${USER_AGENT}`,
      'Connection: close',
    ];
    if (auth) lines.push(`Proxy-Authorization: ${auth}`);
    lines.push('', '');
    const resp = await writeAndRead(socket, lines.join('\r\n'), { deadline, sentAt: started, headersOnly: true });
    if (resp.status === 407) throw new CheckError('AUTH_FAILED', 'proxy requires authentication for CONNECT (407)');
    if (resp.status < 200 || resp.status >= 300) {
      throw new CheckError('NETWORK_ERROR', `proxy refused CONNECT tunnel (HTTP ${resp.status})`);
    }
    return { socket, headers: resp.headers, timings: { tcpMs, tlsMs, connectMs: Date.now() - started } };
  } catch (err) {
    socket.destroy();
    throw err;
  }
}

/** Upgrade an established tunnel socket to TLS (certificate validation ON). */
function upgradeTls(socket, servername, { deadline }) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tlsSocket = tls.connect({ socket, servername, rejectUnauthorized: true, ca: extraCa() });
    const watchdog = setTimeout(() => {
      tlsSocket.destroy();
      reject(new CheckError('TLS_ERROR', 'TLS handshake timed out'));
    }, Math.max(deadline - Date.now(), 1));
    tlsSocket.once('secureConnect', () => {
      clearTimeout(watchdog);
      resolve({ socket: tlsSocket, handshakeMs: Date.now() - t0, protocol: tlsSocket.getProtocol() });
    });
    tlsSocket.once('error', (err) => {
      clearTimeout(watchdog);
      reject(new CheckError('TLS_ERROR', `TLS handshake failed: ${shortTlsError(err)}`));
    });
  });
}

module.exports = { connectToProxy, requestViaProxy, connectViaProxy, upgradeTls, shortTlsError, USER_AGENT, writeAndRead };
