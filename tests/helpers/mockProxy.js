'use strict';
/**
 * Hermetic mock infrastructure for tests & benchmarks:
 *  - echo target (reports caller IP + optional injected headers)
 *  - HTTP proxy (auth, CONNECT tunneling, stall, flaky modes)
 *  - SOCKS5 proxy (auth, tunneling)
 *  - TLS target (self-signed or custom CA)
 *  - geo provider (ip-api /batch compatible)
 */
const net = require('net');
const http = require('http');
const tls = require('tls');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

/** close() that also destroys lingering connections so tests exit cleanly. */
function closable(server) {
  const sockets = new Set();
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  return () => new Promise((resolve) => {
    for (const s of sockets) { try { s.destroy(); } catch { /* noop */ } }
    server.close(() => resolve());
  });
}

/** Echo target: /echo returns {origin, headers}. Query flags: leak=1, via=1.
 * opts.originOverride: report a fixed origin (simulates a public egress IP)
 * while headers still reflect the real caller. */
function createEchoServer(opts = {}) {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const realOrigin = req.socket.remoteAddress.replace('::ffff:', '');
    const origin = opts.originOverride || realOrigin;
    const headers = { ...req.headers };
    if (u.searchParams.get('leak') === '1') headers['x-forwarded-for'] = realOrigin;
    if (u.searchParams.get('via') === '1') headers.via = '1.1 mock-proxy (no client ip)';
    if (u.searchParams.get('suspicious') === '1') headers['x-mock-proxy'] = 'yes';
    const body = JSON.stringify({ origin, headers });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  });
  return { server, ready: listen(server), close: () => new Promise((r) => server.close(r)) };
}

/** Read one HTTP request head (headers end) from socket, invoke handler.
 * opts.dropFirstByte: destroy the socket if the first byte matches (e.g. 0x05
 * from a SOCKS client hitting an HTTP mock) so probes fail fast. */
function readHead(socket, cb, opts = {}) {
  let buf = Buffer.alloc(0);
  let first = true;
  const onData = (d) => {
    if (first) {
      first = false;
      if (opts.dropFirstByte !== undefined && d[0] === opts.dropFirstByte) {
        socket.destroy();
        return;
      }
    }
    buf = Buffer.concat([buf, d]);
    const idx = buf.indexOf('\r\n\r\n');
    if (idx !== -1) {
      socket.off('data', onData);
      const leftover = buf.slice(idx + 4);
      cb(buf.slice(0, idx).toString('latin1'), leftover);
    }
  };
  socket.on('data', onData);
  socket.on('error', () => {});
}

function parseReqHead(head) {
  const [line, ...lines] = head.split('\r\n');
  const headers = {};
  for (const l of lines) {
    const i = l.indexOf(':');
    if (i > 0) headers[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim();
  }
  return { line, headers };
}

function cannedEchoResponse(statusMsg, extraHeaders = {}) {
  const body = JSON.stringify({ origin: '93.184.216.34', headers: { host: 'echo.test' } });
  const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...extraHeaders };
  const head = `HTTP/1.1 ${statusMsg}\r\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n`;
  return { head: Buffer.from(head), body: Buffer.from(body) };
}

/** Forward an absolute-form HTTP request like a real proxy would. */
function forwardAbsolute(clientSocket, reqHead) {
  const firstLine = reqHead.split('\r\n')[0];
  const m = /^[A-Z]+\s+(\S+)\s+HTTP\/\d\.\d$/i.exec(firstLine);
  if (!m) {
    clientSocket.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n');
    return;
  }
  const url = m[1];
  const req = http.get(url, { headers: { 'User-Agent': 'ProxyCheck/1.0', Accept: 'application/json' } }, (res) => {
    const chunks = [];
    res.on('data', (d) => chunks.push(d));
    res.on('end', () => {
      const body = Buffer.concat(chunks);
      const head = `HTTP/1.1 ${res.statusCode} ${res.statusMessage || ''}\r\nContent-Type: ${res.headers['content-type'] || 'application/json'}\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`;
      clientSocket.end(Buffer.concat([Buffer.from(head), body]));
    });
  });
  req.on('error', () => {
    clientSocket.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  });
}

/**
 * Mock HTTP proxy.
 * opts: { user, pass, stall: bool, failFirst: n, refusedConnect: bool, noConnect: bool }
 */
function createHttpProxy(opts = {}) {
  let reqCount = 0;
  let active = 0;
  let maxActive = 0;
  let totalConnections = 0;
  const stats = { requests: 0, connects: 0, rejected: 0 };

  const server = net.createServer((socket) => {
    totalConnections++;
    active++;
    maxActive = Math.max(maxActive, active);
    socket.on('close', () => { active--; });
    socket.on('error', () => {});

    readHead(socket, (head, leftover) => {
      const { line, headers } = parseReqHead(head);
      stats.requests++;
      const authOk = !opts.user || headers['proxy-authorization'] === `Basic ${Buffer.from(`${opts.user}:${opts.pass}`).toString('base64')}`;

      if (opts.stall) return; // never respond → client timeout
      if (/^CONNECT /i.test(line)) {
        stats.connects++;
        if (!authOk) {
          socket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="mock"\r\n\r\n');
          return;
        }
        if (opts.refusedConnect) {
          socket.write('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
          return;
        }
        if (opts.noConnect) return; // silence → timeout
        socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
        const m = /^CONNECT ([^:\s]+):(\d+)/i.exec(line);
        const target = m ? { host: m[1], port: Number(m[2]) } : null;
        const tunnel = net.connect(target && target.port, target && target.host);
        tunnel.on('error', () => socket.destroy());
        socket.pipe(tunnel);
        tunnel.pipe(socket);
        if (leftover.length) tunnel.write(leftover);
        return;
      }

      if (!opts.user || authOk) {
        if (opts.failFirst && reqCount++ < opts.failFirst) {
          stats.rejected++;
          socket.destroy(); // simulate flaky proxy
          return;
        }
        if (opts.canned) {
          const resp = cannedEchoResponse('200 OK');
          socket.write(Buffer.concat([resp.head, resp.body]));
          socket.end();
        } else {
          forwardAbsolute(socket, head); // behave like a real forwarding proxy
        }
      } else {
        socket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="mock"\r\nContent-Length: 0\r\n\r\n');
      }
    }, { dropFirstByte: 0x05 });
  });

  return {
    server,
    ready: listen(server),
    close: closable(server),
    stats: () => ({ ...stats, active, maxActive, totalConnections }),
  };
}

/** Mock SOCKS5 proxy (CONNECT tunneling with optional user/pass auth). */
function createSocks5Proxy(opts = {}) {
  const stats = { handshakes: 0, authFailures: 0, connects: 0 };
  const server = net.createServer((socket) => {
    socket.on('error', () => {});
    let stage = 0;
    let first = true;
    let buf = Buffer.alloc(0);
    socket.on('data', (d) => {
      // A real SOCKS5 client starts its greeting with 0x05. Anything else
      // (e.g. an HTTP-proxy probe) is dropped so protocol auto-detection
      // behaves realistically.
      if (first) {
        first = false;
        if (d[0] !== 0x05) {
          socket.destroy();
          return;
        }
      }
      buf = Buffer.concat([buf, d]);
      if (stage === 0) {
        if (buf.length < 2) return;
        const nmethods = buf[1];
        if (buf.length < 2 + nmethods) return;
        buf = buf.slice(2 + nmethods);
        stats.handshakes++;
        if (opts.user) {
          socket.write(Buffer.from([0x05, 0x02]));
          stage = 1;
        } else {
          socket.write(Buffer.from([0x05, 0x00]));
          stage = 2;
        }
      } else if (stage === 1) {
        if (buf.length < 2) return;
        const ulen = buf[1];
        if (buf.length < 2 + ulen + 1) return;
        const plen = buf[2 + ulen];
        if (buf.length < 2 + ulen + 1 + plen) return;
        const user = buf.slice(2, 2 + ulen).toString();
        const pass = buf.slice(3 + ulen, 3 + ulen + plen).toString();
        buf = buf.slice(3 + ulen + 1 + plen);
        if (user === opts.user && pass === opts.pass) {
          socket.write(Buffer.from([0x01, 0x00]));
          stage = 2;
        } else {
          stats.authFailures++;
          socket.write(Buffer.from([0x01, 0x01]));
          socket.destroy();
        }
      }
      if (stage === 2) {
        if (buf.length < 4) return;
        const atyp = buf[3];
        let need = 0;
        if (atyp === 0x01) need = 4 + 2;
        else if (atyp === 0x03) { if (buf.length < 4) return; need = 1 + buf[4] + 2; }
        else if (atyp === 0x04) need = 16 + 2;
        if (buf.length < 4 + need) return;
        const req = buf.slice(0, 4 + need);
        buf = buf.slice(4 + need);
        stage = 3;
        stats.connects++;
        socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]));
        // tunnel: the client always writes its HTTP request right after the
        // connect reply — wait for it, then forward it and close.
        socket.once('data', (reqData) => {
          const idx = reqData.indexOf('\r\n\r\n');
          const head = reqData.slice(0, idx === -1 ? reqData.length : idx).toString('latin1');
          forwardAbsolute(socket, head);
        });
      }
    });
  });
  return { server, ready: listen(server), close: closable(server), stats: () => ({ ...stats }) };
}

/** Generate a throwaway CA + server cert (SAN: localhost + 127.0.0.1). */
function generateCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pc-cert-'));
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  const ca = path.join(dir, 'ca.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', cert,
    '-days', '2', '-nodes', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
  ]);
  fs.copyFileSync(cert, ca);
  return { key, cert, ca };
}

/** Mock TLS target answering /cdn-cgi/trace-style responses. */
function createTlsTarget(certInfo) {
  const server = tls.createServer({ key: fs.readFileSync(certInfo.key), cert: fs.readFileSync(certInfo.cert) }, (socket) => {
    socket.on('error', () => {});
    socket.on('data', () => {
      const body = 'ip=93.184.216.34\r\n';
      socket.write(`HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
    });
  });
  return { server, ready: listen(server), close: closable(server) };
}

/** ip-api /batch compatible geo provider. */
function createGeoServer() {
  const stats = { requests: 0 };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      stats.requests++;
      let arr = [];
      try { arr = JSON.parse(body); } catch { /* noop */ }
      const out = arr.map((e) => ({
        status: 'success',
        query: e.query,
        country: 'Narnia',
        countryCode: 'NA',
        regionName: 'Eastern Narnia',
        city: 'Cair Paravel',
        lat: 12.34,
        lon: 56.78,
        timezone: 'Narnia/Cair',
        as: 'AS64512 Mock Networks LLC',
        org: 'Mock Networks LLC',
        isp: 'Mock ISP',
        reverse: `${e.query}.mock.ptr`,
      }));
      const payload = JSON.stringify(out);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) });
      res.end(payload);
    });
  });
  return { server, ready: listen(server), close: closable(server), stats: () => ({ ...stats }) };
}

async function waitFor(fn, timeoutMs = 10000, intervalMs = 40) {
  const start = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - start > timeoutMs) throw new Error('waitFor: timeout');
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

module.exports = {
  createEchoServer,
  createHttpProxy,
  createSocks5Proxy,
  createTlsTarget,
  createGeoServer,
  generateCert,
  waitFor,
};
