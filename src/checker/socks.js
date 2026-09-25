'use strict';
/**
 * SOCKS4 / SOCKS4a / SOCKS5 client (outbound only).
 * Handshakes are implemented on a raw socket so we can measure handshake
 * latency precisely and reuse the tunnel for HTTP requests / TLS upgrades.
 */
const net = require('net');
const dns = require('dns');
const { CheckError, fromOsError } = require('../errors');
const { safeLookup } = require('../validation');

/** Minimal single-slot buffered reader over a socket. */
function createReader(socket) {
  let buf = Buffer.alloc(0);
  let waiter = null;

  const failWaiter = (err) => {
    if (waiter) {
      const w = waiter;
      waiter = null;
      clearTimeout(w.timer);
      w.reject(err);
    }
  };

  socket.on('data', (d) => {
    buf = buf.length ? Buffer.concat([buf, d]) : d;
    if (waiter && buf.length >= waiter.need) {
      const out = buf.slice(0, waiter.need);
      buf = buf.slice(waiter.need);
      const w = waiter;
      waiter = null;
      clearTimeout(w.timer);
      w.resolve(out);
    }
  });
  socket.on('error', () => failWaiter(new CheckError('NETWORK_ERROR', 'connection error during SOCKS handshake')));
  socket.on('close', () => failWaiter(new CheckError('NETWORK_ERROR', 'connection closed during SOCKS handshake')));

  return {
    readExact(n, ms, label) {
      if (buf.length >= n) {
        const out = buf.slice(0, n);
        buf = buf.slice(n);
        return Promise.resolve(out);
      }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          waiter = null;
          reject(new CheckError('TIMEOUT', `${label || 'SOCKS handshake'} timed out`));
        }, ms);
        waiter = { need: n, resolve, reject, timer };
      });
    },
    leftover() {
      const b = buf;
      buf = Buffer.alloc(0);
      return b.length ? b : null;
    },
  };
}

function connectToProxy(proxy, deadline, allowPrivate) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) return Promise.reject(new CheckError('TIMEOUT', 'deadline exhausted before connect'));
  return new Promise((resolve, reject) => {
    const socket = net.connect({
      host: proxy.host,
      port: proxy.port,
      lookup: safeLookup(allowPrivate),
    });
    let settled = false;
    const watchdog = setTimeout(() => {
      socket.destroy();
      if (!settled) { settled = true; reject(new CheckError('TIMEOUT', `proxy TCP connect timed out after ${remaining}ms`)); }
    }, remaining);
    socket.once('connect', () => {
      clearTimeout(watchdog);
      if (!settled) { settled = true; resolve(socket); }
    });
    socket.once('error', (err) => {
      clearTimeout(watchdog);
      if (!settled) { settled = true; reject(fromOsError(err, 'proxy TCP connect failed')); }
    });
  });
}

const SOCKS5_REPLIES = {
  1: 'general SOCKS server failure',
  2: 'connection not allowed by ruleset',
  3: 'network unreachable (proxy side)',
  4: 'host unreachable (proxy side)',
  5: 'connection refused (proxy side)',
  6: 'TTL expired (proxy side)',
  7: 'command not supported by proxy',
  8: 'address type not supported by proxy',
};

/**
 * Establish a SOCKS tunnel to destHost:destPort.
 * @returns {Promise<{socket, handshakeMs, remoteResolve, strategy}>}
 */
async function socksConnect(proxy, destHost, destPort, { version, deadline, allowPrivate }) {
  const socket = await connectToProxy(proxy, deadline, allowPrivate);
  const reader = createReader(socket);
  const started = Date.now();
  const rem = () => Math.max(deadline - Date.now(), 1);
  let remoteResolve = false;

  try {
    if (version === 5) {
      const methods = proxy.hasAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]);
      socket.write(methods);
      const greeting = await reader.readExact(2, rem(), 'SOCKS5 greeting');
      if (greeting[0] !== 0x05) throw new CheckError('UNSUPPORTED_PROTOCOL', 'server did not answer SOCKS5 greeting');
      const method = greeting[1];
      if (method === 0x02) {
        if (!proxy.hasAuth) throw new CheckError('AUTH_FAILED', 'proxy requires username/password authentication');
        const user = Buffer.from(String(proxy.username || ''), 'utf8');
        const pass = Buffer.from(String(proxy.password || ''), 'utf8');
        socket.write(Buffer.concat([
          Buffer.from([0x01, user.length]), user,
          Buffer.from([pass.length]), pass,
        ]));
        const authReply = await reader.readExact(2, rem(), 'SOCKS5 auth');
        if (authReply[0] !== 0x01 || authReply[1] !== 0x00) {
          throw new CheckError('AUTH_FAILED', 'username/password authentication rejected by proxy');
        }
      } else if (method !== 0x00) {
        throw new CheckError('AUTH_FAILED', 'no acceptable SOCKS5 authentication method');
      }

      let atyp; let addrBytes;
      const isV4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(destHost);
      const isV6 = destHost.includes(':');
      if (isV4) {
        atyp = 0x01;
        addrBytes = Buffer.from(destHost.split('.').map(Number));
      } else if (isV6) {
        atyp = 0x04;
        addrBytes = Buffer.from(require('../validation').v6ToBigInt(destHost).toString(16).padStart(32, '0'), 'hex');
      } else {
        atyp = 0x03;
        const hb = Buffer.from(destHost, 'utf8');
        if (hb.length > 255) throw new CheckError('INVALID_PROXY', 'hostname too long');
        addrBytes = Buffer.concat([Buffer.from([hb.length]), hb]);
        remoteResolve = true; // SOCKS5 carries the hostname → proxy resolves DNS
      }
      const req = Buffer.alloc(6 + addrBytes.length);
      req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = atyp;
      addrBytes.copy(req, 4);
      req.writeUInt16BE(destPort, 4 + addrBytes.length);
      socket.write(req);

      const head = await reader.readExact(4, rem(), 'SOCKS5 connect reply');
      if (head[0] !== 0x05) throw new CheckError('UNSUPPORTED_PROTOCOL', 'malformed SOCKS5 reply');
      if (head[1] !== 0x00) {
        const why = SOCKS5_REPLIES[head[1]] || 'unknown SOCKS5 error';
        const category = head[1] === 5 ? 'CONNECTION_REFUSED' : head[1] === 6 ? 'TIMEOUT' : head[1] === 7 || head[1] === 8 ? 'UNSUPPORTED_PROTOCOL' : 'NETWORK_ERROR';
        throw new CheckError(category, `SOCKS5 connect failed: ${why}`);
      }
      const atypR = head[3];
      if (atypR === 0x01) await reader.readExact(6, rem(), 'SOCKS5 reply addr');
      else if (atypR === 0x04) await reader.readExact(18, rem(), 'SOCKS5 reply addr');
      else if (atypR === 0x03) {
        const lenByte = await reader.readExact(1, rem(), 'SOCKS5 reply addr');
        await reader.readExact(lenByte[0] + 2, rem(), 'SOCKS5 reply addr');
      }
    } else if (version === 4 || version === '4a') {
      let ipBytes;
      let hostnameChunk = null;
      const isV4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(destHost);
      if (isV4) {
        ipBytes = Buffer.from(destHost.split('.').map(Number));
      } else if (version === '4a') {
        ipBytes = Buffer.from([0, 0, 0, 1]);
        hostnameChunk = Buffer.concat([Buffer.from(destHost, 'utf8'), Buffer.from([0x00])]);
        remoteResolve = true;
      } else {
        // plain SOCKS4 cannot carry hostnames: resolve locally
        let resolved;
        try {
          resolved = await dns.lookup(destHost, { family: 4 });
        } catch {
          throw new CheckError('DNS_ERROR', 'SOCKS4 requires an IP or a locally resolvable hostname');
        }
        ipBytes = Buffer.from(resolved.address.split('.').map(Number));
      }
      const user = Buffer.from(String(proxy.username || ''), 'utf8');
      const parts = [Buffer.from([0x04, 0x01]), (() => { const p = Buffer.alloc(2); p.writeUInt16BE(destPort); return p; })(), ipBytes, user, Buffer.from([0x00])];
      if (hostnameChunk) parts.push(hostnameChunk);
      socket.write(Buffer.concat(parts));
      const reply = await reader.readExact(8, rem(), 'SOCKS4 connect reply');
      const code = reply[1];
      if (code !== 0x5a) {
        const why = { 0x5b: 'request rejected or failed', 0x5c: 'not reachable / identd required', 0x5d: 'identd verification failed' }[code] || 'unknown SOCKS4 error';
        throw new CheckError(code === 0x5b ? 'CONNECTION_REFUSED' : 'NETWORK_ERROR', `SOCKS4 connect failed: ${why}`);
      }
    } else {
      throw new CheckError('UNSUPPORTED_PROTOCOL', `unknown SOCKS version ${version}`);
    }
  } catch (err) {
    socket.destroy();
    throw err;
  }

  const leftover = reader.leftover();
  if (leftover) socket.unshift(leftover);
  return { socket, handshakeMs: Date.now() - started, remoteResolve, strategy: `socks${version === 5 ? 5 : version === '4a' ? '4a' : 4}` };
}

module.exports = { socksConnect, connectToProxy, createReader };
