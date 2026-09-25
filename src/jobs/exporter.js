'use strict';
/**
 * Export formatting: TXT / CSV / JSON.
 *
 * Credential policy: exports NEVER contain passwords unless the caller
 * explicitly passes includeCredentials=true AND the job actually has
 * authenticated proxies. Passwords are pulled from the server-side proxy
 * records only at that point.
 */
const { ApiError } = require('../errors');

function csvEscape(v) {
  if (v == null) return '';
  const s = String(v);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function txtLine(proxy, opts) {
  const hostPart = proxy.host.includes(':') ? `[${proxy.host}]` : proxy.host;
  const scheme = opts.scheme && proxy.protocol ? `${proxy.protocol}://` : '';
  if (opts.credentials && proxy.hasAuth) {
    return `${scheme}${proxy.username || ''}:${proxy.password || ''}@${hostPart}:${proxy.port}`;
  }
  return `${scheme}${hostPart}:${proxy.port}`;
}

const CSV_COLUMNS = [
  'proxy', 'status', 'protocol', 'exit_ip', 'country', 'country_code', 'region', 'city',
  'latitude', 'longitude', 'timezone', 'asn', 'as_org', 'isp', 'reverse_dns',
  'latency_tcp_ms', 'latency_handshake_ms', 'latency_request_ms', 'latency_total_ms',
  'https_supported', 'tls_version', 'cert_valid', 'anonymity', 'auth_required',
  'auth_provided', 'auth_ok', 'http_status', 'error_category', 'error_message',
  'confidence', 'dns', 'attempts', 'checked_at',
];

function csvRow(result, credentialsProxy) {
  const g = result.geo || {};
  const proxyStr = credentialsProxy
    ? txtLine(credentialsProxy, { scheme: true, credentials: true })
    : result.input;
  return [
    proxyStr,
    result.status,
    result.protocol || '',
    result.exitIp || '',
    g.country || '', g.countryCode || '', g.region || '', g.city || '',
    g.latitude != null ? g.latitude : '', g.longitude != null ? g.longitude : '',
    g.timezone || '',
    g.asn || '', g.asOrg || '', g.isp || '', g.reverse || '',
    result.latency.tcpMs != null ? result.latency.tcpMs : '',
    result.latency.handshakeMs != null ? result.latency.handshakeMs : '',
    result.latency.requestMs != null ? result.latency.requestMs : '',
    result.latency.totalMs != null ? result.latency.totalMs : '',
    result.https.supported == null ? 'unknown' : result.https.supported ? 'yes' : 'no',
    result.https.tlsVersion || '',
    result.https.certValid == null ? '' : result.https.certValid ? 'yes' : 'no',
    result.anonymity.level,
    result.auth.required ? 'yes' : 'no',
    result.auth.provided ? 'yes' : 'no',
    result.auth.ok == null ? '' : result.auth.ok ? 'yes' : 'no',
    result.httpStatus || '',
    result.errorCategory || '',
    result.errorMessage || '',
    result.confidence,
    result.dns || '',
    result.attempts,
    result.checkedAt,
  ].map(csvEscape).join(',');
}

/**
 * @param {Array} results filtered, serialized results
 * @param {object} opts
 * @param {string} format txt|csv|json
 * @param {boolean} includeCredentials expose user:pass@host:port (explicit only)
 * @param {Map} proxyRecords seq -> server-side proxy record (for credentials)
 * @param {boolean} scheme include protocol:// prefix in TXT output
 */
function formatExport(results, { format = 'txt', includeCredentials = false, proxyRecords = null, scheme = false }) {
  switch (format) {
    case 'txt': {
      const lines = results.map((r) => {
        const rec = includeCredentials ? proxyRecords && proxyRecords.get(r.seq) : null;
        if (includeCredentials && !rec) throw new ApiError(400, 'EXPORT_CREDENTIALS_UNAVAILABLE', 'Credential-preserving export requires server-side proxy records.');
        return txtLine(rec || { host: r.host, port: r.port, protocol: r.protocol, hasAuth: false }, { scheme, credentials: includeCredentials });
      });
      return lines.join('\n') + (lines.length ? '\n' : '');
    }
    case 'csv': {
      const head = CSV_COLUMNS.join(',');
      const rows = results.map((r) => csvRow(r, includeCredentials ? proxyRecords && proxyRecords.get(r.seq) : null));
      return '\ufeff' + head + '\n' + rows.join('\n') + (rows.length ? '\n' : '');
    }
    case 'json': {
      const payload = {
        exportedAt: new Date().toISOString(),
        generator: 'ProxyCheck/1.0',
        count: results.length,
        credentialsIncluded: Boolean(includeCredentials),
        results: results.map((r) => {
          if (!includeCredentials) return r;
          const rec = proxyRecords && proxyRecords.get(r.seq);
          return { ...r, input: rec ? txtLine(rec, { scheme: true, credentials: true }) : r.input };
        }),
      };
      return JSON.stringify(payload, null, 2);
    }
    default:
      throw new ApiError(400, 'BAD_FORMAT', 'format must be one of: txt, csv, json');
  }
}

module.exports = { formatExport, CSV_COLUMNS, txtLine };
