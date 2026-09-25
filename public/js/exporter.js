/** Export modal: client-side generation for normal exports; the server is
 * used only for credential-preserving exports (passwords never reach the
 * client results). */

import { state, allResults } from './state.js';
import { applyFilters } from './filters.js';
import { download, toast } from './util.js';

function csvEscape(v) {
  if (v == null) return '';
  const s = String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const COLUMNS = ['proxy', 'status', 'protocol', 'exit_ip', 'country', 'country_code', 'region', 'city', 'latitude', 'longitude', 'timezone', 'asn', 'as_org', 'isp', 'reverse_dns', 'latency_tcp_ms', 'latency_handshake_ms', 'latency_request_ms', 'latency_total_ms', 'https_supported', 'tls_version', 'anonymity', 'auth_required', 'auth_ok', 'http_status', 'error_category', 'confidence', 'dns', 'attempts', 'checked_at'];

function toCsv(rows) {
  const lines = rows.map((r) => {
    const g = r.geo || {};
    return [
      r.input, r.status, r.protocol || '', r.exitIp || '', g.country || '', g.countryCode || '', g.region || '', g.city || '',
      g.latitude != null ? g.latitude : '', g.longitude != null ? g.longitude : '', g.timezone || '',
      g.asn || '', g.asOrg || '', g.isp || '', g.reverse || '',
      r.latency.tcpMs != null ? r.latency.tcpMs : '', r.latency.handshakeMs != null ? r.latency.handshakeMs : '',
      r.latency.requestMs != null ? r.latency.requestMs : '', r.latency.totalMs != null ? r.latency.totalMs : '',
      r.https.supported == null ? 'unknown' : r.https.supported ? 'yes' : 'no', r.https.tlsVersion || '',
      r.anonymity.level, r.auth.required ? 'yes' : 'no', r.auth.ok == null ? '' : r.auth.ok ? 'yes' : 'no',
      r.httpStatus || '', r.errorCategory || '', r.confidence, r.dns || '', r.attempts, r.checkedAt,
    ].map(csvEscape).join(',');
  });
  return '\ufeff' + COLUMNS.join(',') + '\n' + lines.join('\n') + (lines.length ? '\n' : '');
}

function toTxt(rows, includeScheme) {
  return rows.map((r) => {
    const scheme = includeScheme && r.protocol ? `${r.protocol}://` : '';
    const host = r.host.includes(':') ? `[${r.host}]` : r.host;
    return `${scheme}${host}:${r.port}`;
  }).join('\n') + (rows.length ? '\n' : '');
}

function toJson(rows, opts) {
  return JSON.stringify({
    exportedAt: new Date().toISOString(),
    generator: 'ProxyCheck/1.0 (client export)',
    demo: state.demo || undefined,
    count: rows.length,
    credentialsIncluded: false,
    results: rows.map((r) => (opts.stripLarge ? { ...r, responseHeaders: undefined, anonymity: { level: r.anonymity.level, reason: r.anonymity.reason } } : r)),
  }, null, 2);
}

export function scopedRows(scope) {
  const all = allResults();
  if (scope === 'all') return all;
  if (scope === 'alive') return applyFilters(all, { status: 'alive', protocol: 'all', speed: 'all', https: 'all', anonymity: 'all', auth: 'all', country: '', asn: '', q: '' });
  if (scope === 'dead') return applyFilters(all, { status: 'dead', protocol: 'all', speed: 'all', https: 'all', anonymity: 'all', auth: 'all', country: '', asn: '', q: '' });
  return applyFilters(all); // current filter
}

export function generateExport({ format, scope, includeScheme }) {
  const rows = scopedRows(scope);
  switch (format) {
    case 'csv': return { text: toCsv(rows), mime: 'text/csv', ext: 'csv', count: rows.length };
    case 'json': return { text: toJson(rows, { stripLarge: rows.length > 2000 }), mime: 'application/json', ext: 'json', count: rows.length };
    default: return { text: toTxt(rows, includeScheme), mime: 'text/plain', ext: 'txt', count: rows.length };
  }
}

/**
 * Credential-preserving export: always served by the backend with explicit
 * confirmation — the client never holds passwords.
 */
export async function serverCredentialExport(api, { format, scope, jobId }) {
  const params = {
    format,
    include: 'credentials',
    confirm: 'yes',
  };
  if (scope === 'alive') params.status = 'alive';
  if (scope === 'dead') params.status = 'dead';
  const res = await fetch(api.exportUrl(jobId, params));
  if (!res.ok) throw new Error(`export failed: HTTP ${res.status}`);
  return res.text();
}

export function wireExportModal({ els, api, toastEl, jobId, hasAuthResults, isDemo }) {
  const syncCredNote = () => {
    els.creds.checked = false;
    els.creds.disabled = !hasAuthResults || isDemo;
    els.credNote.hidden = true;
  };
  syncCredNote();

  els.creds.addEventListener('change', () => { els.credNote.hidden = !els.creds.checked; });

  const fmt = () => els.modal.querySelector('input[name="exp-format"]:checked').value;
  const scope = () => els.modal.querySelector('input[name="exp-scope"]:checked').value;

  async function doExport(copy) {
    try {
      if (els.creds.checked && !isDemo) {
        if (!jobId()) throw new Error('No server job available for credential export.');
        const text = await serverCredentialExport(api, { format: fmt(), scope: scope(), jobId: jobId() });
        if (copy) {
          await navigator.clipboard.writeText(text);
          toast(toastEl, 'Copied export with credentials to clipboard.', 'ok');
        } else {
          download(`proxycheck-credentials-${Date.now()}.${fmt()}`, text, fmt() === 'json' ? 'application/json' : fmt() === 'csv' ? 'text/csv' : 'text/plain');
          toast(toastEl, 'Export with credentials downloaded. Handle it securely.', 'ok');
        }
        els.modal.classList.remove('open');
        return;
      }
      const out = generateExport({ format: fmt(), scope: scope(), includeScheme: els.scheme.checked });
      if (!out.count) {
        toast(toastEl, 'Nothing matches the selected scope.', 'err');
        return;
      }
      const demoTag = isDemo ? 'demo-' : '';
      if (copy) {
        await navigator.clipboard.writeText(out.text);
        toast(toastEl, `Copied ${out.count} rows to clipboard.`, 'ok');
      } else {
        download(`proxycheck-${demoTag}${Date.now()}.${out.ext}`, out.text, out.mime);
        toast(toastEl, `Exported ${out.count} rows.`, 'ok');
      }
      els.modal.classList.remove('open');
    } catch (e) {
      toast(toastEl, e.message || 'Export failed.', 'err');
    }
  }

  els.download.addEventListener('click', () => doExport(false));
  els.copy.addEventListener('click', () => doExport(true));
  els.close.addEventListener('click', () => els.modal.classList.remove('open'));
  els.modal.addEventListener('click', (e) => { if (e.target === els.modal) els.modal.classList.remove('open'); });

  return { syncCredNote };
}
