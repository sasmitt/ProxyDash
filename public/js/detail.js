/** Proxy detail drawer. */

import { esc, fmtMs, fmtTime } from './util.js';
import { state } from './state.js';

function item(k, v, mono = false, extra = '') {
  return `<div class="d-item"><div class="k">${esc(k)}</div><div class="v ${mono ? 'mono' : ''}">${v == null || v === '' ? 'Unknown' : v}${extra}</div></div>`;
}

function bool(v, yes = 'Supported', no = 'Failed', na = 'Unknown') {
  if (v === true) return `<span class="chip alive">${yes}</span>`;
  if (v === false) return `<span class="chip dead">${no}</span>`;
  return `<span class="chip neutral">${na}</span>`;
}

export function renderDetail(bodyEl, r) {
  if (!r) { bodyEl.innerHTML = '<p class="section-note">Select a proxy row.</p>'; return; }
  const g = r.geo || {};
  const lat = r.latency || {};
  const https = r.https || {};
  const anon = r.anonymity || {};
  const auth = r.auth || {};

  const headers = r.responseHeaders && Object.keys(r.responseHeaders).length
    ? `<table class="kv-table">${Object.entries(r.responseHeaders).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(String(v).slice(0, 160))}</td></tr>`).join('')}</table>`
    : '<p class="section-note">No response headers recorded.</p>';

  const evidence = anon.evidence && anon.evidence.length
    ? `<ul style="margin:6px 0 0;padding-left:18px;font-size:12.5px;color:var(--muted)">${anon.evidence.map((e) => `<li class="mono">${esc(e)}</li>`).join('')}</ul>`
    : '';

  bodyEl.innerHTML = `
    <div class="d-section">
      <h3>Connection</h3>
      <div class="d-grid">
        ${item('Input (masked)', `<span class="mono">${esc(r.input)}</span>`, true, '')}
        ${item('Detected protocol', r.protocol ? r.protocol.toUpperCase() : 'Unknown')}
        ${item('Host', esc(r.host), true)}
        ${item('Port', esc(r.port), true)}
        ${item('Requested protocol', String(r.requestedProtocol || 'auto').toUpperCase())}
        ${item('Authentication', authChipHtml(auth, r))}
      </div>
    </div>

    <div class="d-section">
      <h3>Result</h3>
      <div class="d-grid">
        ${item('Status', r.alive ? '<span class="chip alive">✓ ALIVE</span>' : '<span class="chip dead">✗ DEAD</span>')}
        ${item('Confidence', confChip(r.confidence))}
        ${item('HTTP status', r.httpStatus || '—', true)}
        ${item('Attempts', esc(r.attempts), true)}
        ${item('Last checked', esc(fmtTime(r.checkedAt)), true)}
        ${item('DNS behavior', esc(r.dns || 'Unknown'))}
      </div>
      ${r.alive && r.partial ? '<p class="d-note" style="margin-top:8px">Partially verified: the proxy relayed a response but the controlled test target could not be fully validated through it.</p>' : ''}
      ${!r.alive && r.errorCategory ? `<p class="d-note" style="margin-top:8px"><b>${esc(r.errorCategory)}</b> — ${esc(r.errorMessage || '')}</p>` : ''}
    </div>

    <div class="d-section">
      <h3>Exit &amp; geolocation <span class="section-note">· approximate</span></h3>
      <div class="d-grid">
        ${item('Exit IP', esc(r.exitIp || 'Unknown'), true)}
        ${item('Country', g.country ? `${esc(g.country)}${g.countryCode ? ` (${esc(g.countryCode)})` : ''}` : 'Unknown')}
        ${item('Region', esc(g.region))}
        ${item('City', esc(g.city))}
        ${item('Latitude', g.latitude != null ? esc(g.latitude) : null, true)}
        ${item('Longitude', g.longitude != null ? esc(g.longitude) : null, true)}
        ${item('Timezone', esc(g.timezone))}
        ${item('Geo source', esc(g.state === 'ok' ? g.source : g.state || 'Unknown'))}
      </div>
    </div>

    <div class="d-section">
      <h3>Network / ASN</h3>
      <div class="d-grid">
        ${item('ASN', esc(g.asn), true)}
        ${item('AS organization', esc(g.asOrg))}
        ${item('ISP / network', esc(g.isp))}
        ${item('Organization', esc(g.org))}
        ${item('Reverse DNS', esc(g.reverse), true)}
      </div>
    </div>

    <div class="d-section">
      <h3>Latency</h3>
      <div class="d-grid">
        ${item('Connection (TCP)', lat.tcpMs != null ? fmtMs(lat.tcpMs) : '—', true)}
        ${item('Handshake', lat.handshakeMs != null ? fmtMs(lat.handshakeMs) : '—', true)}
        ${item('First response', lat.requestMs != null ? fmtMs(lat.requestMs) : '—', true)}
        ${item('Total', lat.totalMs != null ? fmtMs(lat.totalMs) : '—', true)}
        ${item('Speed label', esc(r.bucket === 'unknown' ? '—' : r.bucket))}
      </div>
    </div>

    <div class="d-section">
      <h3>HTTPS / TLS <span class="section-note">· certificate validation always on</span></h3>
      <div class="d-grid">
        ${item('HTTPS tunnel', bool(https.supported))}
        ${item('TLS version', esc(https.tlsVersion || '—'), true)}
        ${item('Certificate', https.certValid === true ? '<span class="chip alive">VALID</span>' : https.certValid === false ? '<span class="chip dead">INVALID</span>' : '<span class="chip neutral">—</span>')}
        ${item('TLS exit IP', esc(https.exitIpTls || '—'), true)}
      </div>
      ${https.error ? `<p class="d-note" style="margin-top:8px">${esc(https.error)}</p>` : ''}
      ${https.note ? `<p class="d-note" style="margin-top:8px">${esc(https.note)}</p>` : ''}
    </div>

    <div class="d-section">
      <h3>Anonymity</h3>
      <div class="d-grid d-full">
        ${item('Classification', anonChipHtml(anon.level))}
      </div>
      <p class="d-note">${esc(anon.reason || 'Unknown')}</p>
      ${evidence}
    </div>

    <div class="d-section">
      <h3>HTTP response headers</h3>
      ${headers}
    </div>
  `;
}

function authChipHtml(auth, r) {
  if (auth.ok === false) return '<span class="chip dead">FAILED</span>';
  if (auth.required) return auth.ok === true ? '<span class="chip alive">SUCCESS</span>' : '<span class="chip warn">REQUIRED</span>';
  if (r && r.hasAuth) return '<span class="chip info">CREDS SUPPLIED</span>';
  return '<span class="chip neutral">NO AUTH</span>';
}

function confChip(c) {
  const map = {
    verified: ['alive', 'VERIFIED'],
    partial: ['warn', 'PARTIAL'],
    failed: ['dead', 'FAILED'],
    unknown: ['neutral', 'UNKNOWN'],
  };
  const [cls, label] = map[c] || map.unknown;
  return `<span class="chip ${cls}">${label}</span>`;
}

function anonChipHtml(level) {
  const map = {
    elite: ['alive', 'ELITE / HIGH ANONYMITY'],
    anonymous: ['info', 'ANONYMOUS'],
    transparent: ['warn', 'TRANSPARENT'],
    unknown: ['neutral', 'UNKNOWN'],
  };
  const [cls, label] = map[level] || map.unknown;
  return `<span class="chip ${cls}">${label}</span>`;
}

export function openDrawer(els, seq) {
  state.openSeq = seq;
  const r = state.results[seq];
  renderDetail(els.body, r);
  els.drawer.classList.add('open');
  els.backdrop.classList.add('open');
  els.close.focus();
}

export function closeDrawer(els) {
  state.openSeq = null;
  els.drawer.classList.remove('open');
  els.backdrop.classList.remove('open');
}
